"""HTTP/1.1 client connection pool.

Idle-connection reuse for :class:`flare.http.HttpClient`. Avoids
the per-request TCP / TLS handshake when consecutive requests
target the same origin (RFC 7230 §6.3 keep-alive semantics on the
client side).

The pool is keyed on ``(scheme, host, port)`` -- one idle deque
per origin. ``acquire(key)`` pops the most recently inserted fd
(LIFO so the warmest TCP / TLS state is reused first); ``release``
pushes the fd back onto the deque if there's room; otherwise the
fd is closed. A first read on a freshly-acquired fd that returns
0 (peer closed the keep-alive idly) signals stale, and the caller
retries on a fresh connection (RFC 7230 §6.3.1).

Scope -- the pool is deliberately kept small:

* Plain TCP (``http://``) only. ``https://`` requests still
  full-handshake every time; the TLS resumption work in
  ``flare/tls/`` (Commit 04) lets that handshake be much cheaper,
  and a follow-up commit ties the pool key to the negotiated ALPN
  + the TLS session ticket fingerprint so reusable TLS
  connections land in the same bucket.
* No background eviction thread -- idle entries are evicted
  lazily on the next ``acquire(key)`` if their wallclock-age has
  exceeded :attr:`idle_timeout_ms`.
* Per-host cap (``max_idle_per_host``) and total cap
  (``max_idle_total``) bound memory; over-cap fds are closed
  immediately on release rather than queued.
* Synchronous, single-threaded -- the pool is owned by an
  ``HttpClient`` instance, and ``HttpClient`` is ``Movable`` (not
  ``Copyable``), so the pool is never shared across threads.
  Multi-worker pooling is a future addition.

The ``ClientPool`` struct itself is a thin handle holding the
heap address of an internal ``_ClientPoolState`` (mirrors the
Cancel / Pool ownership patterns used elsewhere in the codebase).
``HttpClient`` stores the address and re-materialises a typed
pointer on every access; on ``HttpClient.__del__`` the state is
freed and any remaining fds are closed.
"""

from std.collections import Dict
from std.ffi import c_int, external_call
from std.memory import UnsafePointer, alloc

from flare.net._libc import _close


# ── _ClientPoolState (heap-allocated) ────────────────────────────────────────


@fieldwise_init
struct _ClientPoolState(Movable):
    """The mutable state behind a :class:`ClientPool` handle.

    Heap-allocated (one per ``ClientPool`` instance). Holds the
    per-origin idle fd deques + the policy knobs. All access goes
    through the typed UnsafePointer materialised by
    :meth:`ClientPool._state` -- the struct is never moved
    in-place after the initial allocation.
    """

    var entries: Dict[String, List[Int]]
    """``key -> [fd, ...]``. ``key`` is the canonicalised origin
    string (``scheme://host:port``); each list is the LIFO idle
    deque of fds for that origin. The list grows on
    :meth:`ClientPool.release` and shrinks on
    :meth:`ClientPool.acquire`."""

    var insertion_ts_ms: Dict[Int, Int]
    """Per-fd insertion timestamp in milliseconds (CLOCK_MONOTONIC).
    Used by :meth:`ClientPool.acquire` to evict entries whose age
    has exceeded :attr:`idle_timeout_ms`. Drained alongside
    ``entries`` so a closed fd never lingers in the timestamp
    map."""

    var max_idle_per_host: Int
    """Maximum number of idle fds the pool keeps per origin.
    Releases above this cap close the fd immediately. Default
    ``8`` (matches Go's ``net/http.Transport``)."""

    var max_idle_total: Int
    """Maximum number of idle fds the pool keeps across all
    origins. Releases above this cap close the fd immediately.
    Default ``64``. ``0`` disables the total cap."""

    var idle_timeout_ms: Int
    """How long an fd may sit idle before being evicted on the
    next :meth:`ClientPool.acquire`. Default ``90_000`` ms
    (matches the Linux kernel's default ``tcp_keepalive_time / 4``
    -- well below typical NAT timeout, well below typical
    server-side idle timeout). ``0`` disables timeout-based
    eviction."""


# ── ClientPool ───────────────────────────────────────────────────────────────


struct ClientPool(Copyable, Movable):
    """Idle-connection pool handle.

    ``Copyable`` because the wrapped state is heap-allocated and
    every copy points to the same ``_ClientPoolState``. The
    OWNER (the original creator -- typically an
    :class:`HttpClient`) is responsible for calling :meth:`free`
    once it's done; copies created during normal use (e.g. by
    Mojo's implicit copy on argument passing) MUST NOT call
    :meth:`free`.

    The pool is an HTTP/1.1 building block; see the module
    docstring for scope.
    """

    var _addr: Int
    """Heap address of the ``_ClientPoolState`` instance. ``0``
    means "no pool" (an :class:`HttpClient` with pooling
    disabled)."""

    @staticmethod
    def disabled() -> ClientPool:
        """Return the no-op handle (``_addr == 0``).

        Equivalent to ``HttpClient(...)`` without pooling: every
        :meth:`acquire` returns ``-1`` and every :meth:`release`
        closes the fd immediately.
        """
        return ClientPool(0)

    @staticmethod
    def new(
        max_idle_per_host: Int = 8,
        max_idle_total: Int = 64,
        idle_timeout_ms: Int = 90_000,
    ) raises -> ClientPool:
        """Allocate a fresh pool with the given caps.

        Args:
            max_idle_per_host: Per-origin idle cap (RFC 7230
                §6.3 keep-alive parallelism budget). 0 disables
                idle-keeping for that origin.
            max_idle_total: Total idle cap across all origins.
                0 disables the total cap.
            idle_timeout_ms: Max wallclock age for a pooled fd
                before it's evicted on the next acquire(key).
                0 disables timeout eviction.
        """
        var p = alloc[_ClientPoolState](1)
        p.init_pointee_move(
            _ClientPoolState(
                Dict[String, List[Int]](),
                Dict[Int, Int](),
                max_idle_per_host,
                max_idle_total,
                idle_timeout_ms,
            )
        )
        return ClientPool(Int(p))

    @always_inline
    def __init__(out self, addr: Int):
        self._addr = addr

    @always_inline
    def enabled(read self) -> Bool:
        """Return ``True`` when ``_addr != 0`` (pooling is on)."""
        return self._addr != 0

    def _state(
        read self,
    ) -> UnsafePointer[_ClientPoolState, MutUntrackedOrigin]:
        """Re-materialise a typed pointer from :attr:`_addr`.

        Mirrors the :class:`flare.http.cancel.Cancel` pattern --
        the typed pointer is rebuilt per access so Mojo's optimiser
        cannot hoist a stale load across function boundaries.
        """
        return UnsafePointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=self._addr
        ).bitcast[_ClientPoolState]()

    @staticmethod
    def build_key(scheme: String, host: String, port: Int) -> String:
        """Canonicalise the origin into a single-string lookup key.

        Format: ``scheme://host:port``. ``port`` is always emitted
        explicitly (no default-port elision) so a pooled
        ``http://api/`` fd can never land in an ``http://api:8080/``
        bucket by accident. Used by both :meth:`acquire` and
        :meth:`release`.
        """
        var key = scheme + "://" + host + ":" + String(port)
        return key^

    def acquire(read self, key: String) raises -> Int:
        """Pop the most-recently-inserted idle fd for ``key``.

        Evicts every fd whose age exceeds
        :attr:`_ClientPoolState.idle_timeout_ms` before pulling
        from the deque (the eviction is lazy / on-acquire, not
        background-driven).

        Returns:
            The fd, or ``-1`` when no idle entry is available
            (pooling disabled, deque empty, or the freshest entry
            was timed out).
        """
        if not self.enabled():
            return -1
        var sp = self._state()
        if key not in sp[].entries:
            return -1
        var now_ms = _monotonic_ms()
        var deque = sp[].entries[key].copy()
        # LIFO with timeout-eviction: pop from the back; if it's
        # too old, ``_close`` it and try the next one. Any survivor
        # is the fd we hand out.
        while len(deque) > 0:
            var fd = deque[len(deque) - 1]
            deque.resize(len(deque) - 1, 0)
            var inserted = sp[].insertion_ts_ms[fd]
            _ = sp[].insertion_ts_ms.pop(fd)
            if (
                sp[].idle_timeout_ms > 0
                and (now_ms - inserted) > sp[].idle_timeout_ms
            ):
                _ = _close(c_int(fd))
                continue
            sp[].entries[key] = deque^
            return fd
        # Deque was drained empty -- remove the key so future
        # ``acquire`` calls don't pay for the empty-list lookup.
        _ = sp[].entries.pop(key)
        return -1

    def release(read self, key: String, fd: Int) raises -> None:
        """Hand ``fd`` back to the pool for ``key``, or close it
        if the cap is reached.

        ``fd`` must be in keep-alive shape -- the caller has
        already confirmed the response was completely read AND the
        server didn't send ``Connection: close``. ``release`` does
        NOT validate this; it trusts the caller.
        """
        if not self.enabled():
            _ = _close(c_int(fd))
            return
        var sp = self._state()
        if sp[].max_idle_per_host <= 0:
            _ = _close(c_int(fd))
            return
        if (
            sp[].max_idle_total > 0
            and self._total_idle() >= sp[].max_idle_total
        ):
            _ = _close(c_int(fd))
            return
        var deque: List[Int]
        if key in sp[].entries:
            deque = sp[].entries[key].copy()
        else:
            deque = List[Int]()
        if len(deque) >= sp[].max_idle_per_host:
            _ = _close(c_int(fd))
            sp[].entries[key] = deque^
            return
        deque.append(fd)
        sp[].entries[key] = deque^
        sp[].insertion_ts_ms[fd] = _monotonic_ms()

    def _total_idle(read self) -> Int:
        """Return the sum of every per-origin deque length.

        Linear in the number of origins -- the pool size is
        expected to be small (single-digit origins for typical
        client workloads). If that assumption breaks, replace with
        an explicitly maintained counter on the state.
        """
        if not self.enabled():
            return 0
        var sp = self._state()
        var total = 0
        for entry in sp[].entries.items():
            total += len(entry.value)
        return total

    def total_idle(read self) -> Int:
        """Public mirror of :meth:`_total_idle` for tests + the
        :meth:`HttpClient.idle_count` accessor."""
        return self._total_idle()

    def free(mut self) raises -> None:
        """Close every pooled fd and free the state.

        Idempotent on ``_addr == 0``: a no-op on a moved-from /
        disabled handle. After ``free`` returns, ``_addr`` is set
        to ``0`` so subsequent ``__del__`` calls (e.g. from a
        moved-from copy) are no-ops.
        """
        if self._addr == 0:
            return
        var sp = self._state()
        for entry in sp[].entries.items():
            for i in range(len(entry.value)):
                _ = _close(c_int(entry.value[i]))
        sp.destroy_pointee()
        sp.free()
        self._addr = 0


# ── monotonic clock helper ──────────────────────────────────────────────────


def _monotonic_ms() -> Int:
    """Return ``CLOCK_MONOTONIC`` in milliseconds.

    Uses the Linux ``clock_gettime`` FFI; on macOS the symbol
    resolves through the libSystem shim that ships with the
    OS. Falls back to ``0`` on FFI failure -- in that case the
    timeout-eviction logic in :meth:`ClientPool.acquire` becomes
    a no-op (every entry's age computes to 0), which is
    conservative.
    """
    var ts_buf = alloc[Int](2)
    ts_buf[0] = 0
    ts_buf[1] = 0
    # CLOCK_MONOTONIC = 1 on linux + macos.
    var rc = external_call["clock_gettime", c_int](c_int(1), ts_buf)
    if Int(rc) != 0:
        ts_buf.free()
        return 0
    var sec = ts_buf[0]
    var nsec = ts_buf[1]
    ts_buf.free()
    return sec * 1000 + nsec // 1_000_000
