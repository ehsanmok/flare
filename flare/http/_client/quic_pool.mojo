"""HTTP/3 (QUIC) client connection pool.

Idle-connection reuse for the :meth:`flare.http.HttpClient._send_h3`
path. A QUIC + TLS handshake is far more expensive than a TCP one, so
keeping an established, control-streams-open
:class:`flare.h3.client.H3ClientConnection` around and reusing it for
the next request to the same origin is the dominant latency win for
back-to-back h3 requests.

The pool mirrors :class:`flare.http.client_pool.ClientPool`:

* Keyed on ``host:port`` -- one LIFO idle deque per origin (warmest
  connection reused first).
* Per-host idle cap + wallclock idle-timeout eviction on
  :meth:`acquire`.
* A thin ``Copyable`` handle over a single heap-allocated
  ``_QuicPoolState`` (pointer-backed interior mutability) so the
  owning ``HttpClient`` can acquire / release from a ``read self``
  method (``_send_h3`` stays read-self, like the Alt-Svc store). The
  OWNER frees the state in ``__del__``; copies must not.

Unlike the h1 pool -- which stores raw fds (``Int``) -- this pool
stores whole ``H3ClientConnection`` values. They are ``Movable`` (a
socket fd + a rustls session can't be copied), so each idle
connection lives in its own heap cell via :class:`flare.runtime.pool.Pool`
and the deque holds the cell addresses (with a parallel
``addr -> insertion-ms`` map for idle-timeout eviction, mirroring the
h1 pool's per-fd timestamp map). ``acquire`` moves the connection out
of its cell; ``release`` moves a connection into a fresh cell.
Dropping a cell runs ``UdpSocket.__del__`` which closes the fd;
:meth:`free` first sends a graceful CONNECTION_CLOSE.

A ``dials`` counter records how many times the owner had to open a
fresh connection (a pool miss). Tests assert it stays at 1 across two
sequential same-origin requests, proving reuse.
"""

from std.collections import Dict, List, Optional
from std.ffi import c_int, external_call
from std.memory import UnsafePointer, alloc

from flare.h3.client import H3ClientConnection
from flare.runtime.pool import Pool


@fieldwise_init
struct _QuicPoolState(Movable):
    """Mutable state behind a :class:`QuicConnectionPool` handle.

    Heap-allocated once; all access goes through the typed pointer
    re-materialised by :meth:`QuicConnectionPool._state`.
    """

    var entries: Dict[String, List[Int]]
    """``host:port -> [cell_addr, ...]`` LIFO idle deque of
    ``H3ClientConnection`` heap-cell addresses."""

    var ts_ms: Dict[Int, Int]
    """``cell_addr -> insertion monotonic-ms``, for idle-timeout
    eviction. Drained alongside ``entries`` so a freed cell never
    lingers."""

    var max_idle_per_host: Int
    """Per-origin idle cap. Releases above this close the connection."""

    var idle_timeout_ms: Int
    """Max wallclock age before an idle connection is evicted on the
    next :meth:`acquire`. ``0`` disables timeout eviction."""

    var dials: Int
    """Count of pool-miss dials the owner reported via
    :meth:`note_dial` -- observability + reuse assertions."""


struct QuicConnectionPool(Copyable, Movable):
    """Idle h3-connection pool handle (pointer-backed)."""

    var _addr: Int
    """Heap address of the ``_QuicPoolState``; ``0`` = pooling off."""

    @staticmethod
    def disabled() -> QuicConnectionPool:
        """The no-op handle: every acquire misses, every release
        drops the connection."""
        return QuicConnectionPool(0)

    @staticmethod
    def new(
        max_idle_per_host: Int = 8,
        idle_timeout_ms: Int = 90_000,
    ) -> QuicConnectionPool:
        """Allocate an enabled pool. Non-raising (the allocation +
        moves can't raise) so it can initialize a ``read self``
        ``HttpClient`` field eagerly, like the Alt-Svc store."""
        var p = alloc[_QuicPoolState](1)
        p.init_pointee_move(
            _QuicPoolState(
                Dict[String, List[Int]](),
                Dict[Int, Int](),
                max_idle_per_host,
                idle_timeout_ms,
                0,
            )
        )
        return QuicConnectionPool(Int(p))

    @always_inline
    def __init__(out self, addr: Int):
        self._addr = addr

    @always_inline
    def enabled(read self) -> Bool:
        return self._addr != 0

    def _state(
        read self,
    ) -> UnsafePointer[_QuicPoolState, MutUntrackedOrigin]:
        return UnsafePointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=self._addr
        ).bitcast[_QuicPoolState]()

    @staticmethod
    def build_key(host: String, port: Int) -> String:
        """Canonical ``host:port`` lookup key (port always explicit so
        a ``:443`` connection never lands in a ``:8443`` bucket)."""
        return host + ":" + String(port)

    def note_dial(read self) -> None:
        """Record that the owner opened a fresh connection (pool
        miss). No-op when pooling is disabled."""
        if not self.enabled():
            return
        var sp = self._state()
        sp[].dials += 1

    def dials(read self) -> Int:
        """How many fresh dials the owner has reported."""
        if not self.enabled():
            return 0
        return self._state()[].dials

    def acquire(read self, key: String) raises -> Optional[H3ClientConnection]:
        """Move out the most-recently-released idle connection for
        ``key``, evicting any that exceeded the idle timeout first.
        Returns ``None`` on a miss (pooling off, deque empty, or all
        survivors timed out)."""
        if not self.enabled():
            return None
        var sp = self._state()
        if key not in sp[].entries:
            return None
        var now_ms = _monotonic_ms()
        var deque = sp[].entries[key].copy()
        while len(deque) > 0:
            var addr = deque[len(deque) - 1]
            deque.resize(len(deque) - 1, 0)
            var inserted = sp[].ts_ms.pop(addr)
            if (
                sp[].idle_timeout_ms > 0
                and (now_ms - inserted) > sp[].idle_timeout_ms
            ):
                # Stale: drop the cell (UdpSocket.__del__ closes fd).
                Pool[H3ClientConnection].free(addr)
                continue
            var cell = Pool[H3ClientConnection].get_ptr(addr)
            var h3 = cell.take_pointee()
            cell.free()
            sp[].entries[key] = deque^
            return Optional(h3^)
        _ = sp[].entries.pop(key)
        return None

    def release(read self, key: String, var h3: H3ClientConnection) raises:
        """Hand ``h3`` back for reuse, or drop it (closing the fd via
        its destructor) when pooling is off or the per-host cap is
        reached."""
        if not self.enabled():
            h3.close()
            return
        var sp = self._state()
        if sp[].max_idle_per_host <= 0:
            h3.close()
            return
        var deque: List[Int]
        if key in sp[].entries:
            deque = sp[].entries[key].copy()
        else:
            deque = List[Int]()
        if len(deque) >= sp[].max_idle_per_host:
            h3.close()
            sp[].entries[key] = deque^
            return
        var addr = Pool[H3ClientConnection].alloc_move(h3^)
        deque.append(addr)
        sp[].entries[key] = deque^
        sp[].ts_ms[addr] = _monotonic_ms()

    def idle_count(read self) -> Int:
        """Total idle connections across all origins."""
        if not self.enabled():
            return 0
        var sp = self._state()
        var total = 0
        for entry in sp[].entries.items():
            total += len(entry.value)
        return total

    def free(mut self) raises -> None:
        """Gracefully CONNECTION_CLOSE + drop every idle connection
        and free the state. Idempotent on a disabled / moved-from
        handle."""
        if self._addr == 0:
            return
        var sp = self._state()
        for entry in sp[].entries.items():
            for i in range(len(entry.value)):
                var addr = entry.value[i]
                # Graceful CONNECTION_CLOSE in place, then destroy the
                # cell (UdpSocket.__del__ closes the fd idempotently).
                Pool[H3ClientConnection].get_ptr(addr)[].quic.shutdown()
                Pool[H3ClientConnection].free(addr)
        sp.destroy_pointee()
        sp.free()
        self._addr = 0


def _monotonic_ms() -> Int:
    """``CLOCK_MONOTONIC`` in milliseconds; ``0`` on FFI failure
    (which makes idle-timeout eviction a conservative no-op)."""
    var ts_buf = alloc[Int](2)
    ts_buf[0] = 0
    ts_buf[1] = 0
    var rc = external_call["clock_gettime", c_int](c_int(1), ts_buf)
    if Int(rc) != 0:
        ts_buf.free()
        return 0
    var sec = ts_buf[0]
    var nsec = ts_buf[1]
    ts_buf.free()
    return sec * 1000 + nsec // 1_000_000
