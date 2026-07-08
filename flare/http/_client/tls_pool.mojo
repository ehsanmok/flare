"""HTTPS (TLS) HTTP/1.1 client connection pool.

Idle-connection reuse for the TLS HTTP/1.1 leg of
:meth:`flare.http.HttpClient._send_h2_or_h1_tls`. A TLS handshake is
much more expensive than a TCP one, so keeping an established
``http/1.1``-negotiated :class:`flare.tls.TlsStream` around and reusing
it for the next request to the same origin removes the per-request
handshake on back-to-back HTTPS requests.

Unlike :class:`flare.http.client_pool.ClientPool` -- which stores raw
fds (``Int``) because a cleartext keep-alive connection has no state
beyond the socket -- this pool stores whole ``TlsStream`` values. A TLS
connection's session lives in the OpenSSL ``SSL*`` the stream owns;
reusing only the fd would force a fresh handshake and defeat the point.
``TlsStream`` is ``Movable`` (an ``SSL*`` cannot be copied), so each
idle stream lives in its own heap cell via
:class:`flare.runtime.pool.Pool` and the deque holds the cell addresses
(with a parallel ``addr -> insertion-ms`` map for idle-timeout
eviction, mirroring the h1 pool's per-fd timestamp map). ``acquire``
moves the stream out of its cell; ``release`` moves a stream into a
fresh cell. Dropping a cell runs ``TlsStream.__del__`` which sends
``close_notify`` and frees the OpenSSL objects.

The pool is keyed on ``scheme://host:port`` (port always explicit so a
``:443`` connection never lands in a ``:8443`` bucket). Only the
``http/1.1`` ALPN result is pooled here; an ``h2`` connection is
multiplexed and handled on the h2 path, never returned to this pool.
"""

from std.collections import Dict, List, Optional
from std.ffi import c_int, external_call
from std.memory import UnsafePointer, alloc
from std.sys.info import CompilationTarget

from ...tls import TlsStream
from ...runtime.pool import Pool

# CLOCK_MONOTONIC clock id: 1 on Linux, 6 on Darwin/macOS (id 1 is
# undefined there, so clock_gettime would fail and the clock read 0).
comptime _CLOCK_MONOTONIC: c_int = c_int(
    6
) if CompilationTarget.is_macos() else c_int(1)


@fieldwise_init
struct _TlsPoolState(Movable):
    """Mutable state behind a :class:`TlsConnectionPool` handle.

    Heap-allocated once; all access goes through the typed pointer
    re-materialised by :meth:`TlsConnectionPool._state`.
    """

    var entries: Dict[String, List[Int]]
    """``scheme://host:port -> [cell_addr, ...]`` LIFO idle deque of
    ``TlsStream`` heap-cell addresses."""

    var ts_ms: Dict[Int, Int]
    """``cell_addr -> insertion monotonic-ms``, for idle-timeout
    eviction. Drained alongside ``entries`` so a freed cell never
    lingers."""

    var max_idle_per_host: Int
    """Per-origin idle cap. Releases above this close the stream."""

    var idle_timeout_ms: Int
    """Max wallclock age before an idle stream is evicted on the next
    :meth:`acquire`. ``0`` disables timeout eviction."""


struct TlsConnectionPool(Copyable, Movable):
    """Idle TLS h1-connection pool handle (pointer-backed).

    ``Copyable`` because the wrapped state is heap-allocated and every
    copy points to the same ``_TlsPoolState``. The OWNER (the
    :class:`HttpClient`) frees the state in ``__del__``; copies made
    during normal use must not.
    """

    var _addr: Int
    """Heap address of the ``_TlsPoolState``; ``0`` = pooling off."""

    @staticmethod
    def disabled() -> TlsConnectionPool:
        """The no-op handle: every acquire misses, every release drops
        the stream."""
        return TlsConnectionPool(0)

    @staticmethod
    def new(
        max_idle_per_host: Int = 8,
        idle_timeout_ms: Int = 90_000,
    ) -> TlsConnectionPool:
        """Allocate an enabled pool. Non-raising so it can initialize a
        ``read self`` ``HttpClient`` field eagerly, like the QUIC pool
        and the Alt-Svc store."""
        var p = alloc[_TlsPoolState](1)
        p.init_pointee_move(
            _TlsPoolState(
                Dict[String, List[Int]](),
                Dict[Int, Int](),
                max_idle_per_host,
                idle_timeout_ms,
            )
        )
        return TlsConnectionPool(Int(p))

    @always_inline
    def __init__(out self, addr: Int):
        self._addr = addr

    @always_inline
    def enabled(read self) -> Bool:
        return self._addr != 0

    def _state(
        read self,
    ) -> UnsafePointer[_TlsPoolState, MutUntrackedOrigin]:
        return UnsafePointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=self._addr
        ).bitcast[_TlsPoolState]()

    @staticmethod
    def build_key(scheme: String, host: String, port: Int) -> String:
        """Canonical ``scheme://host:port`` lookup key (port always
        explicit so a ``:443`` connection never lands in a ``:8443``
        bucket)."""
        return scheme + "://" + host + ":" + String(port)

    def acquire(read self, key: String) raises -> Optional[TlsStream]:
        """Move out the most-recently-released idle stream for ``key``,
        evicting any that exceeded the idle timeout first. Returns
        ``None`` on a miss (pooling off, deque empty, or all survivors
        timed out)."""
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
                # Stale: drop the cell (TlsStream.__del__ closes it).
                Pool[TlsStream].free(addr)
                continue
            var cell = Pool[TlsStream].get_ptr(addr)
            var stream = cell.take_pointee()
            cell.free()
            sp[].entries[key] = deque^
            return Optional(stream^)
        _ = sp[].entries.pop(key)
        return None

    def release(read self, key: String, var stream: TlsStream) raises:
        """Hand ``stream`` back for reuse, or drop it (closing it via
        its destructor) when pooling is off or the per-host cap is
        reached."""
        if not self.enabled():
            stream.close()
            return
        var sp = self._state()
        if sp[].max_idle_per_host <= 0:
            stream.close()
            return
        var deque: List[Int]
        if key in sp[].entries:
            deque = sp[].entries[key].copy()
        else:
            deque = List[Int]()
        if len(deque) >= sp[].max_idle_per_host:
            stream.close()
            sp[].entries[key] = deque^
            return
        var addr = Pool[TlsStream].alloc_move(stream^)
        deque.append(addr)
        sp[].entries[key] = deque^
        sp[].ts_ms[addr] = _monotonic_ms()

    def idle_count(read self) -> Int:
        """Total idle TLS streams across all origins."""
        if not self.enabled():
            return 0
        var sp = self._state()
        var total = 0
        for entry in sp[].entries.items():
            total += len(entry.value)
        return total

    def free(mut self) raises -> None:
        """Drop every idle stream (each ``__del__`` sends close_notify)
        and free the state. Idempotent on a disabled / moved-from
        handle."""
        if self._addr == 0:
            return
        var sp = self._state()
        for entry in sp[].entries.items():
            for i in range(len(entry.value)):
                Pool[TlsStream].free(entry.value[i])
        sp.destroy_pointee()
        sp.free()
        self._addr = 0


def _monotonic_ms() -> Int:
    """``CLOCK_MONOTONIC`` in milliseconds; ``0`` on FFI failure
    (which makes idle-timeout eviction a conservative no-op)."""
    var ts_buf = alloc[Int](2)
    ts_buf[0] = 0
    ts_buf[1] = 0
    var rc = external_call["clock_gettime", c_int](_CLOCK_MONOTONIC, ts_buf)
    if Int(rc) != 0:
        ts_buf.free()
        return 0
    var sec = ts_buf[0]
    var nsec = ts_buf[1]
    ts_buf.free()
    return sec * 1000 + nsec // 1_000_000
