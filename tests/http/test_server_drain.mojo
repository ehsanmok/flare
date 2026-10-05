"""Tests for ``HttpServer.drain`` and ``ShutdownReport``.

``HttpServer.close()`` is a hard stop that cuts in-flight handlers
mid-write; ``HttpServer.drain(timeout_ms) -> ShutdownReport`` is the
recommended graceful shutdown.

Covers:

- ``ShutdownReport`` is a value type with the documented four fields
  and a working constructor.
- ``HttpServer.drain(0)`` is a hard stop equivalent to ``close()``:
  ``_stopping`` becomes ``True`` and the listener closes.
- ``HttpServer.drain(timeout_ms > 0)`` returns a report with
  non-negative counts.
- A negative ``timeout_ms`` is clamped to ``0``.
- Re-exports from ``flare.http`` and the root ``flare`` package
  resolve.
- The unified reactor's shutdown tail flips ``Cancel.SHUTDOWN`` on
  live connections before closing them, and reports how many were
  still in flight.
"""

from std.memory import Pointer
from std.testing import assert_equal, assert_true, assert_false, TestSuite
from std.time import perf_counter_ns

from flare import ShutdownReport as RootShutdownReport
from flare.http import (
    HttpServer,
    Request,
    Response,
    ServerConfig,
    ShutdownReport,
)
from flare.http._reactor.tagged_dispatch import KIND_H1, _pack
from flare.http._server_reactor_epoll import _conn_alloc_addr
from flare.http._unified_reactor_impl import _drain_remaining_conns_unified
from flare.net import SocketAddr
from flare.runtime import Reactor, TimerWheel
from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime._thread import ThreadHandle
from flare.tcp import TcpListener, TcpStream


# ── ShutdownReport struct ────────────────────────────────────────────────────


def test_shutdown_report_constructor() raises:
    var r = ShutdownReport(
        drained=3, timed_out=1, in_flight_at_deadline=1, crashed=0
    )
    assert_equal(r.drained, 3)
    assert_equal(r.timed_out, 1)
    assert_equal(r.in_flight_at_deadline, 1)
    assert_equal(r.crashed, 0)


def test_shutdown_report_zero_state() raises:
    var r = ShutdownReport(
        drained=0, timed_out=0, in_flight_at_deadline=0, crashed=0
    )
    assert_equal(r.drained, 0)
    assert_equal(r.timed_out, 0)
    assert_equal(r.in_flight_at_deadline, 0)


# ── HttpServer.drain ─────────────────────────────────────────────────────────


def test_drain_hard_stop_with_zero_timeout() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var report = srv.drain(timeout_ms=0)
    # Zero timeout is a hard stop; drained=0 records that we did
    # not wait for any in-flight work to finish.
    assert_equal(report.drained, 0)
    assert_equal(report.timed_out, 0)
    assert_equal(report.in_flight_at_deadline, 0)
    assert_true(srv._stopping)


def test_drain_negative_timeout_clamped_to_zero() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    # Negative is clamped to 0 inside drain; behaves like a hard
    # stop and does not panic / return garbage.
    var report = srv.drain(timeout_ms=-100)
    assert_equal(report.drained, 0)
    assert_true(srv._stopping)


def test_drain_with_short_timeout_returns_report() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var report = srv.drain(timeout_ms=50)
    # Best-effort report: the single-threaded reactor cannot
    # observe per-conn drain progress without external state, so
    # we only verify the report is well-formed.
    assert_true(report.drained >= 0)
    assert_true(report.timed_out >= 0)
    assert_true(report.in_flight_at_deadline >= 0)
    assert_true(srv._stopping)


def test_drain_marks_stopping_idempotent() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    _ = srv.drain(0)
    assert_true(srv._stopping)
    # Calling drain again is benign — the listener is already
    # closed and ``_stopping`` is already True.
    _ = srv.drain(0)
    assert_true(srv._stopping)


# ── drain(timeout_ms) is graceful, not a hard stop (APP-46) ─────────────────

comptime _BIG_BODY = 16 * 1024 * 1024


def _big_response(req: Request) raises -> Response:
    var resp = Response(status=200)
    resp.body = List[UInt8](length=_BIG_BODY, fill=UInt8(97))
    return resp^


def _null_ptr() -> Pointer[UInt8, MutUntrackedOrigin]:
    var z = 0
    return Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=z)


def _serve_big_thread(
    arg: Pointer[UInt8, MutUntrackedOrigin]
) -> Pointer[UInt8, MutUntrackedOrigin]:
    var srv = arg.unsafe_bitcast[HttpServer]()
    try:
        srv[].serve(_big_response)
    except:
        pass
    return _null_ptr()


struct _SlowReader(Movable):
    var conn: TcpStream
    var total: Int

    def __init__(out self, var conn: TcpStream):
        self.conn = conn^
        self.total = 0


def _slow_read_thread(
    arg: Pointer[UInt8, MutUntrackedOrigin]
) -> Pointer[UInt8, MutUntrackedOrigin]:
    var r = arg.unsafe_bitcast[_SlowReader]()
    var buf = List[UInt8](length=65536, fill=UInt8(0))
    while True:
        var n: Int
        try:
            n = r[].conn.read(buf.unsafe_ptr(), len(buf))
        except:
            break
        if n <= 0:
            break
        r[].total += n
        _ = libc_nanosleep_ms(5)  # a slow client, not a synchronisation
    return _null_ptr()


def test_drain_lets_an_in_flight_response_finish() raises:
    """``drain(timeout_ms)`` ignored ``timeout_ms``: it set ``_stopping`` at
    once, and the reactor closed every live connection on its next poll,
    cutting a response still being written, exactly like ``close()``."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var addr = srv.local_addr()
    var srv_addr = Int(Pointer[HttpServer, _](to=srv))
    var th = ThreadHandle.spawn_os[_serve_big_thread](
        Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=srv_addr)
    )
    var conn = TcpStream.connect(addr)
    var req = String("GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
    conn.write_all(req.as_bytes())
    conn.set_recv_timeout(10000)
    var rd = _SlowReader(conn^)
    var rd_addr = Int(Pointer[_SlowReader, _](to=rd))
    var rt = ThreadHandle.spawn_os[_slow_read_thread](
        Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=rd_addr)
    )
    # Drain only once the response is in flight, then a little into it.
    for _ in range(250):
        if rd.total > 0:
            break
        _ = libc_nanosleep_ms(20)
    var started = rd.total > 0
    _ = libc_nanosleep_ms(100)

    var t0 = perf_counter_ns()
    _ = srv.drain(timeout_ms=3000)
    var drain_ms = Int((perf_counter_ns() - t0) // 1_000_000)

    rt.join()
    th.join()
    var total = rd.total
    rd.conn.close()
    assert_true(started, "no response bytes reached the client before drain")
    assert_true(
        total >= _BIG_BODY,
        "the in-flight response was cut after " + String(total) + " bytes",
    )
    assert_true(
        drain_ms >= 2900,
        "drain returned after " + String(drain_ms) + " ms, not the timeout",
    )


def test_drain_waits_out_the_timeout_before_stopping() raises:
    """With nothing in flight, ``drain(timeout_ms)`` still holds the
    window open for the full ``timeout_ms`` before it sets ``_stopping``."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var t0 = perf_counter_ns()
    _ = srv.drain(timeout_ms=250)
    var took = Int((perf_counter_ns() - t0) // 1_000_000)
    assert_true(took >= 250, "drain returned after " + String(took) + " ms")
    assert_true(took < 5000, "drain overshot: " + String(took) + " ms")
    assert_true(srv._stopping)


# ── Re-exports resolve from both barrels ────────────────────────────────────


def test_root_package_re_exports_shutdown_report() raises:
    var r = RootShutdownReport(
        drained=2, timed_out=0, in_flight_at_deadline=0, crashed=0
    )
    assert_equal(r.drained, 2)


# ── Reactor shutdown tail flips Cancel.SHUTDOWN ─────────────────────────────


def test_unified_drain_reports_in_flight_and_empties_table() raises:
    """The unified reactor's shutdown tail reports what it closed.

    The legacy epoll loop always flipped ``Cancel.SHUTDOWN`` on live
    connections at shutdown; the unified loop that ``serve()`` actually
    runs used to free them outright, so a cancel-aware handler or a
    streaming body got the socket pulled mid-chunk with no signal. The
    tail now flips first and returns the live count.

    The flip itself is not asserted here: the same call frees the
    handle, and ``CancelCell.__deinit__`` frees the cell, so reading the
    ``Cancel`` afterwards would be a use-after-free. That
    ``signal_drain`` flips every stream cell is covered directly by
    tests/http2/test_h2_per_stream_cancel.mojo; this pins the count
    and the table teardown, which are what the caller observes.
    """
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var accepted = listener.accept()

    var reactor = Reactor()
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    var fd = Int(accepted._socket.fd)
    conns[fd] = _pack(KIND_H1, _conn_alloc_addr(accepted^))

    var wheel = TimerWheel(now_ms=UInt64(0))
    var still_live = _drain_remaining_conns_unified(
        conns, timers, reactor, wheel
    )

    assert_equal(still_live, 1, "drain must report the live connection")
    assert_equal(len(conns), 0, "drain must empty the conn table")
    client.close()
    listener.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
