# PLATFORM: any
"""APP-46: single-worker HttpServer.drain(timeout_ms) ignores timeout_ms and
cuts in-flight responses like close().

Lean: Flare.L4.Drain.drain_ignores_timeout, Flare.Bugs.APP_46.violates_spec
(counterexample) and Flare.Bugs.APP_46.fixed_meets_spec (fix meets spec).
flare/http/server.mojo:1694-1755 @59bda50 (drain sets _stopping and returns
at once), flare/http/_unified_reactor_impl.mojo:1103-1170 and 1000-1046
(the loop exits on the next poll and closes every live connection).

Documented contract: close() (server.mojo:1680-1689) is the "hard stop"
where "in-flight handlers may be cut mid-write -- there is no wait. Use
drain(timeout_ms) for a graceful tear-down"; drain (1695-1701) "waits up to
timeout_ms milliseconds for in-flight reactor events to flush ... and
force-closes everything else when the deadline elapses"; Notes (1729-1731):
"The drain timeout bounds the wait for handlers to return".

Scenario: serve() runs on a second thread (the production shape the drain
example describes). A client requests a 32 MiB response and reads it
slowly: a reader thread takes 64 KiB every 5 ms, so the response sits in
STATE_WRITING for about 2.5 s. 200 ms in, the main thread calls
drain(timeout_ms=5000).

Expected: drain gives the reactor up to 5 s to flush the response; the
client receives all 32 MiB.
Actual: drain returns within milliseconds, the reactor loop exits on its
next poll and closes the connection; the client receives a truncated body.

Minimal fix: in drain, after closing the listener, wait up to timeout_ms
(in short sleeps) before setting _stopping, so the running reactor keeps
flushing in-flight connections during the window.
"""

from std.memory import Pointer
from std.time import perf_counter_ns

from flare.http import HttpServer, Request, Response
from flare.net import SocketAddr
from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime._thread import ThreadHandle
from flare.tcp import TcpStream

comptime BODY = 32 * 1024 * 1024


def _big(req: Request) raises -> Response:
    var resp = Response(status=200)
    resp.body = List[UInt8](length=BODY, fill=UInt8(97))
    return resp^


def _null() -> Pointer[UInt8, MutUntrackedOrigin]:
    var z = 0
    return Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=z)


def _serve_thread(
    arg: Pointer[UInt8, MutUntrackedOrigin]
) -> Pointer[UInt8, MutUntrackedOrigin]:
    var srv = arg.unsafe_bitcast[HttpServer]()
    try:
        srv[].serve(_big)
    except:
        pass
    return _null()


struct Reader(Movable):
    var c: TcpStream
    var total: Int

    def __init__(out self, var c: TcpStream):
        self.c = c^
        self.total = 0


def _read_thread(
    arg: Pointer[UInt8, MutUntrackedOrigin]
) -> Pointer[UInt8, MutUntrackedOrigin]:
    var r = arg.unsafe_bitcast[Reader]()
    var buf = List[UInt8](length=65536, fill=UInt8(0))
    while True:
        var n: Int
        try:
            n = r[].c.read(buf.unsafe_ptr(), len(buf))
        except:
            break
        if n <= 0:
            break
        r[].total += n
        _ = libc_nanosleep_ms(5)
    return _null()


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var addr = srv.local_addr()
    var srv_addr = Int(Pointer[HttpServer, _](to=srv))
    var th = ThreadHandle.spawn_os[_serve_thread](
        Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=srv_addr)
    )

    var c = TcpStream.connect(addr)
    var req = String("GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
    c.write_all(req.as_bytes())
    c.set_recv_timeout(10000)
    var rd = Reader(c^)
    var rd_addr = Int(Pointer[Reader, _](to=rd))
    var rt = ThreadHandle.spawn_os[_read_thread](
        Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=rd_addr)
    )
    # Drain only once the response is in flight (the reactor has accepted
    # the connection and started writing), then 200 ms into it.
    for _ in range(250):
        if rd.total > 0:
            break
        _ = libc_nanosleep_ms(20)
    var started = rd.total > 0
    _ = libc_nanosleep_ms(200)

    var t0 = perf_counter_ns()
    var report = srv.drain(timeout_ms=5000)
    var drain_ms = Int((perf_counter_ns() - t0) // 1_000_000)

    rt.join()
    th.join()
    var total = rd.total
    rd.c.close()

    if not started:
        print("inconclusive: no response bytes reached the client before drain")
        raise Error("APP-46 inconclusive")
    if total < BODY:
        print(
            "BUG REPRODUCED: drain(timeout_ms=5000) returned after "
            + String(drain_ms)
            + " ms (report drained="
            + String(report.drained)
            + " in_flight="
            + String(report.in_flight_at_deadline)
            + ") and the in-flight 32 MiB response was cut: the client"
            + " (reading 64 KiB every 5 ms) got "
            + String(total)
            + " bytes"
        )
        raise Error("APP-46")
    print(
        "OK: in-flight response fully delivered during drain ("
        + String(total)
        + " bytes, drain took "
        + String(drain_ms)
        + " ms)"
    )
