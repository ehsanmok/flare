# PLATFORM: linux
"""CONC-07: an idle io_uring buffer-ring worker never sees the stop flag, so
Scheduler.shutdown() hangs and drain(timeout_ms) detaches every idle worker.

Lean: Flare.Bugs.CONC_07.shutdown_never_returns (for every N, a run that
meets every timing hypothesis except a bounded poll, where N ms after the
stop the worker is still in its poll and shutdown is still joining it),
Flare.Bugs.CONC_07.drain_detaches_idle (drain with any deadline detaches the
idle worker) and Flare.L5.Timed.teardown_done_by / drain_joins_all (with a
capped wait, as on the epoll/kqueue path, both complete within a stated
bound and drain detaches nobody).
flare/http/_server_reactor_uring.mojo:820-852 (the ring is built with
enable_wakeup=False and the loop calls ureactor.poll(1, ...)) and
flare/runtime/uring_reactor.mojo:834-836 (poll(1) with nothing ready blocks
in io_uring_enter(min_complete=1) with no timeout) @59bda50. The scheduler
side is flare/runtime/scheduler.mojo:655-668,746-760 (shutdown stores the
stop flag, then joins) and :829-852 (drain detaches workers that have not
returned by the deadline).

The path is taken by HttpFrontend when io_uring is available and
config.use_bufring is set (frontend.mojo:126-160; HttpServer sets it from
FLARE_BUFRING_HANDLER). The epoll/kqueue loops re-read the flag at least
every 100 ms (_poll_timeout_ms, flare/http/_reactor/lifecycle.mojo:31-47);
this loop re-reads it only when some completion arrives.

Expected: once the stop flag is set, an idle worker returns within about one
poll cap, so drain(2000) joins it (drained == 1) and shutdown() returns.
Actual: the idle worker stays in io_uring_enter; drain(2000) reports it
detached (drained == 0), and the worker returns only after a client
connection produces an accept completion. shutdown() would block in
pthread_join until such a connection arrives.

Deterministic: one worker, no traffic, 300 ms for it to arm and block, a
2000 ms drain budget (20 times the epoll cap), then one connect to release
it so the process exits cleanly.

Minimal fix: bound the wait. For example, keep one IORING_OP_TIMEOUT
(100 ms, relative) armed on the ring and re-arm it when its completion
arrives, so poll(1) returns at least every 100 ms, as the epoll loop does.
"""

from std.ffi import c_int

from flare.http import Handler, HttpFrontend, Request, Response, ServerConfig, ok
from flare.net import SocketAddr
from flare.runtime import Scheduler, is_io_uring_available
from flare.runtime._libc_time import libc_nanosleep_ms, monotonic_now_ms
from flare.runtime.scheduler_stats import WORKER_STAT_DONE, load_worker_stat
from flare.tcp import TcpListener, TcpStream


@fieldwise_init
struct _Hello(Copyable, Handler):
    def serve(self, req: Request) raises -> Response:
        return ok("hi")


def main() raises:
    if not is_io_uring_available():
        print("inconclusive: io_uring not available on this host")
        raise Error("CONC-07 inconclusive")
    var fe = HttpFrontend[_Hello](_Hello(), ServerConfig(use_bufring=True))
    if not fe.requires_per_worker_listener():
        raise Error("setup: the io_uring buffer-ring path was not selected")
    var s = Scheduler[HttpFrontend[_Hello]].start(
        addr=SocketAddr.localhost(0),
        frontend=fe^,
        num_workers=1,
        pin_cores=False,
    )
    if len(s._per_worker_listener_addrs) != 1 or len(s._stats_addrs) != 1:
        raise Error("setup: expected one per-worker listener")
    var lp = Pointer[TcpListener, MutUntrackedOrigin](
        unsafe_from_address=s._per_worker_listener_addrs[0]
    )
    var port = lp[].local_addr().port
    var stats = s._stats_addrs[0]
    _ = libc_nanosleep_ms(300)  # let the worker arm its accept and block
    if load_worker_stat(stats, WORKER_STAT_DONE) != 0:
        raise Error("setup: the worker returned before the stop")
    var t0 = monotonic_now_ms()
    var reports = s.drain(timeout_ms=2000)
    var waited = monotonic_now_ms() - t0
    if reports[0].drained != 0:
        print(
            "OK: the idle io_uring worker saw the stop and was joined after",
            waited,
            "ms",
        )
        return
    # Detached: its stats cell and listener were left allocated (drain's
    # stuck-worker branch), so both are still safe to use here.
    var still_running = load_worker_stat(stats, WORKER_STAT_DONE) == 0
    var c = TcpStream.connect(SocketAddr.localhost(port))
    var t1 = monotonic_now_ms()
    var released = False
    while monotonic_now_ms() - t1 < 2000:
        if load_worker_stat(stats, WORKER_STAT_DONE) != 0:
            released = True
            break
        _ = libc_nanosleep_ms(1)
    c.close()
    print(
        "BUG REPRODUCED: the idle io_uring worker ignored the stop flag for",
        waited,
        "ms; drain detached it (still running: "
        + String(still_running)
        + "), and it returned only after a client connected (returned: "
        + String(released)
        + ")",
    )
    raise Error("CONC-07")
