"""An idle io_uring buffer-ring worker must see the stop flag (CONC-07).

The worker's ring has no wakeup channel and its loop waited with
``poll(1, ...)``, an ``io_uring_enter(min_complete=1)`` with no timeout, so
with no traffic it read the stop flag only when a client happened to
connect. ``Scheduler.shutdown()`` blocked in ``pthread_join`` until then,
and ``drain(timeout_ms)`` detached every idle worker however long the
deadline. The epoll/kqueue loops re-read the flag at least every 100 ms;
the io_uring loops now cap their wait the same way.

Linux with io_uring only; skipped elsewhere.
"""

from std.sys.info import CompilationTarget
from std.testing import assert_equal, assert_true, TestSuite

from flare.http import (
    Handler,
    HttpFrontend,
    Request,
    Response,
    ServerConfig,
    ok,
)
from flare.net import SocketAddr
from flare.runtime import Scheduler, is_io_uring_available
from flare.runtime._libc_time import libc_nanosleep_ms, monotonic_now_ms
from flare.runtime.scheduler_stats import WORKER_STAT_DONE, load_worker_stat
from flare.tcp import TcpListener, TcpStream


@fieldwise_init
struct _Hello(Copyable, Handler):
    def serve(self, req: Request) raises -> Response:
        return ok("hi")


def test_idle_uring_worker_is_joined_by_drain() raises:
    comptime if not CompilationTarget.is_linux():
        return
    if not is_io_uring_available():
        return
    var fe = HttpFrontend[_Hello](_Hello(), ServerConfig(use_bufring=True))
    assert_true(
        fe.requires_per_worker_listener(),
        "the io_uring buffer-ring path was not selected",
    )
    var s = Scheduler[HttpFrontend[_Hello]].start(
        addr=SocketAddr.localhost(0),
        frontend=fe^,
        num_workers=1,
        pin_cores=False,
    )
    assert_equal(len(s._per_worker_listener_addrs), 1)
    var lp = Pointer[TcpListener, MutUntrackedOrigin](
        unsafe_from_address=s._per_worker_listener_addrs[0]
    )
    var port = lp[].local_addr().port
    var stats = s._stats_addrs[0]
    # Let the worker arm its accept and block: nothing is ever connected.
    _ = libc_nanosleep_ms(300)
    assert_equal(load_worker_stat(stats, WORKER_STAT_DONE), 0)
    var t0 = monotonic_now_ms()
    var reports = s.drain(timeout_ms=2000)
    var waited = monotonic_now_ms() - t0
    var joined = reports[0].drained != 0
    if not joined:
        # Detached: release the worker with a connection so the process
        # can exit; its stats cell and listener were left allocated.
        var c = TcpStream.connect(SocketAddr.localhost(port))
        var t1 = monotonic_now_ms()
        while monotonic_now_ms() - t1 < 2000:
            if load_worker_stat(stats, WORKER_STAT_DONE) != 0:
                break
            _ = libc_nanosleep_ms(1)
        c.close()
    assert_true(
        joined,
        "drain detached the idle worker after " + String(waited) + " ms",
    )
    assert_true(waited < 1500, "drain took " + String(waited) + " ms")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
