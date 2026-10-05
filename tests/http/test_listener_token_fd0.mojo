"""A client accepted on fd 0 must still be served (MACH-01).

The reactor loops used to register the listener under reactor token 0 and
each client under token = its fd. ``accept`` returns the lowest free fd, so
once something in the process closed fd 0 (stdin) the next client got fd 0,
hence token 0, hence every one of its events went to the accept drainer and
its request was never read.

Each case forks a server whose handler closes fd 0 on ``/close-stdin`` (the
close happens in the forked child only; the test process keeps its stdin),
then checks that the client accepted on the freed fd 0 gets an answer. One
case per reactor loop that carried the pattern:

* ``serve``             -> ``flare/http/_unified_reactor_impl.mojo``
* ``serve_cancellable`` -> ``run_reactor_loop_cancel``
* ``serve_view``        -> ``run_reactor_loop_view``
* ``serve`` with a ``num_workers=2`` pool shares the unified loop's code.

The static and shared-handler loops in ``_server_reactor_epoll.mojo`` use the
same constant; their request path cannot close fd 0 from inside the handler,
so they are covered by ``test_listener_token_is_not_a_possible_fd``.

No fixed ports: every server binds port 0.
"""

from std.ffi import c_int, external_call
from std.testing import assert_equal, assert_true, TestSuite

from flare.http import (
    HttpServer,
    Request,
    Response,
    Handler,
    WithCancel,
    ok,
)
from flare.http.handler import WithViewCancel
from flare.net import SocketAddr
from flare.runtime import LISTENER_TOKEN, WAKEUP_TOKEN
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


@fieldwise_init
struct _Closer(Copyable, Handler):
    """Closes fd 0 (in the server process) on ``/close-stdin``."""

    def serve(self, req: Request) raises -> Response:
        if req.url == "/close-stdin":
            _ = external_call["close", c_int](c_int(0))
            return ok("closed")
        return ok("hello")


def _closer_fn(req: Request) raises -> Response:
    if req.url == "/close-stdin":
        _ = external_call["close", c_int](c_int(0))
        return ok("closed")
    return ok("hello")


def _ensure_fd0_open() raises:
    """Make sure fd 0 is in use here, so the forked server inherits it and
    the listener cannot be bound to fd 0 itself."""
    if external_call["fcntl", c_int](c_int(0), c_int(1), c_int(0)) >= c_int(0):
        return
    var path = String("/dev/null")
    var fd = external_call["open", c_int](path.unsafe_ptr(), c_int(0))
    if Int(fd) != 0:
        raise Error("setup: could not occupy fd 0")


def _get(port: UInt16, path: String) -> String:
    var got = String("")
    try:
        var s = TcpStream.connect(SocketAddr.localhost(port))
        s.set_recv_timeout(3000)
        var req = (
            "GET " + path + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        _ = s.write(req.as_bytes())
        var buf = List[UInt8](length=4096, fill=0)
        while True:
            var n = s.read(buf.unsafe_ptr(), 4096)
            if n <= 0:
                break
            for i in range(n):
                got += chr(Int(buf[i]))
        s.close()
    except:
        pass
    return got


comptime _VARIANT_SERVE = 0
comptime _VARIANT_CANCELLABLE = 1
comptime _VARIANT_VIEW = 2
comptime _VARIANT_SERVE_POOL = 3


def _run_variant(variant: Int, mut srv: HttpServer) raises:
    if variant == _VARIANT_SERVE:
        srv.serve(_closer_fn)
    elif variant == _VARIANT_CANCELLABLE:
        srv.serve_cancellable(WithCancel[_Closer](_Closer()))
    elif variant == _VARIANT_VIEW:
        srv.serve_view(WithViewCancel[_Closer](_Closer()))
    elif variant == _VARIANT_SERVE_POOL:
        srv.serve(_Closer(), 2, False)
    else:
        raise Error("unknown variant")


def _assert_client_on_freed_fd0_is_served(variant: Int) raises:
    _ensure_fd0_open()
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            _run_variant(variant, srv)
        except:
            pass
        exit()
    usleep(300000)
    var first = _get(port, "/close-stdin")
    var second = _get(port, "/")
    var third = _get(port, "/")
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(first.startswith("HTTP/1.1 200"), "setup request failed")
    assert_true(
        second.startswith("HTTP/1.1 200"),
        "client accepted on freed fd 0 got no response: " + second,
    )
    assert_true(third.startswith("HTTP/1.1 200"), "later client not served")


def test_client_on_freed_fd0_is_served_unified() raises:
    _assert_client_on_freed_fd0_is_served(_VARIANT_SERVE)


def test_client_on_freed_fd0_is_served_cancellable() raises:
    _assert_client_on_freed_fd0_is_served(_VARIANT_CANCELLABLE)


def test_client_on_freed_fd0_is_served_view() raises:
    _assert_client_on_freed_fd0_is_served(_VARIANT_VIEW)


def test_client_on_freed_fd0_is_served_pool() raises:
    _assert_client_on_freed_fd0_is_served(_VARIANT_SERVE_POOL)


def test_listener_token_is_not_a_possible_fd() raises:
    """Client tokens are fds (``0 .. 2^31 - 1``); the listener token must be
    outside that range and differ from the reserved wakeup token."""
    assert_true(LISTENER_TOKEN >= UInt64(1) << 31)
    assert_true(LISTENER_TOKEN != WAKEUP_TOKEN)
    assert_true(LISTENER_TOKEN != UInt64(0))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
