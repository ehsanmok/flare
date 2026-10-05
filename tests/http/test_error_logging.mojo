"""Sanitised error responses are logged with the full message and the
request id (DOC-04; ``docs/security.md``, ``docs/features.md``).

A handler that raises, or an extractor that fails, gets a fixed-reason
response; the message goes to the log together with the inbound
``X-Request-Id`` so an operator can tie the line to the request.

The tests drive an in-process ``ConnHandle`` over loopback (ephemeral
port) with fds 1 and 2 redirected into a pipe for the duration of the
call, and check the captured text.
"""

from std.ffi import c_int, external_call
from std.testing import assert_equal, assert_false, assert_true, TestSuite

from flare.errors import (
    HttpStatusError,
    format_error_log,
    log_handler_error,
)
from flare.http import Extracted, Handler, QueryInt, Request, Response, ok
from flare.http.handler import CancelHandler, FnHandler, ViewHandler
from flare.http.cancel import Cancel
from flare.http.request_view import RequestView
from flare.http.server import ServerConfig
from flare.http._server_reactor_impl import ConnHandle
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.utils import usleep


# ── Handlers ─────────────────────────────────────────────────────────────────


def _boom(req: Request) raises -> Response:
    raise Error("handler-secret")


def _status_error(req: Request) raises -> Response:
    raise HttpStatusError(404, "authored-for-the-client")


@fieldwise_init
struct _CancelBoom(CancelHandler, Copyable):
    def serve(self, req: Request, cancel: Cancel) raises -> Response:
        raise Error("cancel-secret")


@fieldwise_init
struct _ViewBoom(Copyable, ViewHandler):
    def serve_view[
        origin: Origin
    ](self, req: RequestView[origin], cancel: Cancel) raises -> Response:
        raise Error("view-secret")


@fieldwise_init
struct _NeedsInt(Copyable, Defaultable, Handler):
    var n: QueryInt["n"]

    def __init__(out self):
        self.n = QueryInt["n"]()

    def serve(self, req: Request) raises -> Response:
        return ok("n=" + String(self.n.value))


# ── Capture ──────────────────────────────────────────────────────────────────


struct _Capture(Movable):
    """fds 1 and 2 redirected into a pipe until :meth:`finish`."""

    var read_fd: c_int
    var write_fd: c_int
    var saved_out: c_int
    var saved_err: c_int

    def __init__(out self) raises:
        var fds = List[c_int](length=2, fill=0)
        if external_call["pipe", c_int](fds.unsafe_ptr()) != 0:
            raise Error("pipe() failed")
        self.read_fd = fds[0]
        self.write_fd = fds[1]
        self.saved_out = external_call["dup", c_int](c_int(1))
        self.saved_err = external_call["dup", c_int](c_int(2))
        _ = external_call["dup2", c_int](self.write_fd, c_int(1))
        _ = external_call["dup2", c_int](self.write_fd, c_int(2))

    def finish(mut self) -> String:
        _ = external_call["dup2", c_int](self.saved_out, c_int(1))
        _ = external_call["dup2", c_int](self.saved_err, c_int(2))
        _ = external_call["close", c_int](self.saved_out)
        _ = external_call["close", c_int](self.saved_err)
        _ = external_call["close", c_int](self.write_fd)
        var got = List[UInt8]()
        var tmp = List[UInt8](length=4096, fill=0)
        while True:
            var n = external_call["read", Int](
                self.read_fd, tmp.unsafe_ptr(), len(tmp)
            )
            if n <= 0:
                break
            for i in range(n):
                got.append(tmp[i])
        _ = external_call["close", c_int](self.read_fd)
        return String(unsafe_from_utf8=got)


struct _Result(Movable):
    var wire: String
    var log: String

    def __init__(out self, var wire: String, var log: String):
        self.wire = wire^
        self.log = log^


def _request(rid: String) -> String:
    var head = String("GET /x?n=extract-secret HTTP/1.1\r\nHost: a\r\n")
    if rid.byte_length() > 0:
        head += "X-Request-Id: " + rid + "\r\n"
    return head + "\r\n"


struct _Conn(Movable):
    var ch: ConnHandle
    var client: TcpStream
    var listener: TcpListener

    def __init__(out self, req: String) raises:
        self.listener = TcpListener.bind(SocketAddr.localhost(0))
        self.client = TcpStream.connect(
            SocketAddr.localhost(self.listener.local_addr().port)
        )
        var server = self.listener.accept()
        server._socket.set_nonblocking(True)
        self.ch = ConnHandle(server^)
        _ = self.client.write(req.as_bytes())

    def done(self) -> Bool:
        return len(self.ch.write_buf) > 0

    def finish(mut self) -> String:
        var wire = String(unsafe_from_utf8=self.ch.write_buf)
        self.client.close()
        self.listener.close()
        return wire^


def _cfg() -> ServerConfig:
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    return cfg^


def _run_h1[H: Handler](ref h: H, req: String) raises -> _Result:
    var c = _Conn(req)
    var cfg = _cfg()
    var cap = _Capture()
    var failure = String("")
    try:
        for _ in range(100):
            usleep(10000)
            _ = c.ch.on_readable(h, cfg)
            if c.done():
                break
    except e:
        failure = String(e)
    var log = cap.finish()
    if failure.byte_length() > 0:
        raise Error(failure)
    return _Result(c.finish(), log^)


def _run_cancel[H: CancelHandler](ref h: H, req: String) raises -> _Result:
    var c = _Conn(req)
    var cfg = _cfg()
    var cap = _Capture()
    var failure = String("")
    try:
        for _ in range(100):
            usleep(10000)
            _ = c.ch.on_readable_cancel(h, cfg)
            if c.done():
                break
    except e:
        failure = String(e)
    var log = cap.finish()
    if failure.byte_length() > 0:
        raise Error(failure)
    return _Result(c.finish(), log^)


def _run_view[H: ViewHandler](ref h: H, req: String) raises -> _Result:
    var c = _Conn(req)
    var cfg = _cfg()
    var cap = _Capture()
    var failure = String("")
    try:
        for _ in range(100):
            usleep(10000)
            _ = c.ch.on_readable_view(h, cfg)
            if c.done():
                break
    except e:
        failure = String(e)
    var log = cap.finish()
    if failure.byte_length() > 0:
        raise Error(failure)
    return _Result(c.finish(), log^)


def _has_line(log: String, *needles: String) -> Bool:
    for ln in log.split("\n"):
        var all = True
        for n in needles:
            if n not in ln:
                all = False
        if all:
            return True
    return False


# ── Tests ────────────────────────────────────────────────────────────────────


def test_handler_error_is_logged_with_request_id() raises:
    var h = FnHandler(_boom)
    var r = _run_h1(h, _request("rid-500"))
    assert_true(r.wire.startswith("HTTP/1.1 500"))
    assert_false("handler-secret" in r.wire, "the body stays sanitised")
    assert_true(
        _has_line(r.log, "[flare:handler-error]", "rid-500", "handler-secret"),
        "log: " + r.log,
    )


def test_handler_error_without_request_id_logs_a_dash() raises:
    var h = FnHandler(_boom)
    var r = _run_h1(h, _request(""))
    assert_true(r.wire.startswith("HTTP/1.1 500"))
    assert_true(
        _has_line(r.log, "[flare:handler-error]", "rid=-", "handler-secret"),
        "log: " + r.log,
    )


def test_extractor_error_is_logged_with_request_id() raises:
    var h = Extracted[_NeedsInt]()
    var r = _run_h1(h, _request("rid-400"))
    assert_true(r.wire.startswith("HTTP/1.1 400"))
    assert_false("extract-secret" in r.wire, "the body stays sanitised")
    assert_true(
        _has_line(r.log, "[flare:bad-request]", "rid-400", "extract-secret"),
        "log: " + r.log,
    )


def test_cancel_path_handler_error_is_logged_with_request_id() raises:
    var h = _CancelBoom()
    var r = _run_cancel(h, _request("rid-cancel"))
    assert_true(r.wire.startswith("HTTP/1.1 500"))
    assert_true(
        _has_line(
            r.log, "[flare:handler-error]", "rid-cancel", "cancel-secret"
        ),
        "log: " + r.log,
    )


def test_view_path_handler_error_is_logged_with_request_id() raises:
    var h = _ViewBoom()
    var r = _run_view(h, _request("rid-view"))
    assert_true(r.wire.startswith("HTTP/1.1 500"))
    assert_true(
        _has_line(r.log, "[flare:handler-error]", "rid-view", "view-secret"),
        "log: " + r.log,
    )


def test_status_error_is_not_logged_as_a_hidden_message() raises:
    var h = FnHandler(_status_error)
    var r = _run_h1(h, _request("rid-404"))
    assert_true(r.wire.startswith("HTTP/1.1 404"))
    assert_false("handler-error" in r.log, "log: " + r.log)


def test_log_line_format_and_escaping() raises:
    assert_equal(
        format_error_log("handler-error", "abc", "boom"),
        "[flare:handler-error] rid=abc boom",
    )
    assert_equal(
        format_error_log("bad-request", "", "boom"),
        "[flare:bad-request] rid=- boom",
    )
    # A message or id built from request bytes cannot split the line.
    var line = format_error_log("bad-request", "a\nb", "x\r\n[flare:forged]")
    assert_false("\n" in line)
    assert_false("\r" in line)
    assert_equal(
        line, "[flare:bad-request] rid=a\\x0ab x\\x0d\\x0a[flare:forged]"
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
