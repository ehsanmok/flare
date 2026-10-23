"""HTTP/1.1 WebSocket upgrades served on the reactor (``WsUpgrade.on_reactor``).

Forks a real server and drives it with ``WsClient``: echo, fragment
reassembly, the RFC 6455 failure codes, the closing handshake, one
handler copy per connection, plain HTTP on the same port, several
workers, and the idle timeout.
"""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.http import HttpClient, HttpServer, ServerConfig, WsUpgrade
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.net import SocketAddr
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.ws import WsClient, WsFrame, WsOpcode
from flare.ws.client import WsMessage
from flare.ws.server_reactor import WsReactorHandler, WsSession


struct _Http(Copyable, Handler):
    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        var r = Response(200)
        r.body = List[UInt8]("http".as_bytes())
        return r^


@fieldwise_init
struct _Echo(Copyable, WsReactorHandler):
    """Echoes messages; ``count`` answers how many this connection sent,
    which shows each connection has its own copy."""

    var seen: Int

    def on_open(mut self, mut ws: WsSession) raises:
        pass

    def on_message(mut self, mut ws: WsSession, var msg: WsMessage) raises:
        self.seen += 1
        if not msg.is_text:
            ws.send_binary(msg.as_binary())
        elif msg.as_text() == "count":
            ws.send_text(String(self.seen))
        else:
            ws.send_text(msg.as_text())

    def on_close(mut self, mut ws: WsSession, code: Int):
        pass


def _serve(
    workers: Int = 1, idle_ms: Int = 60_000
) raises -> Tuple[Int, UInt16]:
    var cfg = ServerConfig()
    cfg.ws = WsUpgrade.on_reactor(_Echo(0), idle_timeout_ms=idle_ms)
    var srv = HttpServer.bind(SocketAddr.localhost(0), cfg^)
    var port = UInt16(srv.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_Http(), num_workers=workers)
        except:
            pass
        exit()
    usleep(300_000)
    return (pid, port)


def _stop(pid: Int):
    _ = kill(pid, SIGKILL)
    _ = waitpid(pid)


def _url(port: UInt16) -> String:
    return "ws://127.0.0.1:" + String(Int(port)) + "/ws"


def _close_code(f: WsFrame) -> Int:
    if len(f.payload) < 2:
        return 0
    return (Int(f.payload[0]) << 8) | Int(f.payload[1])


def test_echo_text_and_binary() raises:
    var s = _serve()
    var text: String
    var bin: List[UInt8]
    try:
        var ws = WsClient.connect(_url(s[1]))
        ws.send_text("hello")
        text = ws.recv().text_payload()
        ws.send_binary([UInt8(1), UInt8(2), UInt8(3)])
        bin = ws.recv().payload.copy()
    finally:
        _stop(s[0])
    assert_equal(text, "hello")
    assert_equal(len(bin), 3)
    assert_equal(Int(bin[2]), 3)


def test_fragments_are_reassembled() raises:
    var s = _serve()
    var got: String
    try:
        var ws = WsClient.connect(_url(s[1]))
        var a = WsFrame(
            opcode=WsOpcode.TEXT, payload=List[UInt8]("he".as_bytes())
        )
        a.fin = False
        ws.send_frame(a)
        ws.send_frame(
            WsFrame(
                opcode=WsOpcode.CONTINUATION,
                payload=List[UInt8]("llo".as_bytes()),
            )
        )
        got = ws.recv().text_payload()
    finally:
        _stop(s[0])
    assert_equal(got, "hello")


def test_invalid_utf8_is_closed_with_1007() raises:
    var s = _serve()
    var code: Int
    try:
        var ws = WsClient.connect(_url(s[1]))
        ws.send_frame(
            WsFrame(opcode=WsOpcode.TEXT, payload=[UInt8(0xC3), UInt8(0x28)])
        )
        var f = ws.recv()
        assert_equal(f.opcode, WsOpcode.CLOSE)
        code = _close_code(f)
    finally:
        _stop(s[0])
    assert_equal(code, 1007)


def test_close_is_echoed() raises:
    var s = _serve()
    var code: Int
    try:
        var ws = WsClient.connect(_url(s[1]))
        ws.send_frame(WsFrame.close(3000))
        var f = ws.recv()
        assert_equal(f.opcode, WsOpcode.CLOSE)
        code = _close_code(f)
    finally:
        _stop(s[0])
    assert_equal(code, 3000)


def test_each_connection_has_its_own_handler() raises:
    var s = _serve()
    var first: String
    var second: String
    try:
        var a = WsClient.connect(_url(s[1]))
        a.send_text("x")
        _ = a.recv()
        a.send_text("count")
        first = a.recv().text_payload()
        var b = WsClient.connect(_url(s[1]))
        b.send_text("count")
        second = b.recv().text_payload()
    finally:
        _stop(s[0])
    assert_equal(first, "2")
    assert_equal(second, "1")


def test_http_is_still_served_on_the_port() raises:
    var s = _serve()
    var body: String
    try:
        with HttpClient() as c:
            body = c.get("http://127.0.0.1:" + String(Int(s[1])) + "/").text()
    finally:
        _stop(s[0])
    assert_equal(body, "http")


def test_several_workers() raises:
    var s = _serve(workers=2)
    var ok = 0
    try:
        for i in range(8):
            var ws = WsClient.connect(_url(s[1]))
            ws.send_text("m" + String(i))
            if ws.recv().text_payload() == "m" + String(i):
                ok += 1
    finally:
        _stop(s[0])
    assert_equal(ok, 8)


def _dropped_after_idle(url: String) raises -> Bool:
    var ws = WsClient.connect(url)
    usleep(900_000)
    try:
        ws.send_text("late")
        _ = ws.recv()
    except:
        return True
    return False


def test_idle_connection_is_dropped() raises:
    var s = _serve(idle_ms=200)
    var dropped: Bool
    try:
        dropped = _dropped_after_idle(_url(s[1]))
    finally:
        _stop(s[0])
    assert_true(dropped)


def test_active_connection_outlives_the_idle_timeout() raises:
    """Messages keep pushing the idle deadline back: a connection that
    talks every 100 ms outlives a 200 ms idle timeout many times over."""
    var s = _serve(idle_ms=200)
    var ok = 0
    try:
        var ws = WsClient.connect(_url(s[1]))
        for i in range(8):
            usleep(100_000)
            ws.send_text("m" + String(i))
            if ws.recv().text_payload() == "m" + String(i):
                ok += 1
    finally:
        _stop(s[0])
    assert_equal(ok, 8)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
