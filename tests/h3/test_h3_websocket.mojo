"""WebSocket over HTTP/3 (RFC 9220) through ``HttpServer.attach_ws_h3``.

Extended CONNECT was never accepted on h3: the request waited for a FIN
that a tunnel never sends, and nothing could answer it with a stream
that stays open. The client side here is raw QUIC, so the test sees
the exact HEADERS and DATA frames.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.http import HttpServer, ok
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http3 import Http3ClientConnection
from flare.http3.frame import decode_http3_frame, encode_http3_frame
from flare.net import IpAddr, SocketAddr
from flare.qpack import QpackHeader, decode_field_section, encode_field_section
from flare.quic.client import QuicClientConnection
from flare.quic.server import Http3Tunnel, QuicListener, QuicServerConfig
from flare.quic.varint import decode_varint
from flare.quic._server_support import _monotonic_ms
from flare.testing import kill_forked_server
from flare.tls import RustlsQuicConnector
from flare.utils import exit, fork
from flare.ws import WsFrame, WsOpcode
from flare.ws.server_h3 import WsH3Handler, WsOverH3ServerStream


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


@fieldwise_init
struct _Echo(WsH3Handler):
    def on_open(
        mut self, mut carrier: WsOverH3ServerStream, mut listener: QuicListener
    ) raises:
        pass

    def on_message(
        mut self,
        mut carrier: WsOverH3ServerStream,
        mut listener: QuicListener,
        frame: WsFrame,
    ) raises:
        if frame.opcode != WsOpcode.CLOSE:
            carrier.send_frame(listener, WsFrame.text(frame.text_payload()))

    def on_close(
        mut self, mut carrier: WsOverH3ServerStream, mut listener: QuicListener
    ) raises:
        pass


@fieldwise_init
struct _Hello(Copyable, Handler):
    def serve(self, req: Request) raises -> Response:
        return ok("hi")


def _server_cfg() raises -> QuicServerConfig:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return cfg^


def _connect(protocol: String) raises -> List[UInt8]:
    """The HEADERS frame of an extended CONNECT for ``protocol``."""
    var h = List[QpackHeader]()
    h.append(QpackHeader(":method", "CONNECT"))
    h.append(QpackHeader(":protocol", protocol))
    h.append(QpackHeader(":scheme", "https"))
    h.append(QpackHeader(":authority", "localhost"))
    h.append(QpackHeader(":path", "/chat"))
    h.append(QpackHeader("sec-websocket-version", "13"))
    var block = List[UInt8]()
    encode_field_section(h, block)
    var frames = List[UInt8]()
    encode_http3_frame(0x01, Span[UInt8, _](block), frames)
    return frames^


struct _Client(Movable):
    """Raw QUIC client on one request stream; ``rx`` is the in-order
    server-to-client stream bytes, ``fin`` whether the server ended it."""

    var quic: QuicClientConnection
    var sid: UInt64
    var rx: List[UInt8]
    var fin: Bool

    def __init__(out self, addr: SocketAddr, protocol: String) raises:
        var connector = RustlsQuicConnector(
            Path(_FIXDIR + "ca.pem").read_text(), _alpn()
        )
        self.quic = QuicClientConnection.connect(
            addr, connector, String("localhost")
        )
        self.sid = self.quic.open_bidi_stream()
        self.rx = List[UInt8]()
        self.fin = False
        self.quic.send_stream(self.sid, _connect(protocol), fin=False)

    def send_ws(mut self, frame: WsFrame, fin: Bool = False) raises:
        var wire = frame.encode(mask=True)
        var frames = List[UInt8]()
        encode_http3_frame(0x00, Span[UInt8, _](wire), frames)
        self.quic.send_stream(self.sid, frames, fin=fin)

    def pump(mut self, until_frames: Int, until_fin: Bool = False) raises:
        var deadline = _monotonic_ms() + 5_000
        while _monotonic_ms() < deadline:
            var whole = 0
            try:
                whole = len(self.frames())
            except:
                pass  # a frame still partly in flight
            if whole >= until_frames and (self.fin or not until_fin):
                return
            var ev = self.quic.poll(timeout_ms=20)
            for i in range(len(ev.stream_chunks)):
                ref c = ev.stream_chunks[i]
                if c.stream_id == self.sid and Int(c.offset) == len(self.rx):
                    self.rx.extend(Span[UInt8, _](c.data))
                    self.fin = self.fin or c.fin

    def frames(self) raises -> List[Tuple[UInt64, List[UInt8]]]:
        """The H3 frames received so far, as (type, payload)."""
        var out = List[Tuple[UInt64, List[UInt8]]]()
        var pos = 0
        while pos < len(self.rx):
            var rest = Span[UInt8, _](self.rx)[pos:]
            var t = decode_varint(rest)
            var n = decode_varint(rest[t.consumed :])
            var f = decode_http3_frame(rest)
            out.append((t.value, f.payload.copy()))
            pos += t.consumed + n.consumed + Int(n.value)
        return out^

    def status(self) raises -> String:
        var fs = self.frames()
        for h in decode_field_section(Span[UInt8, _](fs[0][1])):
            if h.name == ":status":
                return h.value
        return ""


def _serve(workers: Int = 1) raises -> Tuple[Int, SocketAddr]:
    var cfg = _server_cfg()
    cfg.num_workers = workers
    var srv = HttpServer.bind_with_http3(
        SocketAddr(IpAddr.localhost(), UInt16(0)), cfg^
    )
    srv.attach_ws_h3(_Echo())
    var addr = srv.local_http3_addr()
    var pid = fork()
    if pid == 0:
        try:
            srv.serve_http3[_Hello](_Hello())
        except:
            pass
        exit()
    return (pid, addr)


def test_websocket_over_h3_echoes_and_closes() raises:
    var s = _serve()
    var c = _Client(s[1], "websocket")
    c.send_ws(WsFrame.text("hello"))
    c.pump(until_frames=2)
    c.send_ws(WsFrame.close(1000, ""))
    c.pump(until_frames=3, until_fin=True)
    kill_forked_server(s[0])
    assert_equal(c.status(), "200")
    var fs = c.frames()
    assert_equal(len(fs), 3, "HEADERS, echo DATA, CLOSE DATA")
    var echo = WsFrame.decode_one(Span[UInt8, _](fs[1][1]))
    assert_equal(echo^.take_frame().text_payload(), "hello")
    var close = WsFrame.decode_one(Span[UInt8, _](fs[2][1])).take_frame()
    assert_equal(close.opcode, WsOpcode.CLOSE)
    assert_false(close.masked, "a server never masks (RFC 6455 sec 5.3)")
    assert_true(c.fin, "the server ended the stream after its CLOSE")


def test_a_close_with_fin_is_still_answered() raises:
    """The peer ending its side must not stop ours: a tunnel that got
    CLOSE and FIN together used to drop the CLOSE reply."""
    var s = _serve()
    var c = _Client(s[1], "websocket")
    c.send_ws(WsFrame.close(1000, ""), fin=True)
    c.pump(until_frames=2, until_fin=True)
    kill_forked_server(s[0])
    var fs = c.frames()
    assert_equal(len(fs), 2, "HEADERS, CLOSE DATA")
    var close = WsFrame.decode_one(Span[UInt8, _](fs[1][1])).take_frame()
    assert_equal(close.opcode, WsOpcode.CLOSE)


def test_websocket_over_h3_on_several_workers() raises:
    """Every worker serves tunnels with its own copy of the sidecar;
    attach_ws_h3 used to need a single worker."""
    var s = _serve(4)
    var echoed = 0
    for _ in range(8):
        var c = _Client(s[1], "websocket")
        c.send_ws(WsFrame.text("hi"))
        c.pump(until_frames=2)
        var fs = c.frames()
        if len(fs) >= 2:
            var echo = WsFrame.decode_one(Span[UInt8, _](fs[1][1]))
            if echo^.take_frame().text_payload() == "hi":
                echoed += 1
    kill_forked_server(s[0])
    assert_equal(echoed, 8)


def test_another_protocol_gets_501() raises:
    var s = _serve()
    var c = _Client(s[1], "webtransport")
    c.pump(until_frames=1, until_fin=True)
    kill_forked_server(s[0])
    assert_equal(c.status(), "501")
    assert_true(c.fin)


def test_stale_tunnel_handle_is_refused() raises:
    var cfg = _server_cfg()
    cfg.http3.enable_connect_protocol = True
    var listener = QuicListener.bind(cfg^)
    var addr = listener.local_addr()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var quic = QuicClientConnection.start(addr, connector, String("localhost"))
    for _ in range(40):
        _ = listener.tick(timeout_ms=20)
        _ = listener.drain_all_egress()
        _ = quic.poll(timeout_ms=20)
        if quic.is_established():
            break
    var sid = quic.open_bidi_stream()
    quic.send_stream(sid, _connect("websocket"), fin=False)
    for _ in range(20):
        _ = listener.tick(timeout_ms=10)
        if listener.is_http3_tunnel_request(0, Int(sid)):
            break
    _ = listener.take_http3_request(0, Int(sid))
    var t = listener.open_http3_tunnel(0, Int(sid))
    assert_true(listener.http3_tunnel_open(t))
    # The same slot and stream under another connection's serial: what a
    # handle kept past its connection would hold once the slot is reused.
    var stale = Http3Tunnel(t.slot, t.stream_id, t.serial + 1)
    assert_false(listener.http3_tunnel_open(stale))
    assert_false(
        listener.send_http3_tunnel(
            stale, Span[UInt8, _](List[UInt8](length=4, fill=1))
        )
    )
    assert_equal(len(listener.take_http3_tunnel(stale)), 0)
    listener.close()
    quic.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
