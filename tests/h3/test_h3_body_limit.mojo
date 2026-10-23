"""An h3 request body over ``Http3Config.max_body_size`` gets a 413.

It used to be marked as a protocol error and never answered: the client
waited out its timeout while the stream kept buffering whatever else it
sent, up to the connection's flow-control window. Now the request is
answered 413, and because the client has not finished sending, it is
asked to stop with STOP_SENDING (H3_NO_ERROR, RFC 9114 sec 4.1.2).
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true

from flare.http import ok
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http._h3_workers import pump_h3_requests
from flare.http3.frame import decode_http3_frame, encode_http3_frame
from flare.qpack import QpackHeader, decode_field_section, encode_field_section
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


@fieldwise_init
struct _Ok(Copyable, Handler):
    def serve(self, req: Request) raises -> Response:
        return ok("served")


def test_oversized_upload_gets_413_and_stop_sending() raises:
    var alpn = List[String]()
    alpn.append(String("h3"))
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.http3.max_body_size = 1000
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = alpn.copy()
    var listener = QuicListener.bind(cfg)
    var quic = QuicClientConnection.start(
        listener.local_addr(),
        RustlsQuicConnector(Path(_FIXDIR + "ca.pem").read_text(), alpn^),
        String("localhost"),
    )
    for _ in range(40):
        _ = listener.tick(timeout_ms=10)
        _ = listener.drain_all_egress()
        _ = quic.poll(timeout_ms=10)
        if quic.is_established():
            break
    var h = List[QpackHeader]()
    h.append(QpackHeader(":method", "POST"))
    h.append(QpackHeader(":scheme", "https"))
    h.append(QpackHeader(":authority", "localhost"))
    h.append(QpackHeader(":path", "/upload"))
    var block = List[UInt8]()
    encode_field_section(h, block)
    var req = List[UInt8]()
    encode_http3_frame(0x01, Span[UInt8, _](block), req)
    encode_http3_frame(0x00, List[UInt8](length=2000, fill=7), req)
    var sid = quic.open_bidi_stream()
    quic.send_stream(sid, req, fin=False)  # still uploading
    var handler = _Ok()
    var rx = List[UInt8]()
    var stopped = False
    for _ in range(40):
        _ = listener.tick(timeout_ms=10)
        _ = pump_h3_requests[_Ok](listener, handler)
        _ = listener.drain_all_egress()
        var ev = quic.poll(timeout_ms=10)
        for i in range(len(ev.stream_chunks)):
            if ev.stream_chunks[i].stream_id == sid:
                rx.extend(Span[UInt8, _](ev.stream_chunks[i].data))
        if UInt64(sid) in quic.conn.streams:
            stopped = stopped or quic.conn.streams[sid].send_reset
        if len(rx) > 0 and stopped:
            break
    var status = String("")
    for f in decode_field_section(
        Span[UInt8, _](decode_http3_frame(Span[UInt8, _](rx)).payload)
    ):
        if f.name == ":status":
            status = f.value
    assert_equal(status, "413")
    assert_true(stopped, "STOP_SENDING asked the client to stop uploading")
    listener.close()
    quic.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
