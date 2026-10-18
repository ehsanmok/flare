"""HTTP Datagrams and the Capsule Protocol (RFC 9297).

A tunnel's datagrams carry its Quarter Stream ID; one that cannot
name a stream is H3_DATAGRAM_ERROR, one for a stream that is not an
open tunnel is dropped, and SETTINGS_H3_DATAGRAM is only accepted from
a peer that also negotiated QUIC DATAGRAM frames.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.http3 import (
    CAPSULE_TYPE_DATAGRAM,
    Http3Connection,
    Http3Setting,
    encode_capsule,
    encode_http3_frame,
    encode_http3_settings,
    parse_capsule,
)
from flare.qpack import QpackHeader, encode_field_section
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.varint import encode_varint
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _control(h3_datagram: UInt64) raises -> List[UInt8]:
    """A client control stream: type 0x00, then SETTINGS."""
    var s = List[Http3Setting]()
    s.append(Http3Setting(identifier=0x33, value=h3_datagram))
    var payload = List[UInt8]()
    encode_http3_settings(s, payload)
    var out = List[UInt8]()
    out.append(0x00)
    encode_http3_frame(0x04, Span[UInt8, _](payload), out)
    return out^


def _connect_udp() raises -> List[UInt8]:
    var h = List[QpackHeader]()
    h.append(QpackHeader(":method", "CONNECT"))
    h.append(QpackHeader(":protocol", "connect-udp"))
    h.append(QpackHeader(":scheme", "https"))
    h.append(QpackHeader(":authority", "localhost"))
    h.append(QpackHeader(":path", "/udp"))
    var block = List[UInt8]()
    encode_field_section(h, block)
    var out = List[UInt8]()
    encode_http3_frame(0x01, Span[UInt8, _](block), out)
    return out^


def _dg(qsid: UInt64, body: String) raises -> List[UInt8]:
    var out = encode_varint(qsid)
    out.extend(body.as_bytes())
    return out^


def _turn(mut listener: QuicListener, mut quic: QuicClientConnection) raises:
    _ = listener.tick(timeout_ms=10)
    _ = listener.drain_all_egress()
    _ = quic.poll(timeout_ms=10)


def test_datagrams_ride_a_tunnel_and_bad_ones_close() raises:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_datagram_frame_size = 1200
    cfg.http3.enable_connect_protocol = True
    cfg.http3.h3_datagram = True
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    var listener = QuicListener.bind(cfg^)
    var quic = QuicClientConnection.start(
        listener.local_addr(),
        RustlsQuicConnector(Path(_FIXDIR + "ca.pem").read_text(), _alpn()),
        String("localhost"),
        max_datagram_frame_size=1200,
    )
    for _ in range(40):
        _turn(listener, quic)
        if quic.is_established():
            break
    quic.send_stream(quic.open_uni_stream(), _control(1), fin=False)
    var sid = quic.open_bidi_stream()
    quic.send_stream(sid, _connect_udp(), fin=False)
    for _ in range(20):
        _turn(listener, quic)
        if listener.is_http3_tunnel_request(0, Int(sid)):
            break
    _ = listener.take_http3_request(0, Int(sid))
    var t = listener.open_http3_tunnel(0, Int(sid))

    # Client -> server; the one naming another stream is dropped.
    assert_true(quic.send_datagram(Span[UInt8, _](_dg(sid // 4 + 1, "x"))))
    assert_true(quic.send_datagram(Span[UInt8, _](_dg(sid // 4, "ping"))))
    var got = List[List[UInt8]]()
    for _ in range(20):
        _turn(listener, quic)
        got.extend(listener.take_http3_datagrams(t))
        if len(got) > 0:
            break
    assert_equal(len(got), 1)
    assert_equal(String(unsafe_from_utf8=got[0]), "ping")

    # Server -> client, prefixed with the tunnel's Quarter Stream ID.
    assert_true(listener.send_http3_datagram(t, "pong".as_bytes()))
    var back = List[List[UInt8]]()
    for _ in range(20):
        _ = listener.drain_all_egress()
        back.extend(quic.poll(timeout_ms=10).datagrams.copy())
        if len(back) > 0:
            break
    assert_equal(len(back), 1)
    assert_equal(back[0], _dg(sid // 4, "pong"))

    # A Quarter Stream ID of 2^60 names no stream: H3_DATAGRAM_ERROR.
    assert_true(quic.send_datagram(Span[UInt8, _](_dg(UInt64(1) << 60, ""))))
    for _ in range(20):
        _turn(listener, quic)
        if not listener.connections[0].alive:
            break
    assert_false(listener.connections[0].alive)
    assert_equal(listener.connections[0].conn.close_error_code, UInt64(0x33))
    listener.close()
    quic.close()


def test_settings_h3_datagram_needs_quic_datagrams() raises:
    for v in [UInt64(1), UInt64(2)]:
        var h3 = Http3Connection()
        h3.peer_quic_datagram = v == 2  # 2 is bad whatever QUIC says
        var raised = String("")
        try:
            var c = _control(v)
            h3.feed_stream_frame(2, 0, Span[UInt8, _](c), False)
        except e:
            raised = String(e)
        assert_true("H3_SETTINGS_ERROR" in raised, String(v))


def test_capsule_codec() raises:
    var buf = List[UInt8]()
    encode_capsule(CAPSULE_TYPE_DATAGRAM, "abc".as_bytes(), buf)
    encode_capsule(0x4000, List[UInt8](length=300, fill=7), buf)
    var first = parse_capsule(Span[UInt8, _](buf), 1024).value().copy()
    assert_equal(first[0].capsule_type, CAPSULE_TYPE_DATAGRAM)
    assert_equal(len(first[0].value), 3)
    var rest = Span[UInt8, _](buf)[first[1] :]
    var second = parse_capsule(rest, 1024).value().copy()
    assert_equal(second[0].capsule_type, UInt64(0x4000))
    assert_equal(second[1], len(rest))
    assert_false(Bool(parse_capsule(rest[: len(rest) - 1], 1024)))
    var raised = False
    try:
        _ = parse_capsule(rest, 299)
    except:
        raised = True
    assert_true(raised, "a value over the cap is refused")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
