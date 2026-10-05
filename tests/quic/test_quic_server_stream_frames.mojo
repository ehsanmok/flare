"""The server checks the stream id of every stream frame (QUIC-15,
QUIC-16; RFC 9000 sec 4.6, 19.4, 19.5, 19.10, 19.13).

* ``dispatch_plaintext`` rejects RESET_STREAM, STOP_SENDING,
  MAX_STREAM_DATA and STREAM_DATA_BLOCKED that name a stream half that does
  not exist (STREAM_STATE_ERROR) or a peer stream above the advertised
  limit (STREAM_LIMIT_ERROR), and closes the connection;
* a STREAM frame on a client unidirectional stream above the limit the
  server advertised closes the connection (the bidirectional limit was
  already enforced);
* a connection error raised by the state machine reaches the peer as a
  CONNECTION_CLOSE with its code (loopback).
"""

from std.collections import List
from std.collections.span import Span
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    QuicConnection,
    QuicListener,
    QuicServerConfig,
)
from flare.quic.client import QuicClientConnection
from flare.quic.frame import StreamFrame
from flare.quic.packet import LongHeader
from flare.quic.state import (
    CONN_STATE_CLOSING,
    ConnectionEvents,
    empty_events,
)
from flare.tls import RustlsQuicConnector
from flare.tls.rustls_quic import RustlsQuicConfig


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _cid(seed: Int) -> ConnectionId:
    var b = List[UInt8]()
    for i in range(8):
        b.append(UInt8(seed + i))
    return ConnectionId(bytes=b^)


def _dispatch(var payload: List[UInt8]) raises -> Int:
    """0 when accepted, otherwise the transport error code the server
    connection closed with."""
    var qc = QuicConnection(_cid(1), _cid(0x40))
    try:
        _ = qc.dispatch_plaintext(
            Span[UInt8, _](payload), UInt64(1_000_000), UInt64(0)
        )
    except:
        assert_equal(qc.conn.state, CONN_STATE_CLOSING)
        return Int(qc.conn.close_error_code)
    return 0


def test_frames_on_client_bidi_stream_0_are_accepted() raises:
    assert_equal(_dispatch([0x05, 0x00, 0x00]), 0)  # STOP_SENDING
    assert_equal(_dispatch([0x11, 0x00, 0x10]), 0)  # MAX_STREAM_DATA
    assert_equal(_dispatch([0x04, 0x00, 0x00, 0x00]), 0)  # RESET_STREAM
    assert_equal(_dispatch([0x15, 0x00, 0x00]), 0)  # STREAM_DATA_BLOCKED
    # Client unidirectional stream 2 has a receive half: RESET_STREAM and
    # STREAM_DATA_BLOCKED are fine.
    assert_equal(_dispatch([0x04, 0x02, 0x00, 0x00]), 0)
    assert_equal(_dispatch([0x15, 0x02, 0x00]), 0)


def test_send_only_stream_frames_for_the_receive_half_rejected() raises:
    """RESET_STREAM / STREAM_DATA_BLOCKED on a stream the server
    initiated as unidirectional (id 3): STREAM_STATE_ERROR."""
    assert_equal(_dispatch([0x04, 0x03, 0x00, 0x00]), 5)
    assert_equal(_dispatch([0x15, 0x03, 0x00]), 5)


def test_receive_only_stream_frames_for_the_send_half_rejected() raises:
    """STOP_SENDING / MAX_STREAM_DATA on a client unidirectional stream
    (id 2), which the server can only receive on: STREAM_STATE_ERROR."""
    assert_equal(_dispatch([0x05, 0x02, 0x00]), 5)
    assert_equal(_dispatch([0x11, 0x02, 0x10]), 5)


def test_unopened_server_stream_rejected() raises:
    """The server opened no stream of its own, so STOP_SENDING /
    MAX_STREAM_DATA for server bidirectional stream 1 name one that does
    not exist yet."""
    assert_equal(_dispatch([0x05, 0x01, 0x00]), 5)
    assert_equal(_dispatch([0x11, 0x01, 0x10]), 5)


def test_stream_ids_above_the_advertised_limit_rejected() raises:
    """STREAM_LIMIT_ERROR: client bidi stream 400 is the 101st (100
    allowed), client uni stream 14 the 4th (3 allowed)."""
    assert_equal(_dispatch([0x05, 0x41, 0x90, 0x00]), 4)  # STOP_SENDING 400
    assert_equal(_dispatch([0x04, 0x0E, 0x00, 0x00]), 4)  # RESET_STREAM 14
    assert_equal(_dispatch([0x15, 0x0E, 0x00]), 4)  # STREAM_DATA_BLOCKED 14
    # The last allowed ones pass: bidi 396 (the 100th), uni 10 (the 3rd).
    assert_equal(_dispatch([0x05, 0x41, 0x8C, 0x00]), 0)
    assert_equal(_dispatch([0x04, 0x0A, 0x00, 0x00]), 0)


def _bind_no_tls() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config = RustlsQuicConfig()
    return QuicListener.bind(cfg^)


def _seed(mut listener: QuicListener) raises -> Int:
    var d = List[UInt8]()
    var s = List[UInt8]()
    for i in range(8):
        d.append(UInt8(0xA0 + i))
        s.append(UInt8(0xB0 + i))
    var lh = LongHeader(
        packet_type=PACKET_TYPE_INITIAL,
        version=QUIC_VERSION_1,
        dcid=ConnectionId(bytes=d^),
        scid=ConnectionId(bytes=s^),
        payload_offset=0,
    )
    return listener._accept_initial(
        lh, SocketAddr(IpAddr.localhost(), UInt16(54321))
    )


def _alive_after_stream(sid: UInt64) raises -> Bool:
    var l = _bind_no_tls()
    var slot = _seed(l)
    assert_true(slot >= 0 and l.connections[slot].alive)
    var ev = empty_events()
    ev.stream_chunks.append(
        StreamFrame(
            stream_id=sid, offset=UInt64(0), data=List[UInt8](), fin=False
        )
    )
    l._route_http3_stream_chunks(slot, ev)
    var alive = l.connections[slot].alive
    if not alive:
        var code = Int(l.connections[slot].conn.close_error_code)
        assert_equal(code, 4 if (Int(sid) & 1) == 0 else 5)
    return alive


def test_uni_stream_limit_enforced_on_stream_frames() raises:
    """QUIC-16: the unidirectional limit (3 by default) is enforced like
    the bidirectional one."""
    assert_true(_alive_after_stream(UInt64(2)))  # 1st
    assert_true(_alive_after_stream(UInt64(10)))  # 3rd
    assert_false(_alive_after_stream(UInt64(14)), "4th uni stream accepted")
    assert_false(_alive_after_stream(UInt64(400)), "101st bidi stream accepted")
    assert_false(_alive_after_stream(UInt64(1002)), "uni stream 251 accepted")
    assert_true(_alive_after_stream(UInt64(396)))  # 100th bidi


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def test_state_error_reaches_the_client_as_connection_close() raises:
    """A frame the state machine rejects must be signalled with a
    CONNECTION_CLOSE carrying the code, not dropped silently."""
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    var server = QuicListener.bind(cfg^)
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(60):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete")
    for _ in range(4):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
    # RESET_STREAM on server unidirectional stream 3, straight onto the
    # socket (no client-side guards), padded for the header-protection
    # sample.
    var payload: List[UInt8] = [0x04, 0x03, 0x00, 0x00]
    while len(payload) < 16:
        payload.append(0)
    var dg = client._build_1rtt(payload^, ack_eliciting=True)
    _ = client.sock.send_to(Span[UInt8, _](dg), client.peer)
    var closed = False
    var code = 0
    for _ in range(20):
        _ = server.tick(timeout_ms=20)
        var ev = client.poll(timeout_ms=20)
        if ev.connection_closed:
            closed = True
            code = Int(ev.error_code)
            break
    assert_true(closed, "no CONNECTION_CLOSE reached the client")
    assert_equal(code, 5)
    server.close()
    client.close()


def main() raises:
    test_frames_on_client_bidi_stream_0_are_accepted()
    test_send_only_stream_frames_for_the_receive_half_rejected()
    test_receive_only_stream_frames_for_the_send_half_rejected()
    test_unopened_server_stream_rejected()
    test_stream_ids_above_the_advertised_limit_rejected()
    test_uni_stream_limit_enforced_on_stream_frames()
    test_state_error_reaches_the_client_as_connection_close()
    print("test_quic_server_stream_frames: 7 passed")
