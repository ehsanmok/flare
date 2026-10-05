"""The client checks the stream id of every stream frame (QUIC-17;
RFC 9000 sec 4.6, 19.4, 19.5, 19.8, 19.10, 19.13).

The client has opened bidirectional stream 0 and unidirectional streams 2,
6 and 10 (as the HTTP/3 client does) and advertises 16 streams of each
kind. Frames the server sends for a stream half that does not exist, a
stream the client has not opened, or a stream above the advertised limit
are connection errors (STREAM_STATE_ERROR / STREAM_LIMIT_ERROR).
"""

from std.collections import List
from std.collections.span import Span
from std.testing import assert_equal, assert_false, assert_true

from flare.net.address import IpAddr, SocketAddr
from flare.udp import UdpSocket
from flare.quic.client import QuicClientConnection
from flare.quic.crypto import QuicAead
from flare.quic.packet import ConnectionId
from flare.quic.state import (
    CONN_STATE_CLOSED,
    CONN_STATE_CLOSING,
    empty_events,
    new_connection,
)
from flare.tls.rustls_quic import RustlsQuicSession


def _cid(b: UInt8) -> List[UInt8]:
    var v = List[UInt8]()
    for _ in range(8):
        v.append(b)
    return v^


def _client() raises -> QuicClientConnection:
    var sock = UdpSocket.bind(SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)))
    var c = QuicClientConnection(
        new_connection(UInt64(30_000_000), UInt64(1 << 20)),
        RustlsQuicSession(_cid(0xAA)),
        sock^,
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(9)),
        ConnectionId(bytes=_cid(0xAA)),
        ConnectionId(bytes=_cid(0xDD)),
        QuicAead.AES_128_GCM,
        1452,
    )
    _ = c.open_bidi_stream()
    for _ in range(3):
        _ = c.open_uni_stream()
    return c^


def _verdict(var payload: List[UInt8]) raises -> Int:
    """0 when accepted, otherwise the error code the client closed with."""
    var c = _client()
    var ev = empty_events()
    try:
        c._dispatch_frames(Span[UInt8, _](payload), ev)
    except:
        assert_equal(c.conn.state, CONN_STATE_CLOSING)
        return Int(c.conn.close_error_code)
    return 0


def test_legitimate_server_frames_are_accepted() raises:
    assert_equal(_verdict([0x0A, 0x00, 0x01, 0x41]), 0)  # STREAM 0
    assert_equal(_verdict([0x0A, 0x03, 0x01, 0x41]), 0)  # server uni 3
    assert_equal(_verdict([0x0A, 0x01, 0x01, 0x41]), 0)  # server bidi 1
    assert_equal(_verdict([0x05, 0x00, 0x00]), 0)  # STOP_SENDING 0
    assert_equal(_verdict([0x11, 0x00, 0x10]), 0)  # MAX_STREAM_DATA 0
    # The client's own unidirectional streams can receive STOP_SENDING and
    # MAX_STREAM_DATA (they have a send half).
    assert_equal(_verdict([0x05, 0x02, 0x00]), 0)
    assert_equal(_verdict([0x11, 0x0A, 0x10]), 0)
    # RESET_STREAM / STREAM_DATA_BLOCKED on a server unidirectional stream.
    assert_equal(_verdict([0x04, 0x03, 0x00, 0x00]), 0)
    assert_equal(_verdict([0x15, 0x03, 0x00]), 0)


def test_stream_data_on_a_send_only_stream_rejected() raises:
    """STREAM 2 is the client's own (send-only) control stream."""
    assert_equal(_verdict([0x0A, 0x02, 0x01, 0x41]), 5)
    assert_equal(_verdict([0x04, 0x02, 0x00, 0x00]), 5)  # RESET_STREAM 2
    assert_equal(_verdict([0x15, 0x02, 0x00]), 5)  # STREAM_DATA_BLOCKED 2


def test_frames_for_a_stream_the_client_has_not_opened_rejected() raises:
    assert_equal(_verdict([0x0A, 0x04, 0x01, 0x41]), 5)  # bidi 4 unopened
    assert_equal(_verdict([0x05, 0x04, 0x00]), 5)  # STOP_SENDING 4
    assert_equal(_verdict([0x11, 0x04, 0x10]), 5)  # MAX_STREAM_DATA 4
    assert_equal(_verdict([0x05, 0x0E, 0x00]), 5)  # uni 14 (5th) unopened


def test_receive_only_stream_frames_for_the_send_half_rejected() raises:
    """STOP_SENDING / MAX_STREAM_DATA on a server unidirectional stream
    (id 3), which the client can only receive on."""
    assert_equal(_verdict([0x05, 0x03, 0x00]), 5)
    assert_equal(_verdict([0x11, 0x03, 0x10]), 5)


def test_server_streams_above_the_advertised_limit_rejected() raises:
    """The client advertises 16 streams of each kind: bidi 61 is the 16th,
    65 the 17th; uni 63 is the 16th, 67 the 17th."""
    assert_equal(_verdict([0x0A, 0x3D, 0x01, 0x41]), 0)
    assert_equal(_verdict([0x0A, 0x40, 0x41, 0x01, 0x41]), 4)  # STREAM 65
    assert_equal(_verdict([0x0A, 0x3F, 0x01, 0x41]), 0)
    assert_equal(_verdict([0x0A, 0x40, 0x43, 0x01, 0x41]), 4)  # STREAM 67
    assert_equal(_verdict([0x04, 0x40, 0x43, 0x00, 0x00]), 4)  # RESET 67


def test_a_rejected_frame_closes_the_client() raises:
    """The state error ends the connection: a CONNECTION_CLOSE would go
    out (when 1-RTT keys exist), the client is no longer established and
    the caller is told through ``connection_closed``."""
    var c = _client()
    c.established = True
    var ev = empty_events()
    var payload: List[UInt8] = [0x0A, 0x02, 0x01, 0x41]
    try:
        c._dispatch_frames(Span[UInt8, _](payload), ev)
    except:
        c._fail_on_state_error(ev)
    assert_equal(c.conn.state, CONN_STATE_CLOSED)
    assert_false(c.established)
    assert_true(ev.connection_closed)
    assert_equal(Int(ev.error_code), 5)


def main() raises:
    test_legitimate_server_frames_are_accepted()
    test_stream_data_on_a_send_only_stream_rejected()
    test_frames_for_a_stream_the_client_has_not_opened_rejected()
    test_receive_only_stream_frames_for_the_send_half_rejected()
    test_server_streams_above_the_advertised_limit_rejected()
    test_a_rejected_frame_closes_the_client()
    print("test_quic_client_stream_frames: 6 passed")
