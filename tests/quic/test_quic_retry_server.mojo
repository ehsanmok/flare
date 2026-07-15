"""Server-side QUIC Retry (RFC 9000 sec 8.1) over loopback UDP.

With require_address_validation set, the listener must answer a
token-less Initial with a Retry packet (valid integrity tag, no
connection state committed), then accept an Initial that replays a
valid minted token, and drop one carrying a bogus token. Drives the
real reactor over a loopback socket, mirroring
test_quic_loopback_integration's synth-Initial pattern.
"""

from std.memory import Span
from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    FRAME_TYPE_PADDING,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    QuicListener,
    QuicServerConfig,
    StreamFrame,
    cid_to_hex,
    encode_long_header,
    encode_stream,
    encode_varint,
    protect_initial_packet,
)
from flare.quic.packet import PACKET_TYPE_RETRY, parse_long_header
from flare.quic.retry import verify_retry_integrity
from flare.udp import UdpSocket


def _make_cid(seed: UInt8, length: Int) -> ConnectionId:
    var bytes = List[UInt8]()
    for i in range(length):
        bytes.append(seed + UInt8(i))
    return ConnectionId(bytes^)


def _synth_initial(
    dcid: ConnectionId,
    scid: ConnectionId,
    token: List[UInt8],
) raises -> List[UInt8]:
    """A minimal encrypted Initial with an explicit (possibly empty)
    token, one PADDING-filled plaintext envelope."""
    var frame = StreamFrame(
        stream_id=UInt64(0), offset=UInt64(0), data=List[UInt8](), fin=False
    )
    var plaintext = List[UInt8]()
    encode_stream(frame, plaintext)
    while len(plaintext) < 64:
        plaintext.append(UInt8(FRAME_TYPE_PADDING))

    var hdr = encode_long_header(
        PACKET_TYPE_INITIAL, QUIC_VERSION_1, dcid, scid, type_specific_bits=0
    )
    var prefix = List[UInt8]()
    for i in range(len(hdr)):
        prefix.append(hdr[i])
    var tok_len = encode_varint(UInt64(len(token)))
    for i in range(len(tok_len)):
        prefix.append(tok_len[i])
    for i in range(len(token)):
        prefix.append(token[i])
    var payload_total = len(plaintext) + 1 + 16  # pn_length + AEAD tag
    var plen = encode_varint(UInt64(payload_total))
    for i in range(len(plen)):
        prefix.append(plen[i])
    return protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=UInt64(0),
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid,
        is_server=False,
    )


def _extract_retry_token(retry: List[UInt8]) raises -> List[UInt8]:
    """Token octets = payload_offset .. len-16 (the trailing 16 is the
    integrity tag)."""
    var lh = parse_long_header(Span[UInt8, _](retry))
    var out = List[UInt8]()
    for i in range(lh.payload_offset, len(retry) - 16):
        out.append(retry[i])
    return out^


def _bind_validating_listener() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.require_address_validation = True
    return QuicListener.bind(cfg)


def main() raises:
    print("test_quic_retry_server")
    var listener = _bind_validating_listener()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    client.set_recv_timeout(2000)

    var dcid = _make_cid(UInt8(0xA1), 8)
    var scid = _make_cid(UInt8(0xB2), 8)

    # 1) Token-less Initial -> Retry, no accept.
    _ = client.send_to(
        Span[UInt8, _](_synth_initial(dcid, scid, List[UInt8]())), server_addr
    )
    _ = listener.tick(500)
    assert_equal(listener.connection_count(), 0)

    var buf = List[UInt8](capacity=2048)
    buf.resize(2048, 0)
    var res = client.recv_from(Span[UInt8, _](buf))
    var retry = List[UInt8]()
    for i in range(res[0]):
        retry.append(buf[i])
    var rlh = parse_long_header(Span[UInt8, _](retry))
    assert_equal(rlh.packet_type, PACKET_TYPE_RETRY)
    assert_true(
        verify_retry_integrity(retry, dcid),
        "Retry integrity tag must verify against the original DCID",
    )

    # 2) Replay the minted token -> accept.
    var token = _extract_retry_token(retry)
    assert_true(len(token) > 0, "Retry must carry a token")
    _ = client.send_to(
        Span[UInt8, _](_synth_initial(rlh.scid, scid, token)), server_addr
    )
    _ = listener.tick(500)
    assert_equal(
        listener.connection_count(),
        1,
        "a valid retry token must clear the client for accept",
    )

    # 3) Bogus token -> dropped (still one connection, no new slot).
    var bogus = List[UInt8]()
    for _i in range(len(token)):
        bogus.append(UInt8(0x00))
    var dcid2 = _make_cid(UInt8(0x33), 8)
    _ = client.send_to(
        Span[UInt8, _](_synth_initial(dcid2, scid, bogus)), server_addr
    )
    _ = listener.tick(500)
    assert_equal(
        listener.connection_count(),
        1,
        "an invalid retry token must not create a connection",
    )

    listener.shutdown()
    listener.close()
    print("test_quic_retry_server: 1 passed")
