"""Per-level egress queues + readiness install.

Covers the wiring added to :meth:`QuicListener._dispatch_crypto_frames`:

1. Listener accept allocates a per-slot Handshake-level egress queue
   AND a per-slot 1-RTT-level egress queue parallel to the existing
   Initial-level queue. All three slabs stay in lockstep with
   :attr:`QuicListener.connections`.
2. The per-tick CRYPTO pump now calls
   :func:`_do_have_keys(session, HANDSHAKE)` and
   :func:`_do_have_keys(session, APPLICATION)` after every
   :func:`_do_take_crypto`. When the keys haven't flipped yet
   (rustls hasn't processed a real ClientHello), the connection's
   :attr:`rx_handshake_secret` + :attr:`rx_1rtt_secret` carriers
   stay empty -- the post-Initial decrypt path remains the
   silent-drop gate.
3. The `_inbound_level_for_datagram` helper picks the right
   encryption-level codepoint from the QUIC packet header form
   (long vs short) and the long-header type bits per RFC 9000
   §17.2 / §17.3. Observable indirectly through the dispatch
   path's feed-crypto level argument.

The full key-install-flips-to-True path (KeyChange::Handshake +
KeyChange::OneRtt under a real ClientHello) is what the Phase F
commit 5/6 bench gate exercises end-to-end -- this commit only
adds the plumbing + the negative-control regression tests.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    FRAME_TYPE_PADDING,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    CryptoFrame,
    QuicListener,
    QuicServerConfig,
    cid_to_hex,
    encode_crypto,
    encode_long_header,
    encode_varint,
    protect_initial_packet,
)
from flare.tls import QuicEncryptionLevel, RustlsQuicConfig
from flare.udp import UdpSocket


def _load_fixture_pem() raises -> Tuple[String, String]:
    var cert = Path(
        String("tests/tls/fixtures/rustls-quic-cert/cert.pem")
    ).read_text()
    var key = Path(
        String("tests/tls/fixtures/rustls-quic-cert/key.pem")
    ).read_text()
    return (cert^, key^)


def _make_h3_config() raises -> RustlsQuicConfig:
    var cert_pem: String
    var key_pem: String
    cert_pem, key_pem = _load_fixture_pem()
    var cfg = RustlsQuicConfig()
    cfg.cert_chain_pem = cert_pem^
    cfg.private_key_pem = key_pem^
    cfg.alpn_protocols = List[String]()
    cfg.alpn_protocols.append(String("h3"))
    return cfg^


def _bind_real_pem() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_idle_timeout_ms = UInt64(30_000)
    cfg.rustls_config = _make_h3_config()
    return QuicListener.bind(cfg)


def _make_cid(seed: UInt8, length: Int) -> ConnectionId:
    var bytes = List[UInt8]()
    for i in range(length):
        bytes.append(seed + UInt8(i))
    return ConnectionId(bytes^)


def _crypto_frame_bytes(payload: List[UInt8]) raises -> List[UInt8]:
    var frame = CryptoFrame(offset=UInt64(0), data=payload.copy())
    var out = List[UInt8]()
    encode_crypto(frame, out)
    return out^


def _padded_plaintext(payload: List[UInt8], total: Int) raises -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(len(payload)):
        out.append(payload[i])
    while len(out) < total:
        out.append(UInt8(FRAME_TYPE_PADDING))
    return out^


def _build_synth_initial_with_crypto(
    dcid: ConnectionId,
    scid: ConnectionId,
    packet_number: UInt64,
    var crypto_payload: List[UInt8],
) raises -> List[UInt8]:
    var crypto_bytes = _crypto_frame_bytes(crypto_payload^)
    var plaintext = _padded_plaintext(crypto_bytes, 80)
    var first_bits = 0
    var hdr = encode_long_header(
        PACKET_TYPE_INITIAL,
        QUIC_VERSION_1,
        dcid,
        scid,
        type_specific_bits=first_bits,
    )
    var prefix = List[UInt8]()
    for i in range(len(hdr)):
        prefix.append(hdr[i])
    var token_len_var = encode_varint(UInt64(0))
    for i in range(len(token_len_var)):
        prefix.append(token_len_var[i])
    var aead_overhead = 16
    var payload_total = len(plaintext) + 1 + aead_overhead
    var payload_len_var = encode_varint(UInt64(payload_total))
    for i in range(len(payload_len_var)):
        prefix.append(payload_len_var[i])
    return protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=packet_number,
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid,
        is_server=False,
    )


def test_per_level_egress_queues_allocated_in_lockstep() raises:
    """Accepting an Initial allocates one entry per slot in EACH
    of the three per-level egress queues (Initial, Handshake,
    1-RTT); v0.8 originally only had the Initial-level queue.
    Lockstep with
    :attr:`tls_sessions` + `connections` so the
    :meth:`_dispatch_crypto_frames` pump can index by slot for
    every level."""
    var listener = _bind_real_pem()
    assert_equal(len(listener.tls_egress_queues), 0)
    assert_equal(len(listener.tls_handshake_egress_queues), 0)
    assert_equal(len(listener.tls_1rtt_egress_queues), 0)
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0x10), 8)
    var scid = _make_cid(UInt8(0x20), 8)
    var payload = List[UInt8]()
    for i in range(16):
        payload.append(UInt8(0xAA + i))
    var dg = _build_synth_initial_with_crypto(dcid, scid, UInt64(0), payload^)
    _ = client.send_to(Span[UInt8, _](dg), server_addr)
    var got = listener.tick(500)
    assert_true(got, "tick must observe the inbound datagram")
    assert_equal(listener.connection_count(), 1)
    assert_equal(
        len(listener.tls_egress_queues),
        1,
        "Initial egress queue allocated for slot 0",
    )
    assert_equal(
        len(listener.tls_handshake_egress_queues),
        1,
        "Handshake egress queue allocated for slot 0",
    )
    assert_equal(
        len(listener.tls_1rtt_egress_queues),
        1,
        "1-RTT egress queue allocated for slot 0",
    )
    listener.shutdown()
    listener.close()


def test_synth_initial_does_not_flip_handshake_or_1rtt_keys() raises:
    """A synthetic Initial that rustls REJECTS (the bytes are
    opaque garbage, not a real ClientHello) must NOT flip the
    handshake-readiness sentinel on the connection.  Negative-
    control regression for the pump: without a successful TLS
    state transition, rustls's `KeyChange` never
    fires, so :func:`_do_have_keys` returns 0 at every level and
    the connection's :attr:`rx_handshake_secret` +
    `rx_1rtt_secret` stay empty -- the post-Initial decrypt path
    remains in silent-drop mode."""
    var listener = _bind_real_pem()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0x30), 8)
    var scid = _make_cid(UInt8(0x40), 8)
    var payload = List[UInt8]()
    for i in range(24):
        payload.append(UInt8(i))
    var dg = _build_synth_initial_with_crypto(dcid, scid, UInt64(0), payload^)
    _ = client.send_to(Span[UInt8, _](dg), server_addr)
    var got = listener.tick(500)
    assert_true(got)
    assert_equal(listener.connection_count(), 1)
    var conn = listener.connections[0].copy()
    assert_equal(
        len(conn.rx_handshake_secret),
        0,
        (
            "rustls rejected the synth bytes so no KeyChange fired;"
            " the handshake-readiness sentinel must stay empty"
        ),
    )
    assert_equal(
        len(conn.tx_handshake_secret),
        0,
        "tx side of the same sentinel must also stay empty",
    )
    assert_equal(
        len(conn.rx_1rtt_secret),
        0,
        "1-RTT readiness sentinel must stay empty",
    )
    assert_equal(len(conn.tx_1rtt_secret), 0)
    # All three per-level egress queues stay empty too (rustls
    # didn't accept the bytes so it produced no outbound CRYPTO).
    assert_equal(len(listener.tls_egress_queues[0]), 0)
    assert_equal(len(listener.tls_handshake_egress_queues[0]), 0)
    assert_equal(len(listener.tls_1rtt_egress_queues[0]), 0)
    listener.shutdown()
    listener.close()


def test_multiple_synth_initials_keep_egress_queues_in_lockstep() raises:
    """Three independent connections -> three slots in EACH
    per-level egress queue. The lockstep invariant lives at every
    slot allocation point and is what
    :meth:`_dispatch_crypto_frames` indexes by; a drift here
    would silently route Handshake bytes onto slot 0 when slot 2
    expected them (the kind of bug fuzz_quic_initial_handshake
    won't catch because it runs single-connection)."""
    var listener = _bind_real_pem()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var bases = List[UInt8]()
    bases.append(UInt8(0x50))
    bases.append(UInt8(0x60))
    bases.append(UInt8(0x70))
    for i in range(3):
        var dcid = _make_cid(bases[i], 8)
        var scid = _make_cid(bases[i] + UInt8(8), 8)
        var payload = List[UInt8]()
        payload.append(UInt8(0x16))
        payload.append(UInt8(0x03))
        payload.append(UInt8(0x03))
        var dg = _build_synth_initial_with_crypto(
            dcid, scid, UInt64(0), payload^
        )
        _ = client.send_to(Span[UInt8, _](dg), server_addr)
        var got = listener.tick(500)
        assert_true(got, "tick must observe each inbound datagram")
    assert_equal(listener.connection_count(), 3)
    assert_equal(len(listener.tls_egress_queues), 3)
    assert_equal(len(listener.tls_handshake_egress_queues), 3)
    assert_equal(len(listener.tls_1rtt_egress_queues), 3)
    listener.shutdown()
    listener.close()


def main() raises:
    test_per_level_egress_queues_allocated_in_lockstep()
    test_synth_initial_does_not_flip_handshake_or_1rtt_keys()
    test_multiple_synth_initials_keep_egress_queues_in_lockstep()
    print("test_quic_keys_install: 3 passed")
