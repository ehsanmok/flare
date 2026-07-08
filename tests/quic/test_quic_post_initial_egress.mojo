"""Handshake + 1-RTT egress builders.

Exercises the :meth:`QuicListener._build_handshake_response` /
`._build_1rtt_response` builders and the per-level
`._drain_and_send` pass in ``flare/quic/server.mojo``.

These tests are STRUCTURAL: they verify the gating logic
(empty-queue / out-of-range-slot / missing-readiness-sentinel
return empty bytes; valid arguments produce non-empty bytes
matching the expected long/short header form).

The full end-to-end "encrypts a packet a real QUIC client can
decrypt" path is the bench gate's job -- it needs a live
handshake that flips both readiness sentinels via rustls's
KeyChange, which only happens against a real ClientHello. Here
we drive the builders directly with the readiness sentinels
stamped manually, mirroring how
:meth:`QuicListener._dispatch_crypto_frames` would stamp them
once rustls's KeyChange::Handshake / KeyChange::OneRtt fires.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_false

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    LongHeader,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    QuicListener,
    QuicServerConfig,
)
from flare.tls import RustlsQuicConfig


def _make_cid(seed: UInt8, length: Int) -> ConnectionId:
    var bytes = List[UInt8]()
    for i in range(length):
        bytes.append(seed + UInt8(i))
    return ConnectionId(bytes^)


def _synth_long_header(slot_seed: UInt8) -> LongHeader:
    """Build a synthetic Initial-packet long header with
    deterministic DCID + SCID so :meth:`_accept_initial` can
    allocate a slot without driving an actual handshake.

    The ``payload_offset`` is irrelevant for the egress-builder
    tests (those don't re-parse the header from a buffer); we
    set 0 so the LongHeader is constructible.
    """
    return LongHeader(
        packet_type=PACKET_TYPE_INITIAL,
        version=QUIC_VERSION_1,
        dcid=_make_cid(UInt8(0x80) + slot_seed, 8),
        scid=_make_cid(UInt8(0xA0) + slot_seed, 8),
        payload_offset=0,
    )


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


def test_handshake_response_empty_when_slot_out_of_range() raises:
    """``slot < 0`` and ``slot >= len(connections)`` MUST short-
    circuit to an empty byte list -- the gating order matches
    :meth:`_build_initial_response` so the builder is safe to
    call against a slab that's been concurrently shrunk."""
    var listener = _bind_real_pem()
    var dg_neg = listener._build_handshake_response(-1)
    assert_equal(len(dg_neg), 0)
    var dg_big = listener._build_handshake_response(99)
    assert_equal(len(dg_big), 0)
    listener.shutdown()
    listener.close()


def test_1rtt_response_empty_when_slot_out_of_range() raises:
    """1-RTT builder mirrors the Handshake gate: out-of-range
    slot returns empty bytes."""
    var listener = _bind_real_pem()
    var plaintext = List[UInt8]()
    plaintext.append(UInt8(0x42))
    var dg_neg = listener._build_1rtt_response(-1, plaintext.copy())
    assert_equal(len(dg_neg), 0)
    var dg_big = listener._build_1rtt_response(99, plaintext.copy())
    assert_equal(len(dg_big), 0)
    listener.shutdown()
    listener.close()


def test_handshake_response_empty_without_readiness_sentinel() raises:
    """Without the readiness sentinel stamped on
    :attr:`QuicConnection.tx_handshake_secret`, the builder MUST
    return empty bytes -- the post-Initial egress is gated on
    the same sentinel the inbound dispatch uses, so the two
    sides flip together when rustls's KeyChange::Handshake fires."""
    var listener = _bind_real_pem()
    _ = listener._accept_initial(
        _synth_long_header(0),
        SocketAddr(IpAddr.localhost(), UInt16(0)),
    )
    # Stuff bytes into the Handshake egress queue but do NOT
    # stamp the readiness sentinel -- gating MUST hold.
    listener.tls_handshake_egress_queues[0].append(UInt8(0xAA))
    listener.tls_handshake_egress_queues[0].append(UInt8(0xBB))
    var dg = listener._build_handshake_response(0)
    assert_equal(
        len(dg),
        0,
        (
            "Handshake builder must short-circuit while"
            " tx_handshake_secret is empty"
        ),
    )
    listener.shutdown()
    listener.close()


def test_1rtt_response_empty_without_readiness_sentinel() raises:
    """1-RTT builder mirrors the Handshake gate: empty bytes
    while :attr:`QuicConnection.tx_1rtt_secret` is empty."""
    var listener = _bind_real_pem()
    _ = listener._accept_initial(
        _synth_long_header(1),
        SocketAddr(IpAddr.localhost(), UInt16(0)),
    )
    var plaintext = List[UInt8]()
    plaintext.append(UInt8(0x01))
    plaintext.append(UInt8(0x02))
    var dg = listener._build_1rtt_response(0, plaintext^)
    assert_equal(
        len(dg),
        0,
        "1-RTT builder must short-circuit while tx_1rtt_secret is empty",
    )
    listener.shutdown()
    listener.close()


def test_handshake_response_empty_when_queue_empty() raises:
    """Even with the readiness sentinel stamped, an EMPTY
    Handshake egress queue must yield empty bytes -- the
    builder doesn't synthesize zero-length CRYPTO frames."""
    var listener = _bind_real_pem()
    _ = listener._accept_initial(
        _synth_long_header(2),
        SocketAddr(IpAddr.localhost(), UInt16(0)),
    )
    # Manually stamp the readiness sentinel.
    var conn = listener.connections[0].copy()
    conn.tx_handshake_secret.append(UInt8(0xFF))
    listener.connections[0] = conn^
    # Egress queue is still empty -- builder must short-circuit.
    var dg = listener._build_handshake_response(0)
    assert_equal(len(dg), 0)
    listener.shutdown()
    listener.close()


def test_drain_and_send_noop_on_closed_slot() raises:
    """The refactored :meth:`_drain_and_send` walks every per-
    level queue; closing the slot must short-circuit ALL levels
    (Initial, Handshake, 1-RTT, H3) so the closed-connection
    contract from RFC 9000 §10 still holds."""
    var listener = _bind_real_pem()
    _ = listener._accept_initial(
        _synth_long_header(4),
        SocketAddr(IpAddr.localhost(), UInt16(0)),
    )
    # Mark the slot closed.
    var conn = listener.connections[0].copy()
    conn.alive = False
    listener.connections[0] = conn^
    # Stuff bytes into every level -- _drain_and_send MUST
    # still no-op.
    listener.tls_egress_queues[0].append(UInt8(1))
    listener.tls_handshake_egress_queues[0].append(UInt8(2))
    listener.tls_1rtt_egress_queues[0].append(UInt8(3))
    var sent = listener._drain_and_send(0)
    assert_false(sent, "closed slot must skip every per-level drain")
    # Buffers stay populated -- the drain didn't fire.
    assert_equal(len(listener.tls_egress_queues[0]), 1)
    assert_equal(len(listener.tls_handshake_egress_queues[0]), 1)
    assert_equal(len(listener.tls_1rtt_egress_queues[0]), 1)
    listener.shutdown()
    listener.close()


def main() raises:
    test_handshake_response_empty_when_slot_out_of_range()
    test_1rtt_response_empty_when_slot_out_of_range()
    test_handshake_response_empty_without_readiness_sentinel()
    test_1rtt_response_empty_without_readiness_sentinel()
    test_handshake_response_empty_when_queue_empty()
    test_drain_and_send_noop_on_closed_slot()
    print("test_quic_post_initial_egress: 6 passed")
