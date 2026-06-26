"""QUIC Retry + Version Negotiation codec tests
(``flare.quic.retry`` -- RFC 9000 §17.2.1/§17.2.5, RFC 9001 §5.8).

The Retry Integrity Tag case is the RFC 9001 Appendix A.4 known-answer
vector, so it pins the AEAD construction (key, nonce, pseudo-packet
layout) against the spec. The token cases exercise the HMAC
address-validation token's authenticity, address binding, and expiry.
"""

from std.memory import Span
from std.testing import assert_equal, assert_false, assert_true

from flare.quic.packet import ConnectionId, QUIC_VERSION_1
from flare.quic.retry import (
    encode_retry_packet,
    encode_version_negotiation,
    mint_retry_token,
    retry_integrity_tag,
    validate_retry_token,
    verify_retry_integrity,
)


def _cid(*bytes: Int) -> ConnectionId:
    var out = List[UInt8]()
    for b in bytes:
        out.append(UInt8(b))
    return ConnectionId(bytes=out^)


def _bytes(*bytes: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for b in bytes:
        out.append(UInt8(b))
    return out^


def test_retry_integrity_tag_rfc9001_a4() raises:
    # RFC 9001 Appendix A.4 known-answer. ODCID = 0x8394c8f03e515708;
    # the Retry packet body (with the appendix's arbitrary first byte
    # 0xff) is ff000000010008f067a5502a4262b5746f6b656e and the
    # expected integrity tag is 04a265ba2eff4d829058fb3f0f2496ba.
    # Feeding the canonical body pins the AEAD construction (key, nonce,
    # pseudo-packet layout) against the spec regardless of the unused
    # first-byte bits our encoder picks.
    var odcid = _cid(0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08)
    var body = _bytes(
        0xFF,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x08,
        0xF0,
        0x67,
        0xA5,
        0x50,
        0x2A,
        0x42,
        0x62,
        0xB5,
        0x74,
        0x6F,
        0x6B,
        0x65,
        0x6E,
    )
    var expected = _bytes(
        0x04,
        0xA2,
        0x65,
        0xBA,
        0x2E,
        0xFF,
        0x4D,
        0x82,
        0x90,
        0x58,
        0xFB,
        0x3F,
        0x0F,
        0x24,
        0x96,
        0xBA,
    )
    var tag = retry_integrity_tag(odcid, body)
    assert_equal(len(tag), 16)
    for i in range(len(expected)):
        assert_equal(tag[i], expected[i])


def test_verify_retry_integrity_round_trip() raises:
    var odcid = _cid(0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08)
    var scid = _cid(0xF0, 0x67, 0xA5, 0x50, 0x2A, 0x42, 0x62, 0xB5)
    var dcid = ConnectionId(bytes=List[UInt8]())
    var token = _bytes(0x74, 0x6F, 0x6B, 0x65, 0x6E)
    var packet = encode_retry_packet(QUIC_VERSION_1, dcid, scid, token, odcid)
    assert_true(verify_retry_integrity(packet, odcid))
    # Wrong ODCID must fail the tag check.
    var wrong = _cid(0x00, 0x11, 0x22, 0x33)
    assert_false(verify_retry_integrity(packet, wrong))
    # A tampered tag byte must fail.
    var tampered = packet.copy()
    tampered[len(tampered) - 1] = tampered[len(tampered) - 1] ^ UInt8(0x01)
    assert_false(verify_retry_integrity(tampered, odcid))


def test_retry_token_round_trip() raises:
    var key = _bytes(1, 2, 3, 4, 5, 6, 7, 8)
    var addr = _bytes(192, 168, 0, 1, 0xC3, 0x50)  # ip + port
    var odcid = _cid(0xAA, 0xBB, 0xCC, 0xDD)
    var token = mint_retry_token(key, addr, odcid, UInt64(1000))
    var recovered = validate_retry_token(
        key, token, addr, UInt64(2000), UInt64(10000)
    )
    assert_true(Bool(recovered))
    var got = recovered.value().copy()
    assert_equal(got.length(), 4)
    assert_equal(got.bytes[0], UInt8(0xAA))
    assert_equal(got.bytes[3], UInt8(0xDD))


def test_retry_token_address_mismatch_rejected() raises:
    var key = _bytes(9, 9, 9, 9)
    var addr = _bytes(10, 0, 0, 1, 0x01, 0xBB)
    var odcid = _cid(0x01, 0x02)
    var token = mint_retry_token(key, addr, odcid, UInt64(500))
    var other_addr = _bytes(10, 0, 0, 2, 0x01, 0xBB)
    var recovered = validate_retry_token(
        key, token, other_addr, UInt64(600), UInt64(10000)
    )
    assert_false(Bool(recovered))


def test_retry_token_expired_rejected() raises:
    var key = _bytes(7, 7, 7)
    var addr = _bytes(127, 0, 0, 1, 0x1F, 0x90)
    var odcid = _cid(0xDE, 0xAD)
    var token = mint_retry_token(key, addr, odcid, UInt64(1000))
    # now - issued = 20000 > max_age 10000 -> rejected.
    var recovered = validate_retry_token(
        key, token, addr, UInt64(21000), UInt64(10000)
    )
    assert_false(Bool(recovered))


def test_retry_token_tamper_rejected() raises:
    var key = _bytes(3, 1, 4, 1, 5)
    var addr = _bytes(172, 16, 0, 9, 0x23, 0x28)
    var odcid = _cid(0x11, 0x22, 0x33)
    var token = mint_retry_token(key, addr, odcid, UInt64(100))
    var tampered = token.copy()
    tampered[len(tampered) - 1] = tampered[len(tampered) - 1] ^ UInt8(0xFF)
    var recovered = validate_retry_token(
        key, tampered, addr, UInt64(200), UInt64(10000)
    )
    assert_false(Bool(recovered))


def test_retry_token_wrong_key_rejected() raises:
    var key = _bytes(1, 1, 1, 1)
    var addr = _bytes(8, 8, 8, 8, 0x00, 0x35)
    var odcid = _cid(0x42)
    var token = mint_retry_token(key, addr, odcid, UInt64(100))
    var attacker_key = _bytes(2, 2, 2, 2)
    var recovered = validate_retry_token(
        attacker_key, token, addr, UInt64(150), UInt64(10000)
    )
    assert_false(Bool(recovered))


def test_version_negotiation_shape() raises:
    var dcid = _cid(0x01, 0x02, 0x03, 0x04)
    var scid = _cid(0xAA, 0xBB)
    var versions = List[UInt32]()
    versions.append(QUIC_VERSION_1)
    versions.append(UInt32(0x6B3343CF))  # a grease/draft version
    var pkt = encode_version_negotiation(dcid, scid, versions)
    # First byte high bit set (long header form).
    assert_true((Int(pkt[0]) & 0x80) != 0)
    # Version field is all-zero (marks VN).
    assert_equal(pkt[1], UInt8(0))
    assert_equal(pkt[2], UInt8(0))
    assert_equal(pkt[3], UInt8(0))
    assert_equal(pkt[4], UInt8(0))
    # DCID len + DCID, SCID len + SCID.
    assert_equal(pkt[5], UInt8(4))
    assert_equal(pkt[6], UInt8(0x01))
    assert_equal(pkt[10], UInt8(2))  # scid len at offset 5+1+4
    assert_equal(pkt[11], UInt8(0xAA))
    # Then two 4-byte versions.
    var vstart = 13  # 5 (first+version) + 1+4 (dcid) + 1+2 (scid)
    assert_equal(pkt[vstart], UInt8(0x00))  # QUIC v1 high byte
    assert_equal(pkt[vstart + 3], UInt8(0x01))
    assert_equal(len(pkt), vstart + 8)


def main() raises:
    test_retry_integrity_tag_rfc9001_a4()
    test_verify_retry_integrity_round_trip()
    test_retry_token_round_trip()
    test_retry_token_address_mismatch_rejected()
    test_retry_token_expired_rejected()
    test_retry_token_tamper_rejected()
    test_retry_token_wrong_key_rejected()
    test_version_negotiation_shape()
    print("test_quic_retry: 8 passed")
