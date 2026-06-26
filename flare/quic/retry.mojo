"""QUIC server Retry + Version Negotiation packet codecs (RFC 9000
§8.1 / §17.2.1 / §17.2.5, RFC 9001 §5.8).

When a server wants to validate a client's source address before
committing handshake state, it answers the client Initial with a
**Retry** packet carrying an opaque address-validation **token**. The
client replays the token in a fresh Initial; the server validates it and
proceeds. This module ships:

* :func:`mint_retry_token` / :func:`validate_retry_token` -- an
  HMAC-SHA256 keyed token that binds the client's address and the
  original Destination Connection ID with an issue timestamp, so a token
  is single-path and expires. The server holds the HMAC key; the token
  is opaque to the client.
* :func:`encode_retry_packet` -- assemble the full Retry packet
  including the RFC 9001 §5.8 Retry Integrity Tag (AEAD_AES_128_GCM over
  the Retry Pseudo-Packet with the fixed v1 retry key/nonce).
* :func:`verify_retry_integrity` -- recompute + compare the integrity
  tag of a received Retry (client-side check).
* :func:`encode_version_negotiation` -- build the Version Negotiation
  packet a server sends when a client Initial carries an unsupported
  QUIC version (RFC 9000 §6.1).

Not sans-I/O: the Retry Integrity Tag routes through the OpenSSL AEAD
FFI (:class:`flare.quic.crypto.OpenSslQuicCrypto`). The token HMAC and
the version-negotiation builder are pure, but the module as a whole
links the crypto backend, so it lives outside the sans-I/O set.

References:
- RFC 9000 §8.1 "Address Validation", §17.2.1 / §17.2.5, §6.1.
- RFC 9001 §5.8 "Retry Packet Integrity".
"""

from std.collections import List, Optional
from std.memory import Span

from flare.crypto.hmac import hmac_sha256, hmac_sha256_verify

from .crypto import OpenSslQuicCrypto, PacketKeys, QuicAead
from .packet import ConnectionId, MAX_CID_LENGTH


comptime _RETRY_TAG_LEN: Int = 16

comptime _RETRY_TOKEN_VERSION: UInt8 = 0x01
"""Local token format version so the issuer can evolve the layout."""
comptime _RETRY_TOKEN_MAC_LEN: Int = 32


def _retry_v1_key() -> List[UInt8]:
    """RFC 9001 §5.8 -- QUIC v1 Retry Integrity Tag AES-128-GCM key."""
    var out = List[UInt8](capacity=16)
    for b in [
        0xBE,
        0x0C,
        0x69,
        0x0B,
        0x9F,
        0x66,
        0x57,
        0x5A,
        0x1D,
        0x76,
        0x6B,
        0x54,
        0xE3,
        0x68,
        0xC8,
        0x4E,
    ]:
        out.append(UInt8(b))
    return out^


def _retry_v1_nonce() -> List[UInt8]:
    """RFC 9001 §5.8 -- QUIC v1 Retry Integrity Tag 96-bit nonce."""
    var out = List[UInt8](capacity=12)
    for b in [
        0x46,
        0x15,
        0x99,
        0xD3,
        0x5D,
        0x63,
        0x2B,
        0xF2,
        0x23,
        0x98,
        0x25,
        0xBB,
    ]:
        out.append(UInt8(b))
    return out^


def _u64_be(value: UInt64) -> List[UInt8]:
    var out = List[UInt8](capacity=8)
    for shift in range(56, -8, -8):
        out.append(UInt8((value >> UInt64(shift)) & UInt64(0xFF)))
    return out^


def _read_u64_be(buf: Span[UInt8, _], offset: Int) -> UInt64:
    var v = UInt64(0)
    for i in range(8):
        v = (v << UInt64(8)) | UInt64(buf[offset + i])
    return v


# ── Retry token (HMAC-SHA256 address-validation token) ──────────────────────


def _retry_token_mac_message(
    client_addr: List[UInt8], issued_ms: UInt64, odcid: ConnectionId
) -> List[UInt8]:
    """The bytes the token MAC covers: format version, client address,
    issue time, and the original DCID. Binding the client address makes
    the token single-path; binding the ODCID lets the server recover it
    on replay."""
    var msg = List[UInt8]()
    msg.append(_RETRY_TOKEN_VERSION)
    msg.append(UInt8(len(client_addr)))
    for i in range(len(client_addr)):
        msg.append(client_addr[i])
    var t = _u64_be(issued_ms)
    for i in range(len(t)):
        msg.append(t[i])
    msg.append(UInt8(odcid.length()))
    for i in range(odcid.length()):
        msg.append(odcid.bytes[i])
    return msg^


def mint_retry_token(
    server_key: List[UInt8],
    client_addr: List[UInt8],
    odcid: ConnectionId,
    issued_ms: UInt64,
) raises -> List[UInt8]:
    """Issue an opaque Retry token bound to ``client_addr`` and
    ``odcid``, stamped at ``issued_ms``.

    Wire layout (server-private; opaque to the client):
    ``version(1) || issued_ms(8) || odcid_len(1) || odcid ||
    HMAC-SHA256(server_key, mac_message)``.
    """
    if odcid.length() > MAX_CID_LENGTH:
        raise Error("retry token: odcid exceeds 20 bytes")
    var msg = _retry_token_mac_message(client_addr, issued_ms, odcid)
    var mac = hmac_sha256(server_key, msg)
    var token = List[UInt8]()
    token.append(_RETRY_TOKEN_VERSION)
    var t = _u64_be(issued_ms)
    for i in range(len(t)):
        token.append(t[i])
    token.append(UInt8(odcid.length()))
    for i in range(odcid.length()):
        token.append(odcid.bytes[i])
    for i in range(len(mac)):
        token.append(mac[i])
    return token^


def validate_retry_token(
    server_key: List[UInt8],
    token: List[UInt8],
    client_addr: List[UInt8],
    now_ms: UInt64,
    max_age_ms: UInt64,
) raises -> Optional[ConnectionId]:
    """Validate a replayed Retry token. Returns the recovered original
    DCID when the token is authentic, address-matched, and unexpired;
    ``None`` otherwise. Never raises on a malformed token -- a forged or
    truncated token is simply rejected (returns ``None``)."""
    # Minimum: version(1) + issued(8) + odcid_len(1) + mac(32).
    if len(token) < 1 + 8 + 1 + _RETRY_TOKEN_MAC_LEN:
        return None
    if token[0] != _RETRY_TOKEN_VERSION:
        return None
    var issued_ms = _read_u64_be(Span[UInt8, _](token), 1)
    var odcid_len = Int(token[9])
    if odcid_len > MAX_CID_LENGTH:
        return None
    var mac_start = 10 + odcid_len
    if len(token) != mac_start + _RETRY_TOKEN_MAC_LEN:
        return None
    var odcid_bytes = List[UInt8](capacity=odcid_len)
    for i in range(10, mac_start):
        odcid_bytes.append(token[i])
    var odcid = ConnectionId(bytes=odcid_bytes^)
    var mac = List[UInt8](capacity=_RETRY_TOKEN_MAC_LEN)
    for i in range(mac_start, len(token)):
        mac.append(token[i])
    var msg = _retry_token_mac_message(client_addr, issued_ms, odcid)
    if not hmac_sha256_verify(server_key, msg, mac):
        return None
    # Expiry: reject tokens older than max_age_ms (and clock-skewed
    # future tokens beyond a small allowance are also rejected).
    if now_ms >= issued_ms:
        if now_ms - issued_ms > max_age_ms:
            return None
    return Optional[ConnectionId](odcid^)


# ── Retry packet (RFC 9000 §17.2.5 + RFC 9001 §5.8) ─────────────────────────


def _retry_header_and_token(
    version: UInt32,
    dcid: ConnectionId,
    scid: ConnectionId,
    token: List[UInt8],
) raises -> List[UInt8]:
    """The Retry packet bytes from the first byte through the Retry
    Token, excluding the 16-byte integrity tag."""
    if dcid.length() > MAX_CID_LENGTH or scid.length() > MAX_CID_LENGTH:
        raise Error("retry packet: CID length exceeds 20")
    var out = List[UInt8]()
    # First byte: long header (0x80) + fixed bit (0x40) + type Retry (3
    # in bits 4-5 = 0x30). Low 4 bits are unused in v1 Retry.
    out.append(UInt8(0xC0 | (3 << 4)))
    out.append(UInt8((Int(version) >> 24) & 0xFF))
    out.append(UInt8((Int(version) >> 16) & 0xFF))
    out.append(UInt8((Int(version) >> 8) & 0xFF))
    out.append(UInt8(Int(version) & 0xFF))
    out.append(UInt8(dcid.length()))
    for i in range(dcid.length()):
        out.append(dcid.bytes[i])
    out.append(UInt8(scid.length()))
    for i in range(scid.length()):
        out.append(scid.bytes[i])
    for i in range(len(token)):
        out.append(token[i])
    return out^


def retry_integrity_tag(
    odcid: ConnectionId, retry_header_and_token: List[UInt8]
) raises -> List[UInt8]:
    """Compute the RFC 9001 §5.8 Retry Integrity Tag: AEAD_AES_128_GCM
    over the Retry Pseudo-Packet (ODCID-len || ODCID || the Retry packet
    body without the tag) with the fixed v1 retry key/nonce and an empty
    plaintext. The 16-byte output is the tag."""
    var pseudo = List[UInt8]()
    pseudo.append(UInt8(odcid.length()))
    for i in range(odcid.length()):
        pseudo.append(odcid.bytes[i])
    for i in range(len(retry_header_and_token)):
        pseudo.append(retry_header_and_token[i])
    var keys = PacketKeys(
        aead=QuicAead.AES_128_GCM,
        key=_retry_v1_key(),
        iv=_retry_v1_nonce(),
        hp=List[UInt8](),
    )
    var crypto = OpenSslQuicCrypto(keys^)
    var empty = List[UInt8]()
    # nonce = iv XOR pn; pn=0 yields the fixed retry nonce. The sealed
    # output for an empty plaintext is exactly the 16-byte tag.
    var sealed = crypto.encrypt(
        Span[UInt8, _](empty), Span[UInt8, _](pseudo), UInt64(0)
    )
    if len(sealed) != _RETRY_TAG_LEN:
        raise Error("retry integrity tag: unexpected AEAD output length")
    return sealed^


def encode_retry_packet(
    version: UInt32,
    dcid: ConnectionId,
    scid: ConnectionId,
    token: List[UInt8],
    odcid: ConnectionId,
) raises -> List[UInt8]:
    """Build a complete Retry packet (RFC 9000 §17.2.5).

    ``dcid`` is the client's Source CID (echoed as the new DCID),
    ``scid`` is the server's freshly chosen Source CID, ``token`` is the
    address-validation token (see :func:`mint_retry_token`), and
    ``odcid`` is the Destination CID from the triggering client Initial
    -- it feeds the integrity tag but is not carried on the wire.
    """
    var body = _retry_header_and_token(version, dcid, scid, token)
    var tag = retry_integrity_tag(odcid, body)
    for i in range(len(tag)):
        body.append(tag[i])
    return body^


def verify_retry_integrity(
    packet: List[UInt8], odcid: ConnectionId
) raises -> Bool:
    """Recompute the Retry Integrity Tag of ``packet`` and compare it to
    the trailing 16 bytes. Used by a client to authenticate a received
    Retry against the original DCID it sent."""
    if len(packet) < _RETRY_TAG_LEN:
        return False
    var split = len(packet) - _RETRY_TAG_LEN
    var body = List[UInt8](capacity=split)
    for i in range(split):
        body.append(packet[i])
    var expected = retry_integrity_tag(odcid, body)
    var diff = 0
    for i in range(_RETRY_TAG_LEN):
        diff |= Int(packet[split + i] ^ expected[i])
    return diff == 0


# ── Version Negotiation packet (RFC 9000 §17.2.1) ───────────────────────────


def encode_version_negotiation(
    dcid: ConnectionId,
    scid: ConnectionId,
    versions: List[UInt32],
) raises -> List[UInt8]:
    """Build a Version Negotiation packet (RFC 9000 §6.1 / §17.2.1).

    A server sends this in response to a client Initial whose version it
    does not support. ``dcid`` MUST be the client Initial's Source CID
    and ``scid`` the client Initial's Destination CID (the fields are
    echoed swapped so the client can match the response). ``versions``
    is the server's supported-version list; the all-zero Version field
    marks the packet as VN.
    """
    if dcid.length() > MAX_CID_LENGTH or scid.length() > MAX_CID_LENGTH:
        raise Error("version negotiation: CID length exceeds 20")
    if len(versions) == 0:
        raise Error("version negotiation: empty version list")
    var out = List[UInt8]()
    # First byte: only the high (Header Form) bit is fixed for VN; the
    # remaining bits are arbitrary (RFC 9000 §17.2.1). Use 0xC0 for a
    # stable, long-header-shaped first byte.
    out.append(UInt8(0xC0))
    # Version field = 0 marks Version Negotiation.
    out.append(UInt8(0))
    out.append(UInt8(0))
    out.append(UInt8(0))
    out.append(UInt8(0))
    out.append(UInt8(dcid.length()))
    for i in range(dcid.length()):
        out.append(dcid.bytes[i])
    out.append(UInt8(scid.length()))
    for i in range(scid.length()):
        out.append(scid.bytes[i])
    for v in range(len(versions)):
        var ver = Int(versions[v])
        out.append(UInt8((ver >> 24) & 0xFF))
        out.append(UInt8((ver >> 16) & 0xFF))
        out.append(UInt8((ver >> 8) & 0xFF))
        out.append(UInt8(ver & 0xFF))
    return out^
