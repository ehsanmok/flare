"""``flare.quic.protection`` -- QUIC v1 per-packet header + AEAD
protection (RFC 9001 §5.3-5.4).

The :func:`unprotect_initial_packet` and :func:`protect_initial_packet`
entry points compose the three primitives already in
:mod:`flare.quic.crypto`:

- :func:`flare.quic.crypto.derive_initial_secrets` (RFC 9001 §5.2)
- :func:`flare.quic.crypto.derive_packet_keys` (RFC 9001 §5.1)
- :class:`flare.quic.crypto.OpenSslQuicCrypto` (AEAD + HP mask)

into the full inbound / outbound packet pipeline that the QUIC
server reactor wires per datagram:

* **unprotect** (inbound): strip header protection, reconstruct
  the truncated packet number per RFC 9000 §A.3, decrypt the
  AEAD payload with the unprotected header as associated data,
  return the frame bytes.
* **protect** (outbound): encrypt the frame bytes with the
  unprotected header as AAD, apply header protection to the
  packet-number bytes + the low header bits, return the wire
  bytes ready for ``sendto``.

The post-Initial encryption levels extend the Initial pair:

* :func:`unprotect_handshake_packet` / :func:`protect_handshake_packet`
  -- long-header packets at the Handshake encryption level (RFC
  9000 §17.2.4). Same AEAD + HP shape as Initial but no token
  field in the long-header extras, and the per-direction secret
  is supplied by the caller (the rustls QUIC bridge surfaces it
  through the session slab).
* :func:`unprotect_1rtt_packet` / :func:`protect_1rtt_packet` --
  short-header packets at the 1-RTT encryption level (RFC 9000
  §17.3). Short-header parsing instead of long-header; ``key_phase``
  is exposed for key-update tracking but applying a new key is
  outside this module's scope.

References:
- RFC 9001 §5.3 "AEAD Usage".
- RFC 9001 §5.4 "Header Protection".
- RFC 9000 §17.2 "Long Header Packets" + §17.3 "Short Header Packets".
- RFC 9000 §A.3 "Sample Packet Number Decoding Algorithm".
- aioquic ``aioquic.quic.crypto.CryptoPair`` / ``packet_protection``.
"""

from std.collections import List
from std.memory import Span

from .crypto import (
    OpenSslQuicCrypto,
    QuicAead,
    derive_initial_secrets,
)
from .packet import (
    ConnectionId,
    LongHeader,
    MAX_CID_LENGTH,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    ShortHeader,
    parse_initial_extras,
    parse_long_header,
    parse_short_header,
)
from .varint import decode_varint


# -- Unprotected-packet carrier ----------------------------------------


@fieldwise_init
struct UnprotectedPacket(Copyable, Movable):
    """The output of :func:`unprotect_initial_packet`.

    ``header`` is the unprotected packet header (first byte plus
    the rest of the long header fields plus the packet number),
    ``payload`` is the AEAD-decrypted frame bytes, and
    ``packet_number`` is the reconstructed full packet number per
    RFC 9000 §A.3. ``pn_length`` is the on-wire packet-number
    encoding length in bytes (1..4) so the caller can advance
    cursors without redoing the parse.
    """

    var header: List[UInt8]
    var payload: List[UInt8]
    var packet_number: UInt64
    var pn_length: Int


# -- RFC 9000 §A.3 packet-number reconstruction ------------------------


def decode_packet_number(
    truncated_pn: UInt64, pn_length: Int, largest_pn: UInt64
) -> UInt64:
    """RFC 9000 §A.3 "Sample Packet Number Decoding Algorithm".

    Given the on-wire truncated packet number (``pn_length`` low
    bytes) and the largest packet number the receiver has seen so
    far, reconstruct the full packet number. The algorithm picks
    the candidate that is closest to ``largest_pn + 1`` -- both
    higher and lower windows are checked so out-of-order packets
    decode correctly.
    """
    var pn_nbits = pn_length * 8
    var expected_pn = largest_pn + UInt64(1)
    var pn_win = UInt64(1) << UInt64(pn_nbits)
    var pn_hwin = pn_win >> UInt64(1)
    var pn_mask = pn_win - UInt64(1)
    var candidate_pn = (expected_pn & ~pn_mask) | truncated_pn
    var pn_limit = (UInt64(1) << UInt64(62)) - pn_win
    if candidate_pn + pn_hwin <= expected_pn and candidate_pn < pn_limit:
        return candidate_pn + pn_win
    if candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win:
        return candidate_pn - pn_win
    return candidate_pn


# -- Initial-packet unprotect ------------------------------------------


def unprotect_initial_packet(
    datagram: Span[UInt8, _],
    dcid: ConnectionId,
    is_server: Bool,
    largest_received_pn: UInt64,
    aead_choice: Int = QuicAead.AES_128_GCM,
) raises -> UnprotectedPacket:
    """Strip header protection + AEAD-decrypt an Initial packet.

    ``dcid`` is the Destination Connection ID the *client* placed
    on its first-flight Initial; both endpoints derive the initial
    secrets from it (RFC 9001 §5.2). ``is_server`` picks the
    reader's secret: the server reads with the client's secret
    and writes with the server's secret. ``largest_received_pn``
    is fed into the RFC 9000 §A.3 reconstruction so out-of-order
    packets decode correctly.

    Raises if the packet header is malformed, if the AEAD tag
    fails, or if any of the cursors would overflow the datagram.
    """
    if len(datagram) < 1:
        raise Error("unprotect_initial: empty datagram")
    var lh: LongHeader = parse_long_header(datagram)
    if lh.packet_type != PACKET_TYPE_INITIAL:
        raise Error(
            "unprotect_initial: packet_type "
            + String(lh.packet_type)
            + " is not Initial"
        )
    var ie = parse_initial_extras(datagram, lh.payload_offset)
    var pn_offset = lh.payload_offset + ie.consumed
    var packet_end = pn_offset + Int(ie.payload_length)
    if packet_end > len(datagram):
        raise Error(
            "unprotect_initial: payload-length "
            + String(ie.payload_length)
            + " exceeds datagram size "
            + String(len(datagram))
        )
    var sample_offset = pn_offset + 4
    if sample_offset + 16 > len(datagram):
        raise Error("unprotect_initial: HP sample window exceeds datagram")
    var dcid_bytes = dcid.bytes.copy()
    var secrets = derive_initial_secrets(Span[UInt8, _](dcid_bytes))
    var reader_secret: List[UInt8]
    if is_server:
        reader_secret = secrets.client_initial_secret.copy()
    else:
        reader_secret = secrets.server_initial_secret.copy()
    var crypto = OpenSslQuicCrypto.from_secret(
        Span[UInt8, _](reader_secret), aead_choice
    )
    var mask = crypto.header_protection_mask(
        datagram[sample_offset : sample_offset + 16]
    )
    var unprotected_first = UInt8(Int(datagram[0]) ^ (Int(mask[0]) & 0x0F))
    var pn_length = (Int(unprotected_first) & 0x03) + 1
    if pn_offset + pn_length > len(datagram):
        raise Error("unprotect_initial: packet-number bytes exceed datagram")
    var truncated_pn = UInt64(0)
    var header = List[UInt8]()
    header.append(unprotected_first)
    for i in range(1, pn_offset):
        header.append(datagram[i])
    for i in range(pn_length):
        var b = UInt8(Int(datagram[pn_offset + i]) ^ Int(mask[1 + i]))
        header.append(b)
        truncated_pn = (truncated_pn << 8) | UInt64(b)
    var packet_number = decode_packet_number(
        truncated_pn, pn_length, largest_received_pn
    )
    var ciphertext_start = pn_offset + pn_length
    var ciphertext = datagram[ciphertext_start:packet_end]
    var plaintext = crypto.decrypt(
        ciphertext, Span[UInt8, _](header), packet_number
    )
    return UnprotectedPacket(
        header=header^,
        payload=plaintext^,
        packet_number=packet_number,
        pn_length=pn_length,
    )


# -- Initial-packet protect (egress) -----------------------------------


def protect_initial_packet(
    unprotected_header_prefix: Span[UInt8, _],
    packet_number: UInt64,
    pn_length: Int,
    plaintext: Span[UInt8, _],
    dcid: ConnectionId,
    is_server: Bool,
    aead_choice: Int = QuicAead.AES_128_GCM,
) raises -> List[UInt8]:
    """Build a fully protected Initial packet ready for ``sendto``.

    ``unprotected_header_prefix`` is the long-header bytes from
    the first byte through the payload-length varint (i.e. the
    output of :func:`flare.quic.packet.encode_long_header` plus
    the encoded token + payload-length). The function appends:

    1. The packet-number bytes (truncated to ``pn_length``).
    2. The AEAD ciphertext + 16-byte tag.

    Then it applies header protection to the packet-number bytes
    and the low 4 bits of the first byte per RFC 9001 §5.4.

    ``packet_number`` is reused as the AEAD nonce input
    (RFC 9001 §5.3). The caller is responsible for sequencing
    packet numbers per the RFC's monotonic-per-key rules.
    """
    if pn_length < 1 or pn_length > 4:
        raise Error(
            "protect_initial: pn_length out of [1, 4]: " + String(pn_length)
        )
    var dcid_bytes = dcid.bytes.copy()
    var secrets = derive_initial_secrets(Span[UInt8, _](dcid_bytes))
    var writer_secret: List[UInt8]
    if is_server:
        writer_secret = secrets.server_initial_secret.copy()
    else:
        writer_secret = secrets.client_initial_secret.copy()
    var crypto = OpenSslQuicCrypto.from_secret(
        Span[UInt8, _](writer_secret), aead_choice
    )
    var unprotected_header = List[UInt8]()
    for i in range(len(unprotected_header_prefix)):
        unprotected_header.append(unprotected_header_prefix[i])
    for i in range(pn_length):
        var shift = (pn_length - 1 - i) * 8
        unprotected_header.append(UInt8((Int(packet_number) >> shift) & 0xFF))
    var ciphertext = crypto.encrypt(
        plaintext, Span[UInt8, _](unprotected_header), packet_number
    )
    var protected = List[UInt8]()
    for i in range(len(unprotected_header)):
        protected.append(unprotected_header[i])
    for i in range(len(ciphertext)):
        protected.append(ciphertext[i])
    var pn_offset = len(unprotected_header) - pn_length
    var sample_offset = pn_offset + 4
    if sample_offset + 16 > len(protected):
        raise Error("protect_initial: ciphertext too short for HP sample")
    var sample = List[UInt8]()
    for i in range(16):
        sample.append(protected[sample_offset + i])
    var mask = crypto.header_protection_mask(Span[UInt8, _](sample))
    protected[0] = UInt8(Int(protected[0]) ^ (Int(mask[0]) & 0x0F))
    for i in range(pn_length):
        protected[pn_offset + i] = UInt8(
            Int(protected[pn_offset + i]) ^ Int(mask[1 + i])
        )
    return protected^


# -- Handshake-packet unprotect ----------------------------------------


def unprotect_handshake_packet(
    datagram: Span[UInt8, _],
    reader_secret: Span[UInt8, _],
    largest_received_pn: UInt64,
    aead_choice: Int = QuicAead.AES_128_GCM,
) raises -> UnprotectedPacket:
    """Strip header protection + AEAD-decrypt a Handshake packet.

    Identical RFC 9001 §5.3-§5.4 shape as
    :func:`unprotect_initial_packet`, but:

    * The long-header extras carry only a payload-length varint
      (RFC 9000 §17.2.4 -- no token field, unlike Initial).
    * The per-direction secret comes from the TLS handshake (the
      rustls KeyChange the Q9-W bridge surfaces) rather than the
      DCID-derived Initial secret.

    ``reader_secret`` is the 32-byte (HKDF-SHA-256) handshake
    traffic secret for the *peer's* direction: on a server reading
    a client Handshake packet this is the client_handshake_secret.
    """
    if len(datagram) < 1:
        raise Error("unprotect_handshake: empty datagram")
    var lh: LongHeader = parse_long_header(datagram)
    if lh.packet_type != PACKET_TYPE_HANDSHAKE:
        raise Error(
            "unprotect_handshake: packet_type "
            + String(lh.packet_type)
            + " is not Handshake"
        )
    var len_var = decode_varint(datagram[lh.payload_offset :])
    var pn_offset = lh.payload_offset + len_var.consumed
    var packet_end = pn_offset + Int(len_var.value)
    if packet_end > len(datagram):
        raise Error(
            "unprotect_handshake: payload-length "
            + String(len_var.value)
            + " exceeds datagram size "
            + String(len(datagram))
        )
    var sample_offset = pn_offset + 4
    if sample_offset + 16 > len(datagram):
        raise Error("unprotect_handshake: HP sample window exceeds datagram")
    var crypto = OpenSslQuicCrypto.from_secret(reader_secret, aead_choice)
    var mask = crypto.header_protection_mask(
        datagram[sample_offset : sample_offset + 16]
    )
    var unprotected_first = UInt8(Int(datagram[0]) ^ (Int(mask[0]) & 0x0F))
    var pn_length = (Int(unprotected_first) & 0x03) + 1
    if pn_offset + pn_length > len(datagram):
        raise Error("unprotect_handshake: packet-number bytes exceed datagram")
    var truncated_pn = UInt64(0)
    var header = List[UInt8]()
    header.append(unprotected_first)
    for i in range(1, pn_offset):
        header.append(datagram[i])
    for i in range(pn_length):
        var b = UInt8(Int(datagram[pn_offset + i]) ^ Int(mask[1 + i]))
        header.append(b)
        truncated_pn = (truncated_pn << 8) | UInt64(b)
    var packet_number = decode_packet_number(
        truncated_pn, pn_length, largest_received_pn
    )
    var ciphertext_start = pn_offset + pn_length
    var ciphertext = datagram[ciphertext_start:packet_end]
    var plaintext = crypto.decrypt(
        ciphertext, Span[UInt8, _](header), packet_number
    )
    return UnprotectedPacket(
        header=header^,
        payload=plaintext^,
        packet_number=packet_number,
        pn_length=pn_length,
    )


# -- Handshake-packet protect (egress) ---------------------------------


def protect_handshake_packet(
    unprotected_header_prefix: Span[UInt8, _],
    packet_number: UInt64,
    pn_length: Int,
    plaintext: Span[UInt8, _],
    writer_secret: Span[UInt8, _],
    aead_choice: Int = QuicAead.AES_128_GCM,
) raises -> List[UInt8]:
    """Build a fully protected Handshake packet ready for ``sendto``.

    ``unprotected_header_prefix`` is the long-header bytes from
    the first byte through the payload-length varint -- i.e. the
    output of :func:`flare.quic.packet.encode_long_header` plus
    the encoded payload-length (no token field for Handshake per
    RFC 9000 §17.2.4). The function appends the packet-number
    bytes, AEAD-encrypts the plaintext with the unprotected
    header as AAD, then applies header protection.

    ``writer_secret`` is the local-side handshake traffic secret
    (server_handshake_secret on the server send path); the rustls
    KeyChange surfaces it through Q9-W's session slab.
    """
    if pn_length < 1 or pn_length > 4:
        raise Error(
            "protect_handshake: pn_length out of [1, 4]: " + String(pn_length)
        )
    var crypto = OpenSslQuicCrypto.from_secret(writer_secret, aead_choice)
    var unprotected_header = List[UInt8]()
    for i in range(len(unprotected_header_prefix)):
        unprotected_header.append(unprotected_header_prefix[i])
    for i in range(pn_length):
        var shift = (pn_length - 1 - i) * 8
        unprotected_header.append(UInt8((Int(packet_number) >> shift) & 0xFF))
    var ciphertext = crypto.encrypt(
        plaintext, Span[UInt8, _](unprotected_header), packet_number
    )
    var protected = List[UInt8]()
    for i in range(len(unprotected_header)):
        protected.append(unprotected_header[i])
    for i in range(len(ciphertext)):
        protected.append(ciphertext[i])
    var pn_offset = len(unprotected_header) - pn_length
    var sample_offset = pn_offset + 4
    if sample_offset + 16 > len(protected):
        raise Error("protect_handshake: ciphertext too short for HP sample")
    var sample = List[UInt8]()
    for i in range(16):
        sample.append(protected[sample_offset + i])
    var mask = crypto.header_protection_mask(Span[UInt8, _](sample))
    protected[0] = UInt8(Int(protected[0]) ^ (Int(mask[0]) & 0x0F))
    for i in range(pn_length):
        protected[pn_offset + i] = UInt8(
            Int(protected[pn_offset + i]) ^ Int(mask[1 + i])
        )
    return protected^


# -- 1-RTT packet unprotect (short header) -----------------------------


def unprotect_1rtt_packet(
    datagram: Span[UInt8, _],
    reader_secret: Span[UInt8, _],
    largest_received_pn: UInt64,
    dcid_length: Int,
    aead_choice: Int = QuicAead.AES_128_GCM,
) raises -> UnprotectedPacket:
    """Strip header protection + AEAD-decrypt a 1-RTT (short
    header) packet.

    ``dcid_length`` is the connection's pinned local CID length
    (the short header does not encode the DCID length on the
    wire, per RFC 9000 §17.3). ``reader_secret`` is the peer's
    application traffic secret (client_application_traffic_secret
    on the server read path).

    The HP sample is taken at the four-byte offset after the
    packet number per RFC 9001 §5.4.2; that requires the
    ciphertext to span at least pn_offset + 4 + 16 bytes. The
    first byte's bits 0-4 (reserved + key-phase + pn_length) are
    cleared by header protection.
    """
    if dcid_length < 0 or dcid_length > MAX_CID_LENGTH:
        raise Error(
            "unprotect_1rtt: dcid_length "
            + String(dcid_length)
            + " out of [0, 20]"
        )
    if len(datagram) < 1:
        raise Error("unprotect_1rtt: empty datagram")
    if (Int(datagram[0]) & 0x80) != 0:
        raise Error(
            "unprotect_1rtt: long-header bit set, expected short header"
        )
    var sh: ShortHeader = parse_short_header(datagram, dcid_length)
    var pn_offset = sh.payload_offset
    var sample_offset = pn_offset + 4
    if sample_offset + 16 > len(datagram):
        raise Error("unprotect_1rtt: HP sample window exceeds datagram")
    var crypto = OpenSslQuicCrypto.from_secret(reader_secret, aead_choice)
    var mask = crypto.header_protection_mask(
        datagram[sample_offset : sample_offset + 16]
    )
    # Short header has 5 protected bits (reserved 4-3 + key phase 2
    # + pn length 1-0) per RFC 9001 §5.4.1 versus the long header's
    # 4 bits; the mask's low 5 bits XOR the first byte.
    var unprotected_first = UInt8(Int(datagram[0]) ^ (Int(mask[0]) & 0x1F))
    var pn_length = (Int(unprotected_first) & 0x03) + 1
    if pn_offset + pn_length > len(datagram):
        raise Error("unprotect_1rtt: packet-number bytes exceed datagram")
    var truncated_pn = UInt64(0)
    var header = List[UInt8]()
    header.append(unprotected_first)
    for i in range(1, pn_offset):
        header.append(datagram[i])
    for i in range(pn_length):
        var b = UInt8(Int(datagram[pn_offset + i]) ^ Int(mask[1 + i]))
        header.append(b)
        truncated_pn = (truncated_pn << 8) | UInt64(b)
    var packet_number = decode_packet_number(
        truncated_pn, pn_length, largest_received_pn
    )
    var ciphertext_start = pn_offset + pn_length
    var ciphertext = datagram[ciphertext_start:]
    var plaintext = crypto.decrypt(
        ciphertext, Span[UInt8, _](header), packet_number
    )
    return UnprotectedPacket(
        header=header^,
        payload=plaintext^,
        packet_number=packet_number,
        pn_length=pn_length,
    )


# -- 1-RTT packet protect (egress) -------------------------------------


def protect_1rtt_packet(
    short_header_prefix: Span[UInt8, _],
    packet_number: UInt64,
    pn_length: Int,
    plaintext: Span[UInt8, _],
    writer_secret: Span[UInt8, _],
    aead_choice: Int = QuicAead.AES_128_GCM,
) raises -> List[UInt8]:
    """Build a fully protected 1-RTT packet ready for ``sendto``.

    ``short_header_prefix`` is the unprotected short-header bytes
    from the first byte through the DCID (i.e. the output of
    :func:`flare.quic.packet.encode_short_header`). The function
    appends the packet-number bytes, AEAD-encrypts the plaintext
    with the unprotected short header as AAD, then applies header
    protection.

    Header protection masks five bits of the first byte per
    RFC 9001 §5.4.1 (reserved 4-3 + key-phase 2 + pn-length 1-0),
    versus the long header's four bits.
    """
    if pn_length < 1 or pn_length > 4:
        raise Error(
            "protect_1rtt: pn_length out of [1, 4]: " + String(pn_length)
        )
    var crypto = OpenSslQuicCrypto.from_secret(writer_secret, aead_choice)
    var unprotected_header = List[UInt8]()
    for i in range(len(short_header_prefix)):
        unprotected_header.append(short_header_prefix[i])
    for i in range(pn_length):
        var shift = (pn_length - 1 - i) * 8
        unprotected_header.append(UInt8((Int(packet_number) >> shift) & 0xFF))
    var ciphertext = crypto.encrypt(
        plaintext, Span[UInt8, _](unprotected_header), packet_number
    )
    var protected = List[UInt8]()
    for i in range(len(unprotected_header)):
        protected.append(unprotected_header[i])
    for i in range(len(ciphertext)):
        protected.append(ciphertext[i])
    var pn_offset = len(unprotected_header) - pn_length
    var sample_offset = pn_offset + 4
    if sample_offset + 16 > len(protected):
        raise Error("protect_1rtt: ciphertext too short for HP sample")
    var sample = List[UInt8]()
    for i in range(16):
        sample.append(protected[sample_offset + i])
    var mask = crypto.header_protection_mask(Span[UInt8, _](sample))
    protected[0] = UInt8(Int(protected[0]) ^ (Int(mask[0]) & 0x1F))
    for i in range(pn_length):
        protected[pn_offset + i] = UInt8(
            Int(protected[pn_offset + i]) ^ Int(mask[1 + i])
        )
    return protected^
