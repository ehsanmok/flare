"""``flare.quic.protection`` -- QUIC v1 per-packet header + AEAD
protection (RFC 9001 §5.3-5.4).

The :func:`unprotect_initial_packet` and :func:`protect_initial_packet`
entry points compose the three primitives already in
:mod:`flare.quic.crypto`:

- :func:`flare.quic.crypto.derive_initial_secrets` (RFC 9001 §5.2)
- :func:`flare.quic.crypto.derive_packet_keys` (RFC 9001 §5.1)
- :class:`flare.quic.crypto.OpenSslQuicCrypto` (AEAD + HP mask)

into the full inbound / outbound packet pipeline that the QUIC
server reactor (Track Q3-W) wires per datagram:

* **unprotect** (inbound): strip header protection, reconstruct
  the truncated packet number per RFC 9000 §A.3, decrypt the
  AEAD payload with the unprotected header as associated data,
  return the frame bytes.
* **protect** (outbound): encrypt the frame bytes with the
  unprotected header as AAD, apply header protection to the
  packet-number bytes + the low header bits, return the wire
  bytes ready for ``sendto``.

Only the Initial-packet variants land in this commit (Track Q3-W
commit 2/5); Handshake + 1-RTT use the same primitive but with
keys negotiated by the TLS handshake (commit 4/5 of Track Q3-W
once the rustls bridge surfaces keying material).

References:
- RFC 9001 §5.3 "AEAD Usage".
- RFC 9001 §5.4 "Header Protection".
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
    PACKET_TYPE_INITIAL,
    parse_initial_extras,
    parse_long_header,
)


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
