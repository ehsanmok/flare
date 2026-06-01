"""Unit tests for the gRPC framing + status primitives.

The framing tests lock the on-the-wire byte layout against the
official gRPC HTTP/2 protocol document; the status tests lock
the numeric constants against the gRPC canonical status code
table (which clients ship hard-coded against).
"""

from std.testing import assert_equal, assert_true, assert_false
from std.memory import Span

from flare.grpc import (
    GRPC_COMPRESSION_NONE,
    GRPC_COMPRESSION_COMPRESSED,
    GRPC_STATUS_OK,
    GRPC_STATUS_CANCELLED,
    GRPC_STATUS_NOT_FOUND,
    GRPC_STATUS_DEADLINE_EXCEEDED,
    GRPC_STATUS_INTERNAL,
    GRPC_STATUS_UNAUTHENTICATED,
    GrpcCompressionFlag,
    GrpcStatus,
    decode_grpc_message,
    encode_grpc_message,
)


def _bytes(*vals: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for v in vals:
        out.append(UInt8(v))
    return out^


def test_lpm_round_trip_short_payload() raises:
    """5-byte LPM header + 4-byte payload "ping". Encoded form:
    ``00 00 00 00 04 70 69 6e 67``."""
    var payload = _bytes(0x70, 0x69, 0x6E, 0x67)
    var enc = encode_grpc_message(Span[UInt8](payload), compressed=False)
    assert_equal(len(enc), 9)
    assert_equal(Int(enc[0]), 0x00)  # flag = uncompressed
    assert_equal(Int(enc[1]), 0x00)
    assert_equal(Int(enc[2]), 0x00)
    assert_equal(Int(enc[3]), 0x00)
    assert_equal(Int(enc[4]), 0x04)  # length = 4
    var dec = decode_grpc_message(Span[UInt8](enc))
    assert_false(dec.needs_more)
    assert_equal(dec.consumed, 9)
    assert_false(dec.message.flag.is_compressed())
    assert_equal(len(dec.message.payload), 4)
    assert_equal(Int(dec.message.payload[0]), 0x70)
    assert_equal(Int(dec.message.payload[3]), 0x67)


def test_lpm_round_trip_compressed_flag() raises:
    """Compressed flag round-trips through the codec; the codec
    does *not* run the compression -- caller supplies pre-
    compressed bytes."""
    var payload = _bytes(0x78, 0x9C)  # placeholder zlib header
    var enc = encode_grpc_message(Span[UInt8](payload), compressed=True)
    assert_equal(Int(enc[0]), 0x01)
    var dec = decode_grpc_message(Span[UInt8](enc))
    assert_false(dec.needs_more)
    assert_true(dec.message.flag.is_compressed())


def test_lpm_empty_payload() raises:
    """A zero-length payload is legal (e.g. an empty proto3
    message). Encoded form: ``00 00 00 00 00``."""
    var empty = List[UInt8]()
    var enc = encode_grpc_message(Span[UInt8](empty), compressed=False)
    assert_equal(len(enc), 5)
    var dec = decode_grpc_message(Span[UInt8](enc))
    assert_false(dec.needs_more)
    assert_equal(dec.consumed, 5)
    assert_equal(len(dec.message.payload), 0)


def test_lpm_decoder_needs_more_on_partial_header() raises:
    """Fewer than 5 bytes available means the LPM header is
    incomplete; decoder must request more data rather than
    return junk."""
    var partial = _bytes(0x00, 0x00, 0x00)
    var dec = decode_grpc_message(Span[UInt8](partial))
    assert_true(dec.needs_more)
    assert_equal(dec.consumed, 0)


def test_lpm_decoder_needs_more_on_partial_payload() raises:
    """Length declares 100 bytes but only 5 + 10 are available;
    decoder must request more data."""
    var buf = _bytes(0x00, 0x00, 0x00, 0x00, 0x64)  # length = 100
    for _ in range(10):
        buf.append(UInt8(0xAA))
    var dec = decode_grpc_message(Span[UInt8](buf))
    assert_true(dec.needs_more)
    assert_equal(dec.consumed, 0)


def test_lpm_decoder_handles_back_to_back_frames() raises:
    """Two LPM frames concatenated; the decoder consumes the
    first one and ``consumed`` lets the caller advance to the
    second one cleanly."""
    var p1 = _bytes(0xAA)
    var p2 = _bytes(0xBB, 0xCC)
    var e1 = encode_grpc_message(Span[UInt8](p1))
    var e2 = encode_grpc_message(Span[UInt8](p2))
    var buf = List[UInt8]()
    for i in range(len(e1)):
        buf.append(e1[i])
    for i in range(len(e2)):
        buf.append(e2[i])
    var dec1 = decode_grpc_message(Span[UInt8](buf))
    assert_false(dec1.needs_more)
    assert_equal(dec1.consumed, 6)  # 5 header + 1 payload
    assert_equal(Int(dec1.message.payload[0]), 0xAA)
    # Advance past the first frame and decode the second.
    var rest = Span[UInt8](buf)[dec1.consumed :]
    var dec2 = decode_grpc_message(rest)
    assert_false(dec2.needs_more)
    assert_equal(dec2.consumed, 7)
    assert_equal(Int(dec2.message.payload[1]), 0xCC)


def test_compression_flag_reserved_bits() raises:
    """Bits 1..7 of the flag byte are reserved; the codec accepts
    them (forward compatibility) but exposes a detection helper."""
    var raw = GrpcCompressionFlag(raw=UInt8(0x80))
    assert_false(raw.is_compressed())
    assert_true(raw.has_reserved_bits())
    var clean = GrpcCompressionFlag(raw=UInt8(0x01))
    assert_true(clean.is_compressed())
    assert_false(clean.has_reserved_bits())


def test_status_numeric_constants() raises:
    """The 16 standard status codes have stable numeric values
    that wire-compatible clients depend on. Lock them in here so
    a future renumber breaks a test instead of every gRPC
    integration silently."""
    assert_equal(GRPC_STATUS_OK, 0)
    assert_equal(GRPC_STATUS_CANCELLED, 1)
    assert_equal(GRPC_STATUS_NOT_FOUND, 5)
    assert_equal(GRPC_STATUS_DEADLINE_EXCEEDED, 4)
    assert_equal(GRPC_STATUS_INTERNAL, 13)
    assert_equal(GRPC_STATUS_UNAUTHENTICATED, 16)


def test_status_ok_and_err_constructors() raises:
    var ok = GrpcStatus.ok()
    assert_true(ok.is_ok())
    assert_equal(ok.code, GRPC_STATUS_OK)
    var nf = GrpcStatus.err(GRPC_STATUS_NOT_FOUND, String("missing"))
    assert_false(nf.is_ok())
    assert_equal(nf.code, GRPC_STATUS_NOT_FOUND)
    assert_equal(nf.message, String("missing"))


def test_status_with_details_round_trip() raises:
    """``with_details`` attaches an opaque byte payload that the
    trailer emitter base64-encodes for ``grpc-status-details-bin``.
    The bytes round-trip through ``Optional[List[UInt8]]`` without
    mutation; absence is the default.
    """
    var base = GrpcStatus.err(GRPC_STATUS_INTERNAL, String("see details"))
    assert_false(Bool(base.details))
    var payload = List[UInt8]()
    payload.append(UInt8(0xDE))
    payload.append(UInt8(0xAD))
    payload.append(UInt8(0xBE))
    payload.append(UInt8(0xEF))
    var with_d = base.with_details(payload^)
    assert_true(Bool(with_d.details))
    var bytes = with_d.details.value().copy()
    assert_equal(len(bytes), 4)
    assert_equal(bytes[0], UInt8(0xDE))
    assert_equal(bytes[3], UInt8(0xEF))


def test_status_names() raises:
    """The status-code names are surface-visible (logs, metrics,
    tracer spans) and clients depend on them being stable
    SCREAMING_SNAKE_CASE."""
    assert_equal(GrpcStatus.ok().name(), String("OK"))
    assert_equal(
        GrpcStatus.err(GRPC_STATUS_DEADLINE_EXCEEDED, String("")).name(),
        String("DEADLINE_EXCEEDED"),
    )
    assert_equal(
        GrpcStatus.err(GRPC_STATUS_UNAUTHENTICATED, String("")).name(),
        String("UNAUTHENTICATED"),
    )
    # Out-of-range numeric codes round-trip to a grep-friendly
    # ``UNKNOWN_CODE_<n>`` string.
    assert_equal(
        GrpcStatus.err(42, String("?")).name(), String("UNKNOWN_CODE_42")
    )


def main() raises:
    test_lpm_round_trip_short_payload()
    test_lpm_round_trip_compressed_flag()
    test_lpm_empty_payload()
    test_lpm_decoder_needs_more_on_partial_header()
    test_lpm_decoder_needs_more_on_partial_payload()
    test_lpm_decoder_handles_back_to_back_frames()
    test_compression_flag_reserved_bits()
    test_status_numeric_constants()
    test_status_ok_and_err_constructors()
    test_status_with_details_round_trip()
    test_status_names()
    print("test_grpc: OK")
