"""Fuzz harness: ``flare.grpc.framing.decode_grpc_message``.

Drives the gRPC LPM (Length-Prefixed Message) byte-level decoder
with random sequences. The decoder runs over partial HTTP/2 DATA
buffers in production; it must never panic on a truncated header,
truncated payload, or a length field that declares more bytes than
the buffer holds.

Properties checked:

1. ``decode_grpc_message`` either:
   - returns a ``GrpcDecodeResult`` with ``needs_more=True`` and
     ``consumed=0`` (clean truncation), or
   - returns a ``GrpcDecodeResult`` with ``needs_more=False`` and
     ``consumed == 5 + length`` and ``payload.length == length``,
   - or raises a regular ``Error`` (only the overflow guard does).

2. ``consumed-bytes invariant``: on a successful decode the
   declared length matches the actual payload byte count, and
   the consumed-bytes window equals header + payload length.

3. ``round-trip``: ``encode_grpc_message(payload, compressed) ==
   data[0..consumed]`` on a successful decode when the input
   buffer was the encoder's output. We assert this on
   ``encoded || tail`` inputs the harness synthesises from the
   raw fuzz bytes so the codec is exercised on both directions.

4. ``needs_more`` is monotonic: if the same raw bytes are
   decoded twice the result is byte-identical (re-parse is
   idempotent).

Run:
    pixi run --environment fuzz fuzz-grpc-lpm-decoder
"""

from mozz import fuzz, FuzzConfig

from flare.grpc import (
    decode_grpc_message,
    encode_grpc_message,
)


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


def target(data: List[UInt8]) raises:
    """Three exercises per fuzz run.

    Exercise A — raw decode on the fuzz bytes:
      Validate the decoder's contract on adversarial input directly.

    Exercise B — encode-then-decode round trip:
      Treat the first ~half of the fuzz bytes as a payload and the
      rest as a residual tail; encode the payload, append the tail,
      then decode. Asserts ``consumed == 5 + payload_len`` and the
      decoded payload byte-equals the input payload slice.

    Exercise C — idempotent re-parse:
      Decode the raw fuzz bytes twice; the two results must agree
      on ``needs_more`` and ``consumed``.
    """
    var n = len(data)
    var span = Span[UInt8, _](data)

    # ── A. Direct decode of fuzz bytes ──────────────────────────
    var result_a = decode_grpc_message(span)
    if result_a.needs_more:
        # Clean truncation: consumed must be 0, the codec must not
        # advance into a partial frame.
        _assert(
            result_a.consumed == 0,
            (
                "grpc decode: needs_more implies consumed==0, got "
                + String(result_a.consumed)
            ),
        )
    else:
        # Full frame: consumed = 5 + payload length, payload length
        # matches the declared header length.
        var declared = (
            (Int(data[1]) << 24)
            | (Int(data[2]) << 16)
            | (Int(data[3]) << 8)
            | Int(data[4])
        )
        _assert(
            result_a.consumed == 5 + declared,
            (
                "grpc decode: consumed="
                + String(result_a.consumed)
                + " expected="
                + String(5 + declared)
            ),
        )
        _assert(
            len(result_a.message.payload) == declared,
            "grpc decode: payload length != header length",
        )
        _assert(
            result_a.consumed <= n,
            "grpc decode: consumed > buffer length",
        )

    # ── B. Encode-then-decode round trip ───────────────────────
    # Synthesise a payload slice from the first half of `data`; encode
    # it, append the second half as residual buffer noise. The
    # encoder MUST produce something the decoder accepts cleanly.
    if n >= 2:
        var split = n // 2
        var payload = List[UInt8](capacity=split)
        for i in range(split):
            payload.append(data[i])
        var compressed = (n > 0) and ((Int(data[0]) & 0x01) == 1)
        var frame_bytes = encode_grpc_message(
            Span[UInt8, _](payload), compressed=compressed
        )
        # Append the residual tail so the buffer looks like a stream
        # where the next frame may begin mid-buffer.
        var combined = List[UInt8](capacity=len(frame_bytes) + (n - split))
        for i in range(len(frame_bytes)):
            combined.append(frame_bytes[i])
        for i in range(split, n):
            combined.append(data[i])
        var result_b = decode_grpc_message(Span[UInt8, _](combined))
        _assert(
            not result_b.needs_more,
            "grpc round-trip: encoder output rejected as truncated",
        )
        _assert(
            result_b.consumed == len(frame_bytes),
            (
                "grpc round-trip: consumed="
                + String(result_b.consumed)
                + " expected="
                + String(len(frame_bytes))
            ),
        )
        _assert(
            len(result_b.message.payload) == split,
            "grpc round-trip: payload length lost",
        )
        for i in range(split):
            if result_b.message.payload[i] != payload[i]:
                raise Error(
                    "grpc round-trip: payload byte mismatch at " + String(i)
                )
        # Flag round-trip.
        _assert(
            result_b.message.flag.is_compressed() == compressed,
            "grpc round-trip: compression flag lost",
        )

    # ── C. Idempotent re-parse ─────────────────────────────────
    var result_c = decode_grpc_message(span)
    _assert(
        result_a.needs_more == result_c.needs_more,
        "grpc decode: needs_more drift on re-parse",
    )
    _assert(
        result_a.consumed == result_c.consumed,
        "grpc decode: consumed drift on re-parse",
    )


def main() raises:
    print("=" * 60)
    print("fuzz_grpc_lpm_decoder.mojo — gRPC LPM byte-level decoder")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()

    seeds.append(_bytes(""))
    seeds.append(_bytes("\x00"))
    seeds.append(_bytes("\x00\x00\x00\x00"))
    # Header-only with zero-length payload.
    seeds.append(_bytes("\x00\x00\x00\x00\x00"))
    # 5-byte payload, uncompressed.
    seeds.append(_bytes("\x00\x00\x00\x00\x05hello"))
    # 1-byte payload, compressed flag set.
    seeds.append(_bytes("\x01\x00\x00\x00\x01A"))
    # Length declared larger than buffer (needs_more).
    seeds.append(_bytes("\x00\x00\x00\x00\xFFshort"))
    # Reserved bits in flag (still parseable; high bits forward-
    # compatible).
    seeds.append(_bytes("\xFE\x00\x00\x00\x00"))
    # Two back-to-back frames.
    seeds.append(_bytes("\x00\x00\x00\x00\x01A\x00\x00\x00\x00\x01B"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/grpc_lpm_decoder",
            corpus_dir="fuzz/corpus/grpc_lpm_decoder",
            max_input_len=1024,
        ),
        seeds,
    )
