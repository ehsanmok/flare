import Flare.L3_Protocol.Qpack.FieldSection

/-!
# QPACK-03: string literals become `String`s without UTF-8 validation

flare/qpack/codec.mojo:215-234 @59bda50 (pre-fix) handed the literal payload (raw, or
Huffman-decoded) to `ascii_unchecked_string`, whose contract
(flare/http/proto/ascii.mojo:63-70) requires every byte `< 0x80`. Nothing
upstream checks that, so a literal containing `0xFF` yields a Mojo `String`
holding invalid UTF-8.

Status: resolved. `_literal_to_string` (codec.mojo) now builds the `String` from
the decoded bytes: pure ASCII keeps the `ascii_unchecked_string` fast path,
anything else goes through `String(from_utf8=...)` and raises when it is not
valid UTF-8 (the encoder-stream replayer maps that to
QPACK_ENCODER_STREAM_ERROR; a field section fails as QPACK_DECOMPRESSION_FAILED).
`implOldLiteral` is the pre-fix result (the counterexamples are about it);
`implLiteral` is the shipped decoder (`fixed_rejects`, `fixed_ok`).
Regression tests: tests/qpack/test_qpack.mojo
`test_raw_literal_value_that_is_not_utf8_is_refused` and three siblings,
tests/qpack/test_qpack_dynamic.mojo
`test_non_utf8_literal_on_the_encoder_stream_is_an_error`.
-/
namespace Flare.Bugs.QPACK_03
open Flare.L3.Qpack.FieldSection

/-- Non-Huffman literal, 7-bit length prefix: length 1, payload `0xFF`. -/
def buf : Flare.Bytes := [0x01, 0xFF]

theorem counterexample : implOldLiteral buf 0 7 0x80 = some ([0xFF], 2) := by decide

theorem not_string_ok : ¬ StringOk [0xFF] := by
  unfold StringOk; decide

theorem fixed_rejects : implLiteral buf 0 7 0x80 = none := by decide

/-- Huffman branch: an H-flagged literal whose payload is the Huffman code of
`0xFF` (length prefix `0x80 | len`). -/
def hbuf : Flare.Bytes :=
  (0x80 ||| UInt8.ofNat (Flare.L1.Huffman.encode [0xFF]).length) :: Flare.L1.Huffman.encode [0xFF]

/-- The Huffman branch hands the same invalid byte to `ascii_unchecked_string`. -/
theorem huffman_counterexample : implOldLiteral hbuf 0 7 0x80 = some ([0xFF], hbuf.length) := by
  native_decide

theorem fixed_ok (b : Flare.Bytes) (off p : Nat) (m : UInt8) (s : Flare.Bytes) (o : Nat)
    (h : implLiteral b off p m = some (s, o)) : StringOk s :=
  implLiteral_ok b off p m s o h

end Flare.Bugs.QPACK_03
