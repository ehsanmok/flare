import Flare.L3_Protocol.Qpack.FieldSection

/-!
# QPACK-03: string literals become `String`s without UTF-8 validation

flare/qpack/codec.mojo:215-234 @59bda50 hands the literal payload (raw, or
Huffman-decoded) to `ascii_unchecked_string`, whose contract
(flare/http/proto/ascii.mojo:63-70) requires every byte `< 0x80`. Nothing
upstream checks that, so a literal containing `0xFF` yields a Mojo `String`
holding invalid UTF-8.
-/
namespace Flare.Bugs.QPACK_03
open Flare.L3.Qpack.FieldSection

/-- Non-Huffman literal, 7-bit length prefix: length 1, payload `0xFF`. -/
def buf : Flare.Bytes := [0x01, 0xFF]

theorem counterexample : implLiteral buf 0 7 0x80 = some ([0xFF], 2) := by decide

theorem not_string_ok : ¬ StringOk [0xFF] := by
  unfold StringOk; decide

theorem fixed_rejects : implFixedLiteral buf 0 7 0x80 = none := by decide

/-- Huffman branch: an H-flagged literal whose payload is the Huffman code of
`0xFF` (length prefix `0x80 | len`). -/
def hbuf : Flare.Bytes :=
  (0x80 ||| UInt8.ofNat (Flare.L1.Huffman.encode [0xFF]).length) :: Flare.L1.Huffman.encode [0xFF]

/-- The Huffman branch hands the same invalid byte to `ascii_unchecked_string`. -/
theorem huffman_counterexample : implLiteral hbuf 0 7 0x80 = some ([0xFF], hbuf.length) := by
  native_decide

theorem fixed_ok (b : Flare.Bytes) (off p : Nat) (m : UInt8) (s : Flare.Bytes) (o : Nat)
    (h : implFixedLiteral b off p m = some (s, o)) : StringOk s :=
  implFixedLiteral_ok b off p m s o h

end Flare.Bugs.QPACK_03
