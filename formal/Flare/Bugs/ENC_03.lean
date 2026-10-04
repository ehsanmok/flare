import Flare.L1_Encoding.ByteCursor
/-!
# ENC-03: `ProtoReader` length check overflows; a 64-bit length field moves
the cursor negative and the next read is out of bounds

flare/grpc/proto.mojo:282-283 and :299-300 @59bda50 (`read_bytes`, `skip`
for `WIRE_LEN`):

    var n = Int(self._raw_varint())
    if n < 0 or self.pos + n > len(self.data):
        raise Error(...)
    self.pos += n

`n` is a varint from the request body (up to `2^63 - 1` after the `n < 0`
check). `self.pos + n` is Mojo `Int` arithmetic and wraps, so for
`n > 2^63 - 1 - pos` the sum is negative and the bounds check passes.

Spec (protobuf encoding, length-delimited records; and the reader's own
contract that a truncated field raises): a length-delimited field is
accepted only if `0 ≤ n ≤ len(data) - pos`; the cursor stays in
`[0, len(data)]`.

What goes wrong: on the 11-byte message `12 FF FF FF FF FF FF FF FF 7F 00`
(field 2, wire type LEN, length `2^63 - 1`) `skip` succeeds and sets
`pos = 10 + (2^63 - 1) - 2^64 = -9223372036854775799`; `has_more()` is still
true and the next `read_tag` indexes `data[pos]` out of bounds. This is the
loop in `decode_health_request` (grpc/health.mojo:47-55), so one gRPC
health-check request aborts the server (bounds assertion) or reads wild
memory in an unchecked build. `read_bytes` passes the same check and then
calls `List(capacity=n)` with `n ≈ 2^63`.

* `counterexample`: the trace above, in the model.
* Fix: `if n < 0 or n > len(self.data) - self.pos` (`guardFixed`);
  `fixed_preserves_inv` shows it keeps `0 ≤ pos ≤ len` for every input,
  and `fixed_rejects` that it rejects this message.
-/
namespace Flare.Bugs.ENC_03
open Flare.L1.ByteCursor

def payload : Bytes := [0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00]

def r0 : PReader := ⟨payload, 0⟩

/-- `read_tag` yields field 2, wire type 2 (LEN), cursor at 1. -/
theorem tag : (r0.readTag).map (fun p => (p.1, p.2.pos)) = some ((2, 2), 1) := by
  native_decide

def r1 : PReader := ⟨payload, 1⟩

theorem r1_inv : r1.Inv := by
  simp only [PReader.Inv, PosInv, r1, payload]; decide

/-- `skip` succeeds and leaves the cursor at a negative position while
`has_more()` still holds. -/
theorem skip_result :
    (r1.skipLen).map (fun r => (r.pos, r.hasMore)) = some (-9223372036854775799, true) := by
  native_decide

theorem counterexample : ∃ r', r1.Inv ∧ r1.skipLen = some r' ∧ ¬ r'.Inv ∧ r'.hasMore = true := by
  have h := skip_result
  cases e : r1.skipLen with
  | none => rw [e] at h; cases h
  | some r' =>
    rw [e] at h
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
    refine ⟨r', r1_inv, rfl, ?_, h.2⟩
    intro hI
    have := hI.1
    rw [h.1] at this
    exact absurd this (by decide)

/-- The fix keeps the cursor invariant for every wire input. -/
theorem fixed_preserves_inv (r r' : PReader) (hI : r.Inv) (h : r.skipLenFixed = some r') : r'.Inv :=
  skipLenFixed_inv r r' hI h

theorem fixed_rejects : r1.skipLenFixed = none := by native_decide

end Flare.Bugs.ENC_03
