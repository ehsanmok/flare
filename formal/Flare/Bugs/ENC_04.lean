import Flare.L1_Encoding.ByteCursor
/-!
# ENC-04: `ByteReader._need` overflows; `skip`/`read_bytes`/`read_utf8`
accept a huge `n` and move the cursor negative

flare/io/byte_cursor.mojo:144-155 @59bda50:

    if n < 0 or self.pos + n > len(self.buf):
        raise Error(...)

`self.pos + n` is Mojo `Int` arithmetic and wraps. For
`n > 2^63 - 1 - pos` the sum is negative and the check passes.

Spec (the module's own contract, byte_cursor.mojo:1-8, 114-119): "Every read
is bounds-checked (a short buffer raises rather than reading out of
bounds)"; `0 ≤ pos ≤ len(buf)`.

What goes wrong: after one `read_u8()` on a 4-byte buffer, `skip(Int.MAX)`
succeeds and sets `pos = -2^63`; `remaining()` is then negative and any
later read indexes the span at a negative offset. In-tree callers
(`uds/frame_mux.mojo:126`, `Int(u32)`) cannot reach this
(`guard_iff_of_small`), so the exposure is through the public `flare.io`
API when a caller forwards a 64-bit length.

* `counterexample`: that trace in the model.
* Fix: `if n < 0 or n > len(self.buf) - self.pos` (`needFixed`);
  `fixed_preserves_inv` (every accepted `skip` keeps `0 ≤ pos ≤ len`).
-/
namespace Flare.Bugs.ENC_04
open Flare.L1.ByteCursor

def r1 : Reader := ⟨[1, 2, 3, 4], 1⟩

theorem r1_from_read_u8 : (Reader.readU8 ⟨[1, 2, 3, 4], 0⟩).map (·.2.pos) = some 1 := by
  native_decide

theorem r1_inv : r1.Inv := by
  simp only [Reader.Inv, PosInv, r1]; decide

def INT_MAX : Int64 := 9223372036854775807

theorem skip_result : (r1.skip INT_MAX).map (·.pos) = some (-9223372036854775808) := by
  native_decide

theorem counterexample : ∃ r', r1.Inv ∧ r1.skip INT_MAX = some r' ∧ ¬ r'.Inv := by
  have h := skip_result
  cases e : r1.skip INT_MAX with
  | none => rw [e] at h; cases h
  | some r' =>
    rw [e] at h
    simp only [Option.map_some, Option.some.injEq] at h
    refine ⟨r', r1_inv, rfl, ?_⟩
    intro hI
    have := hI.1
    rw [h] at this
    exact absurd this (by decide)

theorem fixed_preserves_inv (r r' : Reader) (n : Int64) (hI : r.Inv) (h : r.skipFixed n = some r') :
    r'.Inv :=
  skipFixed_inv r r' n hI h

theorem fixed_rejects : r1.skipFixed INT_MAX = none := by native_decide

end Flare.Bugs.ENC_04
