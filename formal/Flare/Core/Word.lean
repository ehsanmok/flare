/-!
# Fixed-width words with Mojo semantics

Mojo `Int` is a 64-bit two's-complement machine integer that wraps on
overflow (no trap in release builds). We model it with Lean's `Int64`
(BitVec-backed, so `bv_decide` applies). `UInt8/16/32/64` map directly.

`fitsI64 n` says a mathematical integer is representable; overflow theorems
are stated as "the Mojo expression's `Int64` value differs from the
mathematical value", which is how silent wraparound bugs are exhibited.
-/
namespace Flare

def I64_MAX : Int := 2^63 - 1
def I64_MIN : Int := -(2^63)

def fitsI64 (n : Int) : Prop := I64_MIN ≤ n ∧ n ≤ I64_MAX

instance (n : Int) : Decidable (fitsI64 n) := by unfold fitsI64; infer_instance

/-- Mojo `Int` arithmetic: wrap to 64 bits. -/
def mojoInt (n : Int) : Int64 := Int64.ofInt n

theorem mojoInt_toInt_of_fits (n : Int) (h : fitsI64 n) : (mojoInt n).toInt = n := by
  unfold mojoInt fitsI64 I64_MIN I64_MAX at *
  rw [Int64.toInt_ofInt]
  exact Int.bmod_eq_of_le (by simp [Int64.size]; omega) (by simp [Int64.size]; omega)

end Flare
