/-!
# Bit-level proof helpers for L1

`bit_blast` proves equalities between fixed-width words by extensionality
over the bits: it reduces `a = b : UIntN` to `∀ i < N, a.getLsbD i = b.getLsbD i`,
unrolls that into `N` concrete goals, and lets `simp` evaluate each bit.
Everything is checked by the kernel (no `bv_decide`, no native code), so the
axiom footprint stays at `propext`/`Quot.sound`/`Classical.choice`.
-/
namespace Flare.L1

theorem forall_lt_succ' {P : Nat → Prop} {n : Nat} :
    (∀ i, i < n + 1 → P i) ↔ (∀ i, i < n → P i) ∧ P n := by
  constructor
  · intro h; exact ⟨fun i hi => h i (by omega), h n (by omega)⟩
  · rintro ⟨h1, h2⟩ i hi
    by_cases e : i = n
    · subst e; exact h2
    · exact h1 i (by omega)

theorem forall_lt_zero' {P : Nat → Prop} : (∀ i, i < 0 → P i) ↔ True := by simp

/-- Bitwise extensionality for `UInt8/16/32/64` followed by per-bit `simp`. -/
syntax "bit_blast" (" [" Lean.Parser.Tactic.simpLemma,* "]")? : tactic
macro_rules
  | `(tactic| bit_blast $[[$ls,*]]?) => do
    let ls := ls.map (·.getElems) |>.getD #[]
    `(tactic| (
      first
        | apply UInt8.toBitVec_inj.mp
        | apply UInt16.toBitVec_inj.mp
        | apply UInt32.toBitVec_inj.mp
        | apply UInt64.toBitVec_inj.mp
      apply BitVec.eq_of_getLsbD_eq
      simp only [Flare.L1.forall_lt_succ', Flare.L1.forall_lt_zero', true_and]
      simp [-UInt16.toUInt16_toUInt8, -UInt32.toUInt32_toUInt8, -UInt32.toUInt32_toUInt16,
        -UInt64.toUInt64_toUInt8, -UInt64.toUInt64_toUInt16, -UInt64.toUInt64_toUInt32,
        UInt8.toBitVec_toUInt16, UInt8.toBitVec_toUInt32, UInt8.toBitVec_toUInt64,
        UInt16.toBitVec_toUInt8, UInt32.toBitVec_toUInt8, UInt64.toBitVec_toUInt8,
        UInt16.toBitVec_toUInt32, UInt32.toBitVec_toUInt64, UInt32.toBitVec_toUInt16,
        UInt64.toBitVec_toUInt32, UInt16.toBitVec_toUInt64, UInt64.toBitVec_toUInt16, $ls,*]))

end Flare.L1
