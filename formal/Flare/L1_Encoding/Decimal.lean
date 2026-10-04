import Flare.Core
/-!
# Decimal digits (shared spec vocabulary)

`dec n` is the shortest ASCII decimal rendering of `n` (what Mojo's
`Writer.write(Int)` produces for non-negative values); `decVal` folds ASCII
digits back into a number. These are spec-side helpers used by the port,
IPv4, status-code and date models.
-/
namespace Flare.L1.Decimal

def isDigit (b : UInt8) : Bool := 48 ≤ b && b ≤ 57

/-- Value of an ASCII digit string, most significant first. -/
def decVal (bs : Bytes) : Nat := bs.foldl (fun v b => v * 10 + (b.toNat - 48)) 0

/-- ASCII byte of decimal digit `d`. -/
def digitB (d : Nat) : UInt8 := UInt8.ofNat (48 + d)

/-- Shortest decimal rendering (no leading zeros; `"0"` for zero). -/
def dec (n : Nat) : Bytes :=
  if n < 10 then [digitB n] else dec (n / 10) ++ [digitB (n % 10)]
termination_by n
decreasing_by omega

theorem foldl_digit_append (a b : Bytes) (v : Nat) :
    (a ++ b).foldl (fun v b => v * 10 + (b.toNat - 48)) v =
      b.foldl (fun v b => v * 10 + (b.toNat - 48)) (a.foldl (fun v b => v * 10 + (b.toNat - 48)) v) := by
  simp [List.foldl_append]

theorem digit_toNat (d : Nat) (h : d < 10) : (digitB d).toNat = 48 + d := by
  unfold digitB; rw [UInt8.toNat_ofNat']; omega

theorem digitB_isDigit (d : Nat) (h : d < 10) : isDigit (digitB d) = true := by
  simp only [isDigit, Bool.and_eq_true, decide_eq_true_eq, UInt8.le_iff_toNat_le]
  rw [digit_toNat _ h]; decide +revert

theorem decVal_dec (n : Nat) : decVal (dec n) = n := by
  induction n using Nat.strongRecOn with
  | ind n ih =>
    rw [dec]; split
    · simp only [decVal, List.foldl_cons, List.foldl_nil]; rw [digit_toNat n (by omega)]; omega
    · have := ih (n / 10) (by omega)
      simp only [decVal, List.foldl_append, List.foldl_cons, List.foldl_nil] at *
      rw [this, digit_toNat _ (Nat.mod_lt _ (by decide))]; omega

theorem dec_ne_nil (n : Nat) : dec n ≠ [] := by
  rw [dec]; split <;> simp

theorem dec_all_digit (n : Nat) : ∀ b ∈ dec n, isDigit b = true := by
  induction n using Nat.strongRecOn with
  | ind n ih =>
    rw [dec]; split
    · intro b hb; simp at hb; subst hb; exact digitB_isDigit _ (by omega)
    · intro b hb; simp at hb
      rcases hb with hb | hb
      · exact ih _ (by omega) b hb
      · subst hb; exact digitB_isDigit _ (Nat.mod_lt _ (by decide))

theorem dec_length_le (n k : Nat) (h : n < 10 ^ (k + 1)) : (dec n).length ≤ k + 1 := by
  induction k generalizing n with
  | zero => rw [dec]; split <;> simp_all
  | succ k ih =>
    rw [dec]; split
    · simp
    · simp only [List.length_append, List.length_cons, List.length_nil]
      have := ih (n / 10) (by rw [Nat.pow_succ] at h; omega)
      omega

theorem dec_length_pos (n : Nat) : 0 < (dec n).length := by
  have := dec_ne_nil n; cases h : dec n <;> simp_all

/-- No leading zero unless the number is zero. -/
theorem dec_head (n : Nat) (h : 0 < n) : (dec n).head? ≠ some 48 := by
  induction n using Nat.strongRecOn with
  | ind n ih =>
    rw [dec]; split
    · simp only [List.head?_cons, ne_eq, Option.some.injEq]; intro e
      have := congrArg UInt8.toNat e; rw [digit_toNat _ (by omega)] at this
      simp at this; omega
    · have := ih (n / 10) (by omega) (by omega)
      rw [List.head?_append]
      have hne := dec_ne_nil (n / 10)
      cases hd : dec (n / 10) with
      | nil => exact absurd hd hne
      | cons x xs => simp_all

/-- `decVal` is bounded by the digit count. -/
theorem decVal_lt (bs : Bytes) (h : ∀ b ∈ bs, isDigit b = true) : decVal bs < 10 ^ bs.length := by
  unfold decVal
  suffices ∀ v, bs.foldl (fun v b => v * 10 + (b.toNat - 48)) v < (v + 1) * 10 ^ bs.length by
    simpa using this 0
  induction bs with
  | nil => intro v; simp
  | cons b bs ih =>
    intro v
    simp only [List.foldl_cons, List.length_cons]
    have hb := h b (by simp)
    simp only [isDigit, Bool.and_eq_true, decide_eq_true_eq, UInt8.le_iff_toNat_le] at hb
    have := ih (fun x hx => h x (by simp [hx])) (v * 10 + (b.toNat - 48))
    simp at hb
    calc _ < (v * 10 + (b.toNat - 48) + 1) * 10 ^ bs.length := this
      _ ≤ (v + 1) * 10 ^ (bs.length + 1) := by
        rw [Nat.pow_succ]
        have : v * 10 + (b.toNat - 48) + 1 ≤ (v + 1) * 10 := by omega
        calc _ ≤ ((v + 1) * 10) * 10 ^ bs.length := Nat.mul_le_mul_right _ this
          _ = _ := by rw [Nat.mul_comm (10 ^ _) 10, ← Nat.mul_assoc]

end Flare.L1.Decimal
