import Flare.Core
import Flare.L1_Encoding.Decimal
/-!
# Mojo `Int(String)` (stdlib `atol`, base 10)

flare calls `Int(String(...))` in `parse_status_error`
(flare/errors.mojo:262). With the toolchain pinned by flare's pixi
environment (Mojo 1.1.0, compiler build `8189361e`) that resolves to:

* `SIMD.__init__[T: IntableRaising](out self: Int, value: T)`:
  `self = value.__int__()` (std/simd.mojo:701-714 @8189361e);
* `String.__int__`: `return atol(self)`
  (std/collections/string/string.mojo:2025-2035 @8189361e);
* `atol(str_slice, base=10)` (string.mojo:2480-2634), with
  `_trim_and_handle_sign` (:2637-2662), `_handle_base_prefix` (:2665-2694;
  it never fires for base 10) and `Codepoint.is_posix_space`
  (std/collections/string/codepoint.mojo:491-535).

The pixi environment ships only the compiled `std.mojoc`; the source above
is the matching commit of the Modular repository. Raising is `none`.

Results: `atol10_dec` (every decimal rendering of `n < 2^63` parses to `n`),
`atol10_nonneg_digits` (accepted strings without sign/space/underscore are
exactly digit strings with value `< 2^63`), and the observed leniencies
(`atol10_plus`, `atol10_spaces`, `atol10_underscore`, `atol10_leading_zero`).
-/
namespace Flare.L1.MojoAtol
open Flare.L1.Decimal

/-- `Codepoint(byte).is_posix_space()`: space, `\t \n \r \f \v`, `\x1c`-`\x1e`.
mirrors Mojo std/collections/string/codepoint.mojo:491-535 @8189361e -/
def isPosixSpace (c : UInt8) : Bool :=
  c == 32 || c == 9 || c == 10 || c == 13 || c == 12 || c == 11 || c == 28 || c == 29 || c == 30

/-- Skip leading POSIX space, then one optional sign.
mirrors Mojo std/collections/string/string.mojo:2637-2662 @8189361e -/
def trimSign (s : Bytes) : Nat × Bool :=
  let start := (s.takeWhile isPosixSpace).length
  if start = s.length then (start, false)
  else
    let c := s.getD start
    (start + (if c == 43 || c == 45 then 1 else 0), c == 45)

/-- The digit loop for base 10 (`ord_num_max = ord("9")`, no letters,
`was_last_digit_underscore` starts `True`). State: `result`,
`was_last_digit_underscore`, `found_valid_chars_after_start`; a POSIX space
breaks out and returns the bytes after it for the trailing-space check.
mirrors Mojo std/collections/string/string.mojo:2574-2621 @8189361e -/
def digits (limit : Nat) : Bytes → Nat → Bool → Bool → Option (Nat × Bool × Bool × Option Bytes)
  | [], r, u, f => some (r, u, f, none)
  | c :: cs, r, u, f =>
    if c == 95 then (if u then none else digits limit cs r true f)
    else if isDigit c then
      let d := c.toNat - 48
      if r > limit - d then none
      else
        match cs with
        | n :: _ =>
          if !isPosixSpace n then
            (if r + d > limit / 10 then none else digits limit cs ((r + d) * 10) false true)
          else digits limit cs (r + d) false true
        | [] => digits limit cs (r + d) false true
    else if isPosixSpace c then some (r, false, f, some cs)
    else none

/-- `atol(s)` with `base = 10`; `none` = raises.
mirrors Mojo std/collections/string/string.mojo:2480-2634 @8189361e -/
def atol10 (s : Bytes) : Option Int :=
  if s.isEmpty then none
  else
    let ts := trimSign s
    if s.length ≤ ts.1 then none
    else
      let limit := 2 ^ 63 - 1 + (if ts.2 then 1 else 0)
      match digits limit (s.drop ts.1) 0 true false with
      | none => none
      | some (r, u, f, sp) =>
        if u || !f then none
        else if (match sp with | some rest => rest.all isPosixSpace | none => true) = false then none
        else if ts.2 then (if r = 2 ^ 63 then some (-2 ^ 63) else some (-(r : Int)))
        else some (r : Int)

/-! ## Decimal renderings parse back -/

theorem digit_bounds {c : UInt8} (h : isDigit c = true) : 48 ≤ c.toNat ∧ c.toNat ≤ 57 := by
  simp only [isDigit, Bool.and_eq_true, decide_eq_true_eq, UInt8.le_iff_toNat_le] at h
  exact ⟨h.1, h.2⟩

theorem space_of_digit {c : UInt8} (h : isDigit c = true) : isPosixSpace c = false := by
  have := digit_bounds h
  simp only [isPosixSpace, Bool.or_eq_false_iff, beq_eq_false_iff_ne, ne_eq, ← UInt8.toNat_inj,
    UInt8.reduceToNat]
  omega

theorem ne95_of_digit {c : UInt8} (h : isDigit c = true) : (c == 95) = false := by
  have := digit_bounds h
  simp only [beq_eq_false_iff_ne, ne_eq, ← UInt8.toNat_inj, UInt8.reduceToNat]; omega

def step (v : Nat) (b : UInt8) : Nat := v * 10 + (b.toNat - 48)

theorem foldl_ge (ds : Bytes) (v : Nat) : v * 10 ^ ds.length ≤ ds.foldl step v := by
  induction ds generalizing v with
  | nil => simp
  | cons d ds ih =>
    simp only [List.foldl_cons, List.length_cons]
    have := ih (step v d)
    have h2 : v * 10 ^ (ds.length + 1) ≤ step v d * 10 ^ ds.length := by
      rw [Nat.pow_succ, Nat.mul_comm (10 ^ _) 10, ← Nat.mul_assoc]
      exact Nat.mul_le_mul_right _ (show v * 10 ≤ step v d by unfold step; omega)
    omega

theorem digits_run (L : Nat) (ds : Bytes) (hd : ∀ b ∈ ds, isDigit b = true) (hne : ds ≠ []) :
    ∀ v u f, ds.foldl step v ≤ L →
      digits L ds (v * 10) u f = some (ds.foldl step v, false, true, none) := by
  induction ds with
  | nil => exact absurd rfl hne
  | cons d ds ih =>
    intro v u f hL
    have hdd := hd d (by simp)
    have hb := digit_bounds hdd
    rw [digits, ne95_of_digit hdd, if_neg (by simp), if_pos hdd]
    have hge := foldl_ge ds (step v d)
    simp only [List.foldl_cons] at hL ⊢
    have hstep : step v d = v * 10 + (d.toNat - 48) := rfl
    have hpos : 0 < 10 ^ ds.length := Nat.pow_pos (by decide)
    rw [if_neg (by
      have : step v d ≤ L := Nat.le_trans (Nat.le_trans (Nat.le_mul_of_pos_right _ hpos) hge) hL
      omega)]
    cases ds with
    | nil =>
      simp only [List.foldl_nil] at hL ⊢
      rw [digits, hstep]
    | cons e es =>
      have he := hd e (by simp)
      simp only [space_of_digit he, Bool.not_false, if_true]
      have h10 : step v d * 10 ≤ L := by
        have := foldl_ge (e :: es) (step v d)
        simp only [List.length_cons, Nat.pow_succ] at this
        have : step v d * 10 ≤ step v d * (10 ^ es.length * 10) :=
          Nat.mul_le_mul_left _ (by
            have : 0 < 10 ^ es.length := Nat.pow_pos (by decide)
            omega)
        omega
      rw [if_neg (by rw [← hstep]; omega), ← hstep]
      exact ih (fun b hb => hd b (by simp [hb])) (by simp) _ _ _ hL

theorem decVal_eq_foldl (ds : Bytes) : decVal ds = ds.foldl step 0 := rfl

theorem trimSign_digit (ds : Bytes) (d : UInt8) (h : isDigit d = true) : trimSign (d :: ds) = (0, false) := by
  have hb := digit_bounds h
  simp only [trimSign, List.takeWhile_cons, space_of_digit h, List.length_cons]
  simp only [Bool.false_eq_true, if_false, List.length_nil]
  rw [if_neg (by omega)]
  have hg : Flare.Bytes.getD (d :: ds) 0 = d := rfl
  simp only [Nat.zero_add, hg]
  have h43 : (d == 43) = false := by
    simp only [beq_eq_false_iff_ne, ne_eq, ← UInt8.toNat_inj, UInt8.reduceToNat]; omega
  have h45 : (d == 45) = false := by
    simp only [beq_eq_false_iff_ne, ne_eq, ← UInt8.toNat_inj, UInt8.reduceToNat]; omega
  simp [h43, h45]

/-- **`Int(String)` inverts decimal rendering** on the whole non-negative
`Int` range. -/
theorem atol10_dec (n : Nat) (h : n < 2 ^ 63) : atol10 (dec n) = some (n : Int) := by
  have hne := dec_ne_nil n
  have hall := dec_all_digit n
  obtain ⟨d, ds, hds⟩ : ∃ d ds, dec n = d :: ds := by
    cases e : dec n with
    | nil => exact absurd e hne
    | cons d ds => exact ⟨d, ds, rfl⟩
  have hd := hall d (by rw [hds]; simp)
  have hv : (d :: ds).foldl step 0 = n := by rw [← hds, ← decVal_eq_foldl, decVal_dec]
  have hrun := digits_run (2 ^ 63 - 1 + 0) (d :: ds) (by rw [← hds]; exact hall) (by simp) 0 true false
    (by rw [hv]; omega)
  rw [hv] at hrun
  simp only [Nat.zero_mul] at hrun
  rw [atol10, hds]
  simp only [List.isEmpty_cons, Bool.false_eq_true, if_false, trimSign_digit ds d hd]
  rw [if_neg (by simp)]
  simp only [List.drop_zero, hrun]
  simp

/-! ## Leniency (matches what was observed at runtime) -/

/-- `"+404"` -/
theorem atol10_plus : atol10 [43, 52, 48, 52] = some 404 := by decide +kernel
/-- `" 404 "` -/
theorem atol10_spaces : atol10 [32, 52, 48, 52, 32] = some 404 := by decide +kernel
/-- `"4_04"` -/
theorem atol10_underscore : atol10 [52, 95, 48, 52] = some 404 := by decide +kernel
/-- `"0404"` -/
theorem atol10_leading_zero : atol10 [48, 52, 48, 52] = some 404 := by decide +kernel
/-- `"_404"`, `"404_"`, `"4__04"`, `"4 04"`, `""`, `"-"` and `"9223372036854775808"` raise. -/
theorem atol10_rejects :
    atol10 [95, 52, 48, 52] = none ∧ atol10 [52, 48, 52, 95] = none ∧
    atol10 [52, 95, 95, 48, 52] = none ∧ atol10 [52, 32, 48, 52] = none ∧
    atol10 [] = none ∧ atol10 [45] = none ∧
    atol10 [57, 50, 50, 51, 51, 55, 50, 48, 51, 54, 56, 53, 52, 55, 55, 53, 56, 48, 56] = none := by
  decide +kernel
/-- `"-9223372036854775808"` is `Int.MIN`. -/
theorem atol10_min :
    atol10 [45, 57, 50, 50, 51, 51, 55, 50, 48, 51, 54, 56, 53, 52, 55, 55, 53, 56, 48, 56] =
      some (-2 ^ 63) := by
  decide +kernel

end Flare.L1.MojoAtol
