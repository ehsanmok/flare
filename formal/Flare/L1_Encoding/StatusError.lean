import Flare.Core
import Flare.L1_Encoding.Decimal
import Flare.L1_Encoding.MojoAtol
/-!
# `HttpStatusError` wire format (errors.mojo)

Mojo's `raises` erases error types, so a handler's intentional status error
crosses the `Handler.serve` boundary as its rendered string
`HttpStatusError(<status>): <message>` and is decoded again by
`parse_status_error`. The docstring calls the pair "a defined codec".

Model: strings are their UTF-8 bytes. `String.find(sub, start)` is
`findFrom` (first occurrence at or after `start`). `parse` takes the integer
parser as a parameter `atol`; flare's is Mojo's `Int(String)`, modelled
from the stdlib source as `MojoAtol.atol10`. Reason phrases are a
parameter.

Theorems:
* `parse_render_mojo`: with Mojo's `Int(String)`, for every status in
  `[100, 599]` and every message (including ones containing `)` or `): `),
  parsing the rendering returns the same status and message.
  (`parse_render_of` / `parse_render` state it for any `atol` that parses
  the rendered status.)
* `parse_status_range`: anything `parse` accepts has a status in
  `[100, 599]` and the input starts with the prefix.

Not a bug: `Int(String)` also accepts `+404`, ` 404 `, `4_04` and
`0404` (`MojoAtol.atol10_plus` etc., and observed), so `parse` accepts some
strings `render` never produces. Only `render` output reaches `parse` in flare.
-/
namespace Flare.L1.StatusError
open Flare.L1.Decimal

set_option linter.unusedSimpArgs false

/-- ASCII `HttpStatusError(`. mirrors flare/errors.mojo:87 @59bda50 -/
def PREFIX : Bytes := [72, 116, 116, 112, 83, 116, 97, 116, 117, 115, 69, 114, 114, 111, 114, 40]

/-- `)` and `): ` -/
def RP : Bytes := [41]
def MARK : Bytes := [41, 58, 32]

/-- mirrors flare/errors.mojo:217-231 @59bda50 (`write_to`, non-negative status) -/
def render (status : Nat) (msg : Bytes) : Bytes := PREFIX ++ dec status ++ MARK ++ msg

/-- `String.find(pat, start)`: first match at or after `i`. -/
def findFrom (s pat : Bytes) (i : Nat) : Option Nat :=
  if s.length ≤ i then none
  else if pat.isPrefixOf (s.drop i) then some i
  else findFrom s pat (i + 1)
termination_by s.length - i

def AtolDec (atol : Bytes → Option Int) : Prop := ∀ n : Nat, atol (dec n) = some (n : Int)

/-- mirrors flare/errors.mojo:246-273 @59bda50 -/
def parse (atol : Bytes → Option Int) (reason : Int → Bytes) (s : Bytes) : Option (Int × Bytes) :=
  if !PREFIX.isPrefixOf s then none
  else
    let lp := PREFIX.length - 1
    match findFrom s RP lp with
    | none => none
    | some rp =>
      if rp ≤ lp + 1 then none
      else
        match atol ((s.take rp).drop (lp + 1)) with
        | none => none
        | some status =>
          if status < 100 ∨ status > 599 then none
          else
            let message := match findFrom s MARK lp with
              | some mk => s.drop (mk + 3)
              | none => reason status
            some (status, message)

/-! ## `findFrom` lemmas -/

theorem findFrom_skip (P D T pat : Bytes) (a : UInt8) (hp : pat.head? = some a)
    (hD : ∀ b ∈ D, b ≠ a) (hT : T ≠ []) :
    findFrom (P ++ D ++ T) pat P.length = findFrom (P ++ D ++ T) pat (P.length + D.length) := by
  induction D generalizing P with
  | nil => simp
  | cons d D ih =>
    rw [findFrom]
    have hlen : ¬ (P ++ d :: D ++ T).length ≤ P.length := by
      have : T.length ≠ 0 := by intro h; exact hT (List.eq_nil_of_length_eq_zero h)
      simp only [List.length_append, List.length_cons]; omega
    rw [if_neg hlen]
    have hdrop : (P ++ d :: D ++ T).drop P.length = d :: (D ++ T) := by simp
    have hnp : pat.isPrefixOf (d :: (D ++ T)) = false := by
      cases pat with
      | nil => simp at hp
      | cons x xs =>
        simp only [List.head?_cons, Option.some.injEq] at hp; subst hp
        have := hD d (by simp)
        simp [List.isPrefixOf, this.symm]
    rw [hdrop, hnp]
    simp only [Bool.false_eq_true, if_false]
    have := ih (P ++ [d]) (fun b hb => hD b (by simp [hb]))
    simp only [List.append_assoc, List.singleton_append, List.length_append,
      List.length_singleton, List.cons_append, List.nil_append] at this ⊢
    rw [this]
    simp only [List.length_cons]
    congr 1; omega

theorem findFrom_hit (P T pat : Bytes) (hp : pat.isPrefixOf T = true) (hT : T ≠ []) :
    findFrom (P ++ T) pat P.length = some P.length := by
  rw [findFrom]
  have : T.length ≠ 0 := by intro h; exact hT (List.eq_nil_of_length_eq_zero h)
  rw [if_neg (by simp; omega)]
  simp [hp]

/-! ## Round trip -/

theorem digits_ne_rp (n : Nat) : ∀ b ∈ (40 : UInt8) :: dec n, b ≠ 41 := by
  intro b hb
  simp only [List.mem_cons] at hb
  rcases hb with rfl | hb
  · decide
  · have := dec_all_digit n b hb
    intro e; subst e; revert this; decide

theorem parse_render_of (atol : Bytes → Option Int) (reason : Int → Bytes)
    (status : Nat) (hA : atol (dec status) = some (status : Int)) (msg : Bytes)
    (h1 : 100 ≤ status) (h2 : status ≤ 599) :
    parse atol reason (render status msg) = some ((status : Int), msg) := by
  have hP : PREFIX = PREFIX.take 15 ++ [40] := by decide
  have hs : render status msg = PREFIX.take 15 ++ ((40 : UInt8) :: dec status) ++ (MARK ++ msg) := by
    unfold render; conv => lhs; rw [hP]
    simp
  have hl15 : (PREFIX.take 15).length = 15 := by decide
  have hpre : PREFIX.isPrefixOf (render status msg) = true := by
    unfold render
    rw [List.isPrefixOf_iff_prefix]
    simp only [List.append_assoc]
    exact List.prefix_append _ _
  have hMne : MARK ++ msg ≠ [] := by simp [MARK]
  have frp : findFrom (render status msg) RP 15 = some (16 + (dec status).length) := by
    rw [hs]
    generalize PREFIX.take 15 = Q at hl15 ⊢
    rw [← hl15, findFrom_skip _ _ _ RP 41 rfl (digits_ne_rp status) hMne]
    have := findFrom_hit (Q ++ ((40 : UInt8) :: dec status)) (MARK ++ msg) RP
      (by simp [RP, MARK, List.isPrefixOf]) hMne
    simp only [List.length_append, List.length_cons] at this ⊢
    rw [hl15] at this ⊢
    rw [this]; congr 1; omega
  have fmk : findFrom (render status msg) MARK 15 = some (16 + (dec status).length) := by
    rw [hs]
    generalize PREFIX.take 15 = Q at hl15 ⊢
    rw [← hl15, findFrom_skip _ _ _ MARK 41 rfl (digits_ne_rp status) hMne]
    have := findFrom_hit (Q ++ ((40 : UInt8) :: dec status)) (MARK ++ msg) MARK
      (by simp [MARK, List.isPrefixOf]) hMne
    simp only [List.length_append, List.length_cons] at this ⊢
    rw [hl15] at this ⊢
    rw [this]; congr 1; omega
  have hdl := dec_length_pos status
  have hslice : ((render status msg).take (16 + (dec status).length)).drop (15 + 1) = dec status := by
    have e : render status msg = (PREFIX ++ dec status) ++ (MARK ++ msg) := by simp [render]
    have : PREFIX.length = 16 := rfl
    rw [e, List.take_left' (by simp [this]), List.drop_left' this]
  have hrest : (render status msg).drop (16 + (dec status).length + 3) = msg := by
    unfold render
    have : PREFIX.length = 16 := rfl
    have hm : MARK.length = 3 := rfl
    rw [show 16 + (dec status).length + 3 = (PREFIX ++ dec status ++ MARK).length by
      simp [this, hm]; omega]
    simp
  unfold parse
  rw [hpre]
  simp only [Bool.not_true, Bool.false_eq_true, if_false]
  have h15 : PREFIX.length - 1 = 15 := rfl
  simp only [h15, frp]
  rw [if_neg (by omega), hslice, hA]
  dsimp only
  rw [if_neg (by omega), fmk]
  dsimp only
  rw [hrest]

theorem parse_render (atol : Bytes → Option Int) (reason : Int → Bytes) (hA : AtolDec atol)
    (status : Nat) (msg : Bytes) (h1 : 100 ≤ status) (h2 : status ≤ 599) :
    parse atol reason (render status msg) = some ((status : Int), msg) :=
  parse_render_of atol reason status (hA status) msg h1 h2

/-- **The codec round trip with Mojo's actual `Int(String)`** (`atol10`,
modelled from the stdlib source), no assumption left. -/
theorem parse_render_mojo (reason : Int → Bytes) (status : Nat) (msg : Bytes)
    (h1 : 100 ≤ status) (h2 : status ≤ 599) :
    parse MojoAtol.atol10 reason (render status msg) = some ((status : Int), msg) :=
  parse_render_of _ reason status (MojoAtol.atol10_dec status (by omega)) msg h1 h2

theorem parse_status_range (atol : Bytes → Option Int) (reason : Int → Bytes) (s : Bytes)
    (st : Int) (m : Bytes) (h : parse atol reason s = some (st, m)) :
    100 ≤ st ∧ st ≤ 599 ∧ PREFIX.isPrefixOf s = true := by
  unfold parse at h
  split at h
  · cases h
  · next hp =>
    simp only [Bool.not_eq_true', Bool.not_eq_false] at hp
    dsimp only at h
    split at h
    · cases h
    · split at h
      · cases h
      · split at h
        · cases h
        · split at h
          · cases h
          · next st' _ hr =>
            simp only [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, -⟩ := h
            exact ⟨by omega, by omega, hp⟩

end Flare.L1.StatusError
