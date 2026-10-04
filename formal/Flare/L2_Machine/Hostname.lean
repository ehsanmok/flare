import Flare.Core
import Flare.L1_Encoding.Utf8

/-!
# Hostname validation in `resolve`

Model of the pre-`getaddrinfo` checks in `flare/dns/resolver.mojo:68-107`.

flare documents four rules (resolver.mojo:71-79): no NUL, no CR/LF, no `@`,
and "RFC 1035 §2.3.4 limits FQDNs to 253 octets and individual labels to
63 octets". flare does not claim RFC 952/1123 LDH syntax (letters, digits,
hyphen) and does not check it; empty labels (`a..b`) are left to
`getaddrinfo`, which rejects them. The spec here is therefore the
documented one:

* `Valid h`: non-empty, none of the four forbidden bytes, every label
  (`splitOnP` on `.`) at most 63 bytes, and the name at most 253 bytes
  *not counting one trailing root dot* — RFC 1035 §2.3.4 bounds the wire
  form at 255 octets, which is 253 text bytes for a relative-looking name
  and 254 for the same name written absolute (`example.com.`).

Proved:
* `scan_ok_iff`: the per-byte loop accepts iff no forbidden byte and every
  label is at most 63 bytes;
* `validate_sound`: flare never accepts an invalid name;
* `validate_gap`: the only valid names flare rejects are 254 bytes long
  and end in `.` (NET-08); `validateFixed_iff` closes the gap;
* the too-long error text cuts the name at byte 20, possibly inside a
  UTF-8 sequence (NET-09); `truncChars_wf` proves the fixed cut is
  well-formed.
-/
namespace Flare.L2.Hostname
open Flare.L1.Utf8 (WF leadLen WF_cons_iff WfHead seqOK)

def dot : UInt8 := 0x2E

/-- NUL, LF, CR, `@` (resolver.mojo:90-95) -/
def forbidden (b : UInt8) : Bool := b == 0 || b == 0x0A || b == 0x0D || b == 0x40

inductive Res where
  | ok | empty | tooLong | forbidden | label
  deriving DecidableEq, Repr

/-- the per-byte loop, `ll` = `label_len`.
mirrors flare/dns/resolver.mojo:88-107 @59bda50 -/
def scan : Bytes → Nat → Res
  | [], _ => .ok
  | b :: r, ll =>
    if forbidden b then .forbidden
    else if b = dot then scan r 0
    else if ll + 1 > 63 then .label
    else scan r (ll + 1)

/-- mirrors flare/dns/resolver.mojo:68-107 @59bda50 -/
def validate (h : Bytes) : Res :=
  if h.length = 0 then .empty
  else if h.length > 253 then .tooLong
  else scan h 0

def isDot (b : UInt8) : Bool := b == dot

def labels (h : Bytes) : List Bytes := h.splitOnP isDot

/-- text length of the name without one trailing root dot -/
def nameLen (h : Bytes) : Nat := if h.getLast? = some dot then h.length - 1 else h.length

/-- the documented rules -/
def Valid (h : Bytes) : Prop :=
  h ≠ [] ∧ (∀ b ∈ h, forbidden b = false) ∧ nameLen h ≤ 253 ∧ ∀ l ∈ labels h, l.length ≤ 63

instance : DecidablePred Valid := fun h => by unfold Valid; infer_instance

theorem scan_ok_iff : ∀ (r : Bytes) (ll : Nat), ll ≤ 63 →
    (scan r ll = .ok ↔ (∀ b ∈ r, forbidden b = false) ∧
      ∀ hd tl, r.splitOnP isDot = hd :: tl → ll + hd.length ≤ 63 ∧ ∀ l ∈ tl, l.length ≤ 63)
  | [], ll, hll => by
    simp only [scan, true_iff, List.not_mem_nil, false_implies, implies_true, true_and]
    intro hd tl h
    simp only [List.splitOnP_nil, List.cons.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp [hll]
  | b :: r, ll, hll => by
    simp only [scan]
    by_cases hf : forbidden b = true
    · rw [if_pos hf]
      simp only [reduceCtorEq, false_iff, not_and]
      intro h; have := h b List.mem_cons_self; rw [hf] at this; cases this
    · rw [if_neg hf]
      have hf' : forbidden b = false := by simpa using hf
      rw [List.splitOnP_cons_eq_if_modifyHead]
      by_cases hd : b = dot
      · rw [if_pos hd, if_pos (by simp [isDot, hd]), scan_ok_iff r 0 (by omega)]
        constructor
        · rintro ⟨h1, h2⟩
          refine ⟨fun x hx => ?_, fun hd' tl h => ?_⟩
          · rcases List.mem_cons.1 hx with rfl | hx; exact hf'; exact h1 x hx
          · simp only [List.cons.injEq] at h; obtain ⟨rfl, rfl⟩ := h
            refine ⟨by simpa using hll, fun l hl => ?_⟩
            obtain ⟨hd2, tl2, h2'⟩ := List.exists_cons_of_ne_nil (List.splitOnP_ne_nil isDot r)
            rw [h2'] at hl
            obtain ⟨a1, a2⟩ := h2 hd2 tl2 h2'
            rcases List.mem_cons.1 hl with rfl | hl; omega; exact a2 l hl
        · rintro ⟨h1, h2⟩
          refine ⟨fun x hx => h1 x (List.mem_cons_of_mem _ hx), fun hd2 tl2 h2' => ?_⟩
          obtain ⟨_, a2⟩ := h2 [] (r.splitOnP isDot) rfl
          rw [h2'] at a2
          exact ⟨by simpa using a2 hd2 List.mem_cons_self,
            fun l hl => a2 l (List.mem_cons_of_mem _ hl)⟩
      · rw [if_neg hd, if_neg (show ¬ (isDot b = true) by simp [isDot, hd])]
        obtain ⟨hd2, tl2, h2'⟩ := List.exists_cons_of_ne_nil (List.splitOnP_ne_nil isDot r)
        rw [h2']
        simp only [List.modifyHead_cons]
        by_cases hl : ll + 1 > 63
        · rw [if_pos hl]
          simp only [reduceCtorEq, false_iff, not_and]
          intro _ h; have := (h (b :: hd2) tl2 rfl).1; simp at this; omega
        · rw [if_neg hl, scan_ok_iff r (ll + 1) (by omega)]
          constructor
          · rintro ⟨h1, h2⟩
            refine ⟨fun x hx => ?_, fun hd' tl h => ?_⟩
            · rcases List.mem_cons.1 hx with rfl | hx; exact hf'; exact h1 x hx
            · simp only [List.cons.injEq] at h; obtain ⟨rfl, rfl⟩ := h
              obtain ⟨a1, a2⟩ := h2 hd2 tl2 h2'
              exact ⟨by simp; omega, a2⟩
          · rintro ⟨h1, h2⟩
            refine ⟨fun x hx => h1 x (List.mem_cons_of_mem _ hx), fun hd' tl h => ?_⟩
            rw [h2'] at h; injection h with e1 e2; subst e1; subst e2
            obtain ⟨a1, a2⟩ := h2 (b :: hd2) tl2 rfl
            exact ⟨by simp at a1; omega, a2⟩

theorem scan_ok_iff_labels (h : Bytes) :
    scan h 0 = .ok ↔ (∀ b ∈ h, forbidden b = false) ∧ ∀ l ∈ labels h, l.length ≤ 63 := by
  rw [scan_ok_iff h 0 (by omega)]
  obtain ⟨hd, tl, hs⟩ := List.exists_cons_of_ne_nil (List.splitOnP_ne_nil isDot h)
  unfold labels
  rw [hs]
  constructor
  · rintro ⟨h1, h2⟩
    obtain ⟨a1, a2⟩ := h2 hd tl rfl
    refine ⟨h1, fun l hl => ?_⟩
    rcases List.mem_cons.1 hl with rfl | hl; omega; exact a2 l hl
  · rintro ⟨h1, h2⟩
    refine ⟨h1, fun hd' tl' he => ?_⟩
    simp only [List.cons.injEq] at he; obtain ⟨rfl, rfl⟩ := he
    exact ⟨by simpa using h2 hd List.mem_cons_self, fun l hl => h2 l (List.mem_cons_of_mem _ hl)⟩

theorem nameLen_le (h : Bytes) : nameLen h ≤ h.length := by
  unfold nameLen; split <;> omega

theorem length_le_nameLen (h : Bytes) : h.length ≤ nameLen h + 1 := by
  unfold nameLen; split <;> omega

/-- **Sound**: whatever flare accepts satisfies the documented rules. -/
theorem validate_sound (h : Bytes) (hv : validate h = .ok) : Valid h := by
  unfold validate at hv
  by_cases h0 : h.length = 0
  · rw [if_pos h0] at hv; cases hv
  rw [if_neg h0] at hv
  by_cases h1 : h.length > 253
  · rw [if_pos h1] at hv; cases hv
  rw [if_neg h1] at hv
  obtain ⟨a, b⟩ := (scan_ok_iff_labels h).1 hv
  exact ⟨fun he => h0 (by rw [he]; rfl), a, by have := nameLen_le h; omega, b⟩

/-- **The gap**: a valid name flare rejects is exactly 254 bytes long and
ends in the root dot. -/
theorem validate_gap (h : Bytes) (hv : Valid h) (hr : validate h ≠ .ok) :
    h.length = 254 ∧ h.getLast? = some dot := by
  obtain ⟨hne, hf, hl, hlab⟩ := hv
  have hs : scan h 0 = .ok := (scan_ok_iff_labels h).2 ⟨hf, hlab⟩
  have h0 : h.length ≠ 0 := fun e => hne (List.eq_nil_of_length_eq_zero e)
  unfold validate at hr
  rw [if_neg h0] at hr
  by_cases h1 : h.length > 253
  · unfold nameLen at hl
    split at hl
    · rename_i hd; exact ⟨by omega, hd⟩
    · omega
  · rw [if_neg h1] at hr; exact absurd hs hr

/-- the fix for NET-08: allow one more byte for a trailing root dot -/
def validateFixed (h : Bytes) : Res :=
  if h.length = 0 then .empty
  else if nameLen h > 253 then .tooLong
  else scan h 0

/-- **Fixed validation is exactly the documented rules.** -/
theorem validateFixed_iff (h : Bytes) : validateFixed h = .ok ↔ Valid h := by
  unfold validateFixed
  constructor
  · intro hv
    by_cases h0 : h.length = 0
    · rw [if_pos h0] at hv; cases hv
    rw [if_neg h0] at hv
    by_cases h1 : nameLen h > 253
    · rw [if_pos h1] at hv; cases hv
    rw [if_neg h1] at hv
    obtain ⟨a, b⟩ := (scan_ok_iff_labels h).1 hv
    exact ⟨fun he => h0 (by rw [he]; rfl), a, by omega, b⟩
  · rintro ⟨hne, hf, hl, hlab⟩
    have h0 : h.length ≠ 0 := fun e => hne (List.eq_nil_of_length_eq_zero e)
    rw [if_neg h0, if_neg (by omega)]
    exact (scan_ok_iff_labels h).2 ⟨hf, hlab⟩

/-! ## The too-long error text -/

/-- `"…"` in UTF-8 -/
def ellipsis : Bytes := [0xE2, 0x80, 0xA6]

/-- the variable part of the too-long message:
`String(unsafe_from_utf8=host_bytes[:20]) + "…"`.
mirrors flare/dns/resolver.mojo:82-87 @59bda50 -/
def tooLongTail (h : Bytes) : Bytes := h.take 20 ++ ellipsis

/-- the fix for NET-09: keep whole characters only, at most `k` bytes -/
def truncChars : Nat → Bytes → Bytes
  | _, [] => []
  | k, a :: r =>
    if 0 < leadLen a ∧ leadLen a ≤ k ∧ leadLen a ≤ r.length + 1 then
      (a :: r).take (leadLen a) ++ truncChars (k - leadLen a) ((a :: r).drop (leadLen a))
    else []
termination_by _ h => h.length
decreasing_by simp only [List.length_drop, List.length_cons]; omega

def tooLongTailFixed (h : Bytes) : Bytes := truncChars 20 h ++ ellipsis

theorem truncChars_wf (h : Bytes) (hw : WF h) (k : Nat) : WF (truncChars k h) := by
  match h, hw with
  | [], _ => rw [truncChars]; exact WF.nil
  | a :: r, hw =>
    rw [truncChars]
    split
    · obtain ⟨⟨a', r', he, _, _, hs⟩, hd⟩ := (WF_cons_iff a r).1 hw
      simp only [List.cons.injEq] at he; obtain ⟨rfl, rfl⟩ := he
      exact WF.app hs (truncChars_wf _ hd _)
    · exact WF.nil
termination_by h.length
decreasing_by simp only [List.length_drop, List.length_cons]; omega

theorem truncChars_length (h : Bytes) (k : Nat) : (truncChars k h).length ≤ k := by
  match h with
  | [] => rw [truncChars]; simp
  | a :: r =>
    rw [truncChars]
    split
    · rename_i hc
      have := truncChars_length ((a :: r).drop (leadLen a)) (k - leadLen a)
      simp only [List.length_append, List.length_take, List.length_cons]
      omega
    · simp
termination_by h.length
decreasing_by simp only [List.length_drop, List.length_cons]; omega

theorem ellipsis_wf : WF ellipsis := by
  have : seqOK ellipsis := by simp only [ellipsis, seqOK]; decide
  have := WF.app this WF.nil
  simpa using this

/-- **Fix meets spec**: for a well-formed host the fixed message tail is
well-formed UTF-8 and quotes at most 20 bytes of the host. -/
theorem tooLongTailFixed_wf (h : Bytes) (hw : WF h) :
    WF (tooLongTailFixed h) ∧ (truncChars 20 h).length ≤ 20 :=
  ⟨Flare.L1.Utf8.WF_append (truncChars_wf h hw 20) ellipsis_wf, truncChars_length h 20⟩

end Flare.L2.Hostname
