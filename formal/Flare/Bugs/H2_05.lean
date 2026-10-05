import Flare.Bugs.H2_Fixtures

/-!
# H2-05: content-length wraps in Int64 and only the first field counts

Status: resolved. `_declared_content_length` now parses `1*DIGIT` with an
overflow guard, checks every content-length field, and answers a
malformed value with `-2`; `_commit_header_block` resets the stream with
PROTOCOL_ERROR. The counterexamples below are about `declaredCLOld`, the
code before the fix; `fixed` and `fixed_shipped` are about the shipped
`declaredCLFixed`.

Before the fix, `_declared_content_length` (flare/http2/state.mojo:748-765 @59bda50)
folded the digits of the first `content-length` field into a Mojo `Int`
(64-bit, wrapping) and ignores any later `content-length` field. A value
of 2^64+5 is read as 5, and `content-length: 5` followed by
`content-length: 10` is read as 5. A 5-octet body is then accepted as
complete in both cases.

RFC 9110 §8.6: `Content-Length = 1*DIGIT`; a recipient that gets
several values that differ must reject the message (or treat it as an
error), and "a recipient MUST anticipate potentially large decimal
numerals and prevent parsing errors due to integer conversion overflows".
RFC 9113 §8.1.1: a request whose content-length does not equal the sum of
the DATA payload lengths is malformed (stream error PROTOCOL_ERROR).

`CLSound hs r`: the declared length a receiver derives is `-1` only if no
content-length field is present, `-2` (reject), or a number `n` that every
content-length field denotes exactly.
-/
namespace Flare.Bugs.H2_05
open Flare Flare.L3.H2.Conn Flare.L3.H2.Names Flare.Bugs.H2_Fixtures
open Flare.L3.H2.Validate (Header)

/-! ## Spec (RFC 9110 §8.6) -/

def digitsVal? : Bytes → Nat → Option Nat
  | [], a => some a
  | b :: t, a => if b < 48 || b > 57 then none else digitsVal? t (a * 10 + (b.toNat - 48))

/-- The number a `1*DIGIT` field value denotes. -/
def clValue (v : Bytes) : Option Nat := if v = [] then none else digitsVal? v 0

def CLSound (hs : List Header) (r : Int) : Prop :=
  (r = -1 ∧ ∀ h ∈ hs, h.name ≠ kContentLength) ∨ r = -2 ∨
  (∃ n : Nat, r = n ∧ (∃ h ∈ hs, h.name = kContentLength) ∧
    ∀ h ∈ hs, h.name = kContentLength → clValue h.value = some n)

/-! ## Counterexamples -/

def big : List Header := [H "content-length" "18446744073709551621"]
def dup : List Header := [H "content-length" "5", H "content-length" "10"]

theorem bug : declaredCLOld big = 5 ∧ clValue (H "content-length" "18446744073709551621").value =
    some 18446744073709551621 ∧ declaredCLOld dup = 5 := by native_decide

theorem counterexample : ¬ CLSound big (declaredCLOld big) := by
  have e := bug.1
  have v := bug.2.1
  rw [e]
  rintro (⟨h, -⟩ | h | ⟨n, hn, -, hall⟩)
  · cases h
  · cases h
  · have hn' : n = 5 := by omega
    subst hn'
    have := hall _ (List.mem_singleton.mpr rfl) (by native_decide)
    rw [v] at this; cases this

theorem counterexample_dup : ¬ CLSound dup (declaredCLOld dup) := by
  rw [bug.2.2]
  rintro (⟨h, -⟩ | h | ⟨n, hn, -, hall⟩)
  · cases h
  · cases h
  · have hn' : n = 5 := by omega
    subst hn'
    have := hall (H "content-length" "10") (by simp [dup]) (by native_decide)
    have v : clValue (H "content-length" "10").value = some 10 := by native_decide
    rw [v] at this; cases this

/-- The trace (pre-fix model `Fix.none`): request with content-length 2^64+5 and a 5-octet body is
accepted (no RST_STREAM); with the fix it is reset with PROTOCOL_ERROR. -/
def tr (k : UInt8) : List Ev := [.frame settings0, .frame (hdrs 1 false k), .frame (dataF 1 5 true)]

theorem bug_trace : outs Fix.none {} (tr 2) = some [[.settingsAck], [], [.wu 1 5, .wu 0 5]] ∧
    outs Fix.none {} (tr 6) = some [[.settingsAck], [], [.wu 1 5, .wu 0 5]] ∧
    stateOf Fix.none {} (tr 2) 1 = some .hcr := by native_decide

theorem fixed_trace : outs { h2_05 := true } {} (tr 2) = some [[.settingsAck], [.rst 1 ePROTOCOL], [.wu 0 5]] ∧
    outs { h2_05 := true } {} (tr 6) = some [[.settingsAck], [.rst 1 ePROTOCOL], [.wu 0 5]] := by
  native_decide

/-! ## The fix meets the spec -/

theorem digitsVal_ge (v : Bytes) (a n : Nat) (h : digitsVal? v a = some n) : a ≤ n := by
  induction v generalizing a with
  | nil => simp [digitsVal?] at h; omega
  | cons b t ih =>
    simp only [digitsVal?] at h
    split at h
    · cases h
    · have := ih _ h; omega

theorem clParse_sound (v : Bytes) (a n : Nat) (h : clParseFixed v a = some n) : digitsVal? v a = some n := by
  induction v generalizing a with
  | nil => simpa [clParseFixed, digitsVal?] using h
  | cons b t ih =>
    simp only [clParseFixed] at h
    simp only [digitsVal?]
    split at h
    · cases h
    · rename_i hd
      rw [if_neg hd]
      split at h
      · cases h
      · exact ih _ h

theorem clParse_complete (v : Bytes) (a n : Nat) (h : digitsVal? v a = some n) (hn : n ≤ I64MAX) :
    clParseFixed v a = some n := by
  induction v generalizing a with
  | nil => simpa [clParseFixed, digitsVal?] using h
  | cons b t ih =>
    simp only [digitsVal?] at h
    simp only [clParseFixed]
    split at h
    · cases h
    · rename_i hd
      rw [if_neg hd]
      have hge := digitsVal_ge t _ n h
      rw [if_neg (by unfold I64MAX at *; omega)]
      exact ih _ h

theorem clValue_of_parse (v : Bytes) (n : Nat) (hne : v ≠ []) (h : clParseFixed v 0 = some n) :
    clValue v = some n := by
  simp only [clValue, if_neg hne]; exact clParse_sound v 0 n h

/-- The accumulator after the content-length fields seen so far. -/
theorem go_sound (hs : List Header) :
    (CLSound hs (declaredCLFixedGo hs (-1))) ∧
    (∀ n : Nat, declaredCLFixedGo hs n = -2 ∨
      (declaredCLFixedGo hs n = n ∧ ∀ h ∈ hs, h.name = kContentLength → clValue h.value = some n)) := by
  induction hs with
  | nil =>
    refine ⟨Or.inl ⟨rfl, by simp⟩, fun n => Or.inr ⟨rfl, by simp⟩⟩
  | cons h t ih =>
    obtain ⟨ih1, ih2⟩ := ih
    refine ⟨?_, fun n => ?_⟩
    · simp only [declaredCLFixedGo]
      split
      · rename_i hcl
        split
        · exact Or.inr (Or.inl rfl)
        · rename_i hne
          split
          · exact Or.inr (Or.inl rfl)
          · rename_i m hm
            rw [if_neg (by simp)]
            rcases ih2 m with h2 | ⟨h2, hall⟩
            · exact Or.inr (Or.inl h2)
            · refine Or.inr (Or.inr ⟨m, h2, ⟨h, List.mem_cons_self .., hcl⟩, ?_⟩)
              intro h' hm' hc'
              rcases List.mem_cons.mp hm' with rfl | hm'
              · exact clValue_of_parse _ _ hne hm
              · exact hall h' hm' hc'
      · rename_i hcl
        rcases ih1 with ⟨h1, hno⟩ | h1 | ⟨k, h1, ⟨h', hm', hc'⟩, hall⟩
        · refine Or.inl ⟨h1, ?_⟩
          intro h' hm'
          rcases List.mem_cons.mp hm' with rfl | hm'
          · exact hcl
          · exact hno h' hm'
        · exact Or.inr (Or.inl h1)
        · refine Or.inr (Or.inr ⟨k, h1, ⟨h', List.mem_cons_of_mem _ hm', hc'⟩, ?_⟩)
          intro h'' hm'' hc''
          rcases List.mem_cons.mp hm'' with rfl | hm''
          · exact absurd hc'' hcl
          · exact hall h'' hm'' hc''
    · simp only [declaredCLFixedGo]
      split
      · rename_i hcl
        split
        · exact Or.inl rfl
        · rename_i hne
          split
          · exact Or.inl rfl
          · rename_i m hm
            split
            · exact Or.inl rfl
            · rename_i hnm
              have hmn : m = n := by
                simp only [Bool.and_eq_true, decide_eq_true_eq, not_and, ne_eq, Decidable.not_not] at hnm
                have := hnm (by omega); omega
              subst hmn
              rcases ih2 m with h2 | ⟨h2, hall⟩
              · exact Or.inl h2
              · refine Or.inr ⟨h2, ?_⟩
                intro h' hm' hc'
                rcases List.mem_cons.mp hm' with rfl | hm'
                · exact clValue_of_parse _ _ hne hm
                · exact hall h' hm' hc'
      · rename_i hcl
        rcases ih2 n with h2 | ⟨h2, hall⟩
        · exact Or.inl h2
        · refine Or.inr ⟨h2, ?_⟩
          intro h' hm' hc'
          rcases List.mem_cons.mp hm' with rfl | hm'
          · exact absurd hc' hcl
          · exact hall h' hm' hc'

/-- **Fixed (sound)**: the fixed parser's result always meets `CLSound`. -/
theorem fixed (hs : List Header) : CLSound hs (declaredCLFixed hs) := (go_sound hs).1

/-- **Fixed (complete)**: when every content-length field denotes the same
`n` that fits in an Int64, the fixed parser returns `n` (or `-1` if there
is no such field). -/
theorem fixed_complete (hs : List Header) (n : Nat) (hn : n ≤ I64MAX)
    (hall : ∀ h ∈ hs, h.name = kContentLength → clValue h.value = some n) :
    declaredCLFixed hs = -1 ∨ declaredCLFixed hs = n := by
  unfold declaredCLFixed
  suffices H : ∀ (d : Int), (d = -1 ∨ d = n) → declaredCLFixedGo hs d = -1 ∨ declaredCLFixedGo hs d = n from
    H (-1) (Or.inl rfl)
  induction hs with
  | nil => intro d hd; simpa [declaredCLFixedGo] using hd
  | cons h t ih =>
    intro d hd
    have hall' : ∀ h ∈ t, h.name = kContentLength → clValue h.value = some n :=
      fun h' hm hc => hall h' (List.mem_cons_of_mem _ hm) hc
    simp only [declaredCLFixedGo]
    split
    · rename_i hcl
      have hv := hall h (List.mem_cons_self ..) hcl
      unfold clValue at hv
      split at hv
      · cases hv
      · rename_i hne
        rw [if_neg hne, clParse_complete _ _ _ hv hn]
        simp only
        rw [if_neg (by rcases hd with rfl | rfl <;> simp)]
        exact ih hall' n (Or.inr rfl)
    · exact ih hall' d hd

/-- The shipped model carries the H2-05 fix: `commitTail` uses
`declaredCLFixed`, which meets `CLSound`, and both repro requests are
reset with PROTOCOL_ERROR. -/
theorem fixed_shipped : Fix.shipped.h2_05 = true ∧ (∀ hs, CLSound hs (declaredCLFixed hs)) ∧
    outs Fix.shipped {} (tr 2) = some [[.settingsAck], [.rst 1 ePROTOCOL], [.wu 0 5]] ∧
    outs Fix.shipped {} (tr 6) = some [[.settingsAck], [.rst 1 ePROTOCOL], [.wu 0 5]] :=
  ⟨rfl, fixed, by native_decide, by native_decide⟩

end Flare.Bugs.H2_05
