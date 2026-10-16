import Flare.L3_Protocol.H2.Conn

/-!
# HTTP/2 request content-length (RFC 9110 §8.6, RFC 9113 §8.1.1)

`declaredCL` (`_declared_content_length`) parses every `content-length`
field as `1*DIGIT` with an Int64 overflow guard and answers `-2` (reset
with PROTOCOL_ERROR in `commitTail`) for a malformed value or for fields
that disagree.

RFC 9110 §8.6: `Content-Length = 1*DIGIT`; a recipient that gets several
values that differ must reject the message, and "a recipient MUST
anticipate potentially large decimal numerals and prevent parsing errors
due to integer conversion overflows". RFC 9113 §8.1.1: a request whose
content-length does not equal the sum of the DATA payload lengths is
malformed.

`CLSound hs r`: the declared length is `-1` only if no content-length
field is present, `-2` (reject), or a number `n` that every content-length
field denotes exactly. `declaredCL_sound` proves it for every header list;
`declaredCL_complete` proves the parser accepts every agreeing set of
fields whose value fits in an Int64.
-/
namespace Flare.L3.H2.ContentLength
open Flare Flare.L3.H2.Conn Flare.L3.H2.Names
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

/-! ## The parser meets the spec -/

theorem digitsVal_ge (v : Bytes) (a n : Nat) (h : digitsVal? v a = some n) : a ≤ n := by
  induction v generalizing a with
  | nil => simp [digitsVal?] at h; omega
  | cons b t ih =>
    simp only [digitsVal?] at h
    split at h
    · cases h
    · have := ih _ h; omega

theorem clParse_sound (v : Bytes) (a n : Nat) (h : clParse v a = some n) : digitsVal? v a = some n := by
  induction v generalizing a with
  | nil => simpa [clParse, digitsVal?] using h
  | cons b t ih =>
    simp only [clParse] at h
    simp only [digitsVal?]
    split at h
    · cases h
    · rename_i hd
      rw [if_neg hd]
      split at h
      · cases h
      · exact ih _ h

theorem clParse_complete (v : Bytes) (a n : Nat) (h : digitsVal? v a = some n) (hn : n ≤ I64MAX) :
    clParse v a = some n := by
  induction v generalizing a with
  | nil => simpa [clParse, digitsVal?] using h
  | cons b t ih =>
    simp only [digitsVal?] at h
    simp only [clParse]
    split at h
    · cases h
    · rename_i hd
      rw [if_neg hd]
      have hge := digitsVal_ge t _ n h
      rw [if_neg (by unfold I64MAX at *; omega)]
      exact ih _ h

theorem clValue_of_parse (v : Bytes) (n : Nat) (hne : v ≠ []) (h : clParse v 0 = some n) :
    clValue v = some n := by
  simp only [clValue, if_neg hne]; exact clParse_sound v 0 n h

/-- The accumulator after the content-length fields seen so far. -/
theorem go_sound (hs : List Header) :
    (CLSound hs (declaredCLGo hs (-1))) ∧
    (∀ n : Nat, declaredCLGo hs n = -2 ∨
      (declaredCLGo hs n = n ∧ ∀ h ∈ hs, h.name = kContentLength → clValue h.value = some n)) := by
  induction hs with
  | nil =>
    refine ⟨Or.inl ⟨rfl, by simp⟩, fun n => Or.inr ⟨rfl, by simp⟩⟩
  | cons h t ih =>
    obtain ⟨ih1, ih2⟩ := ih
    refine ⟨?_, fun n => ?_⟩
    · simp only [declaredCLGo]
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
    · simp only [declaredCLGo]
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

/-- **Sound**: the declared length always meets `CLSound`. -/
theorem declaredCL_sound (hs : List Header) : CLSound hs (declaredCL hs) := (go_sound hs).1

/-- **Complete**: when every content-length field denotes the same `n`
that fits in an Int64, the parser returns `n` (or `-1` if there is no such
field). -/
theorem declaredCL_complete (hs : List Header) (n : Nat) (hn : n ≤ I64MAX)
    (hall : ∀ h ∈ hs, h.name = kContentLength → clValue h.value = some n) :
    declaredCL hs = -1 ∨ declaredCL hs = n := by
  unfold declaredCL
  suffices H : ∀ (d : Int), (d = -1 ∨ d = n) → declaredCLGo hs d = -1 ∨ declaredCLGo hs d = n from
    H (-1) (Or.inl rfl)
  induction hs with
  | nil => intro d hd; simpa [declaredCLGo] using hd
  | cons h t ih =>
    intro d hd
    have hall' : ∀ h ∈ t, h.name = kContentLength → clValue h.value = some n :=
      fun h' hm hc => hall h' (List.mem_cons_of_mem _ hm) hc
    simp only [declaredCLGo]
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

end Flare.L3.H2.ContentLength
