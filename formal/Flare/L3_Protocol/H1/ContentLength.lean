import Flare.L3_Protocol.H1.HeaderText

/-!
# Content-Length grammar (RFC 9110 §8.6)

`parse_content_length_bytes` (`flare/http/_scan.mojo:259-294`), modelled as
`Text.parseCL`, accepts exactly

    OWS 1*18DIGIT OWS [ (CR / LF) *OCTET ]

and returns the decimal value, which is below `10^18` and so fits a signed
64-bit `Int`. Everything else gives `-1` (CONTENT_LENGTH_INVALID):

* `parseCL_complete`: every string of that shape parses to its digits' value;
* `parseCL_sound`: every nonnegative result comes from such a shape;
* `parseCL_fits`: every result is `< 10^18`, hence `fitsI64`;
* `parseCL_invalid`: every rejected input yields exactly `-1`.

The trailing `(CR / LF) *OCTET` comes from the reactor calling this parser on
`buf[pos+15 : header_end]`, which runs on past the end of the line. The
parser calls it on a stripped field value, which cannot contain CR or LF
because the value check rejects them first.
-/
namespace Flare.L3.H1.ContentLength
open Flare Flare.L3.H1.Text

/-- What may follow the digits and trailing OWS. -/
def Tail (t : Bytes) : Prop := t = [] ∨ ∃ c r, t = c :: r ∧ (c = 13 ∨ c = 10)

theorem isDigit_toNat {d : UInt8} (h : isDigit d = true) : 48 ≤ d.toNat ∧ d.toNat ≤ 57 := by
  simp only [isDigit, Bool.and_eq_true, decide_eq_true_eq] at h
  have h1 : (48:UInt8).toNat ≤ d.toNat := UInt8.le_iff_toNat_le.mp h.1
  have h2 : d.toNat ≤ (57:UInt8).toNat := UInt8.le_iff_toNat_le.mp h.2
  simp at h1 h2; omega

theorem foldl_lt : ∀ (ds : Bytes) (acc : Nat), (∀ d ∈ ds, isDigit d = true) →
    ds.foldl (fun acc d => acc * 10 + (d.toNat - 48)) acc < (acc + 1) * 10 ^ ds.length
  | [], acc, _ => by simp
  | d :: ds, acc, h => by
    have hd := isDigit_toNat (h d (by simp))
    have ih := foldl_lt ds (acc * 10 + (d.toNat - 48)) (fun x hx => h x (by simp [hx]))
    rw [List.foldl_cons]
    have : (acc * 10 + (d.toNat - 48) + 1) * 10 ^ ds.length ≤ (acc + 1) * 10 ^ (d :: ds).length := by
      rw [List.length_cons, Nat.pow_succ]
      have : acc * 10 + (d.toNat - 48) + 1 ≤ (acc + 1) * 10 := by omega
      calc (acc * 10 + (d.toNat - 48) + 1) * 10 ^ ds.length
          ≤ ((acc + 1) * 10) * 10 ^ ds.length := Nat.mul_le_mul_right _ this
        _ = (acc + 1) * (10 ^ ds.length * 10) := by rw [Nat.mul_assoc, Nat.mul_comm 10]
    omega

/-- At most 18 digits are below `10^18`. -/
theorem decVal_lt {ds : Bytes} (h : ∀ d ∈ ds, isDigit d = true) (hl : ds.length ≤ 18) :
    decVal ds < 10 ^ 18 := by
  have := foldl_lt ds 0 h
  have hp : 10 ^ ds.length ≤ 10 ^ 18 := Nat.pow_le_pow_right (by decide) hl
  unfold decVal; omega

theorem finCL_cases (v : Int) (t : Bytes) : (Tail t ∧ finCL v t = v) ∨ (¬ Tail t ∧ finCL v t = -1) := by
  cases t with
  | nil => exact Or.inl ⟨Or.inl rfl, rfl⟩
  | cons c r =>
    by_cases hc : c = 13 ∨ c = 10
    · exact Or.inl ⟨Or.inr ⟨c, r, rfl, hc⟩, by simp [finCL, hc]⟩
    · refine Or.inr ⟨?_, by simp [finCL, hc]⟩
      rintro (h | ⟨c', r', h, hc'⟩)
      · cases h
      · cases h; exact hc hc'

/-- **Rejection is `-1`.** -/
theorem parseCL_invalid (l : Bytes) : parseCL l = -1 ∨ 0 ≤ parseCL l := by
  unfold parseCL
  dsimp only
  split
  · exact Or.inl rfl
  · rcases finCL_cases (decVal ((l.dropWhile isWS).takeWhile isDigit))
      (((l.dropWhile isWS).dropWhile isDigit).dropWhile isWS) with ⟨_, h⟩ | ⟨_, h⟩
    · rw [h]; exact Or.inr (Int.natCast_nonneg _)
    · exact Or.inl h

/-- **Soundness.** A nonnegative result comes from `OWS 1*18DIGIT OWS Tail`
and is the value of those digits. -/
theorem parseCL_sound {l : Bytes} (h : 0 ≤ parseCL l) :
    ∃ p ds q t, l = p ++ ds ++ q ++ t ∧ (∀ x ∈ p, isWS x = true) ∧ (∀ x ∈ ds, isDigit x = true) ∧
      1 ≤ ds.length ∧ ds.length ≤ 18 ∧ (∀ x ∈ q, isWS x = true) ∧ Tail t ∧
      parseCL l = (decVal ds : Int) := by
  have e1 := (List.takeWhile_append_dropWhile (p := isWS) (l := l)).symm
  have e2 := (List.takeWhile_append_dropWhile (p := isDigit) (l := l.dropWhile isWS)).symm
  have e3 := (List.takeWhile_append_dropWhile (p := isWS)
    (l := (l.dropWhile isWS).dropWhile isDigit)).symm
  unfold parseCL at h ⊢
  dsimp only at h ⊢
  split at h
  · simp at h
  · rename_i hlen
    rw [if_neg hlen]
    rcases finCL_cases (decVal ((l.dropWhile isWS).takeWhile isDigit))
      (((l.dropWhile isWS).dropWhile isDigit).dropWhile isWS) with ⟨ht, hf⟩ | ⟨_, hf⟩
    · refine ⟨l.takeWhile isWS, (l.dropWhile isWS).takeWhile isDigit,
        ((l.dropWhile isWS).dropWhile isDigit).takeWhile isWS,
        ((l.dropWhile isWS).dropWhile isDigit).dropWhile isWS, ?_, fun x hx => mem_takeWhile hx,
        fun x hx => mem_takeWhile hx, by omega, by omega, fun x hx => mem_takeWhile hx, ht, hf⟩
      conv => lhs; rw [e1, e2, e3]
      simp only [List.append_assoc]
    · rw [hf] at h; simp at h

theorem takeWhile_all {p : UInt8 → Bool} : ∀ {l : Bytes}, (∀ x ∈ l, p x = true) → l.takeWhile p = l
  | [], _ => rfl
  | a :: as, h => by
    simp only [List.takeWhile_cons, h a (by simp), if_true]
    rw [takeWhile_all (fun x hx => h x (by simp [hx]))]

theorem dropWhile_all {p : UInt8 → Bool} : ∀ {l : Bytes}, (∀ x ∈ l, p x = true) → l.dropWhile p = []
  | [], _ => rfl
  | a :: as, h => by
    simp only [List.dropWhile_cons, h a (by simp), if_true]
    exact dropWhile_all (fun x hx => h x (by simp [hx]))

theorem dropWhile_ws_digit {ds m : Bytes} (hne : ds ≠ []) (hd : ∀ x ∈ ds, isDigit x = true) :
    (ds ++ m).dropWhile isWS = ds ++ m := by
  cases ds with
  | nil => exact absurd rfl hne
  | cons d ds' =>
    have : isWS d = false := isDigit_ws (hd d (by simp))
    simp [List.dropWhile_cons, this]

theorem tail_takeWhile_digit {q t : Bytes} (hq : ∀ x ∈ q, isWS x = true) (ht : Tail t) :
    (q ++ t).takeWhile isDigit = [] := by
  cases q with
  | cons c q' =>
    have hc := hq c (by simp)
    have : isDigit c = false := by
      have : c = 32 ∨ c = 9 := by simpa [isWS] using hc
      rcases this with rfl | rfl <;> decide
    simp [List.takeWhile_cons, this]
  | nil =>
    rcases ht with rfl | ⟨c, r, rfl, hc⟩
    · rfl
    · rcases hc with rfl | rfl <;> rfl

/-- **Completeness.** `OWS 1*18DIGIT OWS Tail` parses to the digits' value. -/
theorem parseCL_complete {p ds q t : Bytes} (hp : ∀ x ∈ p, isWS x = true)
    (hd : ∀ x ∈ ds, isDigit x = true) (h1 : 1 ≤ ds.length) (h18 : ds.length ≤ 18)
    (hq : ∀ x ∈ q, isWS x = true) (ht : Tail t) :
    parseCL (p ++ ds ++ q ++ t) = (decVal ds : Int) := by
  have hne : ds ≠ [] := fun e => by simp [e] at h1
  have hnil := tail_takeWhile_digit hq ht
  have a1 : (p ++ ds ++ q ++ t).dropWhile isWS = ds ++ (q ++ t) := by
    rw [List.append_assoc, List.append_assoc, dropWhile_ws_prefix p _ hp, dropWhile_ws_digit hne hd]
  have a2 : (ds ++ (q ++ t)).takeWhile isDigit = ds := by
    rw [takeWhile_append_of_nil hnil ds, takeWhile_all hd]
  have a3 : (ds ++ (q ++ t)).dropWhile isDigit = q ++ t := by
    rw [dropWhile_append_of_nil hnil ds, dropWhile_all hd, List.nil_append]
  have a4 : (q ++ t).dropWhile isWS = t := by
    rw [dropWhile_ws_prefix q t hq]
    rcases ht with rfl | ⟨c, r, rfl, hc⟩
    · rfl
    · rcases hc with rfl | rfl <;> rfl
  unfold parseCL
  dsimp only
  rw [a1, a2, a3, a4, if_neg (by omega)]
  rcases ht with rfl | ⟨c, r, rfl, hc⟩
  · rfl
  · simp [finCL, hc]

/-- **Fits Int64.** Every value `parse_content_length_bytes` returns is in
`[-1, 10^18)`. -/
theorem parseCL_fits (l : Bytes) : -1 ≤ parseCL l ∧ parseCL l < 10 ^ 18 := by
  rcases parseCL_invalid l with h | h
  · rw [h]; decide
  · obtain ⟨_, ds, _, _, _, _, hd, _, h18, _, _, hv⟩ := parseCL_sound h
    rw [hv]
    have := decVal_lt hd h18
    omega

theorem parseCL_fitsI64 (l : Bytes) : fitsI64 (parseCL l) := by
  have := parseCL_fits l
  unfold fitsI64 I64_MIN I64_MAX; omega

end Flare.L3.H1.ContentLength
