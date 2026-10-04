import Flare.Core
/-!
# UTF-8 validation (RFC 3629)

Three pieces of flare decide UTF-8 well-formedness:

* `_is_valid_utf8` in `io/byte_cursor.mojo` (used by `ByteReader.read_utf8`),
* `_is_valid_utf8` in `ws/frame.mojo` (WebSocket TEXT frames, RFC 6455 §8.1),
  which is the same code over a `List` instead of a `Span`,
* `_step` / `utf8_lossy_string` in `http/proto/utf8.mojo` (U+FFFD
  substitution for `Request.text()` and friends).

**Spec.** `seqOK` is the RFC 3629 §4 ABNF (`UTF8-1 .. UTF8-4`, identical to
Unicode §3.9 Table 3-7) and `WF` is `UTF8-octets = *( UTF8-char )`.
`seqOK_iff_encode` checks the byte table against the RFC 3629 §3 bit-pattern
definition: a sequence is well-formed iff it is the encoding of a Unicode
scalar value (≤ U+10FFFF, not a surrogate).

**Results.** `isValidUtf8_iff` (both validators accept exactly `WF`),
`step_pos_iff` / `step_neg` (the lossy classifier is exact),
`lossy_wf` (lossy output is always well-formed), `lossy_of_wf`
(identity on well-formed input) and `scan_none_iff` (the lossy decoder's
fast path agrees with the validators).

**Maximal subparts (Unicode 15 §3.9, D93b).** `MaxSub x k` says the first
`k` bytes of `x` are its maximal subpart; `pfx_iff` gives a closed form of
"initial subsequence of a well-formed sequence". `Subst x o` is the §3.9
"U+FFFD Substitution of Maximal Subparts" relation and is functional
(`Subst.unique`). `step_maxSub` (the classifier returns minus the maximal
subpart length) and `lossy_subst` / `lossy_eq_iff_subst` (`utf8_lossy_string`
computes exactly that substitution) close the claim in the Mojo docstring.
-/
namespace Flare.L1.Utf8
open Flare.Bytes (getD)

-- equation lemmas for the 4-deep list patterns below need more than the default depth
set_option maxRecDepth 2000
set_option linter.unusedSimpArgs false

/-! ## Spec: RFC 3629 -/

/-- RFC 3629 §4: `UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4`. -/
def seqOK : Bytes → Prop
  | [] => False
  | [a] => a.toNat ≤ 0x7F
  | [a, b] => 0xC2 ≤ a.toNat ∧ a.toNat ≤ 0xDF ∧ 0x80 ≤ b.toNat ∧ b.toNat ≤ 0xBF
  | [a, b, c] =>
    ((a.toNat = 0xE0 ∧ 0xA0 ≤ b.toNat ∧ b.toNat ≤ 0xBF) ∨
     (((0xE1 ≤ a.toNat ∧ a.toNat ≤ 0xEC) ∨ (0xEE ≤ a.toNat ∧ a.toNat ≤ 0xEF)) ∧
        0x80 ≤ b.toNat ∧ b.toNat ≤ 0xBF) ∨
     (a.toNat = 0xED ∧ 0x80 ≤ b.toNat ∧ b.toNat ≤ 0x9F)) ∧
    0x80 ≤ c.toNat ∧ c.toNat ≤ 0xBF
  | [a, b, c, d] =>
    ((a.toNat = 0xF0 ∧ 0x90 ≤ b.toNat ∧ b.toNat ≤ 0xBF) ∨
     (0xF1 ≤ a.toNat ∧ a.toNat ≤ 0xF3 ∧ 0x80 ≤ b.toNat ∧ b.toNat ≤ 0xBF) ∨
     (a.toNat = 0xF4 ∧ 0x80 ≤ b.toNat ∧ b.toNat ≤ 0x8F)) ∧
    0x80 ≤ c.toNat ∧ c.toNat ≤ 0xBF ∧ 0x80 ≤ d.toNat ∧ d.toNat ≤ 0xBF
  | _ :: _ :: _ :: _ :: _ :: _ => False

/-- RFC 3629 §4: `UTF8-octets = *( UTF8-char )`. -/
inductive WF : Bytes → Prop
  | nil : WF []
  | app {s r : Bytes} : seqOK s → WF r → WF (s ++ r)

/-- Unicode scalar value: `0..0x10FFFF` minus the surrogates. -/
def IsScalar (c : Nat) : Prop := c ≤ 0x10FFFF ∧ ¬ (0xD800 ≤ c ∧ c ≤ 0xDFFF)

/-- RFC 3629 §3: the bit-pattern encoding of a code point. -/
def encode (c : Nat) : Bytes :=
  if c < 0x80 then [UInt8.ofNat c]
  else if c < 0x800 then [UInt8.ofNat (0xC0 + c / 64), UInt8.ofNat (0x80 + c % 64)]
  else if c < 0x10000 then
    [UInt8.ofNat (0xE0 + c / 4096), UInt8.ofNat (0x80 + c / 64 % 64), UInt8.ofNat (0x80 + c % 64)]
  else
    [UInt8.ofNat (0xF0 + c / 262144), UInt8.ofNat (0x80 + c / 4096 % 64),
     UInt8.ofNat (0x80 + c / 64 % 64), UInt8.ofNat (0x80 + c % 64)]

def decode2 (a b : UInt8) : Nat := (a.toNat - 0xC0) * 64 + (b.toNat - 0x80)
def decode3 (a b c : UInt8) : Nat :=
  (a.toNat - 0xE0) * 4096 + (b.toNat - 0x80) * 64 + (c.toNat - 0x80)
def decode4 (a b c d : UInt8) : Nat :=
  (a.toNat - 0xF0) * 262144 + (b.toNat - 0x80) * 4096 + (c.toNat - 0x80) * 64 + (d.toNat - 0x80)

/-- Inverse of `encode` on well-formed sequences. -/
def decode : Bytes → Nat
  | [] => 0
  | [a] => a.toNat
  | [a, b] => decode2 a b
  | [a, b, c] => decode3 a b c
  | [a, b, c, d] => decode4 a b c d
  | _ :: _ :: _ :: _ :: _ :: _ => 0

theorem u8_eq_of_toNat {a : UInt8} {n : Nat} (h : a.toNat = n) : UInt8.ofNat n = a := by
  subst h; simp

theorem encode_seqOK (c : Nat) (h : IsScalar c) : seqOK (encode c) := by
  unfold IsScalar at h
  unfold encode
  split
  · simp only [seqOK, UInt8.toNat_ofNat']; omega
  split
  · simp only [seqOK, UInt8.toNat_ofNat']; omega
  split
  · simp only [seqOK, UInt8.toNat_ofNat']; omega
  · simp only [seqOK, UInt8.toNat_ofNat']; omega

theorem decode_encode (c : Nat) (h : IsScalar c) : decode (encode c) = c := by
  unfold IsScalar at h
  unfold encode
  split
  · simp only [decode, decode2, decode3, decode4, UInt8.toNat_ofNat']; omega
  split
  · simp only [decode, decode2, decode3, decode4, UInt8.toNat_ofNat']; omega
  split
  · simp only [decode, decode2, decode3, decode4, UInt8.toNat_ofNat']; omega
  · simp only [decode, decode2, decode3, decode4, UInt8.toNat_ofNat']; omega

theorem encode_decode (s : Bytes) (h : seqOK s) : IsScalar (decode s) ∧ encode (decode s) = s := by
  match s, h with
  | [a], h =>
    simp only [seqOK] at h
    refine ⟨by simp only [IsScalar, decode, decode2, decode3, decode4]; omega, ?_⟩
    simp only [decode]; rw [encode, if_pos (show a.toNat < 0x80 by omega)]
    simp
  | [a, b], h =>
    simp only [seqOK] at h
    refine ⟨by simp only [IsScalar, decode, decode2, decode3, decode4]; omega, ?_⟩
    simp only [decode, decode2, decode3, decode4]
    rw [encode, if_neg (by omega), if_pos (by omega)]
    simp only [List.cons.injEq, and_true]
    exact ⟨u8_eq_of_toNat (by omega), u8_eq_of_toNat (by omega)⟩
  | [a, b, c], h =>
    simp only [seqOK] at h
    refine ⟨by simp only [IsScalar, decode, decode2, decode3, decode4]; omega, ?_⟩
    simp only [decode, decode2, decode3, decode4]
    rw [encode, if_neg (by omega), if_neg (by omega), if_pos (by omega)]
    simp only [List.cons.injEq, and_true]
    exact ⟨u8_eq_of_toNat (by omega), u8_eq_of_toNat (by omega), u8_eq_of_toNat (by omega)⟩
  | [a, b, c, d], h =>
    simp only [seqOK] at h
    refine ⟨by simp only [IsScalar, decode, decode2, decode3, decode4]; omega, ?_⟩
    simp only [decode, decode2, decode3, decode4]
    rw [encode, if_neg (by omega), if_neg (by omega), if_neg (by omega)]
    simp only [List.cons.injEq, and_true]
    exact ⟨u8_eq_of_toNat (by omega), u8_eq_of_toNat (by omega), u8_eq_of_toNat (by omega),
      u8_eq_of_toNat (by omega)⟩

/-- The RFC 3629 §4 byte table is exactly the image of the §3 encoding on
scalar values. -/
theorem seqOK_iff_encode (s : Bytes) : seqOK s ↔ ∃ c, IsScalar c ∧ encode c = s := by
  constructor
  · intro h; exact ⟨decode s, encode_decode s h⟩
  · rintro ⟨c, hc, rfl⟩; exact encode_seqOK c hc


/-! ## Structure of `WF` -/

/-- Sequence length announced by a lead byte (0: not a lead byte). -/
def leadLen (a : UInt8) : Nat :=
  if a.toNat ≤ 0x7F then 1
  else if 0xC2 ≤ a.toNat ∧ a.toNat ≤ 0xDF then 2
  else if 0xE0 ≤ a.toNat ∧ a.toNat ≤ 0xEF then 3
  else if 0xF0 ≤ a.toNat ∧ a.toNat ≤ 0xF4 then 4
  else 0

theorem leadLen_1 {a : UInt8} (h : a.toNat ≤ 0x7F) : leadLen a = 1 := by
  unfold leadLen; rw [if_pos h]
theorem leadLen_2 {a : UInt8} (h : 0xC2 ≤ a.toNat ∧ a.toNat ≤ 0xDF) : leadLen a = 2 := by
  unfold leadLen; rw [if_neg (by omega), if_pos h]
theorem leadLen_3 {a : UInt8} (h : 0xE0 ≤ a.toNat ∧ a.toNat ≤ 0xEF) : leadLen a = 3 := by
  unfold leadLen; rw [if_neg (by omega), if_neg (by omega), if_pos h]
theorem leadLen_4 {a : UInt8} (h : 0xF0 ≤ a.toNat ∧ a.toNat ≤ 0xF4) : leadLen a = 4 := by
  unfold leadLen; rw [if_neg (by omega), if_neg (by omega), if_neg (by omega), if_pos h]
theorem leadLen_0 {a : UInt8} (h1 : 0x80 ≤ a.toNat) (h2 : ¬ (0xC2 ≤ a.toNat ∧ a.toNat ≤ 0xDF))
    (h3 : ¬ (0xE0 ≤ a.toNat ∧ a.toNat ≤ 0xEF)) (h4 : ¬ (0xF0 ≤ a.toNat ∧ a.toNat ≤ 0xF4)) :
    leadLen a = 0 := by
  unfold leadLen; rw [if_neg (by omega), if_neg h2, if_neg h3, if_neg h4]

theorem seqOK_shape {s : Bytes} (h : seqOK s) : ∃ a t, s = a :: t ∧ leadLen a = s.length := by
  match s, h with
  | [a], h => simp only [seqOK] at h; exact ⟨a, [], rfl, leadLen_1 h⟩
  | [a, b], h => simp only [seqOK] at h; exact ⟨a, [b], rfl, leadLen_2 (by omega)⟩
  | [a, b, c], h => simp only [seqOK] at h; exact ⟨a, [b, c], rfl, leadLen_3 (by omega)⟩
  | [a, b, c, d], h => simp only [seqOK] at h; exact ⟨a, [b, c, d], rfl, leadLen_4 (by omega)⟩

/-- A well-formed character starts at the head of `x`. -/
def WfHead (x : Bytes) : Prop :=
  ∃ a r, x = a :: r ∧ 0 < leadLen a ∧ leadLen a ≤ x.length ∧ seqOK (x.take (leadLen a))

theorem WF_cons_iff (a : UInt8) (r : Bytes) :
    WF (a :: r) ↔ WfHead (a :: r) ∧ WF ((a :: r).drop (leadLen a)) := by
  constructor
  · intro h
    generalize hx : a :: r = x at h
    cases h with
    | nil => cases hx
    | @app s t hs ht =>
      obtain ⟨a', t', rfl, hl⟩ := seqOK_shape hs
      simp only [List.cons_append, List.cons.injEq] at hx
      obtain ⟨rfl, rfl⟩ := hx
      have hs' : ((a :: t') ++ t).take (leadLen a) = a :: t' := by
        rw [hl, List.take_left]
      have hd : ((a :: t') ++ t).drop (leadLen a) = t := by
        rw [hl, List.drop_left]
      refine ⟨⟨a, t' ++ t, rfl, ?_, ?_, ?_⟩, ?_⟩
      · rw [hl]; simp
      · rw [hl]; simp
      · rw [hs']; exact hs
      · rw [hd]; exact ht
  · rintro ⟨⟨a', r', he, -, -, hs⟩, hw⟩
    simp only [List.cons.injEq] at he; obtain ⟨rfl, rfl⟩ := he
    have := WF.app hs hw
    rwa [List.take_append_drop] at this

theorem WF_append {x y : Bytes} (hx : WF x) (hy : WF y) : WF (x ++ y) := by
  induction hx with
  | nil => exact hy
  | app hs _ ih => rw [List.append_assoc]; exact WF.app hs ih

theorem WF_of_seqOK {s : Bytes} (h : seqOK s) : WF s := by
  have := WF.app h WF.nil; rwa [List.append_nil] at this

/-! ## Index-loop helpers -/

theorem drop_eq_getD_cons (data : Bytes) (i : Nat) (h : i < data.length) :
    data.drop i = getD data i :: data.drop (i + 1) := by
  rw [List.drop_eq_getElem_cons h]; simp [getD, List.getElem?_eq_getElem h]

/-! ## `_is_valid_utf8` (byte_cursor and ws/frame) -/

/-- mirrors flare/io/byte_cursor.mojo:52-107 @59bda50; flare/ws/frame.mojo:553-606
@59bda50 is the same loop over a `List[UInt8]`. The `while i < n` loop with
early `return False` is the tail recursion on `i`. -/
def validFrom (data : Bytes) (i : Nat) : Bool :=
  if i < data.length then
    let n := data.length
    let b := getD data i
    if b ≤ 0x7F then validFrom data (i + 1)
    else if b ≥ 0xC2 && b ≤ 0xDF then
      if i + 1 ≥ n then false
      else if getD data (i + 1) < 0x80 || getD data (i + 1) > 0xBF then false
      else validFrom data (i + 2)
    else if b ≥ 0xE0 && b ≤ 0xEF then
      if i + 2 ≥ n then false
      else
        let b1 := getD data (i + 1)
        let b2 := getD data (i + 2)
        if b1 < 0x80 || b1 > 0xBF || b2 < 0x80 || b2 > 0xBF then false
        else if b == 0xE0 && b1 < 0xA0 then false
        else if b == 0xED && b1 > 0x9F then false
        else validFrom data (i + 3)
    else if b ≥ 0xF0 && b ≤ 0xF4 then
      if i + 3 ≥ n then false
      else
        let b1 := getD data (i + 1)
        let b2 := getD data (i + 2)
        let b3 := getD data (i + 3)
        if b1 < 0x80 || b1 > 0xBF || b2 < 0x80 || b2 > 0xBF || b3 < 0x80 || b3 > 0xBF then false
        else if b == 0xF0 && b1 < 0x90 then false
        else if b == 0xF4 && b1 > 0x8F then false
        else validFrom data (i + 4)
    else false
  else true
termination_by data.length - i

/-- `_is_valid_utf8(data)` -/
def isValidUtf8 (data : Bytes) : Bool := validFrom data 0

theorem wfHead_cons (a : UInt8) (r : Bytes) :
    WfHead (a :: r) ↔ 0 < leadLen a ∧ leadLen a ≤ r.length + 1 ∧ seqOK ((a :: r).take (leadLen a)) := by
  constructor
  · rintro ⟨a', r', he, h1, h2, h3⟩
    simp only [List.cons.injEq] at he; obtain ⟨rfl, rfl⟩ := he
    exact ⟨h1, by simpa using h2, h3⟩
  · rintro ⟨h1, h2, h3⟩; exact ⟨a, r, rfl, h1, by simpa using h2, h3⟩

theorem ite_false_else (c : Prop) [Decidable c] (x : Bool) :
    (if c then false else x) = (!decide c && x) := by
  by_cases h : c <;> simp [h]

/-- Normalise `UInt8` comparisons to `Nat` ones. -/
macro "u8norm" : tactic => `(tactic|
  simp only [UInt8.le_iff_toNat_le, UInt8.lt_iff_toNat_lt, ← UInt8.toNat_inj, ge_iff_le, gt_iff_lt,
    Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, UInt8.toNat_ofNat',
    Bool.not_eq_true', decide_eq_false_iff_not, Bool.and_eq_true, ite_false_else,
    Bool.and_eq_false_iff, Bool.or_eq_false_iff,
    Nat.reducePow, Nat.reduceMod, UInt8.reduceToNat])

/-- Close `guards ∧ WF rest ↔ (WfHead conditions) ∧ WF rest` by arithmetic. -/
macro "wf_close" : tactic => `(tactic| (
  simp only [Nat.add_assoc, Nat.reduceAdd, List.length_drop, ← and_assoc]
  apply and_congr_left; intro _
  constructor <;> intro _ <;> omega))

theorem validFrom_iff (data : Bytes) (i : Nat) : validFrom data i = true ↔ WF (data.drop i) := by
  induction h : data.length - i using Nat.strongRecOn generalizing i with
  | ind k ih =>
  rw [validFrom]
  by_cases hi : i < data.length
  · simp only [if_pos hi]
    rw [drop_eq_getD_cons data i hi, WF_cons_iff, wfHead_cons]
    generalize getD data i = a
    have hcls : a.toNat ≤ 0x7F ∨ (0x80 ≤ a.toNat ∧ a.toNat ≤ 0xC1) ∨ (0xC2 ≤ a.toNat ∧ a.toNat ≤ 0xDF) ∨
        (0xE0 ≤ a.toNat ∧ a.toNat ≤ 0xEF) ∨ (0xF0 ≤ a.toNat ∧ a.toNat ≤ 0xF4) ∨ 0xF5 ≤ a.toNat := by
      omega
    rcases hcls with hc | hc | hc | hc | hc | hc
    · rw [if_pos (by u8norm; omega), leadLen_1 hc, ih _ (by omega) (i + 1) rfl]
      simp [seqOK, hc]
    · rw [if_neg (by u8norm; omega), if_neg (by u8norm; omega), if_neg (by u8norm; omega),
        if_neg (by u8norm; omega), leadLen_0 (by omega) (by omega) (by omega) (by omega)]
      simp
    · rw [if_neg (by u8norm; omega), if_pos (by u8norm; omega), leadLen_2 hc]
      by_cases hn : i + 1 ≥ data.length
      · rw [if_pos hn]; simp; omega
      · rw [if_neg hn, drop_eq_getD_cons data (i + 1) (by omega)]
        generalize getD data (i + 1) = b1
        u8norm
        rw [ih _ (by omega) (i + 2) rfl]
        simp only [List.take, List.drop, seqOK, List.length_cons]
        wf_close
    · rw [if_neg (by u8norm; omega), if_neg (by u8norm; omega), if_pos (by u8norm; omega), leadLen_3 hc]
      by_cases hn : i + 2 ≥ data.length
      · rw [if_pos hn]; simp; omega
      · rw [if_neg hn, drop_eq_getD_cons data (i + 1) (by omega),
          drop_eq_getD_cons data (i + 2) (by omega)]
        generalize getD data (i + 1) = b1
        generalize getD data (i + 2) = b2
        u8norm
        rw [ih _ (by omega) (i + 3) rfl]
        simp only [List.take, List.drop, seqOK, List.length_cons]
        wf_close
    · rw [if_neg (by u8norm; omega), if_neg (by u8norm; omega), if_neg (by u8norm; omega),
        if_pos (by u8norm; omega), leadLen_4 hc]
      by_cases hn : i + 3 ≥ data.length
      · rw [if_pos hn]; simp; omega
      · rw [if_neg hn, drop_eq_getD_cons data (i + 1) (by omega),
          drop_eq_getD_cons data (i + 2) (by omega), drop_eq_getD_cons data (i + 3) (by omega)]
        generalize getD data (i + 1) = b1
        generalize getD data (i + 2) = b2
        generalize getD data (i + 3) = b3
        u8norm
        rw [ih _ (by omega) (i + 4) rfl]
        simp only [List.take, List.drop, seqOK, List.length_cons]
        wf_close
    · rw [if_neg (by u8norm; omega), if_neg (by u8norm; omega), if_neg (by u8norm; omega),
        if_neg (by u8norm; omega), leadLen_0 (by omega) (by omega) (by omega) (by omega)]
      simp
  · simp only [if_neg hi, true_iff]
    rw [List.drop_eq_nil_of_le (by omega)]; exact WF.nil

/-- **Validator correctness** (`byte_cursor._is_valid_utf8`, `ws.frame._is_valid_utf8`):
the validator accepts exactly the RFC 3629 well-formed byte strings. -/
theorem isValidUtf8_iff (data : Bytes) : isValidUtf8 data = true ↔ WF data := by
  simpa [isValidUtf8] using validFrom_iff data 0

/-! ## `http/proto/utf8.mojo`: `_step` and `utf8_lossy_string` -/

/-- mirrors flare/http/proto/utf8.mojo:24-27 @59bda50 -/
def isContB (b : UInt8) : Bool := b ≥ 0x80 && b ≤ 0xBF

/-- mirrors flare/http/proto/utf8.mojo:30-90 @59bda50 (`n = len(data)`; the
mutable `lo`/`hi` are the `let`s). -/
def step (data : Bytes) (i : Nat) : Int :=
  let n := data.length
  let b := getD data i
  if b ≤ 0x7F then 1
  else if b ≥ 0xC2 && b ≤ 0xDF then
    if i + 1 < n && isContB (getD data (i + 1)) then 2 else -1
  else if b ≥ 0xE0 && b ≤ 0xEF then
    let lo : UInt8 := if b == 0xE0 then 0xA0 else 0x80
    let hi : UInt8 := if b == 0xED then 0x9F else 0xBF
    if i + 1 ≥ n || getD data (i + 1) < lo || getD data (i + 1) > hi then -1
    else if i + 2 ≥ n || !isContB (getD data (i + 2)) then -2
    else 3
  else if b ≥ 0xF0 && b ≤ 0xF4 then
    let lo : UInt8 := if b == 0xF0 then 0x90 else 0x80
    let hi : UInt8 := if b == 0xF4 then 0x8F else 0xBF
    if i + 1 ≥ n || getD data (i + 1) < lo || getD data (i + 1) > hi then -1
    else if i + 2 ≥ n || !isContB (getD data (i + 2)) then -2
    else if i + 3 ≥ n || !isContB (getD data (i + 3)) then -3
    else 4
  else -1

theorem take_drop_getD (data : Bytes) (i k : Nat) (h : i + k ≤ data.length) :
    (data.drop i).take k = (List.range k).map (fun j => getD data (i + j)) := by
  apply List.ext_getElem
  · simp; omega
  · intro j h1 h2
    simp only [List.getElem_take, List.getElem_drop, List.getElem_map, List.getElem_range, getD]
    rw [List.getElem?_eq_getElem (by simp at h2; omega)]; rfl

theorem wfHead_drop (data : Bytes) (i : Nat) (hi : i < data.length) :
    WfHead (data.drop i) ↔ 0 < leadLen (getD data i) ∧ i + leadLen (getD data i) ≤ data.length ∧
      seqOK ((List.range (leadLen (getD data i))).map (fun j => getD data (i + j))) := by
  have e := drop_eq_getD_cons data i hi
  have : WfHead (data.drop i) ↔ 0 < leadLen (getD data i) ∧
      leadLen (getD data i) ≤ (data.drop (i + 1)).length + 1 ∧
      seqOK ((data.drop i).take (leadLen (getD data i))) := by
    conv => lhs; rw [e]
    rw [wfHead_cons, ← e]
  rw [this, List.length_drop]
  by_cases hk : i + leadLen (getD data i) ≤ data.length
  · rw [take_drop_getD _ _ _ hk]; constructor
    · rintro ⟨h1, -, h3⟩; exact ⟨h1, hk, h3⟩
    · rintro ⟨h1, -, h3⟩; exact ⟨h1, by omega, h3⟩
  · constructor
    · rintro ⟨-, h2, -⟩; omega
    · rintro ⟨-, h2, -⟩; omega

/-- The classifier is exact: a positive result is the length of the
well-formed character at `i`; a negative result means no well-formed
character starts at `i` and `-w ∈ 1..3` bytes (all in bounds) are replaced. -/
theorem step_cases (data : Bytes) (i : Nat) (hi : i < data.length) :
    (step data i = leadLen (getD data i) ∧ 0 < leadLen (getD data i) ∧ WfHead (data.drop i)) ∨
    (step data i < 0 ∧ -3 ≤ step data i ∧ i + (-step data i).toNat ≤ data.length ∧
      ¬ WfHead (data.drop i)) := by
  rw [wfHead_drop data i hi]
  have hcls : (getD data i).toNat ≤ 0x7F ∨ (0x80 ≤ (getD data i).toNat ∧ (getD data i).toNat ≤ 0xC1) ∨
      (0xC2 ≤ (getD data i).toNat ∧ (getD data i).toNat ≤ 0xDF) ∨
      (0xE0 ≤ (getD data i).toNat ∧ (getD data i).toNat ≤ 0xEF) ∨
      (0xF0 ≤ (getD data i).toNat ∧ (getD data i).toNat ≤ 0xF4) ∨ 0xF5 ≤ (getD data i).toNat := by
    omega
  unfold step
  rcases hcls with hc | hc | hc | hc | hc | hc
  · rw [leadLen_1 hc, if_pos (by u8norm; omega)]
    left; simp [seqOK, hc]; omega
  · rw [leadLen_0 (by omega) (by omega) (by omega) (by omega), if_neg (by u8norm; omega),
      if_neg (by u8norm; omega), if_neg (by u8norm; omega), if_neg (by u8norm; omega)]
    right; simp; omega
  · rw [leadLen_2 hc, if_neg (by u8norm; omega), if_pos (by u8norm; omega)]
    simp only [List.range_succ, List.range_zero, List.nil_append, List.map_cons, List.map_nil,
      List.cons_append, Nat.add_zero, seqOK, isContB]
    u8norm
    repeat' split
    all_goals (try simp only [UInt8.reduceToNat, Bool.and_eq_false_iff, decide_eq_false_iff_not] at *)
    all_goals omega
  · rw [leadLen_3 hc, if_neg (by u8norm; omega), if_neg (by u8norm; omega), if_pos (by u8norm; omega)]
    simp only [List.range_succ, List.range_zero, List.nil_append, List.map_cons, List.map_nil,
      List.cons_append, Nat.add_zero, seqOK, isContB]
    u8norm
    repeat' split
    all_goals (try simp only [UInt8.reduceToNat, Bool.and_eq_false_iff, decide_eq_false_iff_not] at *)
    all_goals omega
  · rw [leadLen_4 hc, if_neg (by u8norm; omega), if_neg (by u8norm; omega), if_neg (by u8norm; omega),
      if_pos (by u8norm; omega)]
    simp only [List.range_succ, List.range_zero, List.nil_append, List.map_cons, List.map_nil,
      List.cons_append, Nat.add_zero, seqOK, isContB]
    u8norm
    repeat' split
    all_goals (try simp only [UInt8.reduceToNat, Bool.and_eq_false_iff, decide_eq_false_iff_not] at *)
    all_goals omega
  · rw [leadLen_0 (by omega) (by omega) (by omega) (by omega), if_neg (by u8norm; omega),
      if_neg (by u8norm; omega), if_neg (by u8norm; omega), if_neg (by u8norm; omega)]
    right; simp; omega

theorem leadLen_le (a : UInt8) : leadLen a ≤ 4 := by
  unfold leadLen; repeat' split
  all_goals omega

theorem step_ne_zero (data : Bytes) (i : Nat) (hi : i < data.length) : step data i ≠ 0 := by
  rcases step_cases data i hi with ⟨h1, h2, -⟩ | ⟨h1, -⟩ <;> omega

/-- Every loop iteration advances: `0 < |w|` and `i + |w| ≤ n`. -/
theorem step_advance (data : Bytes) (i : Nat) (hi : i < data.length) :
    0 < (step data i).natAbs ∧ i + (step data i).natAbs ≤ data.length := by
  rcases step_cases data i hi with ⟨h1, h2, h3⟩ | ⟨h1, h2, h3, -⟩
  · rw [wfHead_drop data i hi] at h3; omega
  · omega

/-- First loop of `utf8_lossy_string` (flare/http/proto/utf8.mojo:107-114
@59bda50): index of the first ill-formed sequence, if any. -/
def scan (data : Bytes) (i : Nat) : Option Nat :=
  if _h : i < data.length then
    if step data i < 0 then some i else scan data (i + (step data i).natAbs)
  else none
termination_by data.length - i
decreasing_by have := step_advance data i _h; omega

/-- Second loop of `utf8_lossy_string` (flare/http/proto/utf8.mojo:126-137
@59bda50): replace each maximal ill-formed subpart by U+FFFD (`EF BF BD`),
copy well-formed characters. -/
def fix (data : Bytes) (i : Nat) (out : Bytes) : Bytes :=
  if h : i < data.length then
    if step data i < 0 then fix data (i + (step data i).natAbs) (out ++ [0xEF, 0xBF, 0xBD])
    else fix data (i + (step data i).natAbs) (out ++ (data.drop i).take (step data i).natAbs)
  else out
termination_by data.length - i
decreasing_by all_goals (have := step_advance data i h; omega)

/-- mirrors flare/http/proto/utf8.mojo:93-139 @59bda50 (`String(unsafe_from_utf8=)`
is the identity on the byte buffer). -/
def lossy (data : Bytes) : Bytes :=
  if data.length = 0 then []
  else match scan data 0 with
    | none => data
    | some fb => fix data fb (data.take fb)

theorem scan_none_iff (data : Bytes) (i : Nat) : scan data i = none ↔ WF (data.drop i) := by
  induction h : data.length - i using Nat.strongRecOn generalizing i with
  | ind k ih =>
  rw [scan]
  by_cases hi : i < data.length
  · rw [dif_pos hi]
    rcases step_cases data i hi with ⟨h1, h2, h3⟩ | ⟨h1, -, -, h3⟩
    · rw [if_neg (by omega), ih _ (by have := step_advance data i hi; omega) _ rfl]
      rw [h1, drop_eq_getD_cons data i hi, WF_cons_iff, ← drop_eq_getD_cons data i hi, List.drop_drop]
      rw [Int.natAbs_natCast, Nat.add_comm]
      simp only [h3, true_and]
    · rw [if_pos h1]
      simp only [reduceCtorEq, false_iff]
      intro hw; apply h3
      rw [drop_eq_getD_cons data i hi] at hw ⊢
      exact ((WF_cons_iff _ _).mp hw).1
  · rw [dif_neg hi, List.drop_eq_nil_of_le (by omega)]; simp [WF.nil]

/-- Agreement of the lossy decoder's fast path with the validators. -/
theorem scan_none_iff_valid (data : Bytes) : scan data 0 = none ↔ isValidUtf8 data = true := by
  rw [scan_none_iff, isValidUtf8_iff]; simp

theorem scan_some (data : Bytes) (i fb : Nat) (h : scan data i = some fb) :
    i ≤ fb ∧ fb < data.length ∧ WF ((data.take fb).drop i) := by
  induction hk : data.length - i using Nat.strongRecOn generalizing i with
  | ind k ih =>
  rw [scan] at h
  by_cases hi : i < data.length
  · rw [dif_pos hi] at h
    rcases step_cases data i hi with ⟨h1, h2, h3⟩ | ⟨h1, -, -, -⟩
    · rw [if_neg (by omega)] at h
      have adv := step_advance data i hi
      obtain ⟨r1, r2, r3⟩ := ih _ (by omega) _ h rfl
      refine ⟨by omega, r2, ?_⟩
      have hl : (step data i).natAbs = leadLen (getD data i) := by omega
      rw [hl] at r1 r3
      rw [wfHead_drop data i hi] at h3
      have e : (data.take fb).drop i =
          (data.drop i).take (leadLen (getD data i)) ++ (data.take fb).drop (i + leadLen (getD data i)) := by
        rw [← List.take_append_drop (leadLen (getD data i)) ((data.take fb).drop i), List.drop_drop,
          List.drop_take, List.take_take, Nat.add_comm, Nat.min_eq_left (by omega)]
      rw [e, take_drop_getD _ _ _ h3.2.1]
      exact WF.app h3.2.2 r3
    · rw [if_pos h1] at h
      simp only [Option.some.injEq] at h; subst h
      refine ⟨Nat.le_refl _, hi, ?_⟩
      rw [List.drop_eq_nil_of_le (by rw [List.length_take]; exact Nat.min_le_left _ _)]; exact WF.nil
  · rw [dif_neg hi] at h; cases h

theorem replacement_seqOK : seqOK [0xEF, 0xBF, 0xBD] := by
  simp only [seqOK]; decide

theorem fix_wf (data : Bytes) (i : Nat) (out : Bytes) (h : WF out) : WF (fix data i out) := by
  induction hk : data.length - i using Nat.strongRecOn generalizing i out with
  | ind k ih =>
  rw [fix]
  by_cases hi : i < data.length
  · rw [dif_pos hi]
    have adv := step_advance data i hi
    rcases step_cases data i hi with ⟨h1, h2, h3⟩ | ⟨h1, -, -, -⟩
    · rw [if_neg (by omega)]
      apply ih _ (by omega) _ _ _ rfl
      apply WF_append h
      have hl : (step data i).natAbs = leadLen (getD data i) := by omega
      rw [hl]
      rw [wfHead_drop data i hi] at h3
      rw [take_drop_getD _ _ _ h3.2.1]
      exact WF_of_seqOK h3.2.2
    · rw [if_pos h1]
      exact ih _ (by omega) _ _ (WF_append h (WF_of_seqOK replacement_seqOK)) rfl
  · rw [dif_neg hi]; exact h

/-- **The lossy decoder's output is always well-formed UTF-8.** -/
theorem lossy_wf (data : Bytes) : WF (lossy data) := by
  unfold lossy
  split
  · exact WF.nil
  · split
    · next h => exact (scan_none_iff data 0).mp h
    · next fb h =>
      obtain ⟨-, -, h3⟩ := scan_some data 0 fb h
      exact fix_wf _ _ _ (by simpa using h3)

/-- **Identity on well-formed input.** -/
theorem lossy_of_wf (data : Bytes) (h : WF data) : lossy data = data := by
  unfold lossy
  split
  · next h0 => exact (List.eq_nil_of_length_eq_zero h0).symm
  · rw [(scan_none_iff data 0).mpr (by simpa using h)]

theorem lossy_eq_self_iff (data : Bytes) : lossy data = data ↔ WF data :=
  ⟨fun h => h ▸ lossy_wf data, lossy_of_wf data⟩

/-! ## Unicode §3.9 maximal subparts -/

/-- Second byte allowed after lead `a` (Unicode Table 3-7 column 2). -/
def SecOK (a b : UInt8) : Prop :=
  0x80 ≤ b.toNat ∧ b.toNat ≤ 0xBF ∧ (a.toNat = 0xE0 → 0xA0 ≤ b.toNat) ∧
    (a.toNat = 0xED → b.toNat ≤ 0x9F) ∧ (a.toNat = 0xF0 → 0x90 ≤ b.toNat) ∧
    (a.toNat = 0xF4 → b.toNat ≤ 0x8F)

def ContOK (c : UInt8) : Prop := 0x80 ≤ c.toNat ∧ c.toNat ≤ 0xBF

/-- Closed form of "is an initial subsequence of a well-formed sequence". -/
def PfxP : Bytes → Prop
  | [] => True
  | [a] => a.toNat ≤ 0x7F ∨ (0xC2 ≤ a.toNat ∧ a.toNat ≤ 0xF4)
  | [a, b] => 0xC2 ≤ a.toNat ∧ a.toNat ≤ 0xF4 ∧ SecOK a b
  | [a, b, c] => 0xE0 ≤ a.toNat ∧ a.toNat ≤ 0xF4 ∧ SecOK a b ∧ ContOK c
  | [a, b, c, d] => 0xF0 ≤ a.toNat ∧ a.toNat ≤ 0xF4 ∧ SecOK a b ∧ ContOK c ∧ ContOK d
  | _ :: _ :: _ :: _ :: _ :: _ => False

theorem pfx_iff (p : Bytes) : (∃ t, seqOK (p ++ t)) ↔ PfxP p := by
  constructor
  · rintro ⟨t, h⟩
    rcases p with _ | ⟨a, _ | ⟨b, _ | ⟨c, _ | ⟨d, _ | ⟨e, p⟩⟩⟩⟩⟩ <;>
    rcases t with _ | ⟨w, _ | ⟨x, _ | ⟨y, _ | ⟨z, _ | ⟨v, t⟩⟩⟩⟩⟩ <;>
    simp only [List.nil_append, List.cons_append, seqOK, PfxP, SecOK, ContOK] at h ⊢ <;>
    omega
  · intro h
    rcases p with _ | ⟨a, _ | ⟨b, _ | ⟨c, _ | ⟨d, _ | ⟨e, p⟩⟩⟩⟩⟩
    · exact ⟨[0x41], by simp only [seqOK, List.nil_append]; decide⟩
    · simp only [PfxP] at h
      by_cases h1 : a.toNat ≤ 0x7F
      · exact ⟨[], by simp only [seqOK, List.append_nil]; omega⟩
      by_cases h2 : a.toNat ≤ 0xDF
      · exact ⟨[0x80], by simp only [seqOK, List.cons_append, List.nil_append, UInt8.reduceToNat]; omega⟩
      by_cases h3 : a.toNat = 0xE0
      · exact ⟨[0xA0, 0x80], by simp only [seqOK, List.cons_append, List.nil_append, UInt8.reduceToNat]; omega⟩
      by_cases h4 : a.toNat ≤ 0xEF
      · exact ⟨[0x80, 0x80], by simp only [seqOK, List.cons_append, List.nil_append, UInt8.reduceToNat]; omega⟩
      by_cases h5 : a.toNat = 0xF0
      · exact ⟨[0x90, 0x80, 0x80], by
          simp only [seqOK, List.cons_append, List.nil_append, UInt8.reduceToNat]; omega⟩
      · exact ⟨[0x80, 0x80, 0x80], by
          simp only [seqOK, List.cons_append, List.nil_append, UInt8.reduceToNat]; omega⟩
    · simp only [PfxP, SecOK] at h
      by_cases h2 : a.toNat ≤ 0xDF
      · exact ⟨[], by simp only [seqOK, List.append_nil]; omega⟩
      by_cases h4 : a.toNat ≤ 0xEF
      · exact ⟨[0x80], by simp only [seqOK, List.cons_append, List.nil_append, UInt8.reduceToNat]; omega⟩
      · exact ⟨[0x80, 0x80], by
          simp only [seqOK, List.cons_append, List.nil_append, UInt8.reduceToNat]; omega⟩
    · simp only [PfxP, SecOK, ContOK] at h
      by_cases h4 : a.toNat ≤ 0xEF
      · exact ⟨[], by simp only [seqOK, List.append_nil]; omega⟩
      · exact ⟨[0x80], by simp only [seqOK, List.cons_append, List.nil_append, UInt8.reduceToNat]; omega⟩
    · simp only [PfxP, SecOK, ContOK] at h
      exact ⟨[], by simp only [seqOK, List.append_nil]; omega⟩
    · simp only [PfxP] at h

/-- Unicode 15 §3.9 D93b: a *maximal subpart* of `x` (at an unconvertible
offset) is its longest prefix that is either an initial subsequence of a
well-formed code unit sequence, or of length one. -/
def MaxSub (x : Bytes) (k : Nat) : Prop :=
  1 ≤ k ∧ k ≤ x.length ∧ (k = 1 ∨ ∃ t, seqOK (x.take k ++ t)) ∧
    ∀ k', k < k' → k' ≤ x.length → ¬ ∃ t, seqOK (x.take k' ++ t)

theorem take1 (data : Bytes) (i : Nat) (h : i + 1 ≤ data.length) :
    (data.drop i).take 1 = [getD data i] := by
  rw [take_drop_getD _ _ _ h]; simp [List.range_succ]
theorem take2 (data : Bytes) (i : Nat) (h : i + 2 ≤ data.length) :
    (data.drop i).take 2 = [getD data i, getD data (i + 1)] := by
  rw [take_drop_getD _ _ _ h]; simp [List.range_succ]
theorem take3 (data : Bytes) (i : Nat) (h : i + 3 ≤ data.length) :
    (data.drop i).take 3 = [getD data i, getD data (i + 1), getD data (i + 2)] := by
  rw [take_drop_getD _ _ _ h]; simp [List.range_succ]
theorem take4 (data : Bytes) (i : Nat) (h : i + 4 ≤ data.length) :
    (data.drop i).take 4 = [getD data i, getD data (i + 1), getD data (i + 2), getD data (i + 3)] := by
  rw [take_drop_getD _ _ _ h]; simp [List.range_succ]

theorem step_m1 (data : Bytes) (i : Nat) (h : step data i = -1) (hn : i + 2 ≤ data.length) :
    ¬ PfxP [getD data i, getD data (i + 1)] := by
  unfold step at h
  simp only [PfxP, SecOK, isContB] at h ⊢
  simp only [UInt8.le_iff_toNat_le, UInt8.lt_iff_toNat_lt, ← UInt8.toNat_inj, ge_iff_le, gt_iff_lt,
    Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, UInt8.toNat_ofNat',
    Bool.not_eq_true', decide_eq_false_iff_not, ite_false_else,
    Bool.and_eq_false_iff, Bool.or_eq_false_iff,
    Nat.reducePow, Nat.reduceMod, UInt8.reduceToNat] at h
  repeat' split at h
  all_goals (try simp only [UInt8.reduceToNat, Bool.and_eq_false_iff, decide_eq_false_iff_not] at *)
  all_goals omega

theorem step_m2 (data : Bytes) (i : Nat) (h : step data i = -2) :
    PfxP [getD data i, getD data (i + 1)] ∧
      (i + 3 ≤ data.length → ¬ PfxP [getD data i, getD data (i + 1), getD data (i + 2)]) := by
  unfold step at h
  simp only [PfxP, SecOK, ContOK, isContB] at h ⊢
  simp only [UInt8.le_iff_toNat_le, UInt8.lt_iff_toNat_lt, ← UInt8.toNat_inj, ge_iff_le, gt_iff_lt,
    Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, UInt8.toNat_ofNat',
    Bool.not_eq_true', decide_eq_false_iff_not, ite_false_else,
    Bool.and_eq_false_iff, Bool.or_eq_false_iff,
    Nat.reducePow, Nat.reduceMod, UInt8.reduceToNat] at h
  repeat' split at h
  all_goals (try simp only [UInt8.reduceToNat, Bool.and_eq_false_iff, decide_eq_false_iff_not] at *)
  all_goals omega

theorem step_m3 (data : Bytes) (i : Nat) (h : step data i = -3) :
    PfxP [getD data i, getD data (i + 1), getD data (i + 2)] ∧
      (i + 4 ≤ data.length →
        ¬ PfxP [getD data i, getD data (i + 1), getD data (i + 2), getD data (i + 3)]) := by
  unfold step at h
  simp only [PfxP, SecOK, ContOK, isContB] at h ⊢
  simp only [UInt8.le_iff_toNat_le, UInt8.lt_iff_toNat_lt, ← UInt8.toNat_inj, ge_iff_le, gt_iff_lt,
    Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, UInt8.toNat_ofNat',
    Bool.not_eq_true', decide_eq_false_iff_not, ite_false_else,
    Bool.and_eq_false_iff, Bool.or_eq_false_iff,
    Nat.reducePow, Nat.reduceMod, UInt8.reduceToNat] at h
  repeat' split at h
  all_goals (try simp only [UInt8.reduceToNat, Bool.and_eq_false_iff, decide_eq_false_iff_not] at *)
  all_goals omega

theorem pfx_mono (x : Bytes) (k k' : Nat) (hk : k ≤ k') (h : ∃ t, seqOK (x.take k' ++ t)) :
    ∃ t, seqOK (x.take k ++ t) := by
  obtain ⟨t, ht⟩ := h
  refine ⟨(x.take k').drop k ++ t, ?_⟩
  have e : x.take k = (x.take k').take k := by rw [List.take_take, Nat.min_eq_left hk]
  rw [e, ← List.append_assoc, List.take_append_drop]; exact ht

/-- `_step` returns minus the length of the maximal subpart at an offset
where no well-formed character starts. -/
theorem step_maxSub (data : Bytes) (i : Nat) (hi : i < data.length) (hneg : step data i < 0) :
    ¬ WfHead (data.drop i) ∧ MaxSub (data.drop i) (step data i).natAbs := by
  rcases step_cases data i hi with ⟨h1, h2, -⟩ | ⟨-, h2, h3, h4⟩
  · omega
  refine ⟨h4, by omega, by rw [List.length_drop]; omega, ?_, ?_⟩
  · have : step data i = -1 ∨ step data i = -2 ∨ step data i = -3 := by omega
    rcases this with h | h | h
    · left; omega
    · right; rw [show (step data i).natAbs = 2 by omega, pfx_iff, take2 _ _ (by omega)]
      exact (step_m2 data i h).1
    · right; rw [show (step data i).natAbs = 3 by omega, pfx_iff, take3 _ _ (by omega)]
      exact (step_m3 data i h).1
  · intro k' hk' hl hex
    rw [List.length_drop] at hl
    have hnext := pfx_mono _ _ _ hk' hex
    rw [pfx_iff] at hnext
    have : step data i = -1 ∨ step data i = -2 ∨ step data i = -3 := by omega
    rcases this with h | h | h
    · rw [show (step data i).natAbs.succ = 2 by omega, take2 _ _ (by omega)] at hnext
      exact step_m1 data i h (by omega) hnext
    · rw [show (step data i).natAbs.succ = 3 by omega, take3 _ _ (by omega)] at hnext
      exact (step_m2 data i h).2 (by omega) hnext
    · rw [show (step data i).natAbs.succ = 4 by omega, take4 _ _ (by omega)] at hnext
      exact (step_m3 data i h).2 (by omega) hnext

/-- U+FFFD in UTF-8. -/
def fffd : Bytes := [0xEF, 0xBF, 0xBD]

/-- Unicode 15 §3.9 "U+FFFD Substitution of Maximal Subparts" as a relation:
`Subst x o` holds when `o` is `x` with every well-formed character copied and
every maximal subpart (at an unconvertible offset) replaced by one U+FFFD. -/
inductive Subst : Bytes → Bytes → Prop
  | nil : Subst [] []
  | char {s r o : Bytes} : seqOK s → Subst r o → Subst (s ++ r) (s ++ o)
  | bad {x o : Bytes} {k : Nat} : ¬ WfHead x → MaxSub x k → Subst (x.drop k) o → Subst x (fffd ++ o)

theorem wfHead_of_seqOK {s : Bytes} (r : Bytes) (h : seqOK s) : WfHead (s ++ r) := by
  obtain ⟨a, t, rfl, hl⟩ := seqOK_shape h
  refine ⟨a, t ++ r, rfl, ?_, ?_, ?_⟩
  · rw [hl]; simp
  · rw [hl]; simp
  · rw [hl, List.take_left]; exact h

theorem seqOK_unique {s s' r r' : Bytes} (h : seqOK s) (h' : seqOK s') (e : s ++ r = s' ++ r') :
    s = s' ∧ r = r' := by
  obtain ⟨a, t, rfl, hl⟩ := seqOK_shape h
  obtain ⟨a', t', rfl, hl'⟩ := seqOK_shape h'
  simp only [List.cons_append, List.cons.injEq] at e
  obtain ⟨rfl, e⟩ := e
  have hlen : t.length = t'.length := by simp at hl hl'; omega
  have := List.append_inj e hlen
  exact ⟨by rw [this.1], this.2⟩

theorem maxSub_unique {x : Bytes} {k k' : Nat} (h : MaxSub x k) (h' : MaxSub x k') : k = k' := by
  obtain ⟨a1, a2, a3, a4⟩ := h
  obtain ⟨b1, b2, b3, b4⟩ := h'
  by_cases hlt : k < k'
  · rcases b3 with b3 | b3
    · omega
    · exact absurd b3 (a4 k' hlt b2)
  by_cases hgt : k' < k
  · rcases a3 with a3 | a3
    · omega
    · exact absurd a3 (b4 k hgt a2)
  omega

theorem Subst.inv {x o : Bytes} (h : Subst x o) :
    (x = [] ∧ o = []) ∨ (∃ s r o1, seqOK s ∧ x = s ++ r ∧ o = s ++ o1 ∧ Subst r o1) ∨
      (∃ k o1, ¬ WfHead x ∧ MaxSub x k ∧ o = fffd ++ o1 ∧ Subst (x.drop k) o1) := by
  cases h with
  | nil => exact .inl ⟨rfl, rfl⟩
  | char hs hr => exact .inr (.inl ⟨_, _, _, hs, rfl, rfl, hr⟩)
  | bad hw hm hr => exact .inr (.inr ⟨_, _, hw, hm, rfl, hr⟩)

/-- The specification is functional. -/
theorem Subst.unique {x o o' : Bytes} (h : Subst x o) (h' : Subst x o') : o = o' := by
  induction h generalizing o' with
  | nil =>
    rcases h'.inv with ⟨-, rfl⟩ | ⟨s, r, o1, hs, e, -, -⟩ | ⟨k, o1, -, hm, -, -⟩
    · rfl
    · obtain ⟨a, t, rfl, -⟩ := seqOK_shape hs; simp at e
    · have := hm.2.1; simp at this; have := hm.1; omega
  | @char s r o hs _ ih =>
    rcases h'.inv with ⟨e, -⟩ | ⟨s', r', o1, hs', e, rfl, hr'⟩ | ⟨k, o1, hw, -, -, -⟩
    · obtain ⟨a, t, rfl, -⟩ := seqOK_shape hs; simp at e
    · obtain ⟨rfl, rfl⟩ := seqOK_unique hs hs' e
      rw [ih hr']
    · exact absurd (wfHead_of_seqOK r hs) hw
  | @bad x o k hw hm _ ih =>
    rcases h'.inv with ⟨rfl, -⟩ | ⟨s', r', o1, hs', rfl, -, -⟩ | ⟨k', o1, -, hm', rfl, hr'⟩
    · have := hm.2.1; simp at this; have := hm.1; omega
    · exact absurd (wfHead_of_seqOK _ hs') hw
    · rw [maxSub_unique hm hm'] at ih; rw [ih hr']

theorem Subst.of_wf {x : Bytes} (h : WF x) : Subst x x := by
  induction h with
  | nil => exact .nil
  | app hs _ ih => exact .char hs ih

theorem Subst.wf_append {w r o : Bytes} (hw : WF w) (h : Subst r o) : Subst (w ++ r) (w ++ o) := by
  induction hw with
  | nil => simpa using h
  | app hs _ ih => rw [List.append_assoc, List.append_assoc]; exact .char hs ih

theorem fix_subst (data : Bytes) (i : Nat) (out : Bytes) :
    ∃ o, fix data i out = out ++ o ∧ Subst (data.drop i) o := by
  induction hk : data.length - i using Nat.strongRecOn generalizing i out with
  | ind k ih =>
  rw [fix]
  by_cases hi : i < data.length
  · rw [dif_pos hi]
    have adv := step_advance data i hi
    by_cases hneg : step data i < 0
    · rw [if_pos hneg]
      obtain ⟨o, h1, h2⟩ := ih _ (by omega) (i + (step data i).natAbs) (out ++ fffd) rfl
      obtain ⟨hw, hm⟩ := step_maxSub data i hi hneg
      refine ⟨fffd ++ o, by simpa [fffd, List.append_assoc] using h1, .bad hw hm ?_⟩
      rwa [List.drop_drop]
    · rw [if_neg hneg]
      rcases step_cases data i hi with ⟨h1, -, h3⟩ | ⟨h1, -⟩
      · obtain ⟨o, e1, e2⟩ := ih _ (by omega) (i + (step data i).natAbs)
          (out ++ (data.drop i).take (step data i).natAbs) rfl
        refine ⟨(data.drop i).take (step data i).natAbs ++ o, by rw [e1, List.append_assoc], ?_⟩
        have hl : (step data i).natAbs = leadLen (getD data i) := by omega
        rw [wfHead_drop data i hi] at h3
        have hs : seqOK ((data.drop i).take (step data i).natAbs) := by
          rw [hl, take_drop_getD _ _ _ h3.2.1]; exact h3.2.2
        have e : data.drop i = (data.drop i).take (step data i).natAbs ++
            data.drop (i + (step data i).natAbs) := by
          rw [← List.drop_drop, List.take_append_drop]
        have := Subst.char hs e2; rwa [← e] at this
      · omega
  · rw [dif_neg hi, List.drop_eq_nil_of_le (by omega)]; exact ⟨[], by simp, .nil⟩

/-- **Unicode §3.9 maximal-subpart substitution.** `utf8_lossy_string`
copies every well-formed character and replaces each maximal ill-formed
subpart by exactly one U+FFFD. -/
theorem lossy_subst (data : Bytes) : Subst data (lossy data) := by
  unfold lossy
  split
  · next h0 => rw [List.eq_nil_of_length_eq_zero h0]; exact .nil
  · split
    · next h => exact Subst.of_wf (by simpa using (scan_none_iff data 0).mp h)
    · next fb h =>
      obtain ⟨-, -, h3⟩ := scan_some data 0 fb h
      obtain ⟨o, e1, e2⟩ := fix_subst data fb (data.take fb)
      rw [e1, ← List.take_append_drop fb data, List.take_append_drop]
      conv => lhs; rw [← List.take_append_drop fb data]
      exact Subst.wf_append (by simpa using h3) e2

theorem lossy_eq_iff_subst (data o : Bytes) : lossy data = o ↔ Subst data o :=
  ⟨fun h => h ▸ lossy_subst data, fun h => Subst.unique (lossy_subst data) h⟩

end Flare.L1.Utf8
