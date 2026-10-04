import Flare.Core

/-!
# HTTP/1.1 header text: byte classes, transfer-coding lists, Content-Length

Pure helpers shared by the reactor's raw-byte framing scan and the full
request parser:

* `classify` mirrors `classify_transfer_coding`
  (`flare/http/proto/chunked.mojo:63-93`): split on `,`, strip SP/HTAB,
  ASCII-lowercase, drop empty tokens.
* `parseCL` mirrors `parse_content_length_bytes`
  (`flare/http/_scan.mojo:259-294`).

The Mojo `classify_transfer_coding` works on a `String`. The reactor builds
that string with `chr(Int(byte))`, so a byte `≥ 0x80` becomes a 2-byte
code point; no such code point is `,`, SP, HTAB or lowercases to ASCII, so
classifying the raw bytes gives the same verdict. That is the one
modelling step not checked in Lean.
-/
namespace Flare.L3.H1.Text
open Flare

/-! ## Byte classes -/

/-- mirrors flare/http/_scan.mojo:273,289 @59bda50 -/
def isWS (b : UInt8) : Bool := b == 32 || b == 9
/-- mirrors flare/http/_scan.mojo:279 @59bda50 -/
def isDigit (b : UInt8) : Bool := 48 ≤ b && b ≤ 57

/-- mirrors flare/http/proto/chunked.mojo:33-36 @59bda50 -/
def lower (b : UInt8) : UInt8 := if 65 ≤ b ∧ b ≤ 90 then b + 32 else b

/-- `tchar` (RFC 9110 §5.6.2).
mirrors flare/http/_server/parse_util.mojo:125-145 @59bda50 -/
def isTchar (c : UInt8) : Bool :=
  (65 ≤ c && c ≤ 90) || (97 ≤ c && c ≤ 122) || (48 ≤ c && c ≤ 57) ||
  c == 33 || c == 35 || c == 36 || c == 37 || c == 38 ||
  c == 39 || c == 42 || c == 43 || c == 45 || c == 46 ||
  c == 94 || c == 95 || c == 96 || c == 124 || c == 126

/-- mirrors flare/http/_server/parse_util.mojo:148-162 @59bda50 -/
def isFieldVchar (c : UInt8) : Bool := c == 9 || c == 32 || (33 ≤ c && c ≤ 126) || 128 ≤ c

theorem lower_eq_of (h s : UInt8)
    (hs : s.toNat < 65 ∨ 122 < s.toNat ∨ (90 < s.toNat ∧ s.toNat < 97)) (e : lower h = s) :
    h = s := by
  unfold lower at e; split at e
  · rename_i hh
    have h1 := congrArg UInt8.toNat e
    rw [UInt8.toNat_add] at h1
    have : (65:UInt8).toNat ≤ h.toNat := UInt8.le_iff_toNat_le.mp hh.1
    have : h.toNat ≤ (90:UInt8).toNat := UInt8.le_iff_toNat_le.mp hh.2
    simp at *; omega
  · exact e

theorem isWS_of_ne {c : UInt8} (h1 : c ≠ 32) (h2 : c ≠ 9) : isWS c = false := by
  simp [isWS, h1, h2]

theorem isTchar_ws {c : UInt8} (h : isTchar c = true) : isWS c = false := by
  by_cases h1 : c = 32
  · subst h1; exact absurd h (by decide)
  by_cases h2 : c = 9
  · subst h2; exact absurd h (by decide)
  exact isWS_of_ne h1 h2

theorem isDigit_ws {c : UInt8} (h : isDigit c = true) : isWS c = false := by
  by_cases h1 : c = 32
  · subst h1; exact absurd h (by decide)
  by_cases h2 : c = 9
  · subst h2; exact absurd h (by decide)
  exact isWS_of_ne h1 h2

theorem isTchar_colon : isTchar 58 = false := by decide

/-! ## Literals -/

/-- `"transfer-encoding"` -/
def TEn : Bytes := [116,114,97,110,115,102,101,114,45,101,110,99,111,100,105,110,103]
/-- `"content-length"` -/
def CLn : Bytes := [99,111,110,116,101,110,116,45,108,101,110,103,116,104]
/-- `"content-length:"` (the needle of `_match_content_length_prefix`) -/
def CLC : Bytes := CLn ++ [58]
/-- `"chunked"` -/
def CHK : Bytes := [99,104,117,110,107,101,100]

/-- Case-insensitive prefix test; `needle` is a lowercase literal.
mirrors flare/http/proto/chunked.mojo:39-48 and flare/http/_scan.mojo:144-170 @59bda50 -/
def ieqPrefix : Bytes → Bytes → Bool
  | [], _ => true
  | _ :: _, [] => false
  | n :: ns, h :: hs => lower h == n && ieqPrefix ns hs

/-- `ascii_eq_ignore_case`. mirrors flare/http/proto/ascii.mojo:85-118 @59bda50 -/
def ieq (k lit : Bytes) : Bool := k.length == lit.length && ieqPrefix lit k

theorem ieqPrefix_append_left : ∀ (n h t : Bytes), ieqPrefix n h = true → ieqPrefix n (h ++ t) = true
  | [], _, _, _ => rfl
  | _ :: _, [], _, e => by simp [ieqPrefix] at e
  | n :: ns, x :: xs, t, e => by
    simp only [ieqPrefix, Bool.and_eq_true, List.cons_append] at e ⊢
    exact ⟨e.1, ieqPrefix_append_left ns xs t e.2⟩

theorem ieqPrefix_take : ∀ (n h : Bytes), ieqPrefix n h = true → ieqPrefix n (h.take n.length) = true
  | [], _, _ => rfl
  | _ :: _, [], e => by simp [ieqPrefix] at e
  | n :: ns, x :: xs, e => by
    simp only [ieqPrefix, Bool.and_eq_true] at e
    simp only [List.length_cons, List.take_succ_cons, ieqPrefix, Bool.and_eq_true]
    exact ⟨e.1, ieqPrefix_take ns xs e.2⟩

theorem ieqPrefix_length : ∀ (n h : Bytes), ieqPrefix n h = true → n.length ≤ h.length
  | [], _, _ => by simp
  | _ :: _, [], e => by simp [ieqPrefix] at e
  | n :: ns, x :: xs, e => by
    simp only [ieqPrefix, Bool.and_eq_true] at e
    have := ieqPrefix_length ns xs e.2; simp; omega

/-- A needle byte that is not `s` can never be matched by `s`, for the
fixed points `s` of `lower`. -/
theorem ieqPrefix_append_stop : ∀ (n h t : Bytes) (s : UInt8), s ∉ n → lower s = s →
    ieqPrefix n (h ++ s :: t) = ieqPrefix n h
  | [], _, _, _, _, _ => rfl
  | m :: ms, [], t, s, hn, hs => by
    simp only [ieqPrefix, List.nil_append, hs]
    have : s ≠ m := fun e => hn (e ▸ List.mem_cons_self ..)
    simp [this]
  | m :: ms, x :: xs, t, s, hn, hs => by
    simp only [List.cons_append, ieqPrefix]
    rw [ieqPrefix_append_stop ms xs t s (fun h => hn (List.mem_cons_of_mem _ h)) hs]

/-- The first `c` in a byte list (the colon search).
mirrors flare/http/_server/parse.mojo:234-238 @59bda50 -/
def findB (c : UInt8) : Bytes → Option Nat
  | [] => none
  | x :: xs => if x = c then some 0 else (findB c xs).map (· + 1)

theorem findB_spec : ∀ {c : UInt8} {l : Bytes} {k : Nat}, findB c l = some k →
    k < l.length ∧ l.getD k = c ∧ c ∉ l.take k
  | _, [], _, h => by simp [findB] at h
  | c, x :: xs, k, h => by
    simp only [findB] at h
    split at h
    · simp at h; subst h; simp_all [Bytes.getD]
    · rename_i hx
      cases h' : findB c xs with
      | none => simp [h'] at h
      | some j =>
        simp [h'] at h; subst h
        obtain ⟨h1, h2, h3⟩ := findB_spec h'
        refine ⟨by simp; omega, by simpa [Bytes.getD] using h2, ?_⟩
        simp only [List.take_succ_cons, List.mem_cons, not_or]
        exact ⟨fun e => hx e.symm, h3⟩

theorem findB_of (c : UInt8) : ∀ (l : Bytes) (k : Nat), k < l.length → l.getD k = c → c ∉ l.take k →
    findB c l = some k
  | [], _, h, _, _ => by simp at h
  | x :: xs, 0, _, h2, _ => by simp [findB, Bytes.getD] at h2 ⊢; exact h2
  | x :: xs, k + 1, h1, h2, h3 => by
    simp only [List.take_succ_cons, List.mem_cons, not_or] at h3
    simp only [findB, if_neg (fun e : x = c => h3.1 e.symm)]
    rw [findB_of c xs k (by simp at h1; omega) (by simpa [Bytes.getD] using h2) h3.2]; rfl

/-! ## Stripping and transfer-coding tokens -/

def lstrip (l : Bytes) : Bytes := l.dropWhile isWS

/-- `_ascii_strip_slice` / `String.strip(" \t")`: SP/HTAB off both ends.
mirrors flare/http/_server/parse_util.mojo:65-90 @59bda50 -/
def strip (l : Bytes) : Bytes := (lstrip (lstrip l).reverse).reverse

/-- `String.split(",")`.
mirrors flare/http/proto/chunked.mojo:80 @59bda50 -/
def splitComma : Bytes → List Bytes
  | [] => [[]]
  | c :: cs =>
    if c = 44 then [] :: splitComma cs else
    match splitComma cs with
    | [] => [[c]]
    | h :: t => (c :: h) :: t

/-- mirrors flare/http/proto/chunked.mojo:81 @59bda50 -/
def normTok (t : Bytes) : Bytes := (strip t).map lower

/-- The nonempty, stripped, lowercased comma-separated tokens.
mirrors flare/http/proto/chunked.mojo:79-83 @59bda50 -/
def tokens (v : Bytes) : List Bytes := ((splitComma v).map normTok).filter (fun t => !t.isEmpty)

/-- mirrors flare/http/proto/chunked.mojo:79-93 @59bda50 -/
def classifyT (ts : List Bytes) : Int :=
  match ts.getLast? with
  | none => -1
  | some last =>
    if last ≠ CHK then -1 else
    if CHK ∈ ts.dropLast then -1 else
    if ts.length > 1 then -2 else 1

/-- `classify_transfer_coding`. mirrors flare/http/proto/chunked.mojo:63-93 @59bda50 -/
def classify (v : Bytes) : Int := classifyT (tokens v)

theorem splitComma_ne_nil : ∀ l : Bytes, splitComma l ≠ []
  | [] => by simp [splitComma]
  | c :: cs => by
    simp only [splitComma]
    split
    · simp
    · split <;> simp

theorem splitComma_append_comma : ∀ (a b : Bytes), splitComma (a ++ 44 :: b) = splitComma a ++ splitComma b
  | [], b => by simp [splitComma]
  | c :: cs, b => by
    simp only [List.cons_append, splitComma]
    split
    · rw [splitComma_append_comma cs b]; rfl
    · rw [splitComma_append_comma cs b]
      cases h : splitComma cs with
      | nil => exact absurd h (splitComma_ne_nil cs)
      | cons x xs => rfl

theorem tokens_nil : tokens [] = [] := by decide

theorem tokens_append_comma (a b : Bytes) : tokens (a ++ 44 :: b) = tokens a ++ tokens b := by
  simp [tokens, splitComma_append_comma]

theorem lstrip_cons_ws {c : UInt8} (hc : isWS c = true) (l : Bytes) : lstrip (c :: l) = lstrip l := by
  simp [lstrip, List.dropWhile_cons, hc]

theorem strip_cons_ws {c : UInt8} (hc : isWS c = true) (l : Bytes) : strip (c :: l) = strip l := by
  simp [strip, lstrip_cons_ws hc]

theorem strip_snoc_ws {c : UInt8} (hc : isWS c = true) (l : Bytes) : strip (l ++ [c]) = strip l := by
  unfold strip
  have : lstrip (l ++ [c]) = if (lstrip l).isEmpty then [] else lstrip l ++ [c] := by
    simp only [lstrip, List.dropWhile_append]
    by_cases hA : (List.dropWhile isWS l).isEmpty = true <;> simp [hA, List.dropWhile_cons, hc]
  rw [this]
  split
  · rename_i h
    have h' : lstrip l = [] := by simpa using h
    rw [h']
  · simp [lstrip_cons_ws hc]

theorem isWS_ne_comma {c : UInt8} (hc : isWS c = true) : c ≠ 44 := by
  intro h; subst h; simp [isWS] at hc

theorem tokens_cons_ws {c : UInt8} (hc : isWS c = true) (l : Bytes) : tokens (c :: l) = tokens l := by
  unfold tokens
  simp only [splitComma, if_neg (isWS_ne_comma hc)]
  cases h : splitComma l with
  | nil => exact absurd h (splitComma_ne_nil l)
  | cons x xs => simp [normTok, strip_cons_ws hc]

def modLast (f : Bytes → Bytes) : List Bytes → List Bytes
  | [] => []
  | [x] => [f x]
  | x :: y :: ys => x :: modLast f (y :: ys)

theorem splitComma_snoc {c : UInt8} (hc : c ≠ 44) :
    ∀ l : Bytes, splitComma (l ++ [c]) = modLast (· ++ [c]) (splitComma l)
  | [] => by simp [splitComma, hc, modLast]
  | d :: ds => by
    simp only [List.cons_append, splitComma]
    have ih := splitComma_snoc hc ds
    split
    · rw [ih]
      cases h : splitComma ds with
      | nil => exact absurd h (splitComma_ne_nil ds)
      | cons x xs => rfl
    · rw [ih]
      cases h : splitComma ds with
      | nil => exact absurd h (splitComma_ne_nil ds)
      | cons x xs =>
        cases xs with
        | nil => simp [modLast]
        | cons y ys => simp [modLast]

theorem map_modLast {f : Bytes → Bytes} {g : Bytes → Bytes} (hfg : ∀ x, g (f x) = g x) :
    ∀ L : List Bytes, (modLast f L).map g = L.map g
  | [] => rfl
  | [x] => by simp [modLast, hfg]
  | x :: y :: ys => by simp only [modLast, List.map_cons]; rw [map_modLast hfg (y :: ys)]; rfl

theorem tokens_snoc_ws {c : UInt8} (hc : isWS c = true) (l : Bytes) : tokens (l ++ [c]) = tokens l := by
  unfold tokens
  rw [splitComma_snoc (isWS_ne_comma hc), map_modLast (g := normTok)]
  intro x; simp [normTok, strip_snoc_ws hc]

theorem tokens_ws_prefix : ∀ (p l : Bytes), (∀ x ∈ p, isWS x = true) → tokens (p ++ l) = tokens l
  | [], _, _ => rfl
  | x :: xs, l, h => by
    rw [List.cons_append, tokens_cons_ws (h x (List.mem_cons_self ..))]
    exact tokens_ws_prefix xs l (fun y hy => h y (List.mem_cons_of_mem _ hy))

theorem tokens_ws_suffix : ∀ (s l : Bytes), (∀ x ∈ s, isWS x = true) → tokens (l ++ s) = tokens l
  | [], l, _ => by simp
  | x :: xs, l, h => by
    rw [show l ++ x :: xs = (l ++ [x]) ++ xs by simp,
      tokens_ws_suffix xs (l ++ [x]) (fun y hy => h y (List.mem_cons_of_mem _ hy)),
      tokens_snoc_ws (h x (List.mem_cons_self ..))]

theorem mem_takeWhile {p : UInt8 → Bool} : ∀ {l : Bytes} {x : UInt8}, x ∈ l.takeWhile p → p x = true
  | [], _, h => by simp at h
  | a :: as, x, h => by
    simp only [List.takeWhile_cons] at h
    split at h
    · rename_i ha
      rcases List.mem_cons.mp h with h | h
      · subst h; exact ha
      · exact mem_takeWhile h
    · simp at h

/-- `l = p ++ strip l ++ s` with `p`, `s` all SP/HTAB. -/
theorem strip_decomp (l : Bytes) : ∃ p s, l = p ++ strip l ++ s ∧
    (∀ x ∈ p, isWS x = true) ∧ (∀ x ∈ s, isWS x = true) := by
  refine ⟨l.takeWhile isWS, ((lstrip l).reverse.takeWhile isWS).reverse, ?_, fun x hx => mem_takeWhile hx,
    fun x hx => mem_takeWhile (List.mem_reverse.mp hx)⟩
  have h1 : l = l.takeWhile isWS ++ lstrip l := (List.takeWhile_append_dropWhile).symm
  have h2 : lstrip l = strip l ++ ((lstrip l).reverse.takeWhile isWS).reverse := by
    unfold strip
    have e := (List.takeWhile_append_dropWhile (p := isWS) (l := (lstrip l).reverse))
    have e2 := congrArg List.reverse e
    rw [List.reverse_append, List.reverse_reverse] at e2
    unfold lstrip at e2 ⊢
    exact e2.symm
  rw [List.append_assoc, ← h2]; exact h1

theorem tokens_strip (l : Bytes) : tokens (strip l) = tokens l := by
  obtain ⟨p, s, hl, hp, hs⟩ := strip_decomp l
  conv => rhs; rw [hl]
  rw [List.append_assoc, tokens_ws_prefix p _ hp, tokens_ws_suffix s _ hs]

theorem classify_strip (l : Bytes) : classify (strip l) = classify l := by
  simp [classify, tokens_strip]

/-- A string with no SP/HTAB at either end is its own strip. -/
theorem strip_of_all {l : Bytes} (h : ∀ x ∈ l, isWS x = false) : strip l = l := by
  have e1 : ∀ m : Bytes, (∀ x ∈ m, isWS x = false) → lstrip m = m := by
    intro m hm
    cases m with
    | nil => rfl
    | cons a as => simp [lstrip, List.dropWhile_cons, hm a (List.mem_cons_self ..)]
  unfold strip
  rw [e1 l h, e1 l.reverse (fun x hx => h x (List.mem_reverse.mp hx)), List.reverse_reverse]

/-! ## Content-Length (RFC 9110 §8.6)
The digit accumulator. mirrors flare/http/_scan.mojo:278-284 @59bda50 -/
def decVal (ds : Bytes) : Nat := ds.foldl (fun acc d => acc * 10 + (d.toNat - 48)) 0

/-- The tail test after the digits and trailing OWS.
mirrors flare/http/_scan.mojo:286-294 @59bda50 -/
def finCL (v : Int) : Bytes → Int
  | [] => v
  | c :: _ => if c = 13 ∨ c = 10 then v else -1

/-- `parse_content_length_bytes` over `p[start:end]`, `-1` for invalid.
The Mojo loop returns `-1` at the 19th digit; this returns `-1` when the
digit run is longer than 18, which is the same verdict.
mirrors flare/http/_scan.mojo:259-294 @59bda50 -/
def parseCL (l : Bytes) : Int :=
  let l1 := l.dropWhile isWS
  let ds := l1.takeWhile isDigit
  if ds.length = 0 ∨ ds.length > 18 then -1 else
  finCL (decVal ds) ((l1.dropWhile isDigit).dropWhile isWS)

/-- What may follow a field value: nothing, or SP/HTAB then CR or LF. -/
def Term (t : Bytes) : Prop :=
  t.dropWhile isWS = [] ∨ ∃ c r, t.dropWhile isWS = c :: r ∧ (c = 13 ∨ c = 10)

theorem Term.ws_digit {t : Bytes} (h : Term t) : (t.dropWhile isWS).takeWhile isDigit = [] := by
  rcases h with h | ⟨c, r, h, hc⟩
  · simp [h]
  · rw [h]; simp only [List.takeWhile_cons]
    have : isDigit c = false := by rcases hc with rfl | rfl <;> decide
    simp [this]

theorem Term.fin {t : Bytes} (h : Term t) (v : Int) : finCL v (t.dropWhile isWS) = v := by
  rcases h with h | ⟨c, r, h, hc⟩
  · simp [h, finCL]
  · simp [h, finCL, hc]

theorem Term.not_digit {t : Bytes} (h : Term t) : t.takeWhile isDigit = [] := by
  cases t with
  | nil => rfl
  | cons a as =>
    simp only [List.takeWhile_cons]
    split
    · rename_i ha
      exfalso
      have hw := isDigit_ws ha
      have := h.ws_digit
      simp [List.dropWhile_cons, hw, List.takeWhile_cons, ha] at this
    · rfl

theorem takeWhile_append_of_nil {p : UInt8 → Bool} {t : Bytes} (ht : t.takeWhile p = []) :
    ∀ m : Bytes, (m ++ t).takeWhile p = m.takeWhile p
  | [] => by simpa using ht
  | a :: as => by
    simp only [List.cons_append, List.takeWhile_cons]
    split
    · rw [takeWhile_append_of_nil ht as]
    · rfl

theorem dropWhile_of_takeWhile_nil {p : UInt8 → Bool} {t : Bytes} (ht : t.takeWhile p = []) :
    t.dropWhile p = t := by
  cases t with
  | nil => rfl
  | cons a as =>
    simp only [List.takeWhile_cons] at ht
    simp only [List.dropWhile_cons]
    split at ht
    · simp at ht
    · rename_i ha; simp [ha]

theorem dropWhile_append_of_nil {p : UInt8 → Bool} {t : Bytes} (ht : t.takeWhile p = []) :
    ∀ m : Bytes, (m ++ t).dropWhile p = m.dropWhile p ++ t
  | [] => by simpa using dropWhile_of_takeWhile_nil ht
  | a :: as => by
    simp only [List.cons_append, List.dropWhile_cons]
    split
    · exact dropWhile_append_of_nil ht as
    · rfl

/-- Content after the value never changes the verdict. -/
theorem parseCL_append_term (m t : Bytes) (ht : Term t) : parseCL (m ++ t) = parseCL m := by
  unfold parseCL
  simp only [List.dropWhile_append]
  split
  · rename_i hm
    have hm' : m.dropWhile isWS = [] := by simpa using hm
    rw [hm', ht.ws_digit]; simp
  · rw [takeWhile_append_of_nil ht.not_digit, dropWhile_append_of_nil ht.not_digit]
    generalize List.takeWhile isDigit (List.dropWhile isWS m) = ds
    generalize List.dropWhile isDigit (List.dropWhile isWS m) = d
    rw [List.dropWhile_append]
    by_cases hE : (List.dropWhile isWS d).isEmpty = true
    · have hd' : d.dropWhile isWS = [] := by simpa using hE
      rw [if_pos hE, ht.fin, hd']; rfl
    · rw [if_neg hE]
      cases h : d.dropWhile isWS with
      | nil => simp [h] at hE
      | cons e es => rfl

theorem term_cr (r : Bytes) : Term (13 :: r) := Or.inr ⟨13, r, by simp [List.dropWhile_cons, isWS], Or.inl rfl⟩

theorem term_ws {s : Bytes} (h : ∀ x ∈ s, isWS x = true) : Term s := by
  left
  induction s with
  | nil => rfl
  | cons a as ih =>
    simp only [List.dropWhile_cons, h a (List.mem_cons_self ..), if_true]
    exact ih (fun x hx => h x (List.mem_cons_of_mem _ hx))

theorem dropWhile_ws_prefix : ∀ (p x : Bytes), (∀ y ∈ p, isWS y = true) →
    (p ++ x).dropWhile isWS = x.dropWhile isWS
  | [], _, _ => rfl
  | a :: as, x, h => by
    simp only [List.cons_append, List.dropWhile_cons, h a (List.mem_cons_self ..), if_true]
    exact dropWhile_ws_prefix as x (fun y hy => h y (List.mem_cons_of_mem _ hy))

theorem parseCL_strip (l : Bytes) : parseCL (strip l) = parseCL l := by
  obtain ⟨p, s, hl, hp, hs⟩ := strip_decomp l
  have e1 : parseCL l = parseCL (strip l ++ s) := by
    conv => lhs; rw [hl]
    unfold parseCL
    rw [List.append_assoc, dropWhile_ws_prefix p _ hp]
  rw [e1, parseCL_append_term _ _ (term_ws hs)]

end Flare.L3.H1.Text
