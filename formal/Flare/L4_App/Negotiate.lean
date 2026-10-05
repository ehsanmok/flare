import Flare.Core.Bytes

/-!
# Content-coding negotiation (`Accept-Encoding`, RFC 9110 §12.5.3)

Models `_parse_q` and `negotiate_encoding` from `flare/http/middleware.mojo`.

* Byte layer: the header is split on `,`, each entry is stripped, the name
  (before the first `;`) is stripped and ASCII-lowercased, and the weight is
  read from the first `q=`/`Q=` in the parameters by `parseQ`.
* Decision layer: `decide'` / `negotiate` are the shipped decision (fixed,
  APP-20): per-coding maxima and the `*` weight are collected over all
  entries and the pick is made after the loop. `implFold` / `decideOld` /
  `negotiateOld` are the pre-fix loop over `(token, q)` entries with state
  `(best_q, best_enc)` that counted `*` only while `best_q == 0`.
* Spec: `specPick`, written from RFC 9110 §12.5.3 independently of the
  code. The effective weight of a coding is the largest weight of an entry
  naming it, else the weight of `*` (which "matches any available content
  coding not explicitly listed"), else none. The pick is the available
  coding (br only when brotli is linkable) with the highest non-zero
  weight, ties broken br > gzip > identity; when no coding has a non-zero
  weight the response passes through without a content coding.
  RFC 9110 leaves duplicate entries undefined; the spec takes the maximum.
-/
namespace Flare.L4.Negotiate

open Flare

/-! ## Byte layer -/

/-- Mojo `String.strip()` whitespace set (ASCII only):
`" \t\n\v\f\r\x1c\x1d\x1e"`, checked against Mojo 1.1.0 (stdlib
`StringSpan.lstrip`/`rstrip` use `Codepoint.is_posix_space`). -/
def isStripWs (b : UInt8) : Bool :=
  b == 32 || b == 9 || b == 10 || b == 11 || b == 12 || b == 13 ||
  b == 28 || b == 29 || b == 30

/-- Mojo `String.strip()` on bytes. -/
def strip (s : Bytes) : Bytes :=
  ((s.dropWhile isStripWs).reverse.dropWhile isStripWs).reverse

/-- Split on `,` (`44`), always emitting a trailing segment. The Mojo loop
is `mojoLoop` below; `parseHeaderMojo_eq` proves both give the same parsed
entries. -/
def splitComma : Bytes → List Bytes
  | [] => [[]]
  | b :: bs =>
    match splitComma bs with
    | [] => [[b]]  -- unreachable
    | seg :: segs => if b == 44 then [] :: seg :: segs else (b :: seg) :: segs

/-- Byte-wise ASCII lowercase. Mojo appends `chr(Int(c))`, which re-encodes
bytes `≥ 128` as two non-ASCII bytes; that never changes the outcome of a
comparison against the ASCII tokens below, so the byte-preserving map is an
equivalent model for classification. -/
def lowerByte (c : UInt8) : UInt8 := if 65 ≤ c ∧ c ≤ 90 then c + 32 else c
def upperByte (c : UInt8) : UInt8 := if 97 ≤ c ∧ c ≤ 122 then c - 32 else c
def lowerAscii (s : Bytes) : Bytes := s.map lowerByte

/-- Classified coding name. -/
inductive Tok | star | br | gzip | identity | other
  deriving DecidableEq, Repr

def tokOfLower (s : Bytes) : Tok :=
  if s = [42] then .star
  else if s = [98, 114] then .br
  else if s = [103, 122, 105, 112] then .gzip
  else if s = [105, 100, 101, 110, 116, 105, 116, 121] then .identity
  else .other

def classify (name : Bytes) : Tok := tokOfLower (lowerAscii name)

/-- Fractional digits of a qvalue: at most three are consumed, then the
value is scaled to thousandths. -/
def frac : Bytes → Nat → Nat → Nat
  | d :: ds, p, q =>
    if p < 3 ∧ 48 ≤ d ∧ d ≤ 57 then frac ds (p + 1) (q * 10 + (d.toNat - 48))
    else q * 10 ^ (3 - p)
  | [], p, q => q * 10 ^ (3 - p)

/-- mirrors flare/http/middleware.mojo:131-166 @59bda50 -/
def parseQ (v : Bytes) : Nat :=
  match v.dropWhile (fun b => b == 32 || b == 9) with
  | [] => 1000
  | c :: r =>
    if c = 49 then 1000
    else if c ≠ 48 then 1000
    else match r with
      | 46 :: ds => frac ds 0 0
      | _ => 0

/-- First `q=` / `Q=` in the parameter text; returns what follows `=`.
mirrors flare/http/middleware.mojo:220-233 @59bda50 -/
def findQ : Bytes → Option Bytes
  | c :: d :: r => if (c = 113 ∨ c = 81) ∧ d = 61 then some r else findQ (d :: r)
  | _ => none

/-- One stripped, non-empty entry → `(token, q)`.
mirrors flare/http/middleware.mojo:199-233 @59bda50 -/
def parseEntry (entry : Bytes) : Tok × Nat :=
  let name := strip (entry.takeWhile (· ≠ 59))
  let rest := entry.dropWhile (· ≠ 59)
  let q := match rest with
    | [] => 1000
    | _ :: params => match findQ params with
      | some v => parseQ v
      | none => 1000
  (classify name, q)

/-- mirrors flare/http/middleware.mojo:193-202 @59bda50 -/
def parseHeader (h : Bytes) : List (Tok × Nat) :=
  ((splitComma h).map strip).filter (· ≠ []) |>.map parseEntry

/-! ### The Mojo entry loop, index by index -/

/-- "not a comma". -/
def nc (x : UInt8) : Bool := x != 44

/-- `for i in range(pos, n): if src[i] == 44: end = i; break` (with
`end = n` when no comma follows).
mirrors flare/http/middleware.mojo:194-198 @59bda50 -/
def scanComma (s : Bytes) (i : Nat) : Nat :=
  if h : i < s.length then
    if s[i] = 44 then i else scanComma s (i + 1)
  else s.length
termination_by s.length - i

theorem scanComma_eq (s : Bytes) (n : Nat) : ∀ i, i ≤ s.length → s.length - i ≤ n →
    scanComma s i = i + ((s.drop i).takeWhile nc).length := by
  induction n with
  | zero =>
    intro i hi hn
    have : i = s.length := by omega
    subst this; rw [scanComma]; simp
  | succ k ih =>
    intro i hi hn
    by_cases hlt : i < s.length
    · rw [scanComma, dif_pos hlt, List.drop_eq_getElem_cons hlt, List.takeWhile_cons]
      by_cases hc : s[i] = 44
      · simp [hc, nc]
      · have hnc : nc s[i] = true := by simp [nc, hc]
        rw [if_neg hc, if_pos hnc, List.length_cons, ih (i + 1) (by omega) (by omega)]; omega
    · have : i = s.length := by omega
      subst this; rw [scanComma]; simp

theorem scanComma_ge (s : Bytes) (i : Nat) (hi : i ≤ s.length) : i ≤ scanComma s i := by
  rw [scanComma_eq s _ i hi (Nat.le_refl _)]; omega

/-- The `while pos < n` loop: the entry is `accept[pos:end]`, then
`pos = end + 1`. Returns the raw entries in order (stripping and the
empty-entry `continue` are applied by `parseHeaderMojo`).
mirrors flare/http/middleware.mojo:193-202 @59bda50 -/
def mojoLoop (s : Bytes) (pos : Nat) : List Bytes :=
  if h : pos < s.length then
    (s.drop pos).take (scanComma s pos - pos) :: mojoLoop s (scanComma s pos + 1)
  else []
termination_by s.length - pos
decreasing_by have := scanComma_ge s pos (by omega); omega

/-- `negotiate_encoding`'s entry sequence: strip each `accept[pos:end]`,
skip empty ones, parse the rest. -/
def parseHeaderMojo (h : Bytes) : List (Tok × Nat) :=
  ((mojoLoop h 0).map strip).filter (· ≠ []) |>.map parseEntry

theorem dropWhile_eq_drop (p : UInt8 → Bool) (l : Bytes) :
    l.dropWhile p = l.drop (l.takeWhile p).length := by
  induction l with
  | nil => rfl
  | cons a l ih => by_cases h : p a <;> simp [h, ih]

theorem take_length_takeWhile (p : UInt8 → Bool) (l : Bytes) :
    l.take (l.takeWhile p).length = l.takeWhile p := by
  induction l with
  | nil => rfl
  | cons a l ih => by_cases h : p a <;> simp [h, ih]

/-- The loop on a suffix, as a list recursion. -/
def mojoList (t : Bytes) : List Bytes :=
  match t with
  | [] => []
  | b :: bs =>
    (b :: bs).takeWhile nc ::
      (match _hd : (b :: bs).dropWhile nc with
       | [] => []
       | _ :: r => mojoList r)
termination_by t.length
decreasing_by
  have h2 := congrArg List.length _hd
  rw [dropWhile_eq_drop, List.length_drop] at h2
  simp only [List.length_cons] at h2 ⊢
  have : 0 < (List.takeWhile nc (b :: bs)).length ∨ (List.takeWhile nc (b :: bs)).length = 0 := by omega
  omega

theorem mojoList_cons (b : UInt8) (bs : Bytes) :
    mojoList (b :: bs) = (b :: bs).takeWhile nc ::
      (match (b :: bs).dropWhile nc with
       | [] => []
       | _ :: r => mojoList r) := by
  rw [mojoList]
  split <;> rename_i h <;> simp [h]

theorem mojoLoop_eq (s : Bytes) (n : Nat) : ∀ pos, s.length - pos ≤ n →
    mojoLoop s pos = mojoList (s.drop pos) := by
  induction n with
  | zero =>
    intro pos hn
    rw [mojoLoop, dif_neg (by omega), List.drop_eq_nil_of_le (by omega), mojoList]
  | succ k ih =>
    intro pos hn
    by_cases hlt : pos < s.length
    · rw [mojoLoop, dif_pos hlt]
      have he := scanComma_eq s _ pos (by omega) (Nat.le_refl _)
      obtain ⟨b, bs, hbs⟩ : ∃ b bs, s.drop pos = b :: bs :=
        List.exists_cons_of_ne_nil (by simp; omega)
      have htw : (s.drop pos).take (scanComma s pos - pos) = (b :: bs).takeWhile nc := by
        rw [he, Nat.add_sub_cancel_left, hbs]
        exact take_length_takeWhile _ _
      rw [htw, hbs, mojoList_cons]
      congr 1
      have hdw : (b :: bs).dropWhile nc = s.drop (scanComma s pos) := by
        rw [dropWhile_eq_drop, ← hbs, List.drop_drop, he]
      rw [hdw]
      by_cases hend : scanComma s pos < s.length
      · rw [List.drop_eq_getElem_cons hend]
        exact ih _ (by have := scanComma_ge s pos (by omega); omega)
      · have hnil : s.drop (scanComma s pos) = [] := List.drop_eq_nil_of_le (by omega)
        rw [hnil, mojoLoop, dif_neg (by omega)]
    · rw [mojoLoop, dif_neg hlt, List.drop_eq_nil_of_le (by omega), mojoList]

/-- `splitComma` peels the first segment like the Mojo loop, except that it
keeps going after a trailing comma (and returns `[[]]` on `[]`). -/
theorem splitComma_cons (t : Bytes) :
    splitComma t = t.takeWhile nc ::
      (match t.dropWhile nc with
       | [] => []
       | _ :: r => splitComma r) := by
  induction t with
  | nil => rfl
  | cons b bs ih =>
    rw [splitComma, ih]
    by_cases hb : b = 44
    · subst hb; simp [nc]; exact ih.symm
    · have : nc b = true := by simp [nc, hb]
      simp [hb, this]

def keep (l : List Bytes) : List Bytes := (l.map strip).filter (· ≠ [])

theorem keep_cons_congr (x : Bytes) (A B : List Bytes) (h : keep A = keep B) :
    keep (x :: A) = keep (x :: B) := by
  simp only [keep, List.map_cons, List.filter_cons] at h ⊢
  rw [h]

theorem keep_split_eq_mojo (n : Nat) : ∀ t : Bytes, t.length ≤ n →
    keep (splitComma t) = keep (mojoList t) := by
  induction n with
  | zero =>
    intro t ht
    have : t = [] := List.eq_nil_of_length_eq_zero (by omega)
    subst this; simp [keep, splitComma, mojoList, strip]
  | succ k ih =>
    intro t ht
    match t with
    | [] => simp [keep, splitComma, mojoList, strip]
    | b :: bs =>
      rw [splitComma_cons, mojoList_cons]
      apply keep_cons_congr
      have hlen := congrArg List.length
        (List.takeWhile_append_dropWhile (p := nc) (l := b :: bs))
      cases hd : (b :: bs).dropWhile nc with
      | nil => rfl
      | cons x r =>
        rw [hd] at hlen
        simp only [List.length_append, List.length_cons] at hlen ht
        exact ih r (by omega)

/-- **The spec splitter and the Mojo loop agree.** After stripping and
dropping empty entries (what the Mojo loop's `continue` does), `splitComma`
and the index-level Mojo loop yield the same entries, so `parseHeader`
equals the transliterated loop on every header. -/
theorem parseHeaderMojo_eq (h : Bytes) : parseHeaderMojo h = parseHeader h := by
  unfold parseHeaderMojo parseHeader
  have := keep_split_eq_mojo h.length h (Nat.le_refl _)
  unfold keep at this
  rw [mojoLoop_eq h h.length 0 (by omega), List.drop_zero, ← this]

/-! ## Decision layer (the Mojo loop) -/

inductive Enc | br | gzip | identity
  deriving DecidableEq, Repr

/-- Loop body of the pre-fix `negotiate_encoding` (APP-20): `*` counted only
while `best_q == 0` and always selected identity.
mirrors flare/http/middleware.mojo:236-252 @59bda50 -/
def step (brOk : Bool) (s : Nat × Enc) (e : Tok × Nat) : Nat × Enc :=
  let (bq, be) := s
  let (t, q) := e
  match t with
  | .star => if bq = 0 then (q, .identity) else (bq, be)
  | .br => if brOk then (if q > bq ∨ (q = bq ∧ be ≠ .br) then (q, .br) else (bq, be))
           else (bq, be)
  | .gzip => if q > bq ∨ (q = bq ∧ be = .identity) then (q, .gzip) else (bq, be)
  | .identity => if q > bq then (q, .identity) else (bq, be)
  | .other => (bq, be)

def implFold (brOk : Bool) (es : List (Tok × Nat)) : Nat × Enc :=
  es.foldl (step brOk) (0, .identity)

/-- Final decision of the pre-fix loop on a list of parsed entries:
`(encoding, quality)`.
mirrors flare/http/middleware.mojo:253-260 @59bda50 -/
def decideOld (brOk : Bool) (es : List (Tok × Nat)) : Enc × Nat :=
  let (bq, be) := implFold brOk es
  if bq = 0 then (.identity, 0) else (be, bq)

/-- `negotiate_encoding` before the APP-20 fix.
mirrors flare/http/middleware.mojo:169-260 @59bda50 -/
def negotiateOld (brOk : Bool) (accept : Bytes) : Enc × Nat :=
  if accept = [] then (.identity, 1000) else decideOld brOk (parseHeader accept)

/-! ## Spec (RFC 9110 §12.5.3) -/

def optMax (o : Option Nat) (q : Nat) : Option Nat :=
  some (match o with | none => q | some p => max p q)

/-- Largest weight among entries naming `t` (none when `t` is not listed). -/
def explicitQ (es : List (Tok × Nat)) (t : Tok) : Option Nat :=
  es.foldl (fun o e => if e.1 = t then optMax o e.2 else o) none

/-- Effective weight: explicit entry, else `*`, else none. -/
def qOf (es : List (Tok × Nat)) (t : Tok) : Option Nat :=
  match explicitQ es t with
  | some q => some q
  | none => explicitQ es .star

def top (b g i : Nat) : Enc :=
  if b = max b (max g i) then .br else if g = max b (max g i) then .gzip else .identity

/-- The RFC choice from the three effective weights. -/
def choose (b g i : Nat) : Enc × Nat :=
  if max b (max g i) = 0 then (.identity, 0) else (top b g i, max b (max g i))

def specPick (brOk : Bool) (es : List (Tok × Nat)) : Enc × Nat :=
  choose (if brOk then (qOf es .br).getD 0 else 0)
    ((qOf es .gzip).getD 0) ((qOf es .identity).getD 0)

/-! ## qvalue parsing -/

theorem frac_lt (ds : Bytes) (p q : Nat) (hp : p ≤ 3) (hq : q < 10 ^ p) :
    frac ds p q < 1000 := by
  induction ds generalizing p q with
  | nil =>
    simp only [frac]
    have : q * 10 ^ (3 - p) < 10 ^ p * 10 ^ (3 - p) :=
      Nat.mul_lt_mul_of_pos_right hq (Nat.pow_pos (by omega))
    rw [← Nat.pow_add, show p + (3 - p) = 3 by omega] at this; simpa using this
  | cons d ds ih =>
    simp only [frac]
    split
    · rename_i h
      apply ih _ _ (by omega)
      have hd : d.toNat ≤ 57 := by
        have := h.2.2; exact (UInt8.le_iff_toNat_le).1 this
      have hd' : 48 ≤ d.toNat := (UInt8.le_iff_toNat_le).1 h.2.1
      rw [Nat.pow_succ]; omega
    · have : q * 10 ^ (3 - p) < 10 ^ p * 10 ^ (3 - p) :=
        Nat.mul_lt_mul_of_pos_right hq (Nat.pow_pos (by omega))
      rw [← Nat.pow_add, show p + (3 - p) = 3 by omega] at this; simpa using this

/-- Every weight is in `0..1000` (general). -/
theorem parseQ_le (v : Bytes) : parseQ v ≤ 1000 := by
  unfold parseQ
  split
  · omega
  · split
    · omega
    · split
      · omega
      · split
        · exact Nat.le_of_lt (frac_lt _ 0 0 (by omega) (by decide))
        · omega

/-- Malformed weights fail open: a first non-blank byte other than `0`
(including `1.x`, `2`, `-1`, `abc`) yields 1000. -/
theorem parseQ_failOpen (v r : Bytes) (c : UInt8)
    (h : v.dropWhile (fun b => b == 32 || b == 9) = c :: r) (hc : c ≠ 48) :
    parseQ v = 1000 := by
  unfold parseQ; rw [h]; simp only; split <;> simp_all

/-- Decimal value of a digit string. -/
def digitsVal : Bytes → Nat → Nat
  | [], acc => acc
  | d :: ds, acc => digitsVal ds (acc * 10 + (d.toNat - 48))

def isDigit (d : UInt8) : Prop := 48 ≤ d ∧ d ≤ 57

theorem frac_digits (ds : Bytes) (p q : Nat) (hd : ∀ d ∈ ds, isDigit d)
    (hl : p + ds.length ≤ 3) :
    frac ds p q = digitsVal ds q * 10 ^ (3 - p - ds.length) := by
  induction ds generalizing p q with
  | nil => simp [frac, digitsVal]
  | cons d ds ih =>
    simp only [frac, digitsVal, List.length_cons]
    have h1 := hd d (by simp)
    rw [if_pos ⟨by simp at hl; omega, h1.1, h1.2⟩]
    rw [ih _ _ (fun x hx => hd x (by simp [hx])) (by simp at hl; omega)]
    congr 2; omega

/-- RFC 9110 §12.4.2 `"0" "." 0*3DIGIT` is read exactly, in thousandths. -/
theorem parseQ_zero_dot (ds : Bytes) (hd : ∀ d ∈ ds, isDigit d) (hl : ds.length ≤ 3) :
    parseQ (48 :: 46 :: ds) = digitsVal ds 0 * 10 ^ (3 - ds.length) := by
  simp only [parseQ, List.dropWhile]
  simp only [show ((48 : UInt8) == 32 || (48 : UInt8) == 9) = false by decide]
  simp only [show ¬ ((48:UInt8) = 49) by decide, if_false, show ¬ ((48:UInt8) ≠ 48) by decide]
  rw [frac_digits ds 0 0 hd (by omega)]

/-- More than three decimals are truncated (`0.9999` reads as 999). -/
example : parseQ [48, 46, 57, 57, 57, 57] = 999 := by decide
/-- `q=0` alone is zero, `q=1` is 1000. -/
example : parseQ [48] = 0 ∧ parseQ [49] = 1000 ∧ parseQ [32, 48, 46, 53] = 500 := by decide

/-! ## Case-insensitivity of coding names (RFC 9110 §8.4.1) -/

set_option maxRecDepth 20000 in
theorem lowerByte_upperByte_fin :
    ∀ n : Fin 256, lowerByte (upperByte (UInt8.ofNat n.val)) = lowerByte (UInt8.ofNat n.val) := by
  decide

theorem lowerByte_upperByte (c : UInt8) : lowerByte (upperByte c) = lowerByte c := by
  have := lowerByte_upperByte_fin ⟨c.toNat, c.toNat_lt⟩
  simpa using this

/-- Upper-casing a name never changes its classification (general). -/
theorem classify_upper (name : Bytes) :
    classify (name.map upperByte) = classify name := by
  unfold classify lowerAscii
  rw [List.map_map]; congr 1
  apply List.map_congr_left; intro c _; exact lowerByte_upperByte c

/-- `x-gzip` is not recognised (RFC 9110 §8.4.1.3: a recipient SHOULD treat
it as gzip); such an entry is ignored, which only ever yields identity. -/
example : classify [120, 45, 103, 122, 105, 112] = .other := by decide

/-! ## Decision layer vs spec -/

def NoStar (es : List (Tok × Nat)) : Prop := ∀ e ∈ es, e.1 ≠ .star

/-- Invariant of the Mojo loop relative to the running per-coding maxima. -/
def Inv (brOk : Bool) (s : Nat × Enc) (b g i : Option Nat) : Prop :=
  let bb := if brOk then b.getD 0 else 0
  s.1 = max bb (max (g.getD 0) (i.getD 0)) ∧
  (0 < s.1 → s.2 = top bb (g.getD 0) (i.getD 0))

def updE (t : Tok) (o : Option Nat) (e : Tok × Nat) : Option Nat :=
  if e.1 = t then optMax o e.2 else o

theorem optMax_getD (o : Option Nat) (q : Nat) : (optMax o q).getD 0 = max (o.getD 0) q := by
  cases o <;> simp [optMax]

theorem arith_gzip (B b g i q : Nat) (E : Enc) (h1 : B = max b (max g i))
    (h2 : 0 < B → E = top b g i) :
    (if q > B ∨ (q = B ∧ E = .identity) then (q, Enc.gzip) else (B, E)).1 = max b (max (max g q) i) ∧
    (0 < (if q > B ∨ (q = B ∧ E = .identity) then (q, Enc.gzip) else (B, E)).1 →
      (if q > B ∨ (q = B ∧ E = .identity) then (q, Enc.gzip) else (B, E)).2 = top b (max g q) i) := by
  unfold top at *
  cases E <;> grind

theorem arith_br (B b g i q : Nat) (E : Enc) (h1 : B = max b (max g i))
    (h2 : 0 < B → E = top b g i) :
    (if q > B ∨ (q = B ∧ E ≠ .br) then (q, Enc.br) else (B, E)).1 = max (max b q) (max g i) ∧
    (0 < (if q > B ∨ (q = B ∧ E ≠ .br) then (q, Enc.br) else (B, E)).1 →
      (if q > B ∨ (q = B ∧ E ≠ .br) then (q, Enc.br) else (B, E)).2 = top (max b q) g i) := by
  unfold top at *
  cases E <;> grind

theorem arith_id (B b g i q : Nat) (E : Enc) (h1 : B = max b (max g i))
    (h2 : 0 < B → E = top b g i) :
    (if q > B then (q, Enc.identity) else (B, E)).1 = max b (max g (max i q)) ∧
    (0 < (if q > B then (q, Enc.identity) else (B, E)).1 →
      (if q > B then (q, Enc.identity) else (B, E)).2 = top b g (max i q)) := by
  unfold top at *
  cases E <;> grind

theorem inv_step (brOk : Bool) (s : Nat × Enc) (b g i : Option Nat) (e : Tok × Nat)
    (he : e.1 ≠ .star) (h : Inv brOk s b g i) :
    Inv brOk (step brOk s e) (updE .br b e) (updE .gzip g e) (updE .identity i e) := by
  obtain ⟨bq, be⟩ := s
  obtain ⟨t, q⟩ := e
  unfold Inv at *
  obtain ⟨h1, h2⟩ := h
  cases t with
  | star => exact absurd rfl he
  | other => simpa [step, updE] using And.intro h1 h2
  | br =>
    cases brOk with
    | false => simpa [step, updE] using And.intro h1 h2
    | true =>
      have := arith_br bq (b.getD 0) (g.getD 0) (i.getD 0) q be h1 h2
      simpa [step, updE, optMax_getD] using this
  | gzip =>
    have := arith_gzip bq (if brOk then b.getD 0 else 0) (g.getD 0) (i.getD 0) q be h1 h2
    simpa [step, updE, optMax_getD] using this
  | identity =>
    have := arith_id bq (if brOk then b.getD 0 else 0) (g.getD 0) (i.getD 0) q be h1 h2
    simpa [step, updE, optMax_getD] using this

theorem explicitQ_foldl (es : List (Tok × Nat)) (t : Tok) (o : Option Nat) :
    es.foldl (fun o e => if e.1 = t then optMax o e.2 else o) o =
      es.foldl (fun o e => updE t o e) o := rfl

theorem inv_fold (brOk : Bool) (es : List (Tok × Nat)) (hs : NoStar es) :
    ∀ s b g i, Inv brOk s b g i →
      Inv brOk (es.foldl (step brOk) s)
        (es.foldl (updE .br) b) (es.foldl (updE .gzip) g) (es.foldl (updE .identity) i) := by
  induction es with
  | nil => intro s b g i h; exact h
  | cons e es ih =>
    intro s b g i h
    simp only [List.foldl_cons]
    exact ih (fun x hx => hs x (by simp [hx])) _ _ _ _
      (inv_step brOk s b g i e (hs e (by simp)) h)

theorem explicitQ_none_of_noStar (es : List (Tok × Nat)) (hs : NoStar es) :
    explicitQ es .star = none := by
  unfold explicitQ
  suffices ∀ o : Option Nat, o = none →
      es.foldl (fun o e => if e.1 = Tok.star then optMax o e.2 else o) o = none by
    exact this none rfl
  induction es with
  | nil => intro o h; exact h
  | cons e es ih =>
    intro o h; simp only [List.foldl_cons]
    apply ih (fun x hx => hs x (by simp [hx]))
    rw [if_neg (hs e (by simp))]; exact h

/-- **Refinement without `*`** (general): for any entry list with no
wildcard, flare's loop computes exactly the RFC pick — the highest
effective weight among available codings, ties br > gzip > identity,
duplicates resolved by maximum, and passthrough when every weight is 0. -/
theorem opt_match_id (o : Option Nat) :
    (match o with | some q => some q | none => none) = o := by cases o <;> rfl

theorem decideOld_eq_spec_of_noStar (brOk : Bool) (es : List (Tok × Nat)) (hs : NoStar es) :
    decideOld brOk es = specPick brOk es := by
  have h := inv_fold brOk es hs (0, .identity) none none none
    (by simp [Inv])
  unfold decideOld implFold specPick qOf choose
  rw [explicitQ_none_of_noStar es hs]
  simp only [explicitQ, explicitQ_foldl, opt_match_id]
  unfold Inv at h
  obtain ⟨h1, h2⟩ := h
  cases hr : es.foldl (step brOk) (0, Enc.identity) with
  | mk bq be =>
    rw [hr] at h1 h2
    simp only at h1 h2 ⊢
    rw [← h1]
    by_cases hz : bq = 0
    · simp [hz]
    · simp [hz, h2 (by omega)]

theorem optMax_comm (o : Option Nat) (a b : Nat) :
    optMax (optMax o a) b = optMax (optMax o b) a := by
  cases o <;> simp [optMax] <;> omega

theorem explicitQ_perm {es es' : List (Tok × Nat)} (hp : es.Perm es') (t : Tok) :
    explicitQ es t = explicitQ es' t := by
  unfold explicitQ
  apply hp.foldl_eq'
  intro x _ y _ z
  by_cases hx : x.1 = t <;> by_cases hy : y.1 = t <;> simp [hx, hy, optMax_comm]

/-- The RFC pick is independent of entry order (general). -/
theorem specPick_perm (brOk : Bool) {es es' : List (Tok × Nat)} (hp : es.Perm es') :
    specPick brOk es = specPick brOk es' := by
  simp only [specPick, qOf, explicitQ_perm hp]

/-- Order independence of flare's loop on wildcard-free headers (general). -/
theorem decideOld_perm_of_noStar (brOk : Bool) {es es' : List (Tok × Nat)}
    (hp : es.Perm es') (hs : NoStar es) :
    decideOld brOk es = decideOld brOk es' := by
  rw [decideOld_eq_spec_of_noStar brOk es hs,
    decideOld_eq_spec_of_noStar brOk es' (fun e he => hs e (hp.mem_iff.2 he)),
    specPick_perm brOk hp]

theorem fold_not_br (es : List (Tok × Nat)) :
    ∀ s : Nat × Enc, s.2 ≠ .br → (es.foldl (step false) s).2 ≠ .br := by
  induction es with
  | nil => intro s hs; exact hs
  | cons e es ih =>
    intro s hs; simp only [List.foldl_cons]; apply ih
    obtain ⟨bq, be⟩ := s; obtain ⟨t, q⟩ := e
    cases t <;> grind [step]

/-- br is chosen only when brotli is linkable (general, any header). -/
theorem decideOld_br_imp (brOk : Bool) (es : List (Tok × Nat)) :
    (decideOld brOk es).1 = .br → brOk = true := by
  intro h
  cases brOk with
  | true => rfl
  | false =>
    exfalso
    have h0 := fold_not_br es (0, .identity) (by simp)
    unfold decideOld implFold at h
    cases hr : es.foldl (step false) (0, Enc.identity) with
    | mk bq be =>
      rw [hr] at h h0
      simp only at h h0
      by_cases hz : bq = 0 <;> simp_all

/-- Byte-level corollary: any non-empty header without a `*` entry is
negotiated exactly as the RFC spec over its parsed entries. -/
theorem negotiateOld_eq_spec_of_noStar (brOk : Bool) (h : Bytes) (hne : h ≠ [])
    (hs : NoStar (parseHeader h)) :
    negotiateOld brOk h = specPick brOk (parseHeader h) := by
  simp [negotiateOld, hne, decideOld_eq_spec_of_noStar brOk _ hs]

/-! ## Shipped decision (fixed, APP-20: `*` handled per RFC) -/

/-- State: running explicit maxima for br, gzip, identity and `*`. -/
def stepFixed (s : Option Nat × Option Nat × Option Nat × Option Nat) (e : Tok × Nat) :
    Option Nat × Option Nat × Option Nat × Option Nat :=
  let (b, g, i, w) := s
  (updE .br b e, updE .gzip g e, updE .identity i e, updE .star w e)

/-- `negotiate_encoding`'s decision as shipped (fixed, APP-20): the running
maxima for br, gzip, identity and `*` over all entries, then the pick.
mirrors flare/http/middleware.mojo:195-272 (fixed, APP-20) -/
def decide' (brOk : Bool) (es : List (Tok × Nat)) : Enc × Nat :=
  let (b, g, i, w) := es.foldl stepFixed (none, none, none, none)
  let eff := fun (o : Option Nat) => (match o with | some q => some q | none => w).getD 0
  choose (if brOk then eff b else 0) (eff g) (eff i)

theorem foldl_stepFixed (es : List (Tok × Nat)) (b g i w : Option Nat) :
    es.foldl stepFixed (b, g, i, w) =
      (es.foldl (updE .br) b, es.foldl (updE .gzip) g, es.foldl (updE .identity) i,
        es.foldl (updE .star) w) := by
  induction es generalizing b g i w with
  | nil => rfl
  | cons e es ih => simp only [List.foldl_cons, stepFixed]; exact ih _ _ _ _

/-- The shipped decision meets the RFC spec on every entry list (general). -/
theorem decide'_eq_spec (brOk : Bool) (es : List (Tok × Nat)) :
    decide' brOk es = specPick brOk es := by
  unfold decide' specPick qOf explicitQ
  rw [foldl_stepFixed]; rfl

/-- `negotiate_encoding` as shipped. mirrors flare/http/middleware.mojo:169-272
(fixed, APP-20) -/
def negotiate (brOk : Bool) (accept : Bytes) : Enc × Nat :=
  if accept = [] then (.identity, 1000) else decide' brOk (parseHeader accept)

/-- The shipped `negotiate` is the RFC pick over the parsed entries, for every
header (with or without `*`). -/
theorem negotiate_eq_spec (brOk : Bool) (h : Bytes) (hne : h ≠ []) :
    negotiate brOk h = specPick brOk (parseHeader h) := by
  simp [negotiate, hne, decide'_eq_spec]

/-- The shipped decision does not depend on entry order (general, `*`
included). -/
theorem decide'_perm (brOk : Bool) {es es' : List (Tok × Nat)} (hp : es.Perm es') :
    decide' brOk es = decide' brOk es' := by
  rw [decide'_eq_spec, decide'_eq_spec, specPick_perm brOk hp]

/-- The shipped decision never serves an explicitly refused (`q=0`) identity
through `*`: if identity is listed with weight 0, identity is chosen only
when nothing else is acceptable (quality 0). -/
theorem choose_zero_identity (b g : Nat) :
    (choose b g 0).1 = .identity → (choose b g 0).2 = 0 := by
  unfold choose top
  by_cases h : max b (max g 0) = 0
  · rw [if_pos h]; intro _; rfl
  · rw [if_neg h]
    intro hid
    exfalso
    dsimp only at hid
    split at hid
    · cases hid
    · split at hid
      · cases hid
      · omega

theorem decide'_refused_identity (brOk : Bool) (es : List (Tok × Nat))
    (h : explicitQ es .identity = some 0) :
    (decide' brOk es).1 = .identity → (decide' brOk es).2 = 0 := by
  rw [decide'_eq_spec]
  unfold specPick
  simp only [qOf, h, Option.getD_some]
  exact choose_zero_identity _ _

/-- `negotiate_encoding` before the fix, with the index-level entry loop. -/
def negotiateOldMojo (brOk : Bool) (accept : Bytes) : Enc × Nat :=
  if accept = [] then (.identity, 1000) else decideOld brOk (parseHeaderMojo accept)

/-- Every theorem about `negotiateOld` holds for the transliterated loop. -/
theorem negotiateOldMojo_eq : negotiateOldMojo = negotiateOld := by
  funext brOk accept
  simp only [negotiateOldMojo, negotiateOld, parseHeaderMojo_eq]

end Flare.L4.Negotiate
