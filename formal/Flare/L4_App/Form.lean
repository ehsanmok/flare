import Flare.Core.Bytes

/-!
# `application/x-www-form-urlencoded` codec (flare/http/form.mojo)

Byte-level models of `_hex_nibble`, `urldecode` (byte loop `urldecodeBytes`
plus the UTF-8 check added for APP-24), `urlencode`,
`FormData.to_urlencoded` and `parse_form_urlencoded`. A Mojo `raise` is
modelled as `none`.

Spec side: WHATWG URL Living Standard §5.1 (urlencoded parsing) and §5.2
(serializing), plus RFC 3629 for the UTF-8 well-formedness that Mojo's
`String` requires of everything passed to `String(unsafe_from_utf8=...)`.
-/
namespace Flare.L4.Form

open Flare

/-! ## Impl -/

/-- mirrors flare/http/form.mojo:28-47 @59bda50 -/
def hexNibble (c : UInt8) : Option Nat :=
  if 48 ≤ c.toNat ∧ c.toNat ≤ 57 then some (c.toNat - 48)
  else if 97 ≤ c.toNat ∧ c.toNat ≤ 102 then some (c.toNat - 87)
  else if 65 ≤ c.toNat ∧ c.toNat ≤ 70 then some (c.toNat - 55)
  else none

/-- mirrors flare/http/form.mojo:50-87 @59bda50
(the byte loop; the pre-fix `String(unsafe_from_utf8=...)` wrap was the
identity on bytes, and is exactly where validity was lost). The Mojo guard
`if i + 2 >= n: raise` is the "fewer than two bytes after `%`" case. -/
def urldecodeBytes : Bytes → Option Bytes
  | [] => some []
  | c :: r =>
    if c = 43 then (32 :: ·) <$> urldecodeBytes r
    else if c = 37 then
      match r with
      | h :: l :: r' =>
        match hexNibble h, hexNibble l with
        | some a, some b => (UInt8.ofNat (a * 16 + b) :: ·) <$> urldecodeBytes r'
        | _, _ => none
      | [] => none
      | [_] => none
    else (c :: ·) <$> urldecodeBytes r
termination_by b => b.length
decreasing_by all_goals simp_all <;> omega

/-! ## UTF-8 well-formedness (RFC 3629 §4), written independently of flare -/

def tail (b : UInt8) : Bool := 0x80 ≤ b.toNat && b.toNat ≤ 0xBF
def inR (b : UInt8) (lo hi : Nat) : Bool := lo ≤ b.toNat && b.toNat ≤ hi

/-- Length of the well-formed UTF-8 sequence at the head of `bs`, if any
(RFC 3629 `UTF8-char`). -/
def firstSeq : Bytes → Option Nat
  | [] => none
  | a :: r =>
    if a.toNat < 0x80 then some 1
    else if inR a 0xC2 0xDF then
      match r with | b :: _ => if tail b then some 2 else none | _ => none
    else if a.toNat = 0xE0 then
      match r with | b :: c :: _ => if inR b 0xA0 0xBF && tail c then some 3 else none | _ => none
    else if inR a 0xE1 0xEC || inR a 0xEE 0xEF then
      match r with | b :: c :: _ => if tail b && tail c then some 3 else none | _ => none
    else if a.toNat = 0xED then
      match r with | b :: c :: _ => if inR b 0x80 0x9F && tail c then some 3 else none | _ => none
    else if a.toNat = 0xF0 then
      match r with
      | b :: c :: d :: _ => if inR b 0x90 0xBF && tail c && tail d then some 4 else none
      | _ => none
    else if inR a 0xF1 0xF3 then
      match r with
      | b :: c :: d :: _ => if tail b && tail c && tail d then some 4 else none
      | _ => none
    else if a.toNat = 0xF4 then
      match r with
      | b :: c :: d :: _ => if inR b 0x80 0x8F && tail c && tail d then some 4 else none
      | _ => none
    else none

def utf8ValidAux : Nat → Bytes → Bool
  | _, [] => true
  | 0, _ :: _ => false
  | fuel + 1, bs =>
    match firstSeq bs with
    | some k => utf8ValidAux fuel (bs.drop k)
    | none => false

/-- RFC 3629 `UTF8-octets = *( UTF8-char )`. -/
def Utf8Valid (bs : Bytes) : Bool := utf8ValidAux bs.length bs

/-- mirrors flare/http/form.mojo:50-95 (fixed, APP-24): the byte loop followed
by `String(from_utf8=...)`, which raises on ill-formed UTF-8. -/
def urldecode (s : Bytes) : Option Bytes :=
  match urldecodeBytes s with
  | some out => if Utf8Valid out then some out else none
  | none => none

/-- The pre-fix `urldecode` (form.mojo:50-87 @59bda50): the decoded bytes were
wrapped with `String(unsafe_from_utf8=...)` unchecked. -/
abbrev urldecodeOld : Bytes → Option Bytes := urldecodeBytes

/-- The unreserved set of flare's encoder (A-Z a-z 0-9 - . _ ~).
mirrors flare/http/form.mojo:112-120 @59bda50 -/
def unreserved (c : UInt8) : Bool :=
  (48 ≤ c.toNat && c.toNat ≤ 57) || (65 ≤ c.toNat && c.toNat ≤ 90) ||
  (97 ≤ c.toNat && c.toNat ≤ 122) || c.toNat == 45 || c.toNat == 46 ||
  c.toNat == 95 || c.toNat == 126

/-- `HEX[n]` for `HEX = "0123456789ABCDEF"`.
mirrors flare/http/form.mojo:104 @59bda50 -/
def hexDigit (n : Nat) : UInt8 :=
  if n < 10 then UInt8.ofNat (48 + n) else UInt8.ofNat (55 + n)

/-- One byte of `urlencode`. mirrors flare/http/form.mojo:110-128 @59bda50 -/
def encByte (c : UInt8) : Bytes :=
  if unreserved c then [c]
  else if c = 32 then [43]
  else [37, hexDigit (c.toNat / 16), hexDigit (c.toNat % 16)]

/-- mirrors flare/http/form.mojo:90-129 @59bda50 -/
def urlencode (s : Bytes) : Bytes := s.flatMap encByte

def isSep (c : UInt8) : Bool := c = 38 || c = 59

/-- Split off the first pair: bytes before the first `&`/`;`, and the bytes
after it (`[]` when there is no separator: `pos = n + 1` ends the loop).
mirrors flare/http/form.mojo:242-247,263 @59bda50 -/
def breakSep : Bytes → Bytes × Bytes
  | [] => ([], [])
  | c :: r => if isSep c then ([], r) else ((c :: (breakSep r).1), (breakSep r).2)

/-- Split a pair at the first `=`; `none` = no `=` (value `""`).
mirrors flare/http/form.mojo:249-261 @59bda50 -/
def breakEq : Bytes → Bytes × Option Bytes
  | [] => ([], none)
  | c :: r => if c = 61 then ([], some r) else ((c :: (breakEq r).1), (breakEq r).2)

/-- One `name=value` pair, decoded with `dec`.
mirrors flare/http/form.mojo:249-262 @59bda50 -/
def parsePairWith (dec : Bytes → Option Bytes) (f : Bytes) : Option (Bytes × Bytes) := do
  let a ← dec (breakEq f).1
  let b ← dec ((breakEq f).2.getD [])
  pure (a, b)

/-- mirrors flare/http/form.mojo:249-262 (fixed, APP-24): decode with the
validating `urldecode`. -/
def parsePair : Bytes → Option (Bytes × Bytes) := parsePairWith urldecode

theorem breakSep_snd_le (b : Bytes) : (breakSep b).2.length ≤ b.length := by
  induction b with
  | nil => simp [breakSep]
  | cons c r ih => simp only [breakSep]; split <;> simp <;> omega

theorem breakSep_snd_length (c : UInt8) (r : Bytes) :
    (breakSep (c :: r)).2.length ≤ r.length := by
  simp only [breakSep]; split
  · simp
  · exact breakSep_snd_le r

/-- mirrors flare/http/form.mojo:216-264 @59bda50 (the `while pos < n` loop;
an empty pair is skipped), with the decoder as a parameter. -/
def parseFormWith (dec : Bytes → Option Bytes) (b : Bytes) : Option (List (Bytes × Bytes)) :=
  match b with
  | [] => some []
  | c :: r =>
    let f := (breakSep (c :: r)).1
    let rest := (breakSep (c :: r)).2
    if f = [] then parseFormWith dec rest
    else do
      let p ← parsePairWith dec f
      let ps ← parseFormWith dec rest
      pure (p :: ps)
termination_by b.length
decreasing_by all_goals (have := breakSep_snd_length c r; simp_all; omega)

/-- mirrors flare/http/form.mojo:216-270 (fixed, APP-24): `parse_form_urlencoded`
as shipped (validating `urldecode`). -/
def parseForm : Bytes → Option (List (Bytes × Bytes)) := parseFormWith urldecode

/-- `parse_form_urlencoded` before the APP-24 fix (unchecked decode). -/
def parseFormOld : Bytes → Option (List (Bytes × Bytes)) := parseFormWith urldecodeOld

def serPair (p : Bytes × Bytes) : Bytes := urlencode p.1 ++ 61 :: urlencode p.2

/-- mirrors flare/http/form.mojo:199-213 @59bda50 -/
def toUrlencoded : List (Bytes × Bytes) → Bytes
  | [] => []
  | [p] => serPair p
  | p :: ps => serPair p ++ 38 :: toUrlencoded ps

/-! ## Round-trip theorems -/

theorem hexNibble_hexDigit : ∀ n : Fin 16, hexNibble (hexDigit n.val) = some n.val := by
  decide

theorem unreserved_ne (c : UInt8) (h : unreserved c = true) :
    c ≠ 43 ∧ c ≠ 37 ∧ c ≠ 38 ∧ c ≠ 59 ∧ c ≠ 61 := by
  simp only [unreserved, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq,
    beq_iff_eq] at h
  refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hc <;> subst hc <;> simp at h

theorem hexDigit_ok (n : Nat) (h : n < 16) :
    hexDigit n ≠ 38 ∧ hexDigit n ≠ 59 ∧ hexDigit n ≠ 61 := by
  have : ∀ m : Fin 16, hexDigit m.val ≠ 38 ∧ hexDigit m.val ≠ 59 ∧ hexDigit m.val ≠ 61 := by
    decide
  exact this ⟨n, h⟩

theorem urldecodeBytes_plus (r : Bytes) : urldecodeBytes (43 :: r) = (32 :: ·) <$> urldecodeBytes r := by
  conv => lhs; rw [urldecodeBytes.eq_def]
  simp

theorem urldecodeBytes_pct (h l : UInt8) (r : Bytes) :
    urldecodeBytes (37 :: h :: l :: r) =
      (match hexNibble h, hexNibble l with
        | some a, some b => (UInt8.ofNat (a * 16 + b) :: ·) <$> urldecodeBytes r
        | _, _ => none) := by
  conv => lhs; rw [urldecodeBytes.eq_def]
  simp

theorem urldecodeBytes_other (c : UInt8) (r : Bytes) (h1 : c ≠ 43) (h2 : c ≠ 37) :
    urldecodeBytes (c :: r) = (c :: ·) <$> urldecodeBytes r := by
  conv => lhs; rw [urldecodeBytes.eq_def]
  simp [h1, h2]

theorem urldecodeBytes_encByte (c : UInt8) (r : Bytes) :
    urldecodeBytes (encByte c ++ r) = (c :: ·) <$> urldecodeBytes r := by
  unfold encByte
  split
  · rename_i hu
    obtain ⟨h1, h2, -⟩ := unreserved_ne c hu
    simp only [List.singleton_append]; exact urldecodeBytes_other c r h1 h2
  · split
    · subst_vars; exact urldecodeBytes_plus r
    · have hc := c.toNat_lt
      have e1 := hexNibble_hexDigit ⟨c.toNat / 16, by omega⟩
      have e2 := hexNibble_hexDigit ⟨c.toNat % 16, by omega⟩
      simp only at e1 e2
      simp only [List.cons_append, List.nil_append, urldecodeBytes_pct, e1, e2]
      have : c.toNat / 16 * 16 + c.toNat % 16 = c.toNat := by omega
      rw [this, UInt8.ofNat_toNat]

/-- **Round trip**: `urldecodeBytes (urlencode s) = s` for every byte string. -/
theorem urldecodeBytes_urlencode (s : Bytes) : urldecodeBytes (urlencode s) = some s := by
  induction s with
  | nil => simp [urlencode, urldecodeBytes]
  | cons c s ih =>
    simp only [urlencode, List.flatMap_cons] at *
    rw [urldecodeBytes_encByte, ih]; rfl

theorem urlencode_noSep (s : Bytes) : ∀ x ∈ urlencode s, x ≠ 38 ∧ x ≠ 59 ∧ x ≠ 61 := by
  intro x hx
  simp only [urlencode, List.mem_flatMap] at hx
  obtain ⟨c, -, hx⟩ := hx
  unfold encByte at hx
  have hc := c.toNat_lt
  split at hx
  · rename_i hu; simp at hx; subst hx
    obtain ⟨-, -, a, b, d⟩ := unreserved_ne x hu; exact ⟨a, b, d⟩
  · split at hx
    · simp at hx; subst hx; decide
    · simp only [List.mem_cons, List.not_mem_nil, or_false] at hx
      rcases hx with h | h | h <;> subst h
      · decide
      · exact hexDigit_ok _ (by omega)
      · exact hexDigit_ok _ (by omega)

theorem breakSep_append (f r : Bytes) (h : ∀ x ∈ f, isSep x = false) (y : UInt8)
    (hy : isSep y = true) : breakSep (f ++ y :: r) = (f, r) := by
  induction f with
  | nil => simp [breakSep, hy]
  | cons c f ih =>
    have hc := h c (by simp)
    simp [breakSep, hc, ih (fun x hx => h x (by simp [hx]))]

theorem breakSep_nosep (f : Bytes) (h : ∀ x ∈ f, isSep x = false) :
    breakSep f = (f, []) := by
  induction f with
  | nil => rfl
  | cons c f ih =>
    have hc := h c (by simp)
    simp [breakSep, hc, ih (fun x hx => h x (by simp [hx]))]

theorem breakEq_append (f r : Bytes) (h : ∀ x ∈ f, x ≠ 61) :
    breakEq (f ++ 61 :: r) = (f, some r) := by
  induction f with
  | nil => simp [breakEq]
  | cons c f ih =>
    have hc := h c (by simp)
    simp [breakEq, hc, ih (fun x hx => h x (by simp [hx]))]

theorem isSep_false (x : UInt8) (h1 : x ≠ 38) (h2 : x ≠ 59) : isSep x = false := by
  simp [isSep, h1, h2]

theorem serPair_noSep (p : Bytes × Bytes) : ∀ x ∈ serPair p, isSep x = false := by
  intro x hx
  simp only [serPair, List.mem_append, List.mem_cons] at hx
  rcases hx with h | h | h
  · have := urlencode_noSep _ x h; exact isSep_false x this.1 this.2.1
  · subst h; decide
  · have := urlencode_noSep _ x h; exact isSep_false x this.1 this.2.1

theorem parsePairWith_serPair (dec : Bytes → Option Bytes) (p : Bytes × Bytes)
    (h1 : dec (urlencode p.1) = some p.1) (h2 : dec (urlencode p.2) = some p.2) :
    parsePairWith dec (serPair p) = some p := by
  unfold parsePairWith serPair
  rw [breakEq_append _ _ (fun x hx => (urlencode_noSep _ x hx).2.2)]
  simp [h1, h2]

theorem serPair_ne_nil (p : Bytes × Bytes) : serPair p ≠ [] := by simp [serPair]

theorem parseFormWith_cons_sep (dec : Bytes → Option Bytes) (f r : Bytes)
    (hf : ∀ x ∈ f, isSep x = false) (hne : f ≠ []) :
    parseFormWith dec (f ++ 38 :: r) =
      (do let p ← parsePairWith dec f; let ps ← parseFormWith dec r; pure (p :: ps)) := by
  obtain ⟨c, f', rfl⟩ : ∃ c f', f = c :: f' := by cases f <;> simp_all
  conv => lhs; rw [parseFormWith.eq_def]
  simp only [List.cons_append]
  rw [← List.cons_append, breakSep_append _ _ hf 38 (by decide)]
  simp

theorem parseFormWith_single (dec : Bytes → Option Bytes) (f : Bytes)
    (hf : ∀ x ∈ f, isSep x = false) (hne : f ≠ []) :
    parseFormWith dec f = (do let p ← parsePairWith dec f; pure [p]) := by
  obtain ⟨c, f', rfl⟩ : ∃ c f', f = c :: f' := by cases f <;> simp_all
  conv => lhs; rw [parseFormWith.eq_def]
  simp only [breakSep_nosep _ hf]
  simp [parseFormWith]

/-- **Round trip** for any decoder that inverts `urlencode` on the components
that occur: `parse (to_urlencoded fd) = fd`. -/
theorem parseFormWith_toUrlencoded (dec : Bytes → Option Bytes) (ps : List (Bytes × Bytes))
    (h : ∀ p ∈ ps, dec (urlencode p.1) = some p.1 ∧ dec (urlencode p.2) = some p.2) :
    parseFormWith dec (toUrlencoded ps) = some ps := by
  induction ps with
  | nil => simp [toUrlencoded, parseFormWith]
  | cons p ps ih =>
    have hp := h p (by simp)
    have ih' := ih (fun q hq => h q (by simp [hq]))
    cases ps with
    | nil =>
      simp only [toUrlencoded]
      rw [parseFormWith_single _ _ (serPair_noSep p) (serPair_ne_nil p),
        parsePairWith_serPair dec p hp.1 hp.2]; rfl
    | cons q qs =>
      simp only [toUrlencoded] at *
      rw [parseFormWith_cons_sep _ _ _ (serPair_noSep p) (serPair_ne_nil p),
        parsePairWith_serPair dec p hp.1 hp.2, ih']
      rfl

/-- The pre-fix parser round-trips every list of byte-string pairs (names and
values arbitrary, empty allowed) — including ill-formed UTF-8, which is the
APP-24 defect. -/
theorem parseFormOld_toUrlencoded (ps : List (Bytes × Bytes)) :
    parseFormOld (toUrlencoded ps) = some ps :=
  parseFormWith_toUrlencoded _ ps (fun _ _ => ⟨urldecodeBytes_urlencode _, urldecodeBytes_urlencode _⟩)

theorem urldecode_valid (s out : Bytes) (h : urldecode s = some out) :
    Utf8Valid out = true := by
  unfold urldecode at h
  split at h
  · split at h <;> simp_all
  · simp at h

theorem urldecode_urlencode (s : Bytes) (h : Utf8Valid s = true) :
    urldecode (urlencode s) = some s := by
  simp [urldecode, urldecodeBytes_urlencode, h]

/-- The validation only rejects; it never changes a successful decode. -/
theorem urldecode_sub (s out : Bytes) (h : urldecode s = some out) :
    urldecodeBytes s = some out := by
  unfold urldecode at h
  split at h
  · split at h <;> simp_all
  · simp at h

/-- **Round trip** for the shipped parser: for every list of pairs whose names
and values are well-formed UTF-8 (the only ones a Mojo `String` can hold),
`parse_form_urlencoded (to_urlencoded fd) = fd`. -/
theorem parseForm_toUrlencoded (ps : List (Bytes × Bytes))
    (h : ∀ p ∈ ps, Utf8Valid p.1 = true ∧ Utf8Valid p.2 = true) :
    parseForm (toUrlencoded ps) = some ps :=
  parseFormWith_toUrlencoded _ ps
    (fun p hp => ⟨urldecode_urlencode _ (h p hp).1, urldecode_urlencode _ (h p hp).2⟩)

end Flare.L4.Form
