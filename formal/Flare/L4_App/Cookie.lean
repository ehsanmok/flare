import Flare.Core.Bytes
import Flare.Core.Word

/-!
# Cookies (flare/http/cookie.mojo)

Byte-level models of `Cookie.to_set_cookie_header` (with its RFC 6265
§4.1.1 validation), `parse_cookie_header`, `CookieJar.to_request_header`
and `_parse_max_age`. A Mojo `raise` is `none`.

Spec side: RFC 6265 §4.1.1 (`set-cookie-string`, `cookie-octet`, `token`,
`av-octet`), §4.2.1 (`cookie-string = cookie-pair *( ";" SP cookie-pair )`)
and §5.2.2 (Max-Age).
-/
namespace Flare.L4.Cookie

open Flare

/-! ## Byte classes -/

/-- RFC 9110 separators `()<>@,;:\"/[]?={}`. mirrors flare/http/cookie.mojo:172 @59bda50 -/
def separators : List UInt8 := [40, 41, 60, 62, 64, 44, 59, 58, 92, 34, 47, 91, 93, 63, 61, 123, 125]

/-- mirrors flare/http/cookie.mojo:168-175 @59bda50 -/
def isTokenByte (c : UInt8) : Bool :=
  !(c.toNat ≤ 32 || c.toNat ≥ 127) && !(separators.contains c)

/-- mirrors flare/http/cookie.mojo:178-182 @59bda50 -/
def allToken (s : Bytes) : Bool := s.all isTokenByte

/-- RFC 6265 `cookie-octet` (the byte test in flare/http/cookie.mojo:195-201 @59bda50). -/
def isCookieOctet (c : UInt8) : Bool :=
  c.toNat == 0x21 || (0x23 ≤ c.toNat && c.toNat ≤ 0x2B) || (0x2D ≤ c.toNat && c.toNat ≤ 0x3A) ||
  (0x3C ≤ c.toNat && c.toNat ≤ 0x5B) || (0x5D ≤ c.toNat && c.toNat ≤ 0x7E)

/-- mirrors flare/http/cookie.mojo:185-204 @59bda50 -/
def isCookieValue (s : Bytes) : Bool :=
  if 2 ≤ s.length ∧ s.head? = some 34 ∧ s.getLast? = some 34 then
    ((s.drop 1).take (s.length - 2)).all isCookieOctet
  else s.all isCookieOctet

/-- mirrors flare/http/cookie.mojo:207-212 @59bda50 -/
def isAvByte (c : UInt8) : Bool := !(c.toNat < 32 || c.toNat == 127 || c.toNat == 59)

def isAvValue (s : Bytes) : Bool := s.all isAvByte

/-- Mojo `String.strip()` whitespace set (ASCII: `\t\n\v\f\r`, 0x1C-0x1E,
space; checked against Mojo 1.1.0: `"\x1c\x1d\x1e\x0b a \x0c".strip()` has
byte length 1). -/
def isWs (c : UInt8) : Bool := [9, 10, 11, 12, 13, 28, 29, 30, 32].contains c

def isSpTab (c : UInt8) : Bool := c == 32 || c == 9

theorem byte_forall (P : UInt8 → Prop) (h : ∀ n : Fin 256, P (UInt8.ofNat n.val)) :
    ∀ x, P x := by
  intro x
  have := h ⟨x.toNat, x.toNat_lt⟩
  simpa using this

set_option maxRecDepth 100000 in
/-- Facts about every byte a valid cookie value may contain. -/
theorem valueByte_facts : ∀ x : UInt8, (x = 34 ∨ isCookieOctet x = true) →
    x ≠ 59 ∧ isWs x = false ∧ 32 ≤ x.toNat ∧ x.toNat ≠ 127 :=
  byte_forall _ (by decide)

set_option maxRecDepth 100000 in
theorem tokenByte_facts : ∀ x : UInt8, isTokenByte x = true →
    x ≠ 59 ∧ x ≠ 61 ∧ isWs x = false ∧ isSpTab x = false ∧ 32 ≤ x.toNat ∧ x.toNat ≠ 127 :=
  byte_forall _ (by decide)

set_option maxRecDepth 100000 in
theorem avByte_facts : ∀ x : UInt8, isAvByte x = true → x ≠ 59 ∧ 32 ≤ x.toNat ∧ x.toNat ≠ 127 :=
  byte_forall _ (by decide)

theorem cookieValue_bytes (s : Bytes) (h : isCookieValue s = true) :
    ∀ x ∈ s, x = 34 ∨ isCookieOctet x = true := by
  intro x hx
  unfold isCookieValue at h
  split at h
  · rename_i hq
    obtain ⟨hlen, hhd, hlast⟩ := hq
    obtain ⟨ys, rfl⟩ := List.getLast?_eq_some_iff.mp hlast
    cases ys with
    | nil => simp at hlen
    | cons a ys =>
      simp at hhd; subst hhd
      have e : ((34 :: ys ++ [34]).drop 1).take ((34 :: ys ++ [34]).length - 2) = ys := by simp
      rw [e] at h
      simp only [List.cons_append, List.mem_cons, List.mem_append] at hx
      rcases hx with hx | hx | hx
      · exact Or.inl hx
      · exact Or.inr ((List.all_eq_true.mp h) x hx)
      · exact Or.inl (by simpa using hx)
  · exact Or.inr ((List.all_eq_true.mp h) x hx)

/-! ## Set-Cookie serialisation -/

structure Cookie where
  name : Bytes
  value : Bytes
  domain : Bytes
  path : Bytes
  maxAge : Int
  secure : Bool
  httpOnly : Bool
  sameSite : Bytes

def DOMAIN_EQ : Bytes := [68, 111, 109, 97, 105, 110, 61]          -- "Domain="
def PATH_EQ : Bytes := [80, 97, 116, 104, 61]                      -- "Path="
def MAXAGE_EQ : Bytes := [77, 97, 120, 45, 65, 103, 101, 61]       -- "Max-Age="
def SECURE : Bytes := [83, 101, 99, 117, 114, 101]                 -- "Secure"
def HTTPONLY : Bytes := [72, 116, 116, 112, 79, 110, 108, 121]     -- "HttpOnly"
def SAMESITE_EQ : Bytes := [83, 97, 109, 101, 83, 105, 116, 101, 61] -- "SameSite="
def STRICT : Bytes := [83, 116, 114, 105, 99, 116]                 -- "Strict"
def LAX : Bytes := [76, 97, 120]                                   -- "Lax"
def NONE : Bytes := [78, 111, 110, 101]                            -- "None"

def asciiLower (s : Bytes) : Bytes :=
  s.map fun c => if 65 ≤ c.toNat ∧ c.toNat ≤ 90 then c + 32 else c

/-- SameSite normalisation; `none` = raise. (Mojo `String.lower()` is
modelled as ASCII lowering; no non-ASCII code point lowers to one of the
letters of `strict`/`lax`/`none`.) mirrors flare/http/cookie.mojo:112-122 @59bda50 -/
def normSameSite (ss : Bytes) : Option Bytes :=
  if ss = [] then some []
  else if asciiLower ss = [115, 116, 114, 105, 99, 116] then some STRICT
  else if asciiLower ss = [108, 97, 120] then some LAX
  else if asciiLower ss = [110, 111, 110, 101] then some NONE
  else none

/-- `String(n)` for `n ≥ 0`. -/
def decimal (n : Nat) : Bytes :=
  if n < 10 then [UInt8.ofNat (48 + n)] else decimal (n / 10) ++ [UInt8.ofNat (48 + n % 10)]
termination_by n
decreasing_by omega

theorem decimal_digits (n : Nat) : ∀ x ∈ decimal n, 48 ≤ x.toNat ∧ x.toNat ≤ 57 := by
  rw [decimal.eq_def]
  split
  · intro x hx; simp at hx; subst hx; simp [UInt8.toNat_ofNat]; omega
  · intro x hx
    simp only [List.mem_append, List.mem_singleton] at hx
    rcases hx with hx | hx
    · exact decimal_digits (n / 10) x hx
    · subst hx; simp [UInt8.toNat_ofNat]; omega
termination_by n
decreasing_by omega

/-- `out += "; <attr>"` when `b`. -/
def opt (b : Bool) (attr : Bytes) : Bytes := if b then [59, 32] ++ attr else []

/-- mirrors flare/http/cookie.mojo:89-136 @59bda50 -/
def toSetCookie (c : Cookie) : Option Bytes :=
  if c.name = [] ∨ allToken c.name = false then none
  else if isCookieValue c.value = false then none
  else if isAvValue c.domain = false ∨ isAvValue c.path = false then none
  else match normSameSite c.sameSite with
  | none => none
  | some ss =>
    some (c.name ++ [61] ++ c.value
      ++ opt (c.domain ≠ []) (DOMAIN_EQ ++ c.domain)
      ++ opt (c.path ≠ []) (PATH_EQ ++ c.path)
      ++ opt (c.maxAge ≥ 0) (MAXAGE_EQ ++ decimal c.maxAge.toNat)
      ++ opt (c.secure || ss == NONE) SECURE
      ++ opt c.httpOnly HTTPONLY
      ++ opt (ss ≠ []) (SAMESITE_EQ ++ ss))

/-! ### Spec: the attributes the caller asked for (RFC 6265 §4.1.1 cookie-av) -/

def piece (b : Bool) (a : Bytes) : List Bytes := if b then [a] else []

/-- The intended attribute list, in flare's emission order. `Secure` is
intended when requested or when SameSite=None (browsers reject
`SameSite=None` without `Secure`). -/
def intendedAttrs (c : Cookie) (ss : Bytes) : List Bytes :=
  piece (c.domain ≠ []) (DOMAIN_EQ ++ c.domain) ++ piece (c.path ≠ []) (PATH_EQ ++ c.path) ++
  piece (c.maxAge ≥ 0) (MAXAGE_EQ ++ decimal c.maxAge.toNat) ++
  piece (c.secure || ss == NONE) SECURE ++ piece c.httpOnly HTTPONLY ++
  piece (ss ≠ []) (SAMESITE_EQ ++ ss)

def joinAttrs (as : List Bytes) : Bytes := (as.map fun a => [59, 32] ++ a).flatten

theorem opt_eq (b : Bool) (a : Bytes) : opt b a = joinAttrs (piece b a) := by
  cases b <;> simp [opt, piece, joinAttrs]

theorem joinAttrs_append (a b : List Bytes) : joinAttrs (a ++ b) = joinAttrs a ++ joinAttrs b := by
  simp [joinAttrs]

/-- Split at every `;` (the cookie-av separator). -/
def splitSemi : Bytes → List Bytes
  | [] => [[]]
  | c :: r =>
    if c = 59 then [] :: splitSemi r
    else match splitSemi r with
      | x :: xs => (c :: x) :: xs
      | [] => [[c]]

theorem splitSemi_noSemi (a : Bytes) (h : 59 ∉ a) : splitSemi a = [a] := by
  induction a with
  | nil => rfl
  | cons c a ih =>
    simp only [List.mem_cons, not_or] at h
    simp [splitSemi, Ne.symm h.1, ih h.2]

theorem splitSemi_append (a b : Bytes) (h : 59 ∉ a) : splitSemi (a ++ 59 :: b) = a :: splitSemi b := by
  induction a with
  | nil => simp [splitSemi]
  | cons c a ih =>
    simp only [List.mem_cons, not_or] at h
    simp [splitSemi, Ne.symm h.1, ih h.2]

theorem splitSemi_join (as : List Bytes) (has : ∀ a ∈ as, 59 ∉ a) (p : Bytes) (hp : 59 ∉ p) :
    splitSemi (p ++ joinAttrs as) = p :: as.map (32 :: ·) := by
  induction as generalizing p with
  | nil => simp [joinAttrs, splitSemi_noSemi p hp]
  | cons a as ih =>
    have ha := has a (by simp)
    have : p ++ joinAttrs (a :: as) = p ++ 59 :: ((32 :: a) ++ joinAttrs as) := by
      simp [joinAttrs]
    rw [this, splitSemi_append _ _ hp, ih (fun x hx => has x (by simp [hx])) (32 :: a) (by simp; exact ha)]
    simp

/-- The impl's output is `name=value` followed by the intended attributes,
each prefixed `"; "`. -/
theorem toSetCookie_shape (c : Cookie) (out : Bytes) (h : toSetCookie c = some out) :
    ∃ ss, normSameSite c.sameSite = some ss ∧
      out = c.name ++ [61] ++ c.value ++ joinAttrs (intendedAttrs c ss) := by
  unfold toSetCookie at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h
  · simp at h
  · rename_i ss hss
    refine ⟨ss, hss, ?_⟩
    simp only [Option.some.injEq] at h
    rw [← h]
    simp only [intendedAttrs, joinAttrs_append, opt_eq, List.append_assoc]

theorem toSetCookie_valid (c : Cookie) (out : Bytes) (h : toSetCookie c = some out) :
    c.name ≠ [] ∧ allToken c.name = true ∧ isCookieValue c.value = true ∧
      isAvValue c.domain = true ∧ isAvValue c.path = true := by
  unfold toSetCookie at h
  split at h; · simp at h
  rename_i h1
  split at h; · simp at h
  rename_i h2
  split at h; · simp at h
  rename_i h3
  simp only [not_or, Bool.not_eq_false] at h1 h2 h3
  exact ⟨h1.1, h1.2, h2, h3.1, h3.2⟩

theorem normSameSite_cases (s ss : Bytes) (h : normSameSite s = some ss) :
    ss = [] ∨ ss = STRICT ∨ ss = LAX ∨ ss = NONE := by
  unfold normSameSite at h
  split at h
  · cases h; simp
  · split at h
    · cases h; simp
    · split at h
      · cases h; simp
      · split at h
        · cases h; simp
        · cases h

def Clean (a : Bytes) : Prop := ∀ x ∈ a, x ≠ 59 ∧ 32 ≤ x.toNat ∧ x.toNat ≠ 127

instance (a : Bytes) : Decidable (Clean a) := by unfold Clean; infer_instance

theorem clean_app {a b : Bytes} (ha : Clean a) (hb : Clean b) : Clean (a ++ b) := by
  intro x hx; simp only [List.mem_append] at hx; rcases hx with hx | hx
  · exact ha x hx
  · exact hb x hx

theorem mem_piece {b : Bool} {x a : Bytes} (h : a ∈ piece b x) : a = x := by
  cases b <;> simp [piece] at h; exact h

theorem clean_av (s : Bytes) (hs : isAvValue s = true) : Clean s :=
  fun x hx => avByte_facts x ((List.all_eq_true.mp hs) x hx)

theorem clean_decimal (n : Nat) : Clean (decimal n) := by
  intro x hx
  have := decimal_digits _ x hx
  refine ⟨?_, by omega, by omega⟩
  intro e; subst e; simp at this

/-- Every attribute flare emits is `;`-free and control-free. -/
theorem intendedAttrs_clean (c : Cookie) (ss : Bytes) (hss : normSameSite c.sameSite = some ss)
    (hd : isAvValue c.domain = true) (hp : isAvValue c.path = true) :
    ∀ a ∈ intendedAttrs c ss, Clean a := by
  have hs : Clean ss := by
    rcases normSameSite_cases _ _ hss with e | e | e | e <;> subst e <;> decide
  intro a ha
  simp only [intendedAttrs, List.mem_append, or_assoc] at ha
  rcases ha with ha | ha | ha | ha | ha | ha <;> rw [mem_piece ha]
  · exact clean_app (by decide) (clean_av _ hd)
  · exact clean_app (by decide) (clean_av _ hp)
  · exact clean_app (by decide) (clean_decimal _)
  · decide
  · decide
  · exact clean_app (by decide) hs

/-- **Injection freedom.** Splitting the emitted header at `;` yields exactly
`name=value` followed by the intended attributes (each after one SP): no
field can introduce or alter an attribute. -/
theorem toSetCookie_split (c : Cookie) (out : Bytes) (h : toSetCookie c = some out) :
    ∃ ss, normSameSite c.sameSite = some ss ∧
      splitSemi out = (c.name ++ [61] ++ c.value) :: (intendedAttrs c ss).map (32 :: ·) := by
  obtain ⟨-, htok, hval, hd, hp⟩ := toSetCookie_valid c out h
  obtain ⟨ss, hss, rfl⟩ := toSetCookie_shape c out h
  refine ⟨ss, hss, ?_⟩
  apply splitSemi_join
  · intro a ha hm
    exact (intendedAttrs_clean c ss hss hd hp a ha 59 hm).1 rfl
  · simp only [List.mem_append, List.mem_singleton, not_or]
    refine ⟨⟨fun hm => (tokenByte_facts _ ((List.all_eq_true.mp htok) _ hm)).1 rfl,
      by decide⟩, fun hm => ?_⟩
    exact (valueByte_facts _ (cookieValue_bytes _ hval _ hm)).1 rfl

/-- **No CR/LF (no header splitting).** Every byte of the emitted value is
`≥ 0x20` and `≠ 0x7F`. -/
theorem toSetCookie_noCtl (c : Cookie) (out : Bytes) (h : toSetCookie c = some out) :
    ∀ x ∈ out, 32 ≤ x.toNat ∧ x.toNat ≠ 127 := by
  obtain ⟨-, htok, hval, hd, hp⟩ := toSetCookie_valid c out h
  obtain ⟨ss, hss, rfl⟩ := toSetCookie_shape c out h
  intro x hx
  simp only [List.mem_append, List.mem_singleton] at hx
  rcases hx with ((hx | hx) | hx) | hx
  · have := tokenByte_facts _ ((List.all_eq_true.mp htok) _ hx); exact ⟨this.2.2.2.2.1, this.2.2.2.2.2⟩
  · subst hx; decide
  · have := valueByte_facts _ (cookieValue_bytes _ hval _ hx); exact ⟨this.2.2.1, this.2.2.2⟩
  · simp only [joinAttrs, List.mem_flatten, List.mem_map] at hx
    obtain ⟨_, ⟨a, ha, rfl⟩, hx⟩ := hx
    simp only [List.cons_append, List.nil_append, List.mem_cons] at hx
    rcases hx with hx | hx | hx
    · subst hx; decide
    · subst hx; decide
    · have := intendedAttrs_clean c ss hss hd hp a ha x hx; exact ⟨this.2.1, this.2.2⟩

/-- Corollary: no CR (13) or LF (10) byte. -/
theorem toSetCookie_noCRLF (c : Cookie) (out : Bytes) (h : toSetCookie c = some out) :
    (13 : UInt8) ∉ out ∧ (10 : UInt8) ∉ out := by
  constructor <;> intro hm <;> have := (toSetCookie_noCtl c out h _ hm).1 <;> simp at this

/-- **SameSite=None ⇒ Secure**: if the caller asked for SameSite=None (any
case), the header carries the `Secure` attribute. -/
theorem toSetCookie_none_secure (c : Cookie) (out : Bytes) (h : toSetCookie c = some out)
    (hn : asciiLower c.sameSite = [110, 111, 110, 101]) :
    ∃ pre post, out = pre ++ [59, 32] ++ SECURE ++ post := by
  obtain ⟨ss, hss, rfl⟩ := toSetCookie_shape c out h
  have hne : c.sameSite ≠ [] := by intro e; rw [e] at hn; simp [asciiLower] at hn
  have : ss = NONE := by
    unfold normSameSite at hss
    simp only [hne, if_false, hn] at hss
    simp at hss; exact hss.symm
  subst this
  refine ⟨c.name ++ [61] ++ c.value ++ joinAttrs (piece (c.domain ≠ []) (DOMAIN_EQ ++ c.domain) ++
      piece (c.path ≠ []) (PATH_EQ ++ c.path) ++ piece (c.maxAge ≥ 0) (MAXAGE_EQ ++ decimal c.maxAge.toNat)),
    joinAttrs (piece c.httpOnly HTTPONLY ++ piece (NONE ≠ []) (SAMESITE_EQ ++ NONE)), ?_⟩
  simp [intendedAttrs, joinAttrs, piece]

/-! ## Max-Age (`_parse_max_age`) -/

def isDigit (c : UInt8) : Bool := 48 ≤ c.toNat && c.toNat ≤ 57

/-- The digit loop with Mojo `Int` (wrapping Int64) arithmetic.
mirrors flare/http/cookie.mojo:158-164 @59bda50 -/
def digitsAcc : Bytes → Int64 → Option Int64
  | [], acc => some acc
  | c :: r, acc =>
    if c.toNat < 48 ∨ c.toNat > 57 then none
    else digitsAcc r (mojoInt (acc.toInt * 10 + ((c.toNat : Int) - 48)))

/-- The digit string after an optional leading `-`. -/
def digitsPart (c : UInt8) (r : Bytes) : Bytes := if c = 45 then r else c :: r

/-- `none` = `_MAX_AGE_IGNORED`. mirrors flare/http/cookie.mojo:146-165 @59bda50 -/
def parseMaxAge (v : Bytes) : Option Int64 :=
  match v with
  | [] => none
  | c :: r =>
    if (digitsPart c r).length = 0 ∨ (digitsPart c r).length > 18 then none
    else (digitsAcc (digitsPart c r) 0).map fun acc => if c = 45 then mojoInt (-acc.toInt) else acc

/-- Decimal value of a digit string (spec side). -/
def decVal : Bytes → Nat → Nat
  | [], a => a
  | c :: r, a => decVal r (a * 10 + (c.toNat - 48))

/-- RFC 6265 §5.2.2: first char DIGIT or `-`, remainder all DIGITs, value
= the signed decimal. (An empty digit string is ignored.) -/
def specMaxAge (v : Bytes) : Option Int :=
  match v with
  | [] => none
  | c :: r =>
    if digitsPart c r = [] ∨ (digitsPart c r).all isDigit = false then none
    else some (if c = 45 then -(decVal (digitsPart c r) 0 : Int) else (decVal (digitsPart c r) 0 : Int))

theorem decVal_lt (ds : Bytes) (a : Nat) (h : ds.all isDigit = true) :
    decVal ds a < (a + 1) * 10 ^ ds.length := by
  induction ds generalizing a with
  | nil => simp [decVal]
  | cons c r ih =>
    simp only [List.all_cons, Bool.and_eq_true, isDigit, decide_eq_true_eq] at h
    simp only [decVal, List.length_cons, Nat.pow_succ]
    have := ih (a * 10 + (c.toNat - 48)) (by simpa [isDigit] using h.2)
    have h1 : a * 10 + (c.toNat - 48) + 1 ≤ (a + 1) * 10 := by omega
    have h2 := Nat.mul_le_mul_right (10 ^ r.length) h1
    rw [Nat.mul_comm (a+1) 10, Nat.mul_assoc] at h2
    have e : 10 * ((a + 1) * 10 ^ r.length) = (a + 1) * (10 ^ r.length * 10) := by
      rw [Nat.mul_comm 10, Nat.mul_assoc]
    exact Nat.lt_of_lt_of_le this (Nat.le_trans h2 (Nat.le_of_eq e))

theorem fits_of_lt (n : Int) (h0 : -(10 ^ 18 : Int) < n) (h1 : n < 10 ^ 18) : fitsI64 n := by
  unfold fitsI64 I64_MIN I64_MAX
  have : (10 : Int) ^ 18 < 2 ^ 63 - 1 := by decide
  constructor <;> omega

theorem digitsAcc_spec (ds : Bytes) (acc : Int64) (a : Nat) (ha : acc.toInt = a)
    (hb : (a + 1) * 10 ^ ds.length ≤ 10 ^ 18) :
    digitsAcc ds acc = if ds.all isDigit then some (mojoInt (decVal ds a)) else none := by
  induction ds generalizing acc a with
  | nil =>
    simp only [digitsAcc, List.all_nil, if_true, decVal]
    congr 1
    apply Int64.toInt_inj.mp
    rw [mojoInt_toInt_of_fits _ (fits_of_lt _ (by omega) (by simp at hb; omega)), ha]
  | cons c r ih =>
    simp only [digitsAcc, List.all_cons, isDigit, decVal]
    by_cases hc : c.toNat < 48 ∨ c.toNat > 57
    · simp only [hc, if_true]
      have : ¬ (48 ≤ c.toNat ∧ c.toNat ≤ 57) := by omega
      simp [this]
    · simp only [hc, if_false]
      have hd : (decide (48 ≤ c.toNat) && decide (c.toNat ≤ 57)) = true := by simp; omega
      simp only [hd, Bool.true_and]
      have hp : 1 ≤ 10 ^ r.length := Nat.one_le_pow _ _ (by omega)
      have hb' : (a * 10 + (c.toNat - 48) + 1) * 10 ^ r.length ≤ 10 ^ 18 := by
        have h1 : a * 10 + (c.toNat - 48) + 1 ≤ (a + 1) * 10 := by omega
        have h2 := Nat.mul_le_mul_right (10 ^ r.length) h1
        simp only [List.length_cons, Nat.pow_succ] at hb
        rw [Nat.mul_assoc, Nat.mul_comm 10] at h2
        omega
      have hfit : a * 10 + (c.toNat - 48) < 10 ^ 18 := by
        have := Nat.le_mul_of_pos_right (a * 10 + (c.toNat - 48) + 1) hp
        omega
      apply ih
      · rw [mojoInt_toInt_of_fits _ (fits_of_lt _ (by omega) (by push_cast; omega)), ha]
        push_cast; omega
      · exact hb'

theorem pow_len_le (ds : Bytes) (h : ds.length ≤ 18) : (0 + 1) * 10 ^ ds.length ≤ 10 ^ 18 := by
  simp only [Nat.zero_add, Nat.one_mul]
  exact Nat.pow_le_pow_right (by omega) h

/-- Core lemma: for an accepted digit string, the result equals the
mathematical signed decimal and lies strictly inside `(-10^18, 10^18)`. -/
theorem parseMaxAge_core (c : UInt8) (rest : Bytes) (r : Int64) (h : parseMaxAge (c :: rest) = some r) :
    digitsPart c rest ≠ [] ∧ (digitsPart c rest).all isDigit = true ∧
      r.toInt = (if c = 45 then -(decVal (digitsPart c rest) 0 : Int) else (decVal (digitsPart c rest) 0 : Int)) ∧
      (decVal (digitsPart c rest) 0 : Int) < 10 ^ 18 := by
  simp only [parseMaxAge] at h
  split at h
  · cases h
  rename_i hl
  simp only [not_or, Nat.not_lt] at hl
  rw [digitsAcc_spec (digitsPart c rest) 0 0 (by decide) (pow_len_le _ hl.2)] at h
  by_cases hall : (digitsPart c rest).all isDigit = true
  · rw [if_pos hall] at h
    simp only [Option.map_some, Option.some.injEq] at h
    have hlt := decVal_lt _ 0 hall
    have hpow : 10 ^ (digitsPart c rest).length ≤ 10 ^ 18 := Nat.pow_le_pow_right (by omega) hl.2
    simp only [Nat.zero_add, Nat.one_mul] at hlt
    have hlt' : (decVal (digitsPart c rest) 0 : Int) < 10 ^ 18 := by
      have : decVal (digitsPart c rest) 0 < 10 ^ 18 := by omega
      exact_mod_cast this
    have hf : fitsI64 (decVal (digitsPart c rest) 0) := fits_of_lt _ (by omega) hlt'
    have hne : digitsPart c rest ≠ [] := by
      intro e; rw [e] at hl; simp at hl
    refine ⟨hne, hall, ?_, hlt'⟩
    rw [← h]
    split
    · rw [mojoInt_toInt_of_fits _ hf]
      rw [mojoInt_toInt_of_fits _ (fits_of_lt _ (by omega) (by omega))]
    · rw [mojoInt_toInt_of_fits _ hf]
  · rw [if_neg hall] at h; cases h

/-- **Soundness, no wraparound**: whenever flare accepts a Max-Age, its
`Int` value equals the RFC 6265 §5.2.2 value. -/
theorem parseMaxAge_sound (v : Bytes) (r : Int64) (h : parseMaxAge v = some r) :
    specMaxAge v = some r.toInt := by
  cases v with
  | nil => simp [parseMaxAge] at h
  | cons c rest =>
    obtain ⟨hne, hall, hr, -⟩ := parseMaxAge_core c rest r h
    simp only [specMaxAge, hne, hall, false_or, if_false, Bool.true_eq_false, hr]

/-- **Bounded completeness**: every RFC-valid Max-Age with at most 18
digits is accepted with its exact value. -/
theorem parseMaxAge_complete (c : UInt8) (rest : Bytes) (x : Int)
    (h : specMaxAge (c :: rest) = some x) (hl : (digitsPart c rest).length ≤ 18) :
    ∃ r, parseMaxAge (c :: rest) = some r ∧ r.toInt = x := by
  simp only [specMaxAge] at h
  split at h
  · cases h
  rename_i hc
  simp only [not_or, Bool.not_eq_false] at hc
  have hd := digitsAcc_spec (digitsPart c rest) 0 0 (by decide) (pow_len_le _ hl)
  have hlen : (digitsPart c rest).length ≠ 0 := by
    intro e; exact hc.1 (List.eq_nil_of_length_eq_zero e)
  have hp : parseMaxAge (c :: rest) =
      some ((fun acc : Int64 => if c = 45 then mojoInt (-acc.toInt) else acc)
        (mojoInt (decVal (digitsPart c rest) 0))) := by
    simp only [parseMaxAge]; rw [if_neg (by omega), hd, if_pos hc.2]; rfl
  refine ⟨_, hp, ?_⟩
  have h' := parseMaxAge_sound (c :: rest) _ hp
  simp only [specMaxAge, hc.1, hc.2, false_or, if_false, Bool.true_eq_false, Option.some.injEq] at h'
  simp only [Option.some.injEq] at h
  rw [← h', h]

/-- Results lie strictly inside `(-10^18, 10^18)`, hence never equal the
sentinel `_MAX_AGE_IGNORED = -(2^62)`, so modelling it as `none` is sound. -/
theorem parseMaxAge_bound (v : Bytes) (r : Int64) (h : parseMaxAge v = some r) :
    -(10 ^ 18 : Int) < r.toInt ∧ r.toInt < 10 ^ 18 ∧ r.toInt ≠ -(2 ^ 62) := by
  cases v with
  | nil => simp [parseMaxAge] at h
  | cons c rest =>
    obtain ⟨-, -, hr, hlt⟩ := parseMaxAge_core c rest r h
    have h62 : (10 : Int) ^ 18 < 2 ^ 62 := by decide
    have h0 : (0 : Int) ≤ (decVal (digitsPart c rest) 0 : Int) := by omega
    rw [hr]; split <;> refine ⟨by omega, by omega, by omega⟩

/-- Documented deviation (by design): more than 18 digits are ignored. -/
theorem parseMaxAge_long (c : UInt8) (rest : Bytes) (hl : (digitsPart c rest).length > 18) :
    parseMaxAge (c :: rest) = none := by
  simp only [parseMaxAge]; rw [if_pos (Or.inr hl)]

end Flare.L4.Cookie
