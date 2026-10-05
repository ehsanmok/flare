import Flare.Core.Bytes
import Flare.Core.Word
import Std.Tactic.BVDecide

/-!
# `Url.parse` (flare/http/url.mojo)

Byte-level model of flare's HTTP URL parser. Mojo `String`s are modelled as
`Bytes`; the helper `_find` returns `-1` for "absent", modelled as `none`.

Pipeline (mirrors the Mojo control flow, step numbers as in the source):

1. scheme = bytes before the first `"://"`, must be `http` or `https`;
2. fragment = bytes after the **first** `#` (`_find`; the pre-fix code used the
   last `#`, `splitFragmentOld`);
3. authority = bytes before the first `/` or `?`; the rest is path-and-query
   (pre-fix: only `/`, `splitAuthorityOld`);
4. query = bytes after the first `?` of path-and-query;
5. userinfo stripped through the **last** `@` (the pre-fix code used the first); then IPv6 `[..]` or
   `host[:port]` with the port after the **last** `:`.

Spec side (RFC 3986 §3, §3.2, §3.2.2, §3.2.3), written independently:

* `specAuthority rest` – the authority is the longest prefix of the
  hier-part after `"//"` that contains none of `/`, `?`, `#` (§3.2: "The
  authority component ... is terminated by the next slash ("/"), question
  mark ("?"), or number sign ("#") character, or by the end of the URI").
* the host is a contiguous piece of the authority (`HostInAuthority`);
* no RFC 3986 host form (IP-literal, IPv4address, reg-name) contains `@`
  (`HostNoAt`);
* port = `*DIGIT` (flare additionally bounds it to `1..65535`).

The `parseWith` combinator is parameterised by the three splitting steps so
that the buggy pipeline (`parse`) and the fixed ones (`Flare.Bugs.APP_23`,
`Flare.Bugs.APP_25`) share every other line. After the APP-23 and APP-25
fixes `parse` uses the first-`#` fragment split, the `/`-or-`?` authority
split and the last-`@` userinfo strip; `parseOld` is the pre-fix pipeline.
-/
namespace Flare.L4.Url
open Flare

/-! ## Byte constants -/

abbrev cHash : UInt8 := 35
abbrev cSlash : UInt8 := 47
abbrev cColon : UInt8 := 58
abbrev cQ : UInt8 := 63
abbrev cAt : UInt8 := 64
abbrev cLBr : UInt8 := 91
abbrev cRBr : UInt8 := 93

def httpB : Bytes := [104, 116, 116, 112]
def httpsB : Bytes := [104, 116, 116, 112, 115]
def sepB : Bytes := [58, 47, 47]

/-! ## Search helpers -/

/-- mirrors flare/http/url.mojo:218-238 @59bda50 (`_find`: first index `i`
with `sub` a prefix of `s[i:]`; `-1` ↦ `none`; empty `sub` ↦ `0`). -/
def find : Bytes → Bytes → Option Nat
  | [], sub => if sub = [] then some 0 else none
  | c :: cs, sub => if sub.isPrefixOf (c :: cs) then some 0 else (find cs sub).map (· + 1)

/-- First index whose byte satisfies `p`. `_find(s, "<b>")` for a one-byte
needle is `idxWhere (· == b)` (`find_single`). -/
def idxWhere (p : UInt8 → Bool) : Bytes → Option Nat
  | [] => none
  | c :: cs => if p c then some 0 else (idxWhere p cs).map (· + 1)

abbrev idxOf (b : UInt8) (s : Bytes) : Option Nat := idxWhere (· == b) s

theorem idxOf_eq (b : UInt8) (s : Bytes) : idxOf b s = idxWhere (· == b) s := rfl

/-- mirrors flare/http/url.mojo:241-261 @59bda50 (`_rfind`, used only with
one-byte needles `"#"` and `":"`): index of the last occurrence. -/
def rfindB (b : UInt8) : Bytes → Option Nat
  | [] => none
  | c :: cs =>
    match rfindB b cs with
    | some i => some (i + 1)
    | none => if c = b then some 0 else none

theorem find_single (b : UInt8) (s : Bytes) : find s [b] = idxOf b s := by
  induction s with
  | nil => simp [find, idxWhere]
  | cons c cs ih =>
    simp only [find, idxWhere, ih, List.isPrefixOf, Bool.and_true]
    by_cases h : c = b
    · subst h; simp
    · have : (b == c) = false := by simp; exact fun e => h e.symm
      simp [this, h]

/-! ## Port and default port -/

/-- mirrors flare/http/url.mojo:264-269 @59bda50 -/
def defaultPort (scheme : Bytes) : Nat := if scheme = httpsB then 443 else 80

def isDigit (c : UInt8) : Bool := 48 ≤ c && c ≤ 57

/-- The digit loop of `_parse_port` (flare/http/url.mojo:291-296). The Mojo
accumulator is an `Int`; `parsePort_fits` shows the value never leaves the
`Int64` range, so `Nat` arithmetic is faithful. -/
def digitsAcc : Nat → Bytes → Except String Nat
  | acc, [] => .ok acc
  | acc, c :: cs =>
    if c < 48 || c > 57 then .error "invalid port" else digitsAcc (acc * 10 + (c.toNat - 48)) cs

/-- mirrors flare/http/url.mojo:272-299 @59bda50 -/
def parsePort (s : Bytes) : Except String Nat :=
  if s.length = 0 then .error "empty port"
  else if s.length > 5 then .error "port too long"
  else match digitsAcc 0 s with
    | .error e => .error e
    | .ok r => if r < 1 || r > 65535 then .error "port out of range" else .ok r

/-! ## The parser -/

structure Url where
  scheme : Bytes
  host : Bytes
  port : Nat
  path : Bytes
  query : Bytes
  fragment : Bytes
deriving DecidableEq, Repr

/-- Decidable equality on parse results (used by the concrete witnesses). -/
def decEqExcept {α : Type} [DecidableEq α] : (x y : Except String α) → Decidable (x = y)
  | .ok a, .ok b => if h : a = b then isTrue (h ▸ rfl) else isFalse (fun e => by cases e; exact h rfl)
  | .error a, .error b =>
    if h : a = b then isTrue (h ▸ rfl) else isFalse (fun e => by cases e; exact h rfl)
  | .ok _, .error _ => isFalse (fun e => by cases e)
  | .error _, .ok _ => isFalse (fun e => by cases e)

instance instDecEqExceptUrl : DecidableEq (Except String Url) := decEqExcept
instance instDecEqExceptBytes : DecidableEq (Except String Bytes) := decEqExcept

/-- `match idx with none => s | some i => s.take i`. -/
def cutAt (o : Option Nat) (s : Bytes) : Bytes := match o with | none => s | some i => s.take i

/-- Step 5b of flare/http/url.mojo:150-192 @59bda50 (IPv6 literal or
`host[:port]`, port after the last `:`). -/
def hostPort (scheme authority : Bytes) : Except String (Bytes × Nat) :=
  if authority.head? = some cLBr then
    match idxOf cRBr authority with
    | none => .error "unterminated IPv6 literal"
    | some be =>
      let host := (authority.take be).drop 1
      let after := authority.drop (be + 1)
      if after.head? = some cColon then (parsePort (after.drop 1)).map (host, ·)
      else .ok (host, defaultPort scheme)
  else
    match rfindB cColon authority with
    | some c => (parsePort (authority.drop (c + 1))).map (authority.take c, ·)
    | none => .ok (authority, defaultPort scheme)

/-- flare/http/url.mojo:143-148 @59bda50 (pre-fix, APP-25): userinfo stripped
through the **first** `@`. -/
def stripUserinfoOld (a : Bytes) : Bytes :=
  match idxOf cAt a with | some i => a.drop (i + 1) | none => a

/-- flare/http/url.mojo:101-108 @59bda50 (pre-fix, APP-23): fragment after the
**last** `#`. -/
def splitFragmentOld (s : Bytes) : Bytes × Bytes :=
  match rfindB cHash s with | some p => (s.take p, s.drop (p + 1)) | none => (s, [])

/-- flare/http/url.mojo:110-123 @59bda50 (pre-fix, APP-23): authority ends at
the first `/`. -/
def splitAuthorityOld (s : Bytes) : Bytes × Bytes :=
  match idxOf cSlash s with | none => (s, [cSlash]) | some p => (s.take p, s.drop p)

/-- flare/http/url.mojo:125-140 @59bda50 -/
def splitQuery (pq : Bytes) : Bytes × Bytes :=
  match idxOf cQ pq with | some q => (pq.take q, pq.drop (q + 1)) | none => (pq, [])

/-- Steps 2-5 of flare/http/url.mojo:101-197 @59bda50, parameterised by the
fragment split, the authority split and the userinfo strip. -/
def parseRestWith (sf sa : Bytes → Bytes × Bytes) (strip : Bytes → Bytes)
    (scheme s : Bytes) : Except String Url :=
  let s1 := (sf s).1
  let fragment := (sf s).2
  let authority := (sa s1).1
  let pq := (sa s1).2
  let path0 := (splitQuery pq).1
  let query := (splitQuery pq).2
  let path := if path0 = [] then [cSlash] else path0
  match hostPort scheme (strip authority) with
  | .error e => .error e
  | .ok (host, port) =>
    if host = [] then .error "missing host"
    else .ok ⟨scheme, host, port, path, query, fragment⟩

/-- mirrors flare/http/url.mojo:73-197 @59bda50 (step 1, then `parseRestWith`). -/
def parseWith (sf sa : Bytes → Bytes × Bytes) (strip : Bytes → Bytes) (raw : Bytes) :
    Except String Url :=
  match find raw sepB with
  | none => .error "missing scheme"
  | some se =>
    let scheme := raw.take se
    if scheme ≠ httpB ∧ scheme ≠ httpsB then .error "unsupported scheme"
    else parseRestWith sf sa strip scheme (raw.drop (se + 3))

/-- Fragment starts at the **first** `#` (RFC 3986 §3.5, WHATWG).
mirrors flare/http/url.mojo:101-109 (fixed, APP-23) -/
def splitFragment (s : Bytes) : Bytes × Bytes :=
  match idxOf cHash s with | some p => (s.take p, s.drop (p + 1)) | none => (s, [])

/-- Authority ends at the first `/` **or `?`** (RFC 3986 §3.2).
mirrors flare/http/url.mojo:111-135 (fixed, APP-23) -/
def splitAuthority (s : Bytes) : Bytes × Bytes :=
  match idxWhere (fun c => c == cSlash || c == cQ) s with
  | none => (s, [cSlash]) | some p => (s.take p, s.drop p)

/-! ## Userinfo strip as shipped (fixed, APP-25) -/

/-- Userinfo stripped through the **last** `@` (WHATWG, curl): `_rfind(authority,
"@")`.
mirrors flare/http/url.mojo:155-162 (fixed, APP-25) -/
def stripUserinfo (a : Bytes) : Bytes :=
  match rfindB cAt a with | some i => a.drop (i + 1) | none => a

/-- mirrors flare/http/url.mojo:73-205 (fixed, APP-23, APP-25): `Url.parse` as
shipped. -/
def parse : Bytes → Except String Url := parseWith splitFragment splitAuthority stripUserinfo

/-- mirrors flare/http/url.mojo:73-197 @59bda50: `Url.parse` before the
APP-23 / APP-25 fixes (fragment at the last `#`, authority ends only at `/`,
userinfo through the first `@`). -/
def parseOld : Bytes → Except String Url :=
  parseWith splitFragmentOld splitAuthorityOld stripUserinfoOld

/-! ## Spec (RFC 3986 §3.2) -/

def isAuthEnd (c : UInt8) : Bool := c == cSlash || c == cQ || c == cHash

/-- RFC 3986 §3.2: the authority is terminated by the first `/`, `?` or `#`. -/
def specAuthority (rest : Bytes) : Bytes := rest.takeWhile (fun c => !isAuthEnd c)

/-- The host is a contiguous piece of the RFC authority of the input. -/
def HostInAuthority (raw : Bytes) (u : Url) : Prop :=
  ∀ rest, raw = u.scheme ++ sepB ++ rest → u.host <:+: specAuthority rest

/-- No RFC 3986 host form contains `@` (§3.2.2). -/
def HostNoAt (u : Url) : Prop := cAt ∉ u.host

/-! ## Port theorems -/

def decVal (s : Bytes) : Nat := s.foldl (fun a c => a * 10 + (c.toNat - 48)) 0

theorem isDigit_iff (c : UInt8) : (c < 48 || c > 57) = !isDigit c := by
  unfold isDigit; bv_decide

theorem isDigit_toNat {c : UInt8} (h : isDigit c = true) : 48 ≤ c.toNat ∧ c.toNat ≤ 57 := by
  simp [isDigit, UInt8.le_iff_toNat_le] at h; exact h

theorem digitsAcc_ok (acc : Nat) (s : Bytes) :
    digitsAcc acc s = (if s.all isDigit then .ok (s.foldl (fun a c => a * 10 + (c.toNat - 48)) acc)
      else .error "invalid port") := by
  induction s generalizing acc with
  | nil => simp [digitsAcc]
  | cons c cs ih =>
    simp only [digitsAcc, isDigit_iff, ih, List.all_cons, List.foldl_cons]
    by_cases hd : isDigit c = true <;> simp [hd]

theorem foldl_digits_lt (s : Bytes) (acc : Nat) (h : s.all isDigit) :
    s.foldl (fun a c => a * 10 + (c.toNat - 48)) acc < (acc + 1) * 10 ^ s.length := by
  induction s generalizing acc with
  | nil => simp
  | cons c cs ih =>
    simp only [List.all_cons, Bool.and_eq_true] at h
    simp only [List.foldl_cons, List.length_cons]
    have hc : c.toNat - 48 ≤ 9 := by have := isDigit_toNat h.1; omega
    have := ih (acc * 10 + (c.toNat - 48)) h.2
    calc _ < (acc * 10 + (c.toNat - 48) + 1) * 10 ^ cs.length := this
      _ ≤ (acc + 1) * 10 * 10 ^ cs.length := Nat.mul_le_mul_right _ (by omega)
      _ = (acc + 1) * 10 ^ (cs.length + 1) := by
          rw [Nat.pow_succ, Nat.mul_assoc, Nat.mul_comm 10 (10 ^ cs.length)]

/-- Spec of a port string: 1-5 decimal digits whose value is in `1..65535`.
(RFC 3986 allows `*DIGIT` of any length; the 5-digit bound is flare's.) -/
def PortSpec (s : Bytes) (n : Nat) : Prop :=
  s ≠ [] ∧ s.length ≤ 5 ∧ (∀ c ∈ s, isDigit c = true) ∧ n = decVal s ∧ 1 ≤ n ∧ n ≤ 65535

/-- `_parse_port` succeeds exactly on the port spec. -/
theorem parsePort_iff (s : Bytes) (n : Nat) : parsePort s = .ok n ↔ PortSpec s n := by
  unfold parsePort PortSpec decVal
  rw [digitsAcc_ok]
  by_cases h0 : s.length = 0
  · simp [List.length_eq_zero_iff.mp h0]
  · have hne : s ≠ [] := fun e => h0 (by simp [e])
    by_cases h5 : s.length > 5
    · simp [h0, h5]; intros; omega
    · by_cases hd : s.all isDigit
      · have hd' : ∀ c ∈ s, isDigit c = true := by simpa using hd
        simp only [h0, h5, hd, if_false, if_true]
        generalize List.foldl (fun a c => a * 10 + (c.toNat - 48)) 0 s = v
        split
        · rename_i hr; simp only [Bool.or_eq_true, decide_eq_true_eq] at hr
          simp only [reduceCtorEq, false_iff]; rintro ⟨_, _, _, rfl, h1, h2⟩; omega
        · rename_i hr; simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at hr
          simp only [Except.ok.injEq]
          constructor
          · rintro rfl; exact ⟨hne, by omega, hd', rfl, by omega, by omega⟩
          · rintro ⟨_, _, _, rfl, _, _⟩; rfl
      · have : ¬ ∀ c ∈ s, isDigit c = true := by simpa using hd
        simp [h0, h5, hd, this]

/-- No overflow: the `_parse_port` accumulator stays below `10^5`, far
inside the Mojo `Int` (Int64) range, so the 64-bit computation equals the
mathematical one. -/
theorem parsePort_fits (s : Bytes) (h5 : s.length ≤ 5) (hd : s.all isDigit) :
    decVal s < 100000 ∧ fitsI64 (decVal s) := by
  have h := foldl_digits_lt s 0 hd
  have : 10 ^ s.length ≤ 10 ^ 5 := Nat.pow_le_pow_right (by decide) h5
  unfold decVal
  constructor
  · simp at h; omega
  · unfold fitsI64 I64_MIN I64_MAX; simp at h; constructor <;> omega

theorem parsePort_range {s : Bytes} {n : Nat} (h : parsePort s = .ok n) : 1 ≤ n ∧ n ≤ 65535 := by
  have := (parsePort_iff s n).1 h; exact ⟨this.2.2.2.2.1, this.2.2.2.2.2⟩

theorem defaultPort_range (s : Bytes) : 1 ≤ defaultPort s ∧ defaultPort s ≤ 65535 := by
  unfold defaultPort; split <;> omega

theorem defaultPort_http : defaultPort httpB = 80 := by decide
theorem defaultPort_https : defaultPort httpsB = 443 := by decide

/-! ## hostPort -/

theorem map_pair_ok {x : Except String Nat} {g h : Bytes} {p : Nat}
    (e : x.map (g, ·) = .ok (h, p)) : x = .ok p ∧ g = h := by
  cases x <;> simp_all [Except.map]

theorem hostPort_ok {scheme a h : Bytes} {p : Nat} (e : hostPort scheme a = .ok (h, p)) :
    h <:+: a ∧ (p = defaultPort scheme ∨ ∃ s, parsePort s = .ok p) := by
  unfold hostPort at e
  split at e
  · split at e
    · cases e
    · simp only at e
      split at e
      · obtain ⟨h1, rfl⟩ := map_pair_ok e
        exact ⟨(List.drop_suffix _ _).isInfix.trans (List.take_prefix _ _).isInfix, .inr ⟨_, h1⟩⟩
      · cases e
        exact ⟨(List.drop_suffix _ _).isInfix.trans (List.take_prefix _ _).isInfix, .inl rfl⟩
  · split at e
    · obtain ⟨h1, rfl⟩ := map_pair_ok e
      exact ⟨(List.take_prefix _ _).isInfix, .inr ⟨_, h1⟩⟩
    · cases e; exact ⟨List.infix_refl _, .inl rfl⟩

theorem hostPort_port {scheme a h : Bytes} {p : Nat} (e : hostPort scheme a = .ok (h, p)) :
    1 ≤ p ∧ p ≤ 65535 := by
  rcases (hostPort_ok e).2 with rfl | ⟨_, hs⟩
  · exact defaultPort_range _
  · exact parsePort_range hs

theorem hostPort_infix {scheme a h : Bytes} {p : Nat} (e : hostPort scheme a = .ok (h, p)) :
    h <:+: a := (hostPort_ok e).1

/-- IPv6 literal: brackets are stripped and the default port applies. -/
theorem hostPort_ipv6 (scheme ip : Bytes) (h : cRBr ∉ ip) :
    hostPort scheme ([cLBr] ++ ip ++ [cRBr]) = .ok (ip, defaultPort scheme) := by
  have hidx : ∀ (ys : Bytes), idxOf cRBr (ip ++ cRBr :: ys) = some ip.length := by
    intro ys
    induction ip with
    | nil => simp [idxWhere]
    | cons c cs ih =>
      simp only [List.mem_cons, not_or] at h
      simp [idxWhere, Ne.symm h.1, ih h.2]
  unfold hostPort
  have e1 : idxOf cRBr ([cLBr] ++ ip ++ [cRBr]) = some (ip.length + 1) := by
    simp only [List.cons_append]
    simp [idxWhere, hidx [], show cLBr ≠ cRBr by decide]
  rw [e1]; simp

/-- IPv6 literal with an explicit port. -/
theorem hostPort_ipv6_port (scheme ip d : Bytes) (n : Nat) (h : cRBr ∉ ip)
    (hp : parsePort d = .ok n) :
    hostPort scheme ([cLBr] ++ ip ++ [cRBr, cColon] ++ d) = .ok (ip, n) := by
  have hidx : ∀ (ys : Bytes), idxOf cRBr (ip ++ cRBr :: ys) = some ip.length := by
    intro ys
    induction ip with
    | nil => simp [idxWhere]
    | cons c cs ih =>
      simp only [List.mem_cons, not_or] at h
      simp [idxWhere, Ne.symm h.1, ih h.2]
  unfold hostPort
  have e1 : idxOf cRBr ([cLBr] ++ ip ++ [cRBr, cColon] ++ d) = some (ip.length + 1) := by
    simp only [List.cons_append, List.append_assoc]
    simp [idxWhere, hidx, show cLBr ≠ cRBr by decide]
  rw [e1]; simp [hp, Except.map]

theorem rfindB_append_notMem (b : UInt8) (xs ys : Bytes) (h : b ∉ ys) :
    rfindB b (xs ++ ys) = rfindB b xs := by
  induction xs with
  | nil =>
    simp only [List.nil_append, rfindB]
    induction ys with
    | nil => rfl
    | cons c cs ih =>
      simp only [List.mem_cons, not_or] at h
      simp [rfindB, ih h.2, Ne.symm h.1]
  | cons c cs ih => simp [rfindB, ih]

theorem rfindB_none (b : UInt8) (xs : Bytes) (h : b ∉ xs) : rfindB b xs = none := by
  have := rfindB_append_notMem b [] xs h; simpa [rfindB] using this

theorem rfindB_last (b : UInt8) (xs ys : Bytes) (h : b ∉ ys) :
    rfindB b (xs ++ b :: ys) = some xs.length := by
  induction xs with
  | nil => simp [rfindB, rfindB_none b ys h]
  | cons c cs ih => simp [rfindB, ih]

/-- reg-name/IPv4 host followed by `:port` (RFC 3986 §3.2.2-3.2.3): host and
port are recovered exactly. -/
theorem hostPort_regname (scheme h d : Bytes) (n : Nat)
    (hh : cColon ∉ h) (hb : h.head? ≠ some cLBr) (hp : parsePort d = .ok n) :
    hostPort scheme (h ++ [cColon] ++ d) = .ok (h, n) := by
  have hd : cColon ∉ d := by
    intro hm
    have := ((parsePort_iff d n).1 hp).2.2.1 _ hm
    revert this; decide
  unfold hostPort
  have hhead : (h ++ [cColon] ++ d).head? ≠ some cLBr := by
    cases h with
    | nil => simp [show cColon ≠ cLBr by decide]
    | cons c cs => simpa using hb
  rw [if_neg hhead, List.append_assoc, List.singleton_append, rfindB_last _ _ _ hd]
  have hdrop : List.drop (h.length + 1) h = [] := List.drop_eq_nil_of_le (by omega)
  simp [hp, Except.map, List.drop_append, hdrop]

/-- reg-name/IPv4 host without a port: default port. -/
theorem hostPort_regname_default (scheme h : Bytes)
    (hh : cColon ∉ h) (hb : h.head? ≠ some cLBr) :
    hostPort scheme h = .ok (h, defaultPort scheme) := by
  unfold hostPort
  simp [hb, rfindB_none _ _ hh]

/-! ## Port bound for every pipeline -/

theorem parseRestWith_ok {sf sa strip scheme s} {u : Url}
    (e : parseRestWith sf sa strip scheme s = .ok u) :
    ∃ p, hostPort scheme (strip (sa (sf s).1).1) = .ok (u.host, p) ∧ u.port = p ∧
      u.scheme = scheme ∧ u.host ≠ [] := by
  unfold parseRestWith at e
  simp only at e
  split at e
  · cases e
  · rename_i host port hhp
    split at e
    · cases e
    · cases e; exact ⟨port, hhp, rfl, rfl, by assumption⟩

/-- Every successful parse (as shipped or fixed) has a port in `1..65535`. -/
theorem parseWith_port {sf sa strip raw} {u : Url} (e : parseWith sf sa strip raw = .ok u) :
    1 ≤ u.port ∧ u.port ≤ 65535 := by
  unfold parseWith at e
  split at e
  · cases e
  · simp only at e
    split at e
    · cases e
    · obtain ⟨p, hp, rfl, _⟩ := parseRestWith_ok e; exact hostPort_port hp

theorem parse_port {raw : Bytes} {u : Url} (e : parse raw = .ok u) :
    1 ≤ u.port ∧ u.port ≤ 65535 := parseWith_port e

/-! ## `find` and the scheme split -/

theorem find_prefix {s sub : Bytes} {i : Nat} (h : find s sub = some i) : sub <+: s.drop i := by
  induction s generalizing i with
  | nil =>
    simp only [find] at h; split at h
    · cases h; rename_i hs; subst hs; exact List.nil_prefix
    · cases h
  | cons c cs ih =>
    simp only [find] at h
    split at h
    · cases h; rename_i hp; exact List.isPrefixOf_iff_prefix.mp hp
    · cases e : find cs sub with
      | none => simp [e] at h
      | some j => simp [e] at h; subst h; exact ih e

theorem parseWith_split {sf sa strip raw} {u : Url} (e : parseWith sf sa strip raw = .ok u) :
    ∃ rest, raw = u.scheme ++ sepB ++ rest ∧ parseRestWith sf sa strip u.scheme rest = .ok u := by
  unfold parseWith at e
  split at e
  · cases e
  · rename_i se hse
    simp only at e
    split at e
    · cases e
    · obtain ⟨p, _, _, hs, _⟩ := parseRestWith_ok e
      refine ⟨raw.drop (se + 3), ?_, by rw [hs]; exact e⟩
      obtain ⟨t, ht⟩ := find_prefix hse
      have hlen : sepB.length = 3 := rfl
      have : raw.drop se = sepB ++ raw.drop (se + 3) := by
        have h2 : raw.drop (se + 3) = t := by
          rw [← List.drop_drop, ← ht]; simp [hlen]
        rw [h2, ht]
      rw [hs, List.append_assoc, ← this, List.take_append_drop]

/-! ## Fixed pipeline meets the spec (general) -/

theorem cutAt_idxWhere (p : UInt8 → Bool) (s : Bytes) :
    cutAt (idxWhere p s) s = s.takeWhile (fun c => !p c) := by
  induction s with
  | nil => rfl
  | cons c cs ih =>
    unfold cutAt at *
    simp only [idxWhere, List.takeWhile_cons]
    by_cases hc : p c
    · simp [hc]
    · simp only [hc, Bool.not_false, if_true]
      cases e : idxWhere p cs with
      | none => simp [e] at ih ⊢; exact ih
      | some j => simp [e] at ih ⊢; exact ih

theorem takeWhile_takeWhile (p q : UInt8 → Bool) (s : Bytes) :
    (s.takeWhile q).takeWhile p = s.takeWhile (fun c => p c && q c) := by
  induction s with
  | nil => rfl
  | cons c cs ih =>
    simp only [List.takeWhile_cons]
    by_cases hq : q c <;> by_cases hp : p c <;> simp [hq, hp, ih]

theorem fixed_authority_eq_spec (s : Bytes) :
    (splitAuthority (splitFragment s).1).1 = specAuthority s := by
  have h1 : (splitFragment s).1 = cutAt (idxOf cHash s) s := by
    unfold splitFragment cutAt; split <;> simp_all
  have h2 : ∀ t, (splitAuthority t).1 = cutAt (idxWhere (fun c => c == cSlash || c == cQ) t) t := by
    intro t; unfold splitAuthority cutAt; split <;> simp_all
  rw [h2, h1, cutAt_idxWhere, cutAt_idxWhere, takeWhile_takeWhile]
  unfold specAuthority isAuthEnd
  congr 1; funext c; cases c == cSlash <;> cases c == cQ <;> cases c == cHash <;> rfl

theorem stripUserinfoOld_infix (a : Bytes) : stripUserinfoOld a <:+: a := by
  unfold stripUserinfoOld; split
  · exact (List.drop_suffix _ _).isInfix
  · exact List.infix_refl _

theorem stripUserinfo_infix (a : Bytes) : stripUserinfo a <:+: a := by
  unfold stripUserinfo; split
  · exact (List.drop_suffix _ _).isInfix
  · exact List.infix_refl _

theorem rfindB_none_iff (b : UInt8) (a : Bytes) : rfindB b a = none ↔ b ∉ a := by
  induction a with
  | nil => simp [rfindB]
  | cons c cs ih =>
    simp only [rfindB, List.mem_cons, not_or]
    cases e : rfindB b cs with
    | some j =>
      simp only [reduceCtorEq, false_iff, not_and, Classical.not_not]
      intro _
      exact Classical.byContradiction fun h => by have := ih.2 h; simp [e] at this
    | none =>
      have := ih.1 e
      by_cases hc : c = b
      · simp [hc]
      · simp [hc, this, Ne.symm hc]

theorem rfindB_some_drop {b : UInt8} {a : Bytes} {i : Nat} (h : rfindB b a = some i) :
    b ∉ a.drop (i + 1) := by
  induction a generalizing i with
  | nil => simp [rfindB] at h
  | cons c cs ih =>
    simp only [rfindB] at h
    cases e : rfindB b cs with
    | some j => simp [e] at h; subst h; simpa using ih e
    | none =>
      simp [e] at h
      obtain ⟨_, rfl⟩ := h
      simpa using (rfindB_none_iff b cs).1 e

theorem stripUserinfo_noAt (a : Bytes) : cAt ∉ stripUserinfo a := by
  unfold stripUserinfo
  split
  · rename_i i hi; exact rfindB_some_drop hi
  · rename_i hn; exact (rfindB_none_iff _ _).1 (by cases e : rfindB cAt a <;> simp_all)

/-- **APP-25 fix, general.** With the userinfo stripped through the last `@`,
no successful parse yields a host containing `@` (whatever the other steps). -/
theorem parseWith_fixedStrip_noAt (sf sa : Bytes → Bytes × Bytes) (raw : Bytes) (u : Url)
    (e : parseWith sf sa stripUserinfo raw = .ok u) : HostNoAt u := by
  obtain ⟨_, _, e2⟩ := parseWith_split e
  obtain ⟨p, hp, _⟩ := parseRestWith_ok e2
  intro hm
  exact stripUserinfo_noAt _ ((hostPort_infix hp).subset hm)

/-- **APP-23 fix, general.** With the fragment cut at the first `#` and the
authority ending at the first `/` or `?`, every successful parse yields a
host that is a contiguous piece of the RFC 3986 authority, for any userinfo
strip that returns a piece of its input. -/
theorem parseWith_fixedSplit_hostInAuthority (strip : Bytes → Bytes)
    (hs : ∀ a, strip a <:+: a) (raw : Bytes) (u : Url)
    (e : parseWith splitFragment splitAuthority strip raw = .ok u) :
    HostInAuthority raw u := by
  obtain ⟨rest, hr, e2⟩ := parseWith_split e
  intro rest' hr'
  have : rest' = rest := by
    rw [hr] at hr'; exact (List.append_cancel_left hr').symm
  subst this
  obtain ⟨p, hp, _⟩ := parseRestWith_ok e2
  have := (hostPort_infix hp).trans (hs _)
  rwa [fixed_authority_eq_spec] at this

/-- The shipped parser meets both host specs. -/
theorem parse_spec (raw : Bytes) (u : Url) (e : parse raw = .ok u) :
    HostInAuthority raw u ∧ HostNoAt u :=
  ⟨parseWith_fixedSplit_hostInAuthority _ stripUserinfo_infix raw u e,
   parseWith_fixedStrip_noAt _ _ raw u e⟩

/-! ## The pre-fix parser agrees with the fixed one on clean inputs -/

theorem idxWhere_congr (p q : UInt8 → Bool) (s : Bytes) (h : ∀ c ∈ s, p c = q c) :
    idxWhere p s = idxWhere q s := by
  induction s with
  | nil => rfl
  | cons c cs ih =>
    simp only [List.mem_cons, forall_eq_or_imp] at h
    simp [idxWhere, h.1, ih h.2]

theorem idxWhere_none (p : UInt8 → Bool) (s : Bytes) (h : ∀ c ∈ s, p c = false) :
    idxWhere p s = none := by
  induction s with
  | nil => rfl
  | cons c cs ih =>
    simp only [List.mem_cons, forall_eq_or_imp] at h
    simp [idxWhere, h.1, ih h.2]

theorem idxOf_eq_rfindB_of_count (b : UInt8) (a : Bytes) (h : a.count b ≤ 1) :
    idxOf b a = rfindB b a := by
  induction a with
  | nil => rfl
  | cons c cs ih =>
    simp only [idxWhere, rfindB]
    by_cases hc : c = b
    · subst hc
      have h0 : cs.count c = 0 := by simp at h; omega
      have hn : c ∉ cs := List.count_eq_zero.mp h0
      simp [(rfindB_none_iff c cs).2 hn]
    · have h1 : cs.count b ≤ 1 := by
        simp [List.count_cons] at h; simpa [hc] using h
      have hcb : (c == b) = false := by simpa using hc
      have ih' : idxWhere (· == b) cs = rfindB b cs := ih h1
      rw [hcb, if_neg (by simp), ih']
      cases rfindB b cs <;> simp [hc]

/-- **Refinement on clean inputs.** If the text after `"://"` has no `?` and
no `#`, and its RFC authority has at most one `@`, the pre-fix `Url.parse`
gives exactly the shipped (spec-meeting) result. So the APP-23 / APP-25
discrepancies need a `?`, a `#`, or two `@`s. -/
theorem parseOld_eq_parse_of_clean (scheme rest : Bytes)
    (hq : ∀ c ∈ rest, c ≠ cQ ∧ c ≠ cHash) (ha : (specAuthority rest).count cAt ≤ 1) :
    parseRestWith splitFragmentOld splitAuthorityOld stripUserinfoOld scheme rest =
      parseRestWith splitFragment splitAuthority stripUserinfo scheme rest := by
  have hnh : cHash ∉ rest := fun hm => (hq _ hm).2 rfl
  have f1 : splitFragmentOld rest = splitFragment rest := by
    unfold splitFragmentOld splitFragment
    rw [(rfindB_none_iff _ _).2 hnh, idxOf_eq, idxWhere_none]
    intro c hc; simpa using (hq c hc).2
  have f2 : splitAuthorityOld rest = splitAuthority rest := by
    unfold splitAuthorityOld splitAuthority
    rw [idxOf_eq, idxWhere_congr (· == cSlash) (fun c => c == cSlash || c == cQ) rest]
    intro c hc; simp [(hq c hc).1]
  have f1' : (splitFragment rest).1 = rest := by
    unfold splitFragment; rw [idxOf_eq, idxWhere_none]; intro c hc; simpa using (hq c hc).2
  have hauth : (splitAuthority rest).1 = specAuthority rest := by
    have := fixed_authority_eq_spec rest; rwa [f1'] at this
  have f3 : stripUserinfoOld (splitAuthority rest).1 = stripUserinfo (splitAuthority rest).1 := by
    unfold stripUserinfoOld stripUserinfo
    rw [idxOf_eq_rfindB_of_count _ _ (by rw [hauth]; exact ha)]
  unfold parseRestWith
  simp only [f1, f1', f2, f3]

/-- The scheme prefix: `Url.parse ("http://" ++ rest)` runs the pipeline on
`rest`. -/
theorem parse_http (rest : Bytes) :
    parse (httpB ++ sepB ++ rest) =
      parseRestWith splitFragment splitAuthority stripUserinfo httpB rest := by
  simp [parse, parseWith, find, httpB, sepB, List.isPrefixOf, httpsB]

end Flare.L4.Url
