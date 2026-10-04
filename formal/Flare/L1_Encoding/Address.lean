import Flare.Core
import Flare.L1_Encoding.Decimal
/-!
# `net/address.mojo`: strict port parser, `SocketAddr` text codec, IPv4
string predicates

* `parsePortStrict` is proved equal to an RFC-style spec (1–5 ASCII digits,
  value ≤ 65535), including Mojo `Int` (Int64) wrapping arithmetic.
* `SocketAddr.parse ∘ SocketAddr.write_to = id` for addresses that came out
  of `IpAddr.parse` (i.e. canonical `inet_ntop` text). `inet_pton/ntop` are
  abstracted by `InetEnv` and the hypothesis `InetEnv.Valid` (environment
  assumption, stated explicitly in each theorem).
* The IPv4 predicates (`is_loopback`, `is_private`, `is_multicast`,
  `is_unspecified`) work on the string; on canonical dotted quads they are
  proved equal to the numeric RFC 1122/1918/5771 predicates.
-/
namespace Flare.L1.Address
open Flare.L1.Decimal

def b (c : Char) : UInt8 := c.toNat.toUInt8
def str (s : String) : Bytes := s.toList.map b  -- ASCII literals only

/-- Mojo `UInt16(v)` for a Mojo `Int`: truncation to the low 16 bits. -/
def i64toU16 (v : Int64) : UInt16 := UInt16.ofNat (v.toInt % 65536).toNat

/-! ## `_parse_port_strict` -/

/-- The digit loop of `_parse_port_strict` (Mojo `Int` = `Int64`). -/
def portLoop : Bytes → Int64 → Option Int64
  | [], v => some v
  | c :: cs, v =>
    if c < 48 || c > 57 then none
    else portLoop cs (v * 10 + Int64.ofNat (c - 48).toNat)

/-- mirrors flare/net/address.mojo:468-486 @59bda50 -/
def parsePortStrict (digits : Bytes) : Option UInt16 :=
  if digits.length == 0 || digits.length > 5 then none
  else match portLoop digits 0 with
    | none => none
    | some v => if v > 65535 then none else some (i64toU16 v)

/-- Spec: one to five ASCII digits whose decimal value is at most 65535. -/
def portSpec (digits : Bytes) : Option UInt16 :=
  if 1 ≤ digits.length ∧ digits.length ≤ 5 ∧ digits.all isDigit ∧ decVal digits ≤ 65535
  then some (UInt16.ofNat (decVal digits)) else none

theorem isDigit_iff (c : UInt8) : isDigit c = true ↔ 48 ≤ c.toNat ∧ c.toNat ≤ 57 := by
  simp [isDigit, UInt8.le_iff_toNat_le]

theorem portLoop_eq (cs : Bytes) (v : Nat) :
    portLoop cs (Int64.ofNat v) =
      if cs.all isDigit then some (Int64.ofNat (cs.foldl (fun v c => v * 10 + (c.toNat - 48)) v))
      else none := by
  induction cs generalizing v with
  | nil => simp [portLoop]
  | cons c cs ih =>
    simp only [portLoop, List.all_cons, List.foldl_cons]
    by_cases hc : isDigit c = true
    · have hc' := (isDigit_iff c).mp hc
      have h1 : (c < 48 || c > 57) = false := by
        simp [UInt8.lt_iff_toNat_lt]; omega
      rw [h1, if_neg (by simp)]
      have : Int64.ofNat v * 10 + Int64.ofNat (c - 48).toNat =
          Int64.ofNat (v * 10 + (c.toNat - 48)) := by
        rw [UInt8.toNat_sub_of_le _ _ (by simp [UInt8.le_iff_toNat_le]; omega),
          Int64.ofNat_add, Int64.ofNat_mul]; rfl
      rw [this, ih]; simp [hc]
    · have h1 : (c < 48 || c > 57) = true := by
        rw [isDigit_iff] at hc; simp [UInt8.lt_iff_toNat_lt]; omega
      simp [h1, hc]

/-- Functional correctness of the strict port parser. -/
theorem parsePortStrict_eq_spec (digits : Bytes) : parsePortStrict digits = portSpec digits := by
  unfold parsePortStrict portSpec
  by_cases hl : digits.length = 0 ∨ digits.length > 5
  · have : (digits.length == 0 || decide (digits.length > 5)) = true := by
      rcases hl with h | h <;> simp [h]
    rw [if_pos this, if_neg (fun h => by rcases h with ⟨h1, h2, -⟩; omega)]
  · have : (digits.length == 0 || decide (digits.length > 5)) = false := by
      simp only [Bool.or_eq_false_iff, beq_eq_false_iff_ne, decide_eq_false_iff_not]; omega
    rw [if_neg (by simp [this]), show (0 : Int64) = Int64.ofNat 0 from rfl, portLoop_eq]
    by_cases hd : digits.all isDigit = true
    · simp only [hd, if_true]
      have hlt := decVal_lt digits (by simpa using hd)
      have h5 : 10 ^ digits.length ≤ 10 ^ 5 := Nat.pow_le_pow_right (by decide) (by omega)
      have hv : decVal digits < 100000 := by
        have : (10:Nat) ^ 5 = 100000 := by decide
        omega
      unfold decVal at hv ⊢
      generalize digits.foldl (fun v c => v * 10 + (c.toNat - 48)) 0 = N at hv ⊢
      have hN : (Int64.ofNat N).toInt = N := Int64.toInt_ofNat_of_lt (by omega)
      have h65 : (65535 : Int64).toInt = 65535 := by decide
      by_cases hN' : N ≤ 65535
      · have hg : ¬ (Int64.ofNat N > 65535) := by
          rw [gt_iff_lt, Int64.lt_iff_toInt_lt, hN, h65]; omega
        rw [if_neg hg, if_pos ⟨by omega, by omega, trivial, hN'⟩]
        simp only [i64toU16, hN, Option.some.injEq]
        congr 1; omega
      · have hg : Int64.ofNat N > 65535 := by
          rw [gt_iff_lt, Int64.lt_iff_toInt_lt, hN, h65]; omega
        rw [if_pos hg, if_neg (fun h => hN' h.2.2.2)]
    · simp only [hd]; simp

/-! ## `SocketAddr` text codec -/

structure IpAddr where
  addr : Bytes
  v6 : Bool
  deriving DecidableEq, Repr

structure SocketAddr where
  ip : IpAddr
  port : UInt16
  deriving DecidableEq, Repr

/-- The libc boundary: `inet_pton` / `inet_ntop` for both families. -/
structure InetEnv where
  pton4 : Bytes → Option Bytes
  ntop4 : Bytes → Bytes
  pton6 : Bytes → Option Bytes
  ntop6 : Bytes → Bytes

/-- Bytes `IpAddr.parse` / `SocketAddr.parse` reject up front. -/
def badHost (c : UInt8) : Bool := c == 0 || c == 10 || c == 13 || c == b '@'
def badSock (c : UInt8) : Bool := c == 0 || c == 10 || c == 13

def isHex (c : UInt8) : Bool :=
  isDigit c || (97 ≤ c && c ≤ 102) || (65 ≤ c && c ≤ 70)

/-- **Environment assumption** (POSIX `inet_pton(3)`/`inet_ntop(3)`,
RFC 5952): `inet_pton` accepts what `inet_ntop` prints and returns the same
address; canonical text is non-empty; IPv4 text uses only digits and `.`;
IPv6 text uses only hex digits, `:` and `.` and is rejected by
`inet_pton(AF_INET)`. -/
structure InetEnv.Valid (E : InetEnv) : Prop where
  pton4_ntop4 : ∀ x, x.length = 4 → E.pton4 (E.ntop4 x) = some x
  ntop4_ne : ∀ x, E.ntop4 x ≠ []
  ntop4_chars : ∀ x, ∀ c ∈ E.ntop4 x, isDigit c = true ∨ c = b '.'
  pton6_ntop6 : ∀ x, x.length = 16 → E.pton6 (E.ntop6 x) = some x
  pton4_ntop6 : ∀ x, E.pton4 (E.ntop6 x) = none
  ntop6_ne : ∀ x, E.ntop6 x ≠ []
  ntop6_chars : ∀ x, ∀ c ∈ E.ntop6 x, isHex c = true ∨ c = b ':' ∨ c = b '.'

/-- mirrors flare/net/address.mojo:54-150 @59bda50 (`IpAddr.parse`; the
`ntop[0] == 0` failure check is `ntop = []`). -/
def parseIp (E : InetEnv) (s : Bytes) : Option IpAddr :=
  if s = [] then none
  else if s.any badHost then none
  else match E.pton4 s with
    | some x => if E.ntop4 x = [] then none else some ⟨E.ntop4 x, false⟩
    | none => match E.pton6 s with
      | some y => if E.ntop6 y = [] then none else some ⟨E.ntop6 y, true⟩
      | none => none

/-- `_find_char`: index of the first `ch`, or -1. mirrors
flare/net/address.mojo:296-307 @59bda50 -/
def findChar (s : Bytes) (ch : UInt8) : Int :=
  match s.findIdx? (· == ch) with
  | some i => i
  | none => -1

/-- mirrors flare/net/address.mojo:384-433 @59bda50 -/
def parseSock (E : InetEnv) (s : Bytes) : Option SocketAddr :=
  if s = [] then none
  else if s.any badSock then none
  else if s.head? = some (b '[') then
    let close := findChar s (b ']')
    if close < 0 ∨ close + 1 ≥ s.length ∨ s[(close + 1).toNat]? ≠ some (b ':') then none
    else do
      let ip ← parseIp E ((s.take close.toNat).drop 1)
      let p ← parsePortStrict (s.drop (close.toNat + 2))
      pure ⟨ip, p⟩
  else
    let colon := findChar s (b ':')
    if colon < 0 then none
    else do
      let ip ← parseIp E (s.take colon.toNat)
      let p ← parsePortStrict (s.drop (colon.toNat + 1))
      pure ⟨ip, p⟩

/-- mirrors flare/net/address.mojo:454-464 @59bda50 (`SocketAddr.write_to`;
`writer.write(UInt16)` renders the shortest decimal). -/
def render (sa : SocketAddr) : Bytes :=
  if sa.ip.v6 then b '[' :: (sa.ip.addr ++ b ']' :: b ':' :: dec sa.port.toNat)
  else sa.ip.addr ++ b ':' :: dec sa.port.toNat

/-- An `IpAddr` that `IpAddr.parse` can produce. -/
def Canonical (E : InetEnv) (ip : IpAddr) : Prop :=
  (ip.v6 = false ∧ ∃ x, x.length = 4 ∧ ip.addr = E.ntop4 x) ∨
  (ip.v6 = true ∧ ∃ x, x.length = 16 ∧ ip.addr = E.ntop6 x)

theorem parsePortStrict_dec (p : UInt16) : parsePortStrict (dec p.toNat) = some p := by
  rw [parsePortStrict_eq_spec]; unfold portSpec
  have hp := p.toNat_lt
  have hl := dec_length_le p.toNat 4 (by simp at hp ⊢; omega)
  have hpos := dec_length_pos p.toNat
  rw [if_pos ⟨hpos, hl, by simpa using dec_all_digit p.toNat, by rw [decVal_dec]; omega⟩]
  simp [decVal_dec]

/-! character-class facts -/

/-- Bytes that can occur in canonical text are never rejected and are
never one of the structural separators `[`, `]`, `:`. -/
def Plain (c : UInt8) : Prop := badSock c = false ∧ badHost c = false ∧ c ≠ b '[' ∧ c ≠ b ']'

theorem plain_of_range (c : UInt8) (h : (48 ≤ c.toNat ∧ c.toNat ≤ 58) ∨ c.toNat = 46 ∨
    (97 ≤ c.toNat ∧ c.toNat ≤ 102) ∨ (65 ≤ c.toNat ∧ c.toNat ≤ 70)) : Plain c := by
  have e : ∀ k : Nat, k < 256 → (c = UInt8.ofNat k ↔ c.toNat = k) := by
    intro k hk; constructor
    · intro h; subst h; simp; omega
    · intro h; apply UInt8.toNat_inj.mp; simp; omega
  simp only [Plain, badSock, badHost, b, Bool.or_eq_false_iff, beq_eq_false_iff_ne, ne_eq]
  refine ⟨⟨⟨?_, ?_⟩, ?_⟩, ⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩, ?_, ?_⟩ <;>
    first
    | (intro hh; have := congrArg UInt8.toNat hh; simp at this; omega)

theorem digit_plain (c : UInt8) (h : isDigit c = true) : Plain c ∧ c ≠ b ':' := by
  rw [isDigit_iff] at h
  refine ⟨plain_of_range c (Or.inl ⟨h.1, by omega⟩), ?_⟩
  intro hh; have := congrArg UInt8.toNat hh; simp [b] at this; omega

theorem ntop4_plain (E : InetEnv) (hE : E.Valid) (x : Bytes) :
    ∀ c ∈ E.ntop4 x, Plain c ∧ c ≠ b ':' := by
  intro c hc
  rcases hE.ntop4_chars x c hc with h | h
  · exact digit_plain c h
  · subst h; exact ⟨plain_of_range _ (by simp [b]), by decide⟩

theorem ntop6_plain (E : InetEnv) (hE : E.Valid) (x : Bytes) : ∀ c ∈ E.ntop6 x, Plain c := by
  intro c hc
  rcases hE.ntop6_chars x c hc with h | h | h
  · simp only [isHex, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq,
      UInt8.le_iff_toNat_le] at h
    rw [isDigit_iff] at h
    apply plain_of_range; simp at h; omega
  · subst h; apply plain_of_range; simp [b]
  · subst h; apply plain_of_range; simp [b]

theorem dec_plain (n : Nat) : ∀ c ∈ dec n, Plain c ∧ c ≠ b ':' :=
  fun c hc => digit_plain c (dec_all_digit n c hc)

/-! list plumbing -/

theorem take_len_append (x y : Bytes) : (x ++ y).take x.length = x := by simp
theorem drop_len_append (x y : Bytes) : (x ++ y).drop x.length = y := by simp

theorem findChar_append (x y : Bytes) (ch : UInt8) (hx : ∀ c ∈ x, c ≠ ch) :
    findChar (x ++ ch :: y) ch = x.length := by
  unfold findChar
  induction x with
  | nil => simp [List.findIdx?_cons]
  | cons c cs ih =>
    have hc : c ≠ ch := hx c List.mem_cons_self
    have := ih (fun d hd => hx d (List.mem_cons_of_mem _ hd))
    simp only [List.cons_append, List.findIdx?_cons, beq_iff_eq, hc, if_false]
    revert this
    cases List.findIdx? (fun x => x == ch) (cs ++ ch :: y) <;> simp

theorem parseIp_canonical (E : InetEnv) (hE : E.Valid) (ip : IpAddr) (hc : Canonical E ip) :
    parseIp E ip.addr = some ip := by
  obtain ⟨a, v6⟩ := ip
  rcases hc with ⟨hv, x, hx, ha⟩ | ⟨hv, x, hx, ha⟩ <;> simp only at hv ha <;> subst hv ha <;>
    unfold parseIp
  · rw [if_neg (hE.ntop4_ne x), if_neg, hE.pton4_ntop4 x hx]
    · simp [hE.ntop4_ne x]
    · simp only [List.any_eq_true, not_exists, not_and, Bool.not_eq_true]
      intro c hc; exact (ntop4_plain E hE x c hc).1.2.1
  · rw [if_neg (hE.ntop6_ne x), if_neg, hE.pton4_ntop6 x, hE.pton6_ntop6 x hx]
    · simp [hE.ntop6_ne x]
    · simp only [List.any_eq_true, not_exists, not_and, Bool.not_eq_true]
      intro c hc; exact (ntop6_plain E hE x c hc).2.1

/-- **Round trip**: `SocketAddr.parse (String(sa)) = sa` for every socket
address whose IP came from `IpAddr.parse`. -/
theorem parseSock_render (E : InetEnv) (hE : E.Valid) (sa : SocketAddr)
    (hc : Canonical E sa.ip) : parseSock E (render sa) = some sa := by
  obtain ⟨⟨a, v6⟩, p⟩ := sa
  have hpi := parseIp_canonical E hE ⟨a, v6⟩ hc
  have hdc := dec_plain p.toNat
  rcases hc with ⟨hv, x, hx, ha⟩ | ⟨hv, x, hx, ha⟩ <;> simp only at hv ha <;> subst hv ha
  · -- IPv4: "a:port"
    have hcl := ntop4_plain E hE x
    have hne := hE.ntop4_ne x
    simp only [render, Bool.false_eq_true, if_false]
    generalize hA : E.ntop4 x = A at hcl hne hpi
    have hnil : A ++ b ':' :: dec p.toNat ≠ [] := by simp
    have hany : (A ++ b ':' :: dec p.toNat).any badSock = false := by
      simp only [List.any_eq_false, List.mem_append, List.mem_cons]
      intro c hc; rcases hc with hc | hc | hc
      · simp [(hcl c hc).1.1]
      · subst hc; decide
      · simp [(hdc c hc).1.1]
    have hhd : (A ++ b ':' :: dec p.toNat).head? ≠ some (b '[') := by
      cases A with
      | nil => exact absurd rfl hne
      | cons c cs =>
        simp only [List.cons_append, List.head?_cons, ne_eq, Option.some.injEq]
        exact (hcl c List.mem_cons_self).1.2.2.1
    have hcol : findChar (A ++ b ':' :: dec p.toNat) (b ':') = A.length :=
      findChar_append _ _ _ (fun c hc => (hcl c hc).2)
    unfold parseSock
    rw [if_neg hnil, if_neg (by simp [hany]), if_neg hhd]
    simp only [hcol, Int.toNat_natCast]
    rw [if_neg (by omega), take_len_append]
    simp [hpi, List.drop_append, List.drop_eq_nil_of_le (show A.length ≤ A.length + 1 by omega),
      parsePortStrict_dec]
  · -- IPv6: "[a]:port"
    have hcl := ntop6_plain E hE x
    have hne := hE.ntop6_ne x
    simp only [render, if_true]
    generalize hA : E.ntop6 x = A at hcl hne hpi
    have hnil : b '[' :: (A ++ b ']' :: b ':' :: dec p.toNat) ≠ [] := by simp
    have hany : (b '[' :: (A ++ b ']' :: b ':' :: dec p.toNat)).any badSock = false := by
      simp only [List.any_eq_false, List.mem_append, List.mem_cons]
      intro c hc; rcases hc with hc | hc | hc | hc | hc
      · subst hc; decide
      · simp [(hcl c hc).1]
      · subst hc; decide
      · subst hc; decide
      · simp [(hdc c hc).1.1]
    have hclose : findChar (b '[' :: (A ++ b ']' :: b ':' :: dec p.toNat)) (b ']') =
        (A.length + 1 : Nat) := by
      have := findChar_append (b '[' :: A) (b ':' :: dec p.toNat) (b ']') (by
        intro c hc; simp only [List.mem_cons] at hc
        rcases hc with hc | hc
        · subst hc; decide
        · exact (hcl c hc).2.2.2)
      simpa using this
    unfold parseSock
    rw [if_neg hnil, if_neg (by simp [hany]), if_pos (by simp)]
    simp only [hclose, Int.toNat_natCast]
    have hget : (b '[' :: (A ++ b ']' :: b ':' :: dec p.toNat))[A.length + 1 + 1]? = some (b ':') := by
      simp [List.getElem?_append_right]
    rw [if_neg (by
      rw [show ((A.length + 1 : Nat) + 1 : Int).toNat = A.length + 1 + 1 by omega, hget]
      simp; omega)]
    have h1 : (b '[' :: (A ++ b ']' :: b ':' :: dec p.toNat)).take (A.length + 1) = b '[' :: A := by
      simp
    have h2 : (b '[' :: (A ++ b ']' :: b ':' :: dec p.toNat)).drop (A.length + 1 + 2) = dec p.toNat := by
      simp [List.drop_append]
    rw [h1, h2]
    simp [hpi, parsePortStrict_dec]

end Flare.L1.Address
