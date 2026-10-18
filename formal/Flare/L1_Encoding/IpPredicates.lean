import Flare.L1_Encoding.Address
/-!
# IPv4 string predicates vs. numeric predicates

`IpAddr` keeps only the `inet_ntop` text, so `is_loopback`, `is_private`,
`is_multicast`, `is_unspecified` inspect the string. On the canonical
dotted quad `dotted a b c d` (POSIX `inet_ntop(AF_INET)` format: four
shortest decimals joined by `.`) each is proved equal to the numeric
predicate from the RFC (RFC 1122 §3.2.1.3 loopback 127/8, RFC 1918
private ranges, RFC 5771 multicast 224/4).

The predicates do not re-validate the text: the public
`IpAddr(addr, is_v6)` constructor accepts any string, and on non-canonical
input the octet loop happily folds non-digits (see the report, "checked,
not a bug": this is a documented, unenforced precondition).
-/
namespace Flare.L1.IpPredicates
open Flare.L1.Decimal Flare.L1.Address

/-- POSIX `inet_ntop(AF_INET)` text for octets `a.b.c.d`. -/
def dotted (a b c d : Nat) : Bytes :=
  dec a ++ 46 :: (dec b ++ 46 :: (dec c ++ 46 :: dec d))

def startsWith (s p : Bytes) : Bool := p.isPrefixOf s

/-- `_find_char_from`: absolute index of the first `ch` at or after `start`. -/
def findCharFrom (s : Bytes) (ch : UInt8) (start : Nat) : Int :=
  match (s.drop start).findIdx? (· == ch) with
  | some i => (start + i : Nat)
  | none => -1

/-- The octet accumulation loop shared by `is_multicast` and
`_is_172_private` (`octet = octet * 10 + Int(bytes[i]) - Int(ord("0"))`). -/
def octetLoop (bs : Bytes) : Int64 :=
  bs.foldl (fun o c => o * 10 + Int64.ofNat c.toNat - 48) 0

/-- mirrors flare/net/address.mojo#IpAddr.is_loopback+IpAddr.is_unspecified sha=df267ce7fb05 at=59bda50f -/
def isLoopback (ip : IpAddr) : Bool :=
  if ip.v6 then ip.addr == str "::1" else startsWith ip.addr (str "127.")

/-- mirrors flare/net/address.mojo#IpAddr.is_unspecified+IpAddr.is_private sha=d09df47f406a at=59bda50f -/
def isUnspecified (ip : IpAddr) : Bool :=
  if ip.v6 then ip.addr == str "::" else ip.addr == str "0.0.0.0"

/-- mirrors flare/net/address.mojo#_is_172_private+_find_char sha=c7bdfbe64cd1 at=59bda50f -/
def is172Private (addr : Bytes) : Bool :=
  let dot := findCharFrom addr 46 4
  if dot < 0 then false
  else
    let o := octetLoop ((addr.drop 4).take (dot.toNat - 4))
    decide (16 ≤ o) && decide (o ≤ 31)

/-- mirrors flare/net/address.mojo#IpAddr.is_private+IpAddr.is_multicast sha=8acd47fb9f1b at=12630564 -/
def isPrivate (ip : IpAddr) : Bool :=
  if ip.v6 then false
  else if startsWith ip.addr (str "10.") || startsWith ip.addr (str "192.168.") then true
  else if startsWith ip.addr (str "172.") then is172Private ip.addr
  else false

/-- mirrors flare/net/address.mojo#IpAddr.is_multicast sha=b9e0aea32357 at=144ed0a1 (fixed, ENC-01): an IPv6 address is
multicast iff its text starts with `ff` and the first group has four digits
(first `:` at index 4), i.e. the first byte is `0xff` (RFC 4291 §2.7). -/
def isMulticast (ip : IpAddr) : Bool :=
  if ip.v6 then startsWith ip.addr (str "ff") && findChar ip.addr 58 == 4
  else
    let dot := findChar ip.addr 46
    if dot < 0 then false
    else
      let o := octetLoop (ip.addr.take dot.toNat)
      decide (224 ≤ o) && decide (o ≤ 239)

/-! ## Lemmas -/

theorem dec_no_dot (n : Nat) : ∀ c ∈ dec n, c ≠ 46 := by
  intro c hc h; subst h
  have := (isDigit_iff _).mp (dec_all_digit n _ hc); simp at this

theorem dec_inj {m n : Nat} (h : dec m = dec n) : m = n := by
  rw [← decVal_dec m, ← decVal_dec n, h]

/-- Prefix matching across a `.`-terminated field. -/
theorem prefix_field (x y p r : Bytes) (hx : ∀ c ∈ x, c ≠ 46) (hy : ∀ c ∈ y, c ≠ 46) :
    (y ++ 46 :: p).isPrefixOf (x ++ 46 :: r) = (decide (y = x) && p.isPrefixOf r) := by
  induction y generalizing x with
  | nil =>
    cases x with
    | nil => simp [List.isPrefixOf]
    | cons c cs =>
      have : c ≠ 46 := hx c (by simp)
      simp [List.isPrefixOf, Ne.symm this]
  | cons d ds ih =>
    cases x with
    | nil =>
      have : d ≠ 46 := hy d (by simp)
      simp [List.isPrefixOf, this]
    | cons c cs =>
      simp only [List.cons_append, List.isPrefixOf, List.cons.injEq]
      rw [ih cs (fun e he => hx e (by simp [he])) (fun e he => hy e (by simp [he]))]
      by_cases h : d = c <;> simp [h]

theorem dec_lt10 (n : Nat) (h : n < 10) : dec n = [digitB n] := by
  rw [dec]; simp [h]

theorem dec_lt100 (n : Nat) (h1 : 10 ≤ n) (h2 : n < 100) :
    dec n = [digitB (n / 10), digitB (n % 10)] := by
  rw [dec, if_neg (by omega), dec_lt10 _ (by omega)]; rfl

theorem dec_lt1000 (n : Nat) (h1 : 100 ≤ n) (h2 : n < 1000) :
    dec n = [digitB (n / 100), digitB (n / 10 % 10), digitB (n % 10)] := by
  rw [dec, if_neg (by omega), dec_lt100 _ (by omega) (by omega)]
  simp only [List.cons_append, List.nil_append, List.cons.injEq, and_true]
  congr 1; omega

theorem str_10 : str "10." = dec 10 ++ [46] := by rw [dec_lt100 10 (by omega) (by omega)]; decide
theorem str_127 : str "127." = dec 127 ++ [46] := by
  rw [dec_lt1000 127 (by omega) (by omega)]; decide
theorem str_172 : str "172." = dec 172 ++ [46] := by
  rw [dec_lt1000 172 (by omega) (by omega)]; decide
theorem str_192_168 : str "192.168." = dec 192 ++ 46 :: (dec 168 ++ [46]) := by
  rw [dec_lt1000 192 (by omega) (by omega), dec_lt1000 168 (by omega) (by omega)]; decide

theorem startsWith_field (n : Nat) (a : Nat) (r : Bytes) :
    startsWith (dec a ++ 46 :: r) (dec n ++ [46]) = decide (a = n) := by
  unfold startsWith
  rw [prefix_field _ _ _ _ (dec_no_dot a) (dec_no_dot n)]
  by_cases h : a = n
  · subst h; simp [List.isPrefixOf]
  · have : dec n ≠ dec a := fun e => h (dec_inj e).symm
    simp [this, h]

theorem findIdx_append (x y : Bytes) (ch : UInt8) (hx : ∀ c ∈ x, c ≠ ch) :
    (x ++ ch :: y).findIdx? (· == ch) = some x.length := by
  induction x with
  | nil => simp [List.findIdx?_cons]
  | cons c cs ih =>
    have hc : c ≠ ch := hx c List.mem_cons_self
    simp [List.findIdx?_cons, hc, ih (fun d hd => hx d (List.mem_cons_of_mem _ hd))]

theorem field_eq (x x' r r' : Bytes) (hx : ∀ c ∈ x, c ≠ 46) (hx' : ∀ c ∈ x', c ≠ 46)
    (h : x ++ 46 :: r = x' ++ 46 :: r') : x = x' ∧ r = r' := by
  induction x generalizing x' with
  | nil =>
    cases x' with
    | nil => simpa using h
    | cons c cs => simp at h; exact absurd h.1.symm (hx' c (by simp))
  | cons c cs ih =>
    cases x' with
    | nil => simp at h; exact absurd h.1 (hx c (by simp))
    | cons c' cs' =>
      simp only [List.cons_append, List.cons.injEq] at h
      have := ih cs' (fun e he => hx e (by simp [he])) (fun e he => hx' e (by simp [he])) h.2
      exact ⟨by rw [h.1, this.1], this.2⟩

theorem dotted_inj {a b c d a' b' c' d' : Nat} (h : dotted a b c d = dotted a' b' c' d') :
    a = a' ∧ b = b' ∧ c = c' ∧ d = d' := by
  unfold dotted at h
  obtain ⟨h1, h⟩ := field_eq _ _ _ _ (dec_no_dot _) (dec_no_dot _) h
  obtain ⟨h2, h⟩ := field_eq _ _ _ _ (dec_no_dot _) (dec_no_dot _) h
  obtain ⟨h3, h4⟩ := field_eq _ _ _ _ (dec_no_dot _) (dec_no_dot _) h
  exact ⟨dec_inj h1, dec_inj h2, dec_inj h3, dec_inj h4⟩

theorem octetLoop_digits (bs : Bytes) (h : ∀ c ∈ bs, isDigit c = true) :
    octetLoop bs = Int64.ofNat (decVal bs) := by
  unfold octetLoop decVal
  suffices ∀ v, bs.foldl (fun o c => o * 10 + Int64.ofNat c.toNat - 48) (Int64.ofNat v) =
      Int64.ofNat (bs.foldl (fun v c => v * 10 + (c.toNat - 48)) v) from this 0
  induction bs with
  | nil => intro v; rfl
  | cons c cs ih =>
    intro v
    have hc := (isDigit_iff c).mp (h c (by simp))
    simp only [List.foldl_cons]
    rw [← ih (fun d hd => h d (by simp [hd]))]
    congr 1
    have : c.toNat = (c.toNat - 48) + 48 := by omega
    rw [this, Int64.ofNat_add, Int64.ofNat_add, Int64.ofNat_mul]
    simp only [Nat.add_sub_cancel]
    rw [show Int64.ofNat 48 = 48 from rfl, show Int64.ofNat 10 = 10 from rfl]
    rw [← Int64.add_assoc, Int64.add_sub_cancel]

theorem octetLoop_dec (n : Nat) : octetLoop (dec n) = Int64.ofNat n := by
  rw [octetLoop_digits _ (dec_all_digit n), decVal_dec]

theorem int64_ofNat_le (m n : Nat) (hm : m < 2 ^ 63) (hn : n < 2 ^ 63) :
    (Int64.ofNat m ≤ Int64.ofNat n) ↔ m ≤ n := by
  rw [Int64.le_iff_toInt_le, Int64.toInt_ofNat_of_lt hm, Int64.toInt_ofNat_of_lt hn]; omega

/-! ## Main theorems (for octets `< 256`) -/

variable (a b c d : Nat) (ha : a < 256) (hb : b < 256)

theorem isLoopback_dotted : isLoopback ⟨dotted a b c d, false⟩ = decide (a = 127) := by
  simp only [isLoopback, Bool.false_eq_true, if_false, dotted, str_127, startsWith_field]

include ha in
theorem isMulticast_dotted :
    isMulticast ⟨dotted a b c d, false⟩ = (decide (224 ≤ a) && decide (a ≤ 239)) := by
  simp only [isMulticast, Bool.false_eq_true, if_false, dotted]
  simp only [findChar_append _ _ _ (dec_no_dot a), Int.toNat_natCast, take_len_append,
    octetLoop_dec]
  rw [if_neg (by omega)]
  have e1 : (224 : Int64) = Int64.ofNat 224 := rfl
  have e2 : (239 : Int64) = Int64.ofNat 239 := rfl
  rw [e1, e2, decide_eq_decide.mpr (int64_ofNat_le _ _ (by omega) (by omega)),
    decide_eq_decide.mpr (int64_ofNat_le _ _ (by omega) (by omega))]

include hb in
theorem is172_dotted : is172Private (dec 172 ++ 46 :: (dec b ++ 46 :: (dec c ++ 46 :: dec d))) =
    (decide (16 ≤ b) && decide (b ≤ 31)) := by
  have h4 : (dec 172 ++ [46]).length = 4 := by rw [dec_lt1000 172 (by omega) (by omega)]; rfl
  have hd : (dec 172 ++ 46 :: (dec b ++ 46 :: (dec c ++ 46 :: dec d))).drop 4 =
      dec b ++ 46 :: (dec c ++ 46 :: dec d) := by
    rw [← h4, show dec 172 ++ 46 :: (dec b ++ 46 :: (dec c ++ 46 :: dec d)) =
      (dec 172 ++ [46]) ++ (dec b ++ 46 :: (dec c ++ 46 :: dec d)) by simp, drop_len_append]
  unfold is172Private findCharFrom
  simp only [hd]
  simp only [findIdx_append _ _ _ (dec_no_dot b)]
  rw [if_neg (by omega), show ((4 + (dec b).length : Nat) : Int).toNat - 4 = (dec b).length by omega,
    take_len_append, octetLoop_dec]
  have e1 : (16 : Int64) = Int64.ofNat 16 := rfl
  have e2 : (31 : Int64) = Int64.ofNat 31 := rfl
  rw [e1, e2, decide_eq_decide.mpr (int64_ofNat_le _ _ (by omega) (by omega)),
    decide_eq_decide.mpr (int64_ofNat_le _ _ (by omega) (by omega))]

include hb in
theorem isPrivate_dotted : isPrivate ⟨dotted a b c d, false⟩ =
    (decide (a = 10) || (decide (a = 192) && decide (b = 168)) ||
      (decide (a = 172) && decide (16 ≤ b) && decide (b ≤ 31))) := by
  simp only [isPrivate, Bool.false_eq_true, if_false, dotted, str_10, str_172, str_192_168,
    startsWith_field]
  have h192 : startsWith (dec a ++ 46 :: (dec b ++ 46 :: (dec c ++ 46 :: dec d)))
      (dec 192 ++ 46 :: (dec 168 ++ [46])) = (decide (a = 192) && decide (b = 168)) := by
    unfold startsWith
    rw [prefix_field _ _ _ _ (dec_no_dot a) (dec_no_dot 192)]
    have := startsWith_field 168 b (dec c ++ 46 :: dec d)
    unfold startsWith at this; rw [this]
    by_cases h1 : a = 192
    · subst h1; by_cases h2 : b = 168 <;> simp [h2]
    · have : dec 192 ≠ dec a := fun e => h1 (dec_inj e).symm
      simp [this, h1]
  rw [h192]
  by_cases h10 : a = 10
  · subst h10; simp
  · by_cases h192' : a = 192 ∧ b = 168
    · obtain ⟨h1, h2⟩ := h192'; subst h1 h2; simp
    · have e : (decide (a = 10) || (decide (a = 192) && decide (b = 168))) = false := by
        simp only [Bool.or_eq_false_iff, decide_eq_false_iff_not, Bool.and_eq_false_imp,
          decide_eq_true_eq]; omega
      rw [if_neg (by simp [e])]
      by_cases h172 : a = 172
      · subst h172; simp only [decide_true, if_true]
        rw [is172_dotted b c d hb]; simp [h10]
      · simp [h172]; omega

theorem isUnspecified_dotted (ha : a < 256) (hb : b < 256) (hc : c < 256) (hd : d < 256) :
    isUnspecified ⟨dotted a b c d, false⟩ = (decide (a = 0) && decide (b = 0) && decide (c = 0) && decide (d = 0)) := by
  simp only [isUnspecified, Bool.false_eq_true, if_false]
  have h0 : str "0.0.0.0" = dotted 0 0 0 0 := by simp only [dotted, dec_lt10 0 (by omega)]; decide
  rw [h0]
  by_cases hz : a = 0 ∧ b = 0 ∧ c = 0 ∧ d = 0
  · obtain ⟨rfl, rfl, rfl, rfl⟩ := hz; simp
  · have : (dotted a b c d == dotted 0 0 0 0) = false := by
      simp only [beq_eq_false_iff_ne, ne_eq]; intro e
      have := dotted_inj e; omega
    rw [this]
    simp only [Bool.false_eq, Bool.and_eq_false_iff, decide_eq_false_iff_not]; omega

/-! ## IPv6 multicast (ENC-01)

`inet_ntop` prints RFC 5952 text: lowercase hex groups without leading
zeros, separated by `:`. The IPv6 branch of `is_multicast` is
`startswith("ff") and _find_char(addr, ':') == 4`. -/

def hexDigit (d : Nat) : UInt8 := if d < 10 then UInt8.ofNat (48 + d) else UInt8.ofNat (87 + d)

/-- Lowercase hex, no leading zeros (RFC 5952 §4.1, §4.3). -/
def hex (n : Nat) : Bytes :=
  if n < 16 then [hexDigit n] else hex (n / 16) ++ [hexDigit (n % 16)]
termination_by n
decreasing_by omega

/-- The IPv6 branch of `is_multicast`, as a function of the text. -/
def isMulticast6 (addr : Bytes) : Bool :=
  startsWith addr (str "ff") && findChar addr 58 == 4

theorem isMulticast_v6 (addr : Bytes) : isMulticast ⟨addr, true⟩ = isMulticast6 addr := rfl

theorem hexDigit_toNat (d : Nat) (h : d < 16) :
    (hexDigit d).toNat = if d < 10 then 48 + d else 87 + d := by
  unfold hexDigit; split <;> (rw [UInt8.toNat_ofNat']; omega)

theorem hexDigit_ne_colon (d : Nat) (h : d < 16) : hexDigit d ≠ 58 := by
  intro e; have := hexDigit_toNat d h; rw [e] at this
  by_cases hd : d < 10
  · rw [if_pos hd] at this; simp at this; omega
  · rw [if_neg hd] at this; simp at this; omega

theorem hex_no_colon (n : Nat) : ∀ c ∈ hex n, c ≠ 58 := by
  induction n using Nat.strongRecOn with
  | ind n ih =>
    rw [hex]; split
    · intro c hc; simp at hc; subst hc; exact hexDigit_ne_colon n (by omega)
    · intro c hc; simp at hc
      rcases hc with hc | hc
      · exact ih _ (by omega) c hc
      · subst hc; exact hexDigit_ne_colon _ (Nat.mod_lt _ (by decide))

theorem hex_lt16 (n : Nat) (h : n < 16) : hex n = [hexDigit n] := by
  rw [hex, if_pos h]

theorem hex_length_lt4 (n : Nat) (h : n < 4096) : (hex n).length < 4 := by
  by_cases h1 : n < 16
  · rw [hex_lt16 n h1]; simp
  · rw [hex, if_neg h1]
    by_cases h2 : n / 16 < 16
    · rw [hex_lt16 _ h2]; simp
    · rw [hex, if_neg h2, hex_lt16 _ (by omega)]; simp

theorem hex4 (n : Nat) (h1 : 4096 ≤ n) (h2 : n < 65536) :
    hex n = [hexDigit (n / 4096), hexDigit (n / 256 % 16), hexDigit (n / 16 % 16), hexDigit (n % 16)] := by
  rw [hex, if_neg (by omega), hex, if_neg (by omega), hex, if_neg (by omega), hex, if_pos (by omega)]
  have a1 : n / 16 / 16 / 16 = n / 4096 := by omega
  have a2 : n / 16 / 16 % 16 = n / 256 % 16 := by omega
  rw [a1, a2]; rfl

theorem hexDigit_eq_f (d : Nat) (h : d < 16) : hexDigit d = 102 ↔ d = 15 := by
  constructor
  · intro e; have := hexDigit_toNat d h; rw [e] at this
    by_cases hd : d < 10
    · rw [if_pos hd] at this; simp at this; omega
    · rw [if_neg hd] at this; simp at this; omega
  · intro e; subst e; decide

/-- For every first group `g` followed by `:` (every RFC 5952 text whose
first group is not part of the `::` run), the predicate is RFC 4291 §2.7:
the first byte is `0xff`. -/
theorem isMulticast6_correct (g : Nat) (hg : g < 65536) (rest : Bytes) :
    isMulticast6 (hex g ++ 58 :: rest) = decide (g / 256 = 255) := by
  unfold isMulticast6
  have hf : findChar (hex g ++ 58 :: rest) 58 = (hex g).length :=
    findChar_append _ _ _ (hex_no_colon g)
  rw [hf]
  by_cases h4 : 4096 ≤ g
  · rw [hex4 g h4 hg]
    have hs : str "ff" = [102, 102] := by decide
    rw [hs]
    simp only [startsWith, List.cons_append, List.isPrefixOf]
    have e1 := hexDigit_eq_f (g / 4096) (by omega)
    have e2 := hexDigit_eq_f (g / 256 % 16) (by omega)
    rw [Bool.eq_iff_iff]
    simp only [Bool.and_eq_true, beq_iff_eq, Bool.and_true, List.length_cons, List.length_nil,
      decide_eq_true_eq]
    rw [eq_comm (a := (102 : UInt8)), eq_comm (a := (102 : UInt8)), e1, e2]
    constructor
    · rintro ⟨⟨h1, h2⟩, -⟩; omega
    · intro h; exact ⟨⟨by omega, by omega⟩, rfl⟩
  · have := hex_length_lt4 g (by omega)
    have e : (((hex g).length : Int) == 4) = false := by
      simp only [beq_eq_false_iff_ne, ne_eq]; omega
    rw [e, Bool.and_false]
    have : g / 256 ≠ 255 := by omega
    simp [this]

/-- When the first group is inside the `::` run the text starts with `::`
and the predicate says "not multicast", as RFC 4291 does. -/
theorem isMulticast6_compressed (rest : Bytes) :
    isMulticast6 (58 :: 58 :: rest) = false := by
  simp [isMulticast6, startsWith, str, b, List.isPrefixOf]

end Flare.L1.IpPredicates
