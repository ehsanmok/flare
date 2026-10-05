import Flare.L1_Encoding.IpPredicates
/-!
# ENC-01: `IpAddr.is_multicast` misclassifies IPv6 addresses whose first
group prints with fewer than four hex digits

Status: resolved. `is_multicast` now also requires the first `:` at index 4;
`Flare.L1.IpPredicates.isMulticast` mirrors the shipped code and the
counterexample below is about the pre-fix `isMulticastOld`.

RFC 4291 §2.7: IPv6 multicast is `ff00::/8` — the first *byte* is `0xff`.
flare tests `self._addr.startswith("ff")` on the `inet_ntop` text. RFC 5952
§4.1 prints groups without leading zeros, so group values `0x00ff`,
`0x0ff0..0x0fff` also print starting with `ff`: `00ff::1` is rendered
`ff::1` and reported as multicast.

* `counterexample`: the address `00ff::1` (first byte `0x00`) renders as
  `ff::1` under RFC 5952 and the pre-fix `isMulticastOld` returns `true`.
* `isMulticast6Fixed_correct`: the shipped `isMulticast` (also require that
  the first `:` is at index 4, i.e. the first group has four digits) is
  exactly the RFC 4291 predicate for every first-group value.
-/
namespace Flare.Bugs.ENC_01
open Flare.L1.Decimal Flare.L1.Address Flare.L1.IpPredicates

/-! ## RFC 5952 text form (spec) -/

def hexDigit (d : Nat) : UInt8 := if d < 10 then UInt8.ofNat (48 + d) else UInt8.ofNat (87 + d)

/-- Lowercase hex, no leading zeros (RFC 5952 §4.1, §4.3). -/
def hex (n : Nat) : Bytes :=
  if n < 16 then [hexDigit n] else hex (n / 16) ++ [hexDigit (n % 16)]
termination_by n
decreasing_by omega

def joinColon : List Bytes → Bytes
  | [] => []
  | [x] => x
  | x :: xs => x ++ 58 :: joinColon xs

def zrun : List Nat → Nat
  | 0 :: gs => zrun gs + 1
  | _ => 0

/-- Leftmost longest run of ≥ 2 zero groups (RFC 5952 §4.2.2, §4.2.3). -/
def bestRun (gs : List Nat) : Option (Nat × Nat) :=
  (List.range 8).foldl (fun acc i =>
    let r := zrun (gs.drop i)
    match acc with
    | none => if r ≥ 2 then some (i, r) else none
    | some (_, l) => if r > l then some (i, r) else acc) none

/-- RFC 5952 canonical text of eight 16-bit groups. -/
def fmt6 (gs : List Nat) : Bytes :=
  match bestRun gs with
  | none => joinColon (gs.map hex)
  | some (s, l) => joinColon ((gs.take s).map hex) ++ [58, 58] ++ joinColon ((gs.drop (s + l)).map hex)

/-- Groups of a 16-byte address. -/
def groups (x : Bytes) : List Nat := (List.range 8).map fun i => (getD x (2*i)).toNat * 256 + (getD x (2*i+1)).toNat
where getD (x : Bytes) (i : Nat) : UInt8 := Flare.Bytes.getD x i

/-- RFC 4291 §2.7. -/
def multicastSpec (x : Bytes) : Bool := Flare.Bytes.getD x 0 == 0xff

/-! ## Counterexample -/

def addr00ff : Bytes := [0x00, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]

theorem fmt_addr00ff : fmt6 (groups addr00ff) = str "ff::1" := by
  native_decide

/-- Pre-fix IPv6 branch of `is_multicast` (`startswith("ff")` only;
flare/net/address.mojo:232-240 @59bda50). -/
def isMulticastOld (ip : IpAddr) : Bool :=
  if ip.v6 then startsWith ip.addr (str "ff") else isMulticast ip

theorem counterexample :
    isMulticastOld ⟨fmt6 (groups addr00ff), true⟩ = true ∧ multicastSpec addr00ff = false := by
  rw [fmt_addr00ff]; decide

/-! ## Shipped fix: `startswith("ff") and _find_char(addr, ':') == 4` -/

/-- The shipped IPv6 branch, as a function of the text. -/
def isMulticast6Fixed (addr : Bytes) : Bool :=
  startsWith addr (str "ff") && findChar addr 58 == 4

/-- The shipped predicate on an IPv6 address is that branch. -/
theorem isMulticast_v6 (addr : Bytes) : isMulticast ⟨addr, true⟩ = isMulticast6Fixed addr := rfl

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

/-- The fix is correct for every first group `g` (followed by `:`, as in
every RFC 5952 text whose first group is not part of the `::` run). -/
theorem isMulticast6Fixed_correct (g : Nat) (hg : g < 65536) (rest : Bytes) :
    isMulticast6Fixed (hex g ++ 58 :: rest) = decide (g / 256 = 255) := by
  unfold isMulticast6Fixed
  have hf : findChar (hex g ++ 58 :: rest) 58 = (hex g).length :=
    findChar_append _ _ _ (hex_no_colon g)
  rw [hf]
  by_cases h4 : 4096 ≤ g
  · rw [hex4 g h4 hg]
    have hs : str "ff" = [102, 102] := by decide
    rw [hs]
    simp only [startsWith, List.cons_append, List.isPrefixOf, List.isPrefixOf_nil_left]
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
and both the RFC predicate and the fix say "not multicast". -/
theorem isMulticast6Fixed_compressed (rest : Bytes) :
    isMulticast6Fixed (58 :: 58 :: rest) = false := by
  simp [isMulticast6Fixed, startsWith, str, b, List.isPrefixOf]

end Flare.Bugs.ENC_01
