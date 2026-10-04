import Flare.Core
/-!
# HPACK integer representation (http2/hpack.mojo, RFC 7541 §5.1)

An integer with an `N`-bit prefix: if `I < 2^N - 1` it is stored in the
prefix; otherwise the prefix is all ones and `I - (2^N - 1)` follows as
little-endian base-128 digits, the high bit of each byte marking
continuation. The bits of the first byte above the prefix belong to the
caller (representation flags) and are preserved.

flare's decoder adds two limits: it rejects a value above `2^31` and a
fifth continuation byte (`m >= 35`). Values are modeled in `Nat`: every
intermediate is `≤ 2^31 + 127·2^28`, far from the 64-bit range.

Theorems (prefixes `1 ≤ N ≤ 8`):
* `decode_encode`: decoding `encode v N flags` (with any bytes before and
  after) returns `v` and the offset just past the encoding, for all
  `v ≤ 2^31`.
* `encode_flags`: the encoder preserves the flag bits above the prefix.
* `decode_bounds`: any accepted integer is `≤ 2^31`, consumes at least one
  and at most six bytes, and stays inside the buffer.
-/
namespace Flare.L1.HpackInt

set_option linter.unusedSimpArgs false

def maxPrefix (N : Nat) : Nat := 2 ^ N - 1

/-- Continuation loop. mirrors flare/http2/hpack.mojo:119-131 @59bda50 -/
def go (buf : Bytes) (off value m : Nat) : Option (Nat × Nat) :=
  if off ≥ buf.length then none
  else
    let b := (buf.getD off).toNat
    let value := value + ((b &&& 0x7F) <<< m)
    if value > 2 ^ 31 then none
    else if b &&& 0x80 = 0 then some (value, off + 1)
    else if m + 7 ≥ 35 then none
    else go buf (off + 1) value (m + 7)
termination_by 35 - m
decreasing_by omega

/-- mirrors flare/http2/hpack.mojo:101-118 @59bda50 -/
def decode (buf : Bytes) (off N : Nat) : Option (Nat × Nat) :=
  if off ≥ buf.length then none
  else
    let b0 := (buf.getD off).toNat &&& maxPrefix N
    if b0 < maxPrefix N then some (b0, off + 1)
    else go buf (off + 1) b0 0

/-- Continuation bytes. mirrors flare/http2/hpack.mojo:150-153 @59bda50 -/
def encRest (v : Nat) : Bytes :=
  if v ≥ 128 then UInt8.ofNat (0x80 ||| (v &&& 0x7F)) :: encRest (v >>> 7)
  else [UInt8.ofNat v]
termination_by v
decreasing_by rw [Nat.shiftRight_eq_div_pow]; omega

/-- mirrors flare/http2/hpack.mojo:134-153 @59bda50 -/
def encode (value N : Nat) (flags : UInt8) : Bytes :=
  let mp := maxPrefix N
  if value < mp then [(flags &&& UInt8.ofNat (0xFF - mp)) ||| UInt8.ofNat value]
  else ((flags &&& UInt8.ofNat (0xFF - mp)) ||| UInt8.ofNat mp) :: encRest (value - mp)

/-! ## Byte-level facts -/

theorem cont_byte : ∀ x < 128, (128 ||| x) &&& 127 = x ∧ (128 ||| x) &&& 128 = 128 ∧
    128 ||| x < 256 := by decide

theorem last_byte : ∀ x < 128, x &&& 127 = x ∧ x &&& 128 = 0 := by decide

theorem low_mask : ∀ N, 1 ≤ N → N ≤ 8 → (0xFF - maxPrefix N) &&& maxPrefix N = 0 ∧
    maxPrefix N < 256 ∧ 0xFF - maxPrefix N < 256 := by
  intro N h1 h2
  have : N = 1 ∨ N = 2 ∨ N = 3 ∨ N = 4 ∨ N = 5 ∨ N = 6 ∨ N = 7 ∨ N = 8 := by omega
  rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> decide

theorem maxPrefix_pos (N : Nat) (h : 1 ≤ N) : 1 ≤ maxPrefix N := by
  unfold maxPrefix
  have : 2 ≤ 2 ^ N := by
    calc 2 = 2 ^ 1 := rfl
      _ ≤ 2 ^ N := Nat.pow_le_pow_right (by decide) h
  omega

/-- The first byte carries `x` in the prefix whatever the flags are. -/
theorem first_byte (flags : UInt8) (N x : Nat) (h1 : 1 ≤ N) (h2 : N ≤ 8) (hx : x ≤ maxPrefix N) :
    ((flags &&& UInt8.ofNat (0xFF - maxPrefix N)) ||| UInt8.ofNat x).toNat &&& maxPrefix N = x := by
  obtain ⟨hz, hm, hc⟩ := low_mask N h1 h2
  rw [UInt8.toNat_or, UInt8.toNat_and, UInt8.toNat_ofNat', UInt8.toNat_ofNat',
    Nat.mod_eq_of_lt hc, Nat.mod_eq_of_lt (by omega), Nat.and_or_distrib_right, Nat.and_assoc, hz,
    Nat.and_zero, Nat.zero_or]
  unfold maxPrefix at hx ⊢
  rw [Nat.and_two_pow_sub_one_eq_mod]
  have : 0 < 2 ^ N := Nat.two_pow_pos N
  exact Nat.mod_eq_of_lt (by omega)

theorem encode_flags (value N : Nat) (flags : UInt8) (h1 : 1 ≤ N) (h2 : N ≤ 8) :
    ∃ b rest, encode value N flags = b :: rest ∧
      b.toNat &&& (0xFF - maxPrefix N) = flags.toNat &&& (0xFF - maxPrefix N) := by
  obtain ⟨hz, hm, hc⟩ := low_mask N h1 h2
  have key : ∀ x, x ≤ maxPrefix N →
      ((flags &&& UInt8.ofNat (0xFF - maxPrefix N)) ||| UInt8.ofNat x).toNat &&&
        (0xFF - maxPrefix N) = flags.toNat &&& (0xFF - maxPrefix N) := by
    intro x hx
    have hx' : x &&& (0xFF - maxPrefix N) = 0 := by
      have e : x = x &&& maxPrefix N := by
        unfold maxPrefix at hx ⊢
        rw [Nat.and_two_pow_sub_one_eq_mod]
        have : 0 < 2 ^ N := Nat.two_pow_pos N
        exact (Nat.mod_eq_of_lt (by omega)).symm
      rw [e, Nat.and_assoc, Nat.and_comm (maxPrefix N), hz, Nat.and_zero]
    rw [UInt8.toNat_or, UInt8.toNat_and, UInt8.toNat_ofNat', UInt8.toNat_ofNat',
      Nat.mod_eq_of_lt hc, Nat.mod_eq_of_lt (by omega), Nat.and_or_distrib_right, Nat.and_assoc,
      Nat.and_self, hx', Nat.or_zero]
  unfold encode
  dsimp only
  split
  · exact ⟨_, _, rfl, key value (by omega)⟩
  · exact ⟨_, _, rfl, key (maxPrefix N) (Nat.le_refl _)⟩

/-! ## Round trip -/

theorem getD_mid (pre mid rest : Bytes) (i : Nat) (h : i < mid.length) :
    Bytes.getD (pre ++ mid ++ rest) (pre.length + i) = mid.getD i := by
  simp only [Bytes.getD, List.append_assoc, List.getElem?_append_right (Nat.le_add_right _ _),
    Nat.add_sub_cancel_left, List.getElem?_append_left h]

theorem go_encRest (v : Nat) : ∀ (pre rest : Bytes) (acc m : Nat),
    acc + v * 2 ^ m ≤ 2 ^ 31 → v < 2 ^ (35 - m) →
    go (pre ++ encRest v ++ rest) pre.length acc m =
      some (acc + v * 2 ^ m, pre.length + (encRest v).length) := by
  induction v using Nat.strongRecOn with
  | ind v ih =>
  intro pre rest acc m hle hlt
  have hgo := go.eq_1 (pre ++ encRest v ++ rest) pre.length acc m
  rw [hgo]
  have hlen : pre.length < (pre ++ encRest v ++ rest).length := by
    rw [encRest]; split <;> simp
  rw [if_neg (by omega)]
  dsimp only
  by_cases hv : v ≥ 128
  · have e0 : encRest v = UInt8.ofNat (0x80 ||| (v &&& 0x7F)) :: encRest (v >>> 7) := by
      rw [encRest, if_pos hv]
    have hmod : v &&& 0x7F = v % 128 := Nat.and_two_pow_sub_one_eq_mod v 7
    obtain ⟨c1, c2, c3⟩ := cont_byte (v % 128) (Nat.mod_lt _ (by decide))
    have hb : (Bytes.getD (pre ++ encRest v ++ rest) pre.length).toNat = 128 ||| v % 128 := by
      have := getD_mid pre (encRest v) rest 0 (by rw [e0]; simp)
      rw [Nat.add_zero] at this
      rw [this, e0]
      simp only [Bytes.getD, List.getElem?_cons_zero, Option.getD_some, hmod,
        UInt8.toNat_ofNat']
      exact Nat.mod_eq_of_lt c3
    rw [hb, c1, c2, Nat.shiftLeft_eq]
    have hm : m + 7 < 35 := by
      have : 2 ^ 7 < 2 ^ (35 - m) := Nat.lt_of_le_of_lt (by omega) hlt
      have := (Nat.pow_lt_pow_iff_right (by decide : 1 < 2)).1 this
      omega
    have hq : v = v % 128 + 128 * (v / 128) := (Nat.mod_add_div v 128).symm
    have hpow : 2 ^ (m + 7) = 2 ^ m * 128 := by rw [Nat.pow_add]
    have hle' : acc + v % 128 * 2 ^ m ≤ 2 ^ 31 := by
      have : v % 128 * 2 ^ m ≤ v * 2 ^ m := Nat.mul_le_mul_right _ (Nat.mod_le _ _)
      omega
    rw [if_neg (by omega), if_neg (by decide), if_neg (by omega)]
    have hshift : v >>> 7 = v / 128 := Nat.shiftRight_eq_div_pow v 7
    have ih' := ih (v >>> 7) (by rw [hshift]; omega)
      (pre ++ [UInt8.ofNat (0x80 ||| (v &&& 0x7F))]) rest (acc + v % 128 * 2 ^ m) (m + 7)
      (by
        rw [hshift, hpow]
        have : v % 128 * 2 ^ m + v / 128 * (2 ^ m * 128) = v * 2 ^ m := by
          conv => rhs; rw [hq]
          rw [Nat.add_mul, Nat.mul_comm 128 (v / 128), Nat.mul_assoc, Nat.mul_comm 128 (2 ^ m)]
        omega)
      (by
        rw [hshift]
        have h35 : 35 - m = 35 - (m + 7) + 7 := by omega
        rw [h35, Nat.pow_add] at hlt
        exact Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hlt))
    have ea : pre ++ [UInt8.ofNat (0x80 ||| (v &&& 0x7F))] ++ encRest (v >>> 7) ++ rest =
        pre ++ encRest v ++ rest := by rw [e0]; simp
    rw [ea] at ih'
    simp only [List.length_append, List.length_singleton] at ih'
    rw [ih', e0]
    simp only [Option.some.injEq, Prod.mk.injEq, List.length_cons]
    constructor
    · rw [hshift, hpow]
      have : v % 128 * 2 ^ m + v / 128 * (2 ^ m * 128) = v * 2 ^ m := by
        conv => rhs; rw [hq]
        rw [Nat.add_mul, Nat.mul_comm 128 (v / 128), Nat.mul_assoc, Nat.mul_comm 128 (2 ^ m)]
      omega
    · omega
  · have e0 : encRest v = [UInt8.ofNat v] := by rw [encRest, if_neg hv]
    obtain ⟨c1, c2⟩ := last_byte v (by omega)
    have hb : (Bytes.getD (pre ++ encRest v ++ rest) pre.length).toNat = v := by
      have := getD_mid pre (encRest v) rest 0 (by rw [e0]; simp)
      rw [Nat.add_zero] at this
      rw [this, e0]
      simp only [Bytes.getD, List.getElem?_cons_zero, Option.getD_some, UInt8.toNat_ofNat']
      exact Nat.mod_eq_of_lt (by omega)
    rw [hb, c1, c2, Nat.shiftLeft_eq, if_neg (by omega), if_pos rfl, e0]
    rfl

theorem encRest_length_pos (v : Nat) : 1 ≤ (encRest v).length := by
  rw [encRest]; split <;> simp

theorem decode_encode (pre rest : Bytes) (value N : Nat) (flags : UInt8) (h1 : 1 ≤ N) (h2 : N ≤ 8)
    (hv : value ≤ 2 ^ 31) :
    decode (pre ++ encode value N flags ++ rest) pre.length N =
      some (value, pre.length + (encode value N flags).length) := by
  obtain ⟨hz, hm, hc⟩ := low_mask N h1 h2
  unfold decode
  have hlen : pre.length < (pre ++ encode value N flags ++ rest).length := by
    unfold encode; dsimp only; split <;> simp
  rw [if_neg (by omega)]
  dsimp only
  by_cases hs : value < maxPrefix N
  · have e0 : encode value N flags =
        [(flags &&& UInt8.ofNat (0xFF - maxPrefix N)) ||| UInt8.ofNat value] := by
      unfold encode; dsimp only; rw [if_pos hs]
    have hb := getD_mid pre (encode value N flags) rest 0 (by rw [e0]; simp)
    rw [Nat.add_zero] at hb
    rw [hb, e0]
    simp only [Bytes.getD, List.getElem?_cons_zero, Option.getD_some]
    simp only [first_byte flags N value h1 h2 (by omega), if_pos hs, List.length_singleton]
  · have e0 : encode value N flags =
        ((flags &&& UInt8.ofNat (0xFF - maxPrefix N)) ||| UInt8.ofNat (maxPrefix N)) ::
          encRest (value - maxPrefix N) := by
      unfold encode; dsimp only; rw [if_neg hs]
    have hb := getD_mid pre (encode value N flags) rest 0 (by rw [e0]; simp)
    rw [Nat.add_zero] at hb
    rw [hb, e0]
    simp only [Bytes.getD, List.getElem?_cons_zero, Option.getD_some]
    simp only [first_byte flags N (maxPrefix N) h1 h2 (Nat.le_refl _), Nat.lt_irrefl, if_false]
    have := go_encRest (value - maxPrefix N)
      (pre ++ [(flags &&& UInt8.ofNat (0xFF - maxPrefix N)) ||| UInt8.ofNat (maxPrefix N)]) rest
      (maxPrefix N) 0 (by simp; omega) (by simp; omega)
    simp only [List.length_append, List.length_singleton, List.append_assoc,
      List.singleton_append, List.cons_append, List.nil_append] at this
    simp only [List.append_assoc, List.cons_append]
    rw [this]
    simp only [Nat.pow_zero, Nat.mul_one, Option.some.injEq, Prod.mk.injEq, List.length_cons]
    omega

/-! ## Decoder bounds -/

theorem go_bounds (buf : Bytes) (off acc m v o : Nat) (hm : m % 7 = 0) (hm' : m ≤ 28)
    (h : go buf off acc m = some (v, o)) :
    v ≤ 2 ^ 31 ∧ off < o ∧ o ≤ buf.length ∧ 7 * (o - off) ≤ 35 - m := by
  induction hk : 35 - m using Nat.strongRecOn generalizing off acc m with
  | ind k ih =>
  rw [go] at h
  split at h
  · cases h
  · next hl =>
    dsimp only at h
    split at h
    · cases h
    · next hv =>
      split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        exact ⟨by omega, by omega, by omega, by omega⟩
      · split at h
        · cases h
        · next hm7 =>
          have := ih (35 - (m + 7)) (by omega) (off + 1) _ (m + 7) (by omega) (by omega) h rfl
          exact ⟨this.1, by omega, this.2.2.1, by omega⟩

theorem decode_bounds (buf : Bytes) (off N v o : Nat) (h2 : N ≤ 8)
    (h : decode buf off N = some (v, o)) :
    v ≤ 2 ^ 31 ∧ off < o ∧ o ≤ buf.length ∧ o ≤ off + 6 := by
  unfold decode at h
  split at h
  · cases h
  · dsimp only at h
    have hmp : maxPrefix N ≤ 255 := by
      unfold maxPrefix
      have : 2 ^ N ≤ 2 ^ 8 := Nat.pow_le_pow_right (by decide) h2
      have : (2 : Nat) ^ 8 = 256 := rfl
      omega
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨by omega, by omega, by omega, by omega⟩
    · have := go_bounds buf (off + 1) _ 0 v o rfl (by decide) h
      exact ⟨this.1, by omega, this.2.2.1, by omega⟩

end Flare.L1.HpackInt
