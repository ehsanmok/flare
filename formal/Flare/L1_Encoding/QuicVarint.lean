import Flare.Core
import Flare.L1_Encoding.Bits
/-!
# QUIC variable-length integers (quic/varint.mojo, RFC 9000 §16)

A varint is 1, 2, 4 or 8 bytes; the top two bits of the first byte give
the length (`00`, `01`, `10`, `11`), the remaining `8k - 2` bits hold the
value big-endian. Values are at most `2^62 - 1`. RFC 9000 §16: "values do
not need to be encoded on the minimum number of bytes necessary", so a
decoder accepts longer-than-needed forms; the encoder uses the shortest.

Theorems:
* `decode_encode`: for `v ≤ 2^62 - 1`, `encode v` succeeds and decoding it
  (followed by any bytes) returns `v` and the encoded length.
* `encode_none_iff`: `encode` rejects exactly the values above `2^62 - 1`.
* `encode_minimal`: the encoder picks the shortest length that can hold
  the value (`decode_bound` shows a `k`-byte form holds `< 2^(8k-2)`).
* `decode_le_max`, `decode_length`: every decoded value is `≤ 2^62 - 1`,
  the consumed length is 1/2/4/8 and fits in the buffer.
* `decode_nonminimal`: a padded encoding of 1 decodes to 1 (allowed).
-/
namespace Flare.L1.QuicVarint

set_option linter.unusedSimpArgs false

/-- mirrors flare/quic/varint.mojo:33 @59bda50 -/
def VARINT_MAX : UInt64 := 0x3FFFFFFFFFFFFFFF

/-- mirrors flare/quic/varint.mojo:53-67 @59bda50 -/
def encodedLength (v : UInt64) : Option Nat :=
  if v > VARINT_MAX then none
  else if v < 64 then some 1
  else if v < 16384 then some 2
  else if v < 1073741824 then some 4
  else some 8

/-- mirrors flare/quic/varint.mojo:70-104 @59bda50 -/
def encode (v : UInt64) : Option Bytes :=
  match encodedLength v with
  | none => none
  | some 1 => some [(v &&& 0x3F).toUInt8]
  | some 2 => some [((v >>> 8) &&& 0x3F ||| 0x40).toUInt8, (v &&& 0xFF).toUInt8]
  | some 4 => some [((v >>> 24) &&& 0x3F ||| 0x80).toUInt8, ((v >>> 16) &&& 0xFF).toUInt8,
      ((v >>> 8) &&& 0xFF).toUInt8, (v &&& 0xFF).toUInt8]
  | some _ => some [((v >>> 56) &&& 0x3F ||| 0xC0).toUInt8, ((v >>> 48) &&& 0xFF).toUInt8,
      ((v >>> 40) &&& 0xFF).toUInt8, ((v >>> 32) &&& 0xFF).toUInt8,
      ((v >>> 24) &&& 0xFF).toUInt8, ((v >>> 16) &&& 0xFF).toUInt8,
      ((v >>> 8) &&& 0xFF).toUInt8, (v &&& 0xFF).toUInt8]

/-- Length from the two-bit tag. mirrors flare/quic/varint.mojo:121-130 @59bda50 -/
def tagLength (first : UInt8) : Nat :=
  let tag := (first >>> 6).toNat &&& 3
  if tag = 0 then 1 else if tag = 1 then 2 else if tag = 2 then 4 else 8

/-- mirrors flare/quic/varint.mojo:107-138 @59bda50 -/
def decode (buf : Bytes) : Option (UInt64 × Nat) :=
  match buf with
  | [] => none
  | first :: _ =>
    let length := tagLength first
    if buf.length < length then none
    else
      some ((List.range' 1 (length - 1)).foldl
        (fun acc i => (acc <<< 8) ||| (buf.getD i).toUInt64) (first.toUInt64 &&& 0x3F), length)

/-! ## Mask lemmas -/

theorem and_low (v m : UInt64) (k : Nat) (hm : m.toNat = 2 ^ k - 1) (h : v.toNat < 2 ^ k) :
    v &&& m = v := by
  apply UInt64.toNat_inj.mp
  rw [UInt64.toNat_and, hm, Nat.and_two_pow_sub_one_eq_mod]
  exact Nat.mod_eq_of_lt h

theorem le_of_and (v : UInt64) (h : v = v &&& VARINT_MAX) : v ≤ VARINT_MAX := by
  rw [UInt64.le_iff_toNat_le, h, UInt64.toNat_and]
  exact Nat.and_le_right

/-! ## Round trip -/

theorem decode_encode (v : UInt64) (h : v ≤ VARINT_MAX) (rest : Bytes) :
    ∃ e, encode v = some e ∧ decode (e ++ rest) = some (v, e.length) := by
  have hn : ¬ v > VARINT_MAX := by
    simp only [GT.gt, UInt64.lt_iff_toNat_lt, UInt64.le_iff_toNat_le] at h ⊢; omega
  unfold encode encodedLength
  simp only [if_neg hn]
  by_cases h1 : v < 64
  · simp only [if_pos h1]
    refine ⟨_, rfl, ?_⟩
    have t : tagLength (v &&& 0x3F).toUInt8 = 1 := by
      unfold tagLength
      rw [show (v &&& 0x3F).toUInt8 >>> 6 = 0 by bit_blast]; rfl
    simp only [decode, List.cons_append, t, List.length_cons, List.length_append]
    rw [if_neg (by omega)]
    simp only [Nat.sub_self, List.range', List.foldl, Option.some.injEq, Prod.mk.injEq]
    refine ⟨?_, by simp⟩
    rw [show (v &&& 0x3F).toUInt8.toUInt64 &&& 0x3F = v &&& 0x3F by bit_blast]
    exact and_low v 0x3F 6 rfl (by simpa [UInt64.lt_iff_toNat_lt] using h1)
  · simp only [if_neg h1]
    by_cases h2 : v < 16384
    · simp only [if_pos h2]
      refine ⟨_, rfl, ?_⟩
      have t : tagLength ((v >>> 8) &&& 0x3F ||| 0x40).toUInt8 = 2 := by
        unfold tagLength
        rw [show ((v >>> 8) &&& 0x3F ||| 0x40).toUInt8 >>> 6 = 1 by bit_blast]; rfl
      simp only [decode, List.cons_append, t, List.length_cons, List.length_append]
      rw [if_neg (by omega)]
      simp only [List.range', List.foldl, Option.some.injEq, Prod.mk.injEq, and_true,
        Bytes.getD, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.getD_some]
      refine ⟨?_, by simp⟩
      rw [show (((v >>> 8) &&& 0x3F ||| 0x40).toUInt8.toUInt64 &&& 0x3F) <<< 8 |||
          (v &&& 0xFF).toUInt8.toUInt64 = v &&& 0x3FFF by bit_blast]
      exact and_low v 0x3FFF 14 rfl (by simpa [UInt64.lt_iff_toNat_lt] using h2)
    · simp only [if_neg h2]
      by_cases h3 : v < 1073741824
      · simp only [if_pos h3]
        refine ⟨_, rfl, ?_⟩
        have t : tagLength ((v >>> 24) &&& 0x3F ||| 0x80).toUInt8 = 4 := by
          unfold tagLength
          rw [show ((v >>> 24) &&& 0x3F ||| 0x80).toUInt8 >>> 6 = 2 by bit_blast]; rfl
        simp only [decode, List.cons_append, t, List.length_cons, List.length_append]
        rw [if_neg (by omega)]
        simp only [List.range', List.foldl, Option.some.injEq, Prod.mk.injEq, and_true,
          Bytes.getD, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.getD_some]
        refine ⟨?_, by simp⟩
        rw [show (((((v >>> 24) &&& 0x3F ||| 0x80).toUInt8.toUInt64 &&& 0x3F) <<< 8 |||
            ((v >>> 16) &&& 0xFF).toUInt8.toUInt64) <<< 8 |||
            ((v >>> 8) &&& 0xFF).toUInt8.toUInt64) <<< 8 ||| (v &&& 0xFF).toUInt8.toUInt64 =
            v &&& 0x3FFFFFFF by bit_blast]
        exact and_low v 0x3FFFFFFF 30 rfl (by simpa [UInt64.lt_iff_toNat_lt] using h3)
      · simp only [if_neg h3]
        refine ⟨_, rfl, ?_⟩
        have t : tagLength ((v >>> 56) &&& 0x3F ||| 0xC0).toUInt8 = 8 := by
          unfold tagLength
          rw [show ((v >>> 56) &&& 0x3F ||| 0xC0).toUInt8 >>> 6 = 3 by bit_blast]; rfl
        simp only [decode, List.cons_append, t, List.length_cons, List.length_append]
        rw [if_neg (by omega)]
        simp only [List.range', List.foldl, Option.some.injEq, Prod.mk.injEq, and_true,
          Bytes.getD, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.getD_some]
        refine ⟨?_, by simp⟩
        rw [show (((((((((v >>> 56) &&& 0x3F ||| 0xC0).toUInt8.toUInt64 &&& 0x3F) <<< 8 |||
            ((v >>> 48) &&& 0xFF).toUInt8.toUInt64) <<< 8 |||
            ((v >>> 40) &&& 0xFF).toUInt8.toUInt64) <<< 8 |||
            ((v >>> 32) &&& 0xFF).toUInt8.toUInt64) <<< 8 |||
            ((v >>> 24) &&& 0xFF).toUInt8.toUInt64) <<< 8 |||
            ((v >>> 16) &&& 0xFF).toUInt8.toUInt64) <<< 8 |||
            ((v >>> 8) &&& 0xFF).toUInt8.toUInt64) <<< 8 ||| (v &&& 0xFF).toUInt8.toUInt64 =
            v &&& VARINT_MAX by unfold VARINT_MAX; bit_blast]
        exact and_low v VARINT_MAX 62 rfl (by
          simp only [UInt64.le_iff_toNat_le] at h; have : VARINT_MAX.toNat = 2 ^ 62 - 1 := rfl
          omega)

theorem encode_none_iff (v : UInt64) : encode v = none ↔ VARINT_MAX < v := by
  by_cases h : VARINT_MAX < v
  · simp only [encode, encodedLength, GT.gt, if_pos h, true_iff]; exact h
  · obtain ⟨e, he, -⟩ := decode_encode v (by
      simp only [UInt64.lt_iff_toNat_lt, UInt64.le_iff_toNat_le] at h ⊢; omega) []
    rw [he]; simp only [reduceCtorEq, false_iff]; exact h

/-! ## Minimality -/

theorem encode_minimal (v : UInt64) (e : Bytes) (h : encode v = some e) :
    (e.length = 1 ∧ v.toNat < 2 ^ 6) ∨ (e.length = 2 ∧ 2 ^ 6 ≤ v.toNat ∧ v.toNat < 2 ^ 14) ∨
      (e.length = 4 ∧ 2 ^ 14 ≤ v.toNat ∧ v.toNat < 2 ^ 30) ∨
      (e.length = 8 ∧ 2 ^ 30 ≤ v.toNat ∧ v.toNat < 2 ^ 62) := by
  unfold encode encodedLength at h
  have hm : VARINT_MAX.toNat = 2 ^ 62 - 1 := rfl
  by_cases h0 : v > VARINT_MAX
  · simp only [if_pos h0] at h; cases h
  · simp only [if_neg h0] at h
    simp only [GT.gt, UInt64.lt_iff_toNat_lt] at h0
    by_cases h1 : v < 64
    · simp only [if_pos h1, Option.some.injEq] at h; subst h
      simp only [UInt64.lt_iff_toNat_lt] at h1; left; exact ⟨rfl, by simpa using h1⟩
    · simp only [if_neg h1] at h
      simp only [UInt64.lt_iff_toNat_lt] at h1
      by_cases h2 : v < 16384
      · simp only [if_pos h2, Option.some.injEq] at h; subst h
        simp only [UInt64.lt_iff_toNat_lt] at h2
        right; left; refine ⟨rfl, ?_, ?_⟩ <;> simp_all <;> omega
      · simp only [if_neg h2] at h
        simp only [UInt64.lt_iff_toNat_lt] at h2
        by_cases h3 : v < 1073741824
        · simp only [if_pos h3, Option.some.injEq] at h; subst h
          simp only [UInt64.lt_iff_toNat_lt] at h3
          right; right; left; refine ⟨rfl, ?_, ?_⟩ <;> simp_all <;> omega
        · simp only [if_neg h3, Option.some.injEq] at h; subst h
          simp only [UInt64.lt_iff_toNat_lt] at h3
          right; right; right; refine ⟨rfl, ?_, ?_⟩ <;> simp_all <;> omega

/-! ## Decoder bounds -/

theorem tagLength_cases (b : UInt8) :
    tagLength b = 1 ∨ tagLength b = 2 ∨ tagLength b = 4 ∨ tagLength b = 8 := by
  unfold tagLength
  dsimp only
  split
  · exact Or.inl rfl
  · split
    · exact Or.inr (Or.inl rfl)
    · split
      · exact Or.inr (Or.inr (Or.inl rfl))
      · exact Or.inr (Or.inr (Or.inr rfl))

theorem decode_length (buf : Bytes) (v : UInt64) (n : Nat) (h : decode buf = some (v, n)) :
    (n = 1 ∨ n = 2 ∨ n = 4 ∨ n = 8) ∧ n ≤ buf.length := by
  unfold decode at h
  split at h
  · cases h
  · next first rest =>
    simp only at h
    split at h
    · cases h
    · next hl =>
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨-, rfl⟩ := h
      exact ⟨tagLength_cases first, by omega⟩

/-- A `k`-byte form holds at most `8k - 2` value bits. -/
theorem decode_bound (buf : Bytes) (v : UInt64) (n : Nat) (h : decode buf = some (v, n)) :
    v.toNat < 2 ^ (8 * n - 2) := by
  unfold decode at h
  split at h
  · cases h
  · next first rest =>
    simp only at h
    split at h
    · cases h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      generalize first :: rest = buf
      rcases tagLength_cases first with e | e | e | e <;> rw [e] <;>
        simp only [List.range', List.foldl, Nat.reduceMul, Nat.reduceSub]
      · rw [← and_low (first.toUInt64 &&& 0x3F) 0x3F 6 rfl (by
            rw [UInt64.toNat_and]; exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)),
          UInt64.toNat_and]
        exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)
      all_goals
        generalize Bytes.getD buf 1 = b1
        try generalize Bytes.getD buf 2 = b2
        try generalize Bytes.getD buf 3 = b3
        try generalize Bytes.getD buf 4 = b4
        try generalize Bytes.getD buf 5 = b5
        try generalize Bytes.getD buf 6 = b6
        try generalize Bytes.getD buf 7 = b7
      · rw [show (first.toUInt64 &&& 0x3F) <<< 8 ||| b1.toUInt64 =
            ((first.toUInt64 &&& 0x3F) <<< 8 ||| b1.toUInt64) &&& 0x3FFF by bit_blast,
          UInt64.toNat_and]
        exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)
      · rw [show (((first.toUInt64 &&& 0x3F) <<< 8 ||| b1.toUInt64) <<< 8 ||| b2.toUInt64) <<< 8
              ||| b3.toUInt64 =
            ((((first.toUInt64 &&& 0x3F) <<< 8 ||| b1.toUInt64) <<< 8 ||| b2.toUInt64) <<< 8
              ||| b3.toUInt64) &&& 0x3FFFFFFF by bit_blast,
          UInt64.toNat_and]
        exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)
      · rw [show (((((((first.toUInt64 &&& 0x3F) <<< 8 ||| b1.toUInt64) <<< 8 ||| b2.toUInt64)
              <<< 8 ||| b3.toUInt64) <<< 8 ||| b4.toUInt64) <<< 8 ||| b5.toUInt64) <<< 8
              ||| b6.toUInt64) <<< 8 ||| b7.toUInt64 =
            ((((((((first.toUInt64 &&& 0x3F) <<< 8 ||| b1.toUInt64) <<< 8 ||| b2.toUInt64)
              <<< 8 ||| b3.toUInt64) <<< 8 ||| b4.toUInt64) <<< 8 ||| b5.toUInt64) <<< 8
              ||| b6.toUInt64) <<< 8 ||| b7.toUInt64) &&& 0x3FFFFFFFFFFFFFFF by bit_blast,
          UInt64.toNat_and]
        exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)

theorem decode_le_max (buf : Bytes) (v : UInt64) (n : Nat) (h : decode buf = some (v, n)) :
    v ≤ VARINT_MAX := by
  have h1 := decode_bound buf v n h
  have h2 := (decode_length buf v n h).1
  rw [UInt64.le_iff_toNat_le, show VARINT_MAX.toNat = 2 ^ 62 - 1 from rfl]
  rcases h2 with rfl | rfl | rfl | rfl <;> simp at h1 <;> omega

/-- RFC 9000 §16 allows padded forms; flare's decoder accepts them. -/
theorem decode_nonminimal : decode [0x40, 0x01] = some (1, 2) ∧ decode [0x00] = some (0, 1) ∧
    decode [0xC0, 0, 0, 0, 0, 0, 0, 0x01] = some (1, 8) := by
  decide

end Flare.L1.QuicVarint
