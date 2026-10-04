import Flare.L1_Encoding.ByteCursor
/-!
# Protobuf varint (`grpc/proto.mojo`)

`ProtoWriter._raw_varint` emits the base-128 little-endian varint of a
`UInt64` (protobuf encoding guide, "Base 128 Varints"): seven payload bits
per byte, continuation bit `0x80` on every byte but the last.
`ProtoReader._raw_varint` (modelled in `ByteCursor.lean` as
`PReader.rawVarint`) ORs the payload bits in at shifts 0, 7, …, 63 and
raises when the buffer ends or when an 11th byte would be needed
(`shift >= 64`).

Results:
* `writeVarint_length`, `writeVarint_canonical`: the writer emits 1..10
  bytes, every byte but the last has the continuation bit, and the last byte
  is non-zero unless the value is 0, i.e. the shortest (canonical) encoding.
* `rawVarint_writeVarint`: the reader decodes the writer's output for every
  `UInt64`, at any offset and with any trailing bytes, advancing `pos` by
  exactly the encoded length.
* `rawVarint_eleven`: ten continuation bytes in a row are rejected
  ("varint overflow"), so no varint longer than 10 bytes is accepted.
* `tenth_byte_truncates`: in a 10-byte varint only bit 0 of the last byte
  is used, so non-canonical 10-byte forms whose last byte exceeds 1 decode
  modulo 2^64 instead of raising (see the L1 report, "Checked, not a bug").
-/
namespace Flare.L1.ProtoVarint
open Flare.L1.ByteCursor
open Flare.Bytes (getD)

/-- mirrors flare/grpc/proto.mojo:108-117 @59bda50 (`ProtoWriter._raw_varint`) -/
def writeVarint (v : UInt64) : Bytes :=
  let byte : UInt8 := (v &&& 0x7F).toUInt8
  let v' := v >>> 7
  if v' ≠ 0 then (byte ||| 0x80) :: writeVarint v' else [byte]
termination_by v.toNat
decreasing_by
  have : v'.toNat ≠ 0 := fun h => by apply ‹v' ≠ 0›; exact UInt64.toNat_inj.mp (by simpa using h)
  simp only [v', UInt64.toNat_shiftRight] at this ⊢
  simp only [UInt64.reduceToNat, Nat.reduceMod, Nat.shiftRight_eq_div_pow] at this ⊢
  omega

theorem shr7 (v : UInt64) : (v >>> 7).toNat = v.toNat / 128 := by
  rw [UInt64.toNat_shiftRight]; simp [Nat.shiftRight_eq_div_pow]

theorem low7 (v : UInt64) : ((v &&& 0x7F).toUInt8).toNat = v.toNat % 128 := by
  rw [UInt64.toNat_toUInt8, UInt64.toNat_and]
  have : (0x7F : UInt64).toNat = 2 ^ 7 - 1 := rfl
  rw [this, Nat.and_two_pow_sub_one_eq_mod]; omega

theorem or80 (b : UInt8) (h : b.toNat < 128) : (b ||| 0x80).toNat = b.toNat + 128 := by
  rw [UInt8.toNat_or]
  have : (0x80 : UInt8).toNat = 2 ^ 7 * 1 := rfl
  rw [this, Nat.or_comm, ← Nat.two_pow_add_eq_or_of_lt h]; omega

/-- One unfolding step of the writer, on `Nat` values. -/
theorem writeVarint_eq (v : UInt64) :
    writeVarint v = if v.toNat / 128 = 0 then [UInt8.ofNat (v.toNat % 128)]
      else UInt8.ofNat (v.toNat % 128 + 128) :: writeVarint (v >>> 7) := by
  rw [writeVarint]
  have hb : ((v &&& 0x7F).toUInt8) = UInt8.ofNat (v.toNat % 128) := by
    apply UInt8.toNat_inj.mp; rw [low7, UInt8.toNat_ofNat']; omega
  by_cases h : v.toNat / 128 = 0
  · rw [if_pos h, if_neg (by
      intro hne; apply hne; apply UInt64.toNat_inj.mp; rw [shr7]; simpa using h), hb]
  · rw [if_neg h, if_pos (by
      intro he; apply h; have := congrArg UInt64.toNat he; rw [shr7] at this; simpa using this)]
    congr 1
    apply UInt8.toNat_inj.mp
    rw [or80 _ (by rw [low7]; omega), low7, UInt8.toNat_ofNat']; omega

theorem writeVarint_ne_nil (v : UInt64) : writeVarint v ≠ [] := by
  rw [writeVarint_eq]; split <;> simp

/-- The writer emits at most 10 bytes: `⌈bits/7⌉`, at least one. -/
theorem writeVarint_length_aux : ∀ (k : Nat) (v : UInt64), v.toNat < 2 ^ (7 * (k + 1)) →
    (writeVarint v).length ≤ k + 1 := by
  intro k
  induction k with
  | zero =>
    intro v h; rw [writeVarint_eq, if_pos (by omega)]; simp
  | succ k ih =>
    intro v h
    rw [writeVarint_eq]; split
    · simp
    · simp only [List.length_cons]
      have := ih (v >>> 7) (by
        rw [shr7, Nat.div_lt_iff_lt_mul (by decide)]
        have e : 2 ^ (7 * (k + 1)) * 128 = 2 ^ (7 * (k + 1 + 1)) := by
          rw [show 7 * (k + 1 + 1) = 7 * (k + 1) + 7 by omega, Nat.pow_add]
        omega)
      omega

theorem writeVarint_length (v : UInt64) : 1 ≤ (writeVarint v).length ∧ (writeVarint v).length ≤ 10 := by
  refine ⟨?_, writeVarint_length_aux 9 v (by have := v.toNat_lt; omega)⟩
  have := writeVarint_ne_nil v
  cases h : writeVarint v <;> simp_all

/-- Canonical (shortest) form: continuation bit exactly on the non-final
bytes, and a multi-byte encoding never ends in `0x00`. -/
theorem writeVarint_canonical (v : UInt64) :
    ∃ init last, writeVarint v = init ++ [last] ∧ (∀ b ∈ init, 128 ≤ b.toNat) ∧ last.toNat < 128 ∧
      (init ≠ [] → last.toNat ≠ 0) := by
  induction h : v.toNat using Nat.strongRecOn generalizing v with
  | ind n ih =>
    rw [writeVarint_eq]
    by_cases h0 : v.toNat / 128 = 0
    · rw [if_pos h0]
      refine ⟨[], UInt8.ofNat (v.toNat % 128), rfl, by simp, ?_, by simp⟩
      rw [UInt8.toNat_ofNat']; omega
    · rw [if_neg h0]
      obtain ⟨init, last, e, h1, h2, h3⟩ := ih (v >>> 7).toNat (by rw [shr7]; omega) (v >>> 7) rfl
      refine ⟨UInt8.ofNat (v.toNat % 128 + 128) :: init, last, by rw [e]; rfl, ?_, h2, ?_⟩
      · intro b hb
        simp only [List.mem_cons] at hb
        rcases hb with rfl | hb
        · rw [UInt8.toNat_ofNat']; omega
        · exact h1 b hb
      · intro _
        by_cases hi : init = []
        · subst hi
          simp only [List.nil_append] at e
          rw [writeVarint_eq] at e
          split at e
          · next hz =>
            simp only [List.cons.injEq, and_true] at e
            rw [← e, UInt8.toNat_ofNat']; rw [shr7] at hz ⊢; omega
          · simp only [List.cons.injEq] at e; exact absurd e.2 (writeVarint_ne_nil _)
        · exact h3 hi

/-! ## Reader ∘ writer -/

theorem pos_succ (pos : Int64) (p len : Nat) (hp : pos.toInt = p) (hl : p < len) (hlen : len < 2 ^ 63) :
    (pos + 1).toInt = p + 1 := by
  have := add_toInt_of_fits pos 1 (by simp; omega) (by simp; omega)
  simp only [Int64.toInt_one] at this; omega

theorem payload_byte (u : Nat) (b : UInt8) (hb : b = UInt8.ofNat (u % 128) ∨ b = UInt8.ofNat (u % 128 + 128)) :
    (b &&& 0x7F).toNat = u % 128 := by
  rw [UInt8.toNat_and]
  have : (0x7F : UInt8).toNat = 2 ^ 7 - 1 := rfl
  rw [this, Nat.and_two_pow_sub_one_eq_mod]
  rcases hb with rfl | rfl <;> rw [UInt8.toNat_ofNat'] <;> omega

theorem and128 (x : Nat) (hx : x < 256) : x &&& 128 = x / 128 * 128 := by
  have := (by decide +kernel : ∀ i : Fin 256, i.val &&& 128 = i.val / 128 * 128)
  exact this ⟨x, hx⟩

theorem cont_bit (b : UInt8) : (b &&& 0x80 == 0) = decide (b.toNat < 128) := by
  have h1 : (b &&& 0x80).toNat = b.toNat / 128 * 128 := by
    rw [UInt8.toNat_and]; exact and128 _ b.toNat_lt
  by_cases h : b.toNat < 128
  · simp only [h, decide_true, beq_iff_eq]
    apply UInt8.toNat_inj.mp; rw [h1]; simp; omega
  · simp only [h, decide_false, beq_eq_false_iff_ne, ne_eq]
    intro e; have := congrArg UInt8.toNat e; rw [h1] at this; simp at this; omega

theorem getD_of_drop (data t : Bytes) (p : Nat) (b : UInt8) (h : data.drop p = b :: t) :
    getD data p = b := by
  have : (data.drop p)[0]? = some b := by rw [h]; rfl
  rw [List.getElem?_drop, Nat.add_zero] at this
  simp [getD, this]

theorem length_gt_of_drop (data t : Bytes) (p : Nat) (b : UInt8) (h : data.drop p = b :: t) :
    p < data.length := by
  have := congrArg List.length h; simp at this; omega

theorem drop_succ_of_drop (data t : Bytes) (p : Nat) (b : UInt8) (h : data.drop p = b :: t) :
    data.drop (p + 1) = t := by
  rw [← List.drop_drop, h]; rfl

theorem toNat_ofNat_lt (n : Nat) (h : n < 2 ^ 64) : (UInt64.ofNat n).toNat = n := by
  rw [UInt64.toNat_ofNat']; exact Nat.mod_eq_of_lt h

/-- Accumulator step: OR-ing the payload `u % 128` in at `shift = s`. -/
theorem acc_step (acc : UInt64) (V s : Nat) (_hV : V < 2 ^ 64) (hs : s ≤ 63)
    (ha : acc.toNat = V % 2 ^ s) (b : UInt8) (hb : (b &&& 0x7F).toNat = V / 2 ^ s % 128)
    (hfit : V / 2 ^ s % 128 * 2 ^ s < 2 ^ 64) :
    (acc ||| ((b &&& 0x7F).toUInt64 <<< (UInt64.ofNat s))).toNat = V % 2 ^ s + 2 ^ s * (V / 2 ^ s % 128) := by
  rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, hb, ha,
    toNat_ofNat_lt s (by omega), Nat.mod_eq_of_lt (show s < 64 by omega), Nat.shiftLeft_eq,
    Nat.mod_eq_of_lt hfit, Nat.or_comm, Nat.mul_comm, ← Nat.two_pow_add_eq_or_of_lt (Nat.mod_lt _ (Nat.two_pow_pos s))]
  omega

theorem go_write (r : PReader) (post : Bytes) (V : Nat) (hV : V < 2 ^ 64) (hlen : r.data.length < 2 ^ 63) :
    ∀ s, s % 7 = 0 → s ≤ 63 → ∀ (pos : Int64) (p : Nat) (acc : UInt64), pos.toInt = p →
      r.data.drop p = writeVarint (UInt64.ofNat (V / 2 ^ s)) ++ post → acc.toNat = V % 2 ^ s →
      ∃ r', PReader.rawVarint.go r pos s acc = some (UInt64.ofNat V, r') ∧ r'.data = r.data ∧
        r'.pos.toInt = p + (writeVarint (UInt64.ofNat (V / 2 ^ s))).length := by
  intro s
  induction hk : 64 - s using Nat.strongRecOn generalizing s with
  | ind k ih =>
  intro hs7 hs pos p acc hp hd ha
  have hu : (UInt64.ofNat (V / 2 ^ s)).toNat = V / 2 ^ s :=
    toNat_ofNat_lt _ (Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hV)
  have hpow : 0 < 2 ^ s := Nat.two_pow_pos s
  have hdm := Nat.div_add_mod V (2 ^ s)
  rw [writeVarint_eq, hu] at hd
  rw [PReader.rawVarint.go]
  have hl : (Int64.ofNat r.data.length).toInt = r.data.length := Int64.toInt_ofNat_of_lt hlen
  by_cases hlast : V / 2 ^ s / 128 = 0
  · rw [if_pos hlast, List.singleton_append] at hd
    have hpl := length_gt_of_drop _ _ _ _ hd
    rw [if_neg (by simp only [ge_iff_le, Int64.le_iff_toInt_le, hl, hp]; omega),
      dif_neg (by omega)]
    have hbyte := getD_of_drop _ _ _ _ hd
    simp only [hp, Int.toNat_natCast, hbyte]
    rw [cont_bit, UInt8.toNat_ofNat', if_pos (by simp; omega)]
    have hfit : V / 2 ^ s % 128 * 2 ^ s < 2 ^ 64 := by
      have : V / 2 ^ s % 128 * 2 ^ s ≤ V := by
        have := Nat.mod_le (V / 2 ^ s) 128
        have := Nat.mul_le_mul_right (2 ^ s) this
        rw [Nat.mul_comm (V / 2 ^ s)] at this; omega
      omega
    have hacc := acc_step acc V s hV hs ha (UInt8.ofNat (V / 2 ^ s % 128))
      (payload_byte _ _ (.inl rfl)) hfit
    have hs' : s.toUInt64 = UInt64.ofNat s := rfl
    rw [hs']
    refine ⟨{ data := r.data, pos := pos + 1 }, ?_, rfl, ?_⟩
    · have e : (acc ||| (UInt8.ofNat (V / 2 ^ s % 128) &&& 127).toUInt64 <<< UInt64.ofNat s) =
          UInt64.ofNat V := by
        apply UInt64.toNat_inj.mp
        rw [hacc, toNat_ofNat_lt V hV]
        have : V / 2 ^ s % 128 = V / 2 ^ s := by omega
        rw [this]; omega
      rw [e]
    · rw [writeVarint_eq, hu, if_pos hlast, pos_succ pos p r.data.length hp hpl hlen]; simp
  · have hp2 : 2 ^ (s + 7) = 2 ^ s * 128 := by rw [Nat.pow_add]
    have hs7' : s + 7 ≤ 63 := by
      by_cases h : s + 7 ≤ 63
      · exact h
      · have : s = 63 := by omega
        subst this; omega
    have hle : 2 ^ (s + 7) ≤ 2 ^ 63 := Nat.pow_le_pow_right (by decide) hs7'
    have hnext : UInt64.ofNat (V / 2 ^ s) >>> 7 = UInt64.ofNat (V / 2 ^ (s + 7)) := by
      apply UInt64.toNat_inj.mp
      rw [shr7, hu, toNat_ofNat_lt _ (Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hV), hp2,
        Nat.div_div_eq_div_mul]
    rw [if_neg hlast, List.cons_append, hnext] at hd
    have hpl := length_gt_of_drop _ _ _ _ hd
    rw [if_neg (by simp only [ge_iff_le, Int64.le_iff_toInt_le, hl, hp]; omega),
      dif_neg (by omega)]
    have hbyte := getD_of_drop _ _ _ _ hd
    simp only [hp, Int.toNat_natCast, hbyte]
    rw [cont_bit, UInt8.toNat_ofNat', if_neg (by simp; omega)]
    have hfit : V / 2 ^ s % 128 * 2 ^ s < 2 ^ 64 := by
      have := Nat.mul_le_mul_right (2 ^ s) (show V / 2 ^ s % 128 ≤ 127 by omega)
      omega
    have hacc := acc_step acc V s hV hs ha (UInt8.ofNat (V / 2 ^ s % 128 + 128))
      (payload_byte _ _ (.inr rfl)) hfit
    have hs' : s.toUInt64 = UInt64.ofNat s := rfl
    rw [hs']
    have hmod : (acc ||| (UInt8.ofNat (V / 2 ^ s % 128 + 128) &&& 127).toUInt64 <<< UInt64.ofNat s).toNat =
        V % 2 ^ (s + 7) := by
      rw [hacc, hp2, Nat.mod_mul]
    have hp1 := pos_succ pos p r.data.length hp hpl hlen
    obtain ⟨r', h1, h2, h3⟩ := ih (64 - (s + 7)) (by omega) (s + 7) rfl (by omega) hs7' (pos + 1) (p + 1)
      _ hp1 (drop_succ_of_drop _ _ _ _ hd) hmod
    refine ⟨r', h1, h2, ?_⟩
    rw [h3, writeVarint_eq (UInt64.ofNat (V / 2 ^ s)), hu, if_neg hlast, hnext]
    simp only [List.length_cons]; omega

/-- Reader ∘ writer: `_raw_varint` decodes `_raw_varint`'s output for every
`UInt64`, at any offset, with any trailing bytes. -/
theorem rawVarint_writeVarint (r : PReader) (pre post : Bytes) (v : UInt64)
    (hd : r.data = pre ++ writeVarint v ++ post) (hp : r.pos.toInt = pre.length)
    (hlen : r.data.length < 2 ^ 63) :
    ∃ r', r.rawVarint = some (v, r') ∧ r'.data = r.data ∧
      r'.pos.toInt = pre.length + (writeVarint v).length := by
  have hv : UInt64.ofNat (v.toNat / 2 ^ 0) = v := by simp
  have hdrop : r.data.drop pre.length = writeVarint (UInt64.ofNat (v.toNat / 2 ^ 0)) ++ post := by
    rw [hv, hd, List.append_assoc, List.drop_left]
  obtain ⟨r', h1, h2, h3⟩ := go_write r post v.toNat v.toNat_lt hlen 0 rfl (by decide) r.pos
    pre.length 0 hp hdrop (by simp [Nat.mod_one])
  rw [hv] at h3
  refine ⟨r', ?_, h2, h3⟩
  unfold PReader.rawVarint
  rw [h1]; simp

theorem go_none (r : PReader) (hlen : r.data.length < 2 ^ 63) :
    ∀ n s (pos : Int64) (p : Nat) (acc : UInt64), pos.toInt = p → 64 ≤ s + 7 * n →
      (∀ i, i < n → p + i < r.data.length → 128 ≤ (getD r.data (p + i)).toNat) →
      PReader.rawVarint.go r pos s acc = none := by
  have hl : (Int64.ofNat r.data.length).toInt = r.data.length := Int64.toInt_ofNat_of_lt hlen
  intro n
  induction n with
  | zero =>
    intro s pos p acc hp hs _
    rw [PReader.rawVarint.go]
    split
    · rfl
    · rw [dif_pos (by omega)]
  | succ n ih =>
    intro s pos p acc hp hs hc
    rw [PReader.rawVarint.go]
    split
    · rfl
    · next hlt =>
      simp only [ge_iff_le, Int64.le_iff_toInt_le, hl, hp, Int.not_le] at hlt
      split
      · rfl
      · have hb := hc 0 (by omega) (by omega)
        simp only [Nat.add_zero] at hb
        simp only [hp, Int.toNat_natCast]
        rw [cont_bit, if_neg (by simp; omega)]
        exact ih (s + 7) (pos + 1) (p + 1) _ (pos_succ pos p r.data.length hp (by omega) hlen)
          (by omega) (fun i hi hi' => by
            have := hc (i + 1) (by omega) (by omega); rwa [Nat.add_assoc, Nat.add_comm 1 i])

/-- Ten continuation bytes in a row (or a run of continuation bytes cut off by
the end of the buffer) are rejected: no varint longer than 10 bytes is
accepted. -/
theorem rawVarint_eleven (r : PReader) (p : Nat) (hp : r.pos.toInt = p)
    (hlen : r.data.length < 2 ^ 63)
    (hc : ∀ i, i < 10 → p + i < r.data.length → 128 ≤ (getD r.data (p + i)).toNat) :
    r.rawVarint = none :=
  go_none r hlen 10 0 r.pos p 0 hp (by decide) hc

/-- Only bit 0 of a tenth byte reaches the result: `80 80 80 80 80 80 80 80 80 02`
(a non-canonical 10-byte form with payload bit 64 set) decodes to 0 instead of
raising. -/
theorem tenth_byte_truncates :
    (PReader.rawVarint ⟨[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02], 0⟩).map
      (fun x => (x.1, x.2.pos)) = some (0, 10) := by
  decide +kernel

end Flare.L1.ProtoVarint
