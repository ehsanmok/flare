import Flare.Core

/-!
# HTTP/3 frame codec (RFC 9114 §7)

Byte-level model of `flare/http3/frame.mojo`: the QUIC varint decoder it
reuses, `decode_http3_frame` and the SETTINGS payload codec.

Values are modelled as `Nat`: every decoded varint is below `2^62`, so the
Mojo `UInt64`/`Int` conversions on them (`Int(len_var.value)`,
`payload_start + Int(len)`) cannot wrap (`decVarint_lt`).

The varint *encoder* belongs to the L1 layer; round trips here are stated
for any encoder `enc` satisfying `VarintCodec enc`, a hypothesis the L1
proof discharges for flare's `encode_varint`.
-/
namespace Flare.L3.H3

/-- Wire length selected by the two-bit varint tag. -/
def varLen (tag : Nat) : Nat :=
  if tag = 0 then 1 else if tag = 1 then 2 else if tag = 2 then 4 else 8

/-- Value of the first `L` bytes of a varint: low 6 bits of the first byte,
then 8 bits per following byte, big-endian. -/
def vval : Bytes → Nat
  | [] => 0
  | x :: xs => (x.toNat % 64) * 256 ^ xs.length + Bytes.beNat xs

/-- mirrors flare/quic/varint.mojo:111-138 @59bda50 -/
def decVarint (b : Bytes) : Option (Nat × Nat) :=
  match b with
  | [] => none
  | b0 :: _ =>
    let L := varLen (b0.toNat / 64)
    if b.length < L then none else some (vval (b.take L), L)

theorem varLen_pos (t : Nat) : 1 ≤ varLen t ∧ varLen t ≤ 8 := by
  unfold varLen; split <;> (try split) <;> (try split) <;> omega

theorem decVarint_some {b : Bytes} {v k : Nat} (h : decVarint b = some (v, k)) :
    1 ≤ k ∧ k ≤ 8 ∧ k ≤ b.length := by
  cases b with
  | nil => simp [decVarint] at h
  | cons b0 tl =>
    simp only [decVarint] at h
    split at h
    · cases h
    · cases h
      have := varLen_pos (b0.toNat / 64)
      refine ⟨this.1, this.2, ?_⟩
      omega

/-- Prefix stability: a varint decoded from `b` decodes identically from any
extension `b ++ c`. This is what makes the streaming readers chunking
independent. -/
theorem decVarint_append {b c : Bytes} {v k : Nat} (h : decVarint b = some (v, k)) :
    decVarint (b ++ c) = some (v, k) := by
  have hk := decVarint_some h
  unfold decVarint at h ⊢
  cases b with
  | nil => cases h
  | cons b0 tl =>
    simp only [List.cons_append] at h ⊢
    split at h
    · cases h
    · cases h
      rename_i hl
      have : ¬ (b0 :: (tl ++ c)).length < varLen (b0.toNat / 64) := by
        simp only [List.length_cons, List.length_append] at hl ⊢; omega
      rw [if_neg this]
      have e : (b0 :: (tl ++ c)).take (varLen (b0.toNat / 64)) =
          (b0 :: tl).take (varLen (b0.toNat / 64)) := by
        rw [← List.cons_append, List.take_append_of_le_length (by simp at hl ⊢; omega)]
      rw [e]

theorem beNat_lt (b : Bytes) : Bytes.beNat b < 256 ^ b.length := by
  induction b with
  | nil => simp [Bytes.beNat]
  | cons x xs ih =>
    simp only [Bytes.beNat, List.length_cons, Nat.pow_succ]
    have hx := x.toNat_lt
    have : x.toNat * 256 ^ xs.length + Bytes.beNat xs < (x.toNat + 1) * 256 ^ xs.length := by
      rw [Nat.succ_mul]; omega
    have h2 : (x.toNat + 1) * 256 ^ xs.length ≤ 256 * 256 ^ xs.length :=
      Nat.mul_le_mul_right _ (by omega)
    rw [Nat.mul_comm (256 ^ xs.length) 256]; omega

theorem vval_lt (b : Bytes) (hb : b.length ≤ 8) : vval b < 2 ^ 62 := by
  cases b with
  | nil => simp [vval]
  | cons x xs =>
    simp only [vval]
    have h1 := beNat_lt xs
    have hx : x.toNat % 64 < 64 := Nat.mod_lt _ (by decide)
    have hl : xs.length ≤ 7 := by simp at hb; omega
    have : (x.toNat % 64) * 256 ^ xs.length + Bytes.beNat xs < 64 * 256 ^ xs.length := by
      have : (x.toNat % 64 + 1) * 256 ^ xs.length ≤ 64 * 256 ^ xs.length :=
        Nat.mul_le_mul_right _ (by omega)
      rw [Nat.succ_mul] at this; omega
    have h3 : 64 * 256 ^ xs.length ≤ 64 * 256 ^ 7 :=
      Nat.mul_le_mul_left _ (Nat.pow_le_pow_right (by decide) hl)
    have : (64 * 256 ^ 7 : Nat) = 2 ^ 62 := by decide
    omega

/-- Every decoded varint fits in 62 bits, so `Int(value)` in Mojo is exact. -/
theorem decVarint_lt {b : Bytes} {v k : Nat} (h : decVarint b = some (v, k)) : v < 2 ^ 62 := by
  have hk := decVarint_some h
  cases b with
  | nil => simp [decVarint] at h
  | cons b0 tl =>
    simp only [decVarint] at h
    split at h
    · cases h
    · cases h
      exact vval_lt _ (by simp; omega)

/-- Hypothesis on an encoder: decoding its output (followed by anything)
gives the value back and consumes exactly the encoding. Discharged for
`flare/quic/varint.mojo:encode_varint` by the L1 layer. -/
def VarintCodec (enc : Nat → Bytes) : Prop :=
  ∀ v rest, v < 2 ^ 62 → decVarint (enc v ++ rest) = some (v, (enc v).length)

/-! ## Frames -/

/-- Frame header: `(type, length, header_size)`.
mirrors flare/http3/frame.mojo:137-142 @59bda50 (and
flare/http3/request_reader.mojo:176-194, which is the same logic) -/
def parseHeader (buf : Bytes) : Option (Nat × Nat × Nat) :=
  match decVarint buf with
  | none => none
  | some (t, k1) =>
    let rest := buf.drop k1
    if rest.length = 0 then none else
    match decVarint rest with
    | none => none
    | some (l, k2) => some (t, l, k1 + k2)

/-- mirrors flare/http3/frame.mojo:123-159 @59bda50 -/
def decodeFrame (buf : Bytes) : Option (Nat × Bytes) :=
  match parseHeader buf with
  | none => none
  | some (t, l, hs) =>
    if hs + l > buf.length then none else some (t, (buf.drop hs).take l)

/-- mirrors flare/http3/frame.mojo:95-117 @59bda50 -/
def encodeFrame (enc : Nat → Bytes) (t : Nat) (p : Bytes) : Bytes :=
  enc t ++ enc p.length ++ p

theorem parseHeader_some {buf : Bytes} {t l hs : Nat} (h : parseHeader buf = some (t, l, hs)) :
    2 ≤ hs ∧ hs ≤ 16 ∧ hs ≤ buf.length ∧ l < 2 ^ 62 ∧ t < 2 ^ 62 := by
  unfold parseHeader at h
  split at h
  · cases h
  · rename_i t' k1 h1
    simp only at h
    split at h
    · cases h
    · split at h
      · cases h
      · rename_i l' k2 h2
        cases h
        have a := decVarint_some h1
        have b := decVarint_some h2
        have := decVarint_lt h1
        have := decVarint_lt h2
        simp at b
        omega

theorem parseHeader_append {buf c : Bytes} {t l hs : Nat}
    (h : parseHeader buf = some (t, l, hs)) : parseHeader (buf ++ c) = some (t, l, hs) := by
  unfold parseHeader at h ⊢
  split at h
  · cases h
  · rename_i t' k1 h1
    have hk1 := decVarint_some h1
    rw [decVarint_append h1]
    simp only at h ⊢
    split at h
    · cases h
    · rename_i hne
      split at h
      · cases h
      · rename_i l' k2 h2
        have e : (buf ++ c).drop k1 = buf.drop k1 ++ c := List.drop_append_of_le_length hk1.2.2
        rw [e]
        have hne' : ¬ (buf.drop k1 ++ c).length = 0 := by simp at hne ⊢; omega
        rw [if_neg hne', decVarint_append h2]
        exact h

/-- Bounds safety: a decoded payload is an in-bounds slice of the input
(the Mojo loop `for i in range(payload_start, payload_end)` never reads
past `len(buf)`). -/
theorem decodeFrame_bounds {buf p : Bytes} {t : Nat} (h : decodeFrame buf = some (t, p)) :
    ∃ hs, 2 ≤ hs ∧ hs + p.length ≤ buf.length ∧ p = (buf.drop hs).take p.length := by
  unfold decodeFrame at h
  split at h
  · cases h
  · rename_i t' l hs hh
    split at h
    · cases h
    · cases h
      rename_i hle
      have := parseHeader_some hh
      refine ⟨hs, this.1, ?_, ?_⟩
      · simp only [List.length_take, List.length_drop]; omega
      · have : ((buf.drop hs).take l).length = l := by simp; omega
        rw [this]

/-- Round trip: decoding an encoded frame (followed by anything) yields the
type and payload back. -/
theorem decodeFrame_encode (enc : Nat → Bytes) (henc : VarintCodec enc)
    (t : Nat) (p rest : Bytes) (ht : t < 2 ^ 62) (hp : p.length < 2 ^ 62)
    (hpos : ∀ v, 1 ≤ (enc v).length) :
    decodeFrame (encodeFrame enc t p ++ rest) = some (t, p) := by
  unfold decodeFrame parseHeader encodeFrame
  have e1 := henc t (enc p.length ++ p ++ rest) ht
  simp only [List.append_assoc] at e1 ⊢
  rw [e1]
  simp only
  have hd : (enc t ++ (enc p.length ++ (p ++ rest))).drop (enc t).length
      = enc p.length ++ (p ++ rest) := by simp
  rw [hd]
  have hne : ¬ (enc p.length ++ (p ++ rest)).length = 0 := by
    have := hpos p.length; simp only [List.length_append]; omega
  rw [if_neg hne, henc p.length (p ++ rest) hp]
  simp only
  have hle : ¬ ((enc t).length + (enc p.length).length + p.length >
      (enc t ++ (enc p.length ++ (p ++ rest))).length) := by
    simp only [List.length_append]; omega
  rw [if_neg hle]
  have : (enc t ++ (enc p.length ++ (p ++ rest))).drop ((enc t).length + (enc p.length).length)
      = p ++ rest := by
    rw [← List.drop_drop]; simp
  rw [this]; simp

/-! ## SETTINGS payload (RFC 9114 §7.2.4) -/

/-- mirrors flare/http3/frame.mojo:198-218 @59bda50 -/
def decodeSettings (b : Bytes) : Option (List (Nat × Nat)) :=
  if hb : b.length = 0 then some [] else
  match h1 : decVarint b with
  | none => none
  | some (id, k1) =>
    if k1 ≥ b.length then none else
    match decVarint (b.drop k1) with
    | none => none
    | some (v, k2) =>
      match decodeSettings ((b.drop k1).drop k2) with
      | none => none
      | some tl => some ((id, v) :: tl)
termination_by b.length
decreasing_by
  have := decVarint_some h1
  simp; omega

/-- mirrors flare/http3/frame.mojo:172-195 @59bda50 -/
def encodeSettings (enc : Nat → Bytes) : List (Nat × Nat) → Bytes
  | [] => []
  | (i, v) :: tl => enc i ++ enc v ++ encodeSettings enc tl

/-- SETTINGS round trip: identifiers and values (all `< 2^62`) come back in
order. -/
theorem decodeSettings_encode (enc : Nat → Bytes) (henc : VarintCodec enc)
    (hpos : ∀ v, 1 ≤ (enc v).length) (s : List (Nat × Nat))
    (hs : ∀ p ∈ s, p.1 < 2 ^ 62 ∧ p.2 < 2 ^ 62) :
    decodeSettings (encodeSettings enc s) = some s := by
  induction s with
  | nil => unfold encodeSettings; rw [decodeSettings]; simp
  | cons hd tl ih =>
    obtain ⟨i, v⟩ := hd
    have hi := hs (i, v) (by simp)
    have ih' := ih (fun p hp => hs p (by simp [hp]))
    simp only [encodeSettings]
    rw [decodeSettings]
    have hpi := hpos i
    have hpv := hpos v
    have hne : ¬ (enc i ++ enc v ++ encodeSettings enc tl).length = 0 := by
      simp only [List.length_append]; omega
    rw [dif_neg hne]
    have e1 := henc i (enc v ++ encodeSettings enc tl) hi.1
    simp only [List.append_assoc] at e1 ⊢
    split
    · rename_i h; simp only [List.append_assoc] at h; rw [e1] at h; cases h
    · rename_i id k1 h
      simp only [List.append_assoc] at h
      rw [e1] at h
      cases h
      have hlt : ¬ (enc i).length ≥ (enc i ++ (enc v ++ encodeSettings enc tl)).length := by
        simp only [List.length_append]; omega
      rw [if_neg hlt]
      have hd : (enc i ++ (enc v ++ encodeSettings enc tl)).drop (enc i).length
          = enc v ++ encodeSettings enc tl := by simp
      rw [hd, henc v _ hi.2]
      simp only
      have hd2 : (enc v ++ encodeSettings enc tl).drop (enc v).length = encodeSettings enc tl := by
        simp
      rw [hd2, ih']

end Flare.L3.H3
