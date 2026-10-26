import Flare.L1_Encoding.QuicVarint
import Flare.L3_Protocol.H3.ControlStart
import Flare.L3_Protocol.Quic.TransportParams

/-!
# The HTTP/3 and QUIC round trips on flare's varint codec

The H3 frame, SETTINGS, control-stream and transport-parameter round trips
are proved for any encoder meeting `VarintCodec`. This file joins them to
the L1 codec:

* `decVarint_eq`: the H3 model's `decVarint` and `L1.QuicVarint.decode`,
  two models of `flare/quic/varint.mojo#decode_varint`, agree.
* `realEnc_codec`, `realEnc_pos`: `L1.QuicVarint.encode` meets `VarintCodec`
  and the `hpos` side condition.
* `real_*`: the six headline round trips with `enc := realEnc`.

`encode_varint` raises above `VARINT_MAX`, where `QuicVarint.encode` is
`none`; `realEnc` writes a placeholder `[0]` there. Every value the
statements below encode is below `2^62`, so the placeholder is never read.
-/
namespace Flare.L3.H3

open Flare.L1

private theorem shl8_or (x : UInt64) (b : UInt8) (hx : x.toNat < 2 ^ 56) :
    ((x <<< 8) ||| b.toUInt64).toNat = x.toNat * 256 + b.toNat := by
  rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, Nat.shiftLeft_eq]
  have : (8 : UInt64).toNat % 64 = 8 := rfl
  rw [this, Nat.mod_eq_of_lt (by have := b.toNat_lt; omega), Nat.mul_comm,
    ← Nat.two_pow_add_eq_or_of_lt (b.toNat_lt)]

/-- The decoder's continuation loop reads `n` bytes from `s` big-endian onto `a`. -/
theorem fold_beNat (buf : Bytes) : ∀ (n s : Nat) (a : UInt64), s + n ≤ buf.length →
    (a.toNat + 1) * 256 ^ n ≤ 2 ^ 64 →
    ((List.range' s n).foldl (fun (acc : UInt64) i => (acc <<< 8) ||| (buf.getD i).toUInt64) a).toNat =
      a.toNat * 256 ^ n + Bytes.beNat ((buf.drop s).take n) := by
  intro n
  induction n with
  | zero => intro s a _ _; simp [Bytes.beNat]
  | succ n ih =>
    intro s a hs hb
    have hp : 1 ≤ 256 ^ n := Nat.one_le_pow _ _ (by omega)
    have ha : a.toNat < 2 ^ 56 := by
      have : (a.toNat + 1) * 256 ≤ (a.toNat + 1) * 256 ^ (n + 1) :=
        Nat.mul_le_mul_left _ (by rw [Nat.pow_succ]; have := Nat.mul_le_mul_right 256 hp; omega)
      omega
    have hx := (buf.getD s).toNat_lt
    have e := shl8_or a (buf.getD s) ha
    simp only [List.range', List.foldl_cons]
    rw [ih (s + 1) _ (by omega) (by
      rw [e]
      have : (a.toNat * 256 + (buf.getD s).toNat + 1) * 256 ^ n ≤ (a.toNat + 1) * 256 * 256 ^ n :=
        Nat.mul_le_mul_right _ (by omega)
      rw [Nat.pow_succ, ← Nat.mul_assoc] at hb
      have : (a.toNat + 1) * 256 * 256 ^ n = (a.toNat + 1) * 256 ^ n * 256 := by
        rw [Nat.mul_assoc, Nat.mul_comm 256, ← Nat.mul_assoc]
      omega), e]
    have hs' : s < buf.length := by omega
    rw [List.drop_eq_getElem_cons hs', List.take_succ_cons]
    have hg : buf.getD s = buf[s] := by simp [Bytes.getD, List.getElem?_eq_getElem hs']
    have hl : ((buf.drop (s + 1)).take n).length = n := by simp; omega
    simp only [Bytes.beNat, hl, ← hg, Nat.pow_succ, Nat.add_mul, Nat.mul_assoc,
      Nat.mul_comm 256 (256 ^ n)]
    omega

theorem tagLength_eq (b : UInt8) : QuicVarint.tagLength b = varLen (b.toNat / 64) := by
  have h : (b >>> 6).toNat &&& 3 = b.toNat / 64 := by
    rw [UInt8.toNat_shiftRight, show (6 : UInt8).toNat % 8 = 6 from rfl, Nat.shiftRight_eq_div_pow,
      show (3 : Nat) = 2 ^ 2 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
    have := b.toNat_lt
    omega
  simp only [QuicVarint.tagLength, varLen, h]

/-- The two models of `decode_varint` agree: `decVarint` is the L1 decoder
with the value read as a `Nat`. -/
theorem decVarint_eq (b : Bytes) :
    decVarint b = (QuicVarint.decode b).map (fun p => (p.1.toNat, p.2)) := by
  cases b with
  | nil => rfl
  | cons first tl =>
    simp only [decVarint, QuicVarint.decode, tagLength_eq]
    have hL := varLen_pos (first.toNat / 64)
    split
    · rfl
    · rename_i hn
      simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq, and_true]
      have hlen : varLen (first.toNat / 64) - 1 ≤ tl.length := by simp at hn; omega
      have h7 : varLen (first.toNat / 64) - 1 ≤ 7 := by omega
      have ha : (first.toUInt64 &&& 0x3F).toNat = first.toNat % 64 := by
        rw [UInt64.toNat_and, UInt8.toNat_toUInt64, show (0x3F : UInt64).toNat = 2 ^ 6 - 1 from rfl,
          Nat.and_two_pow_sub_one_eq_mod]
      rw [fold_beNat (first :: tl) (varLen (first.toNat / 64) - 1) 1 _ (by simp; omega) (by
        rw [ha]
        have : 256 ^ (varLen (first.toNat / 64) - 1) ≤ 256 ^ 7 := Nat.pow_le_pow_right (by omega) h7
        have : (first.toNat % 64 + 1) * 256 ^ (varLen (first.toNat / 64) - 1) ≤ 64 * 256 ^ 7 :=
          Nat.mul_le_mul (by omega) this
        omega), ha]
      obtain ⟨k, hk⟩ : ∃ k, varLen (first.toNat / 64) = k + 1 := ⟨_, (Nat.succ_pred_eq_of_pos hL.1).symm⟩
      rw [hk, List.take_succ_cons]
      simp only [vval, List.drop_one, List.tail_cons, Nat.add_sub_cancel, List.length_take]
      rw [Nat.min_eq_left (by omega)]

/-- flare's varint encoder (`encode_varint`), as an encoder of naturals. -/
def realEnc (v : Nat) : Bytes := (QuicVarint.encode v.toUInt64).getD [0]

theorem realEnc_codec : VarintCodec realEnc := by
  intro v rest hv
  have hu : v.toUInt64.toNat = v := by
    simp; omega
  have hle : v.toUInt64 ≤ QuicVarint.VARINT_MAX := by
    rw [UInt64.le_iff_toNat_le, hu]
    exact Nat.le_of_lt_succ (by rw [show QuicVarint.VARINT_MAX.toNat = 2 ^ 62 - 1 from rfl]; omega)
  obtain ⟨e, he, hd⟩ := QuicVarint.decode_encode _ hle rest
  simp only [realEnc, he, Option.getD_some, decVarint_eq, hd, Option.map_some, hu]

theorem realEnc_pos (v : Nat) : 1 ≤ (realEnc v).length := by
  unfold realEnc QuicVarint.encode
  split <;> simp

/-! ## The headline round trips on `realEnc` -/

theorem real_decodeFrame_encode (t : Nat) (p rest : Bytes) (ht : t < 2 ^ 62)
    (hp : p.length < 2 ^ 62) :
    decodeFrame (encodeFrame realEnc t p ++ rest) = some (t, p) :=
  decodeFrame_encode realEnc realEnc_codec t p rest ht hp realEnc_pos

theorem real_decodeSettings_encode (s : List (Nat × Nat))
    (hs : ∀ p ∈ s, p.1 < 2 ^ 62 ∧ p.2 < 2 ^ 62) :
    decodeSettings (encodeSettings realEnc s) = some s :=
  decodeSettings_encode realEnc realEnc_codec realEnc_pos s hs

namespace ControlStart

theorem real_emit_control_start (c : Config) (hc : c.Valid) :
    decVarint (emitInitialSettings realEnc c) = some (0x00, (realEnc 0x00).length) ∧
    decodeFrame ((emitInitialSettings realEnc c).drop (realEnc 0x00).length) =
      some (0x04, encodeSettings realEnc (settingsList c)) ∧
    decodeSettings (encodeSettings realEnc (settingsList c)) = some (settingsList c) :=
  emit_control_start realEnc realEnc_codec realEnc_pos c hc

theorem real_implOut_spec (c : Config) (hc : c.Valid) (resp : Nat → Bytes) (reqs : List Nat)
    (h : ClientBidi reqs) : Spec (implOut realEnc c resp reqs) :=
  implOut_spec realEnc realEnc_codec realEnc_pos c hc resp reqs h

end ControlStart

end Flare.L3.H3

namespace Flare.L3.Quic.TransportParams

open Flare.L3.H3 (realEnc realEnc_codec)

theorem real_tlvs_wire (ps : List (Nat × Bytes))
    (h : ∀ p ∈ ps, p.1 < 2 ^ 62 ∧ p.2.length < 2 ^ 62) : tlvs (wire realEnc ps) = some ps :=
  tlvs_wire realEnc realEnc_codec ps h

theorem real_encode_roundtrip (tp : TP) (hs : Sendable tp) :
    ∃ b, encode realEnc tp = .ok b ∧ specDecode b = some tp :=
  encode_roundtrip realEnc realEnc_codec tp hs

end Flare.L3.Quic.TransportParams
