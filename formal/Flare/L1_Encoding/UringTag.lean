import Flare.Core
import Flare.L1_Encoding.Bits
/-!
# io_uring user_data tags and CQE field decoding

`runtime/_uring_optag.mojo` packs an 8-bit op kind and a 56-bit connection
id into the 64-bit `user_data` of each SQE; the completion loop unpacks
them to route CQEs. `runtime/io_uring_sqe.mojo` decodes the CQE: `res` is a
signed 32-bit value read as an unsigned word and sign-extended by hand;
`buffer_id` is the high half of `flags`.

Theorems:
* `unpack_pack`: unpacking a tag gives back `(op, conn_id)` whenever
  `op < 2^8` and `conn_id < 2^56` (so distinct in-range pairs get
  distinct tags, `pack_inj`).
* `pack_unpack`: every 64-bit word is the tag of its own fields.
* `cqeRes_toInt`, `cqeRes_eq_toInt32`: the hand-written sign extension is
  two's-complement reinterpretation of the 32 bits.
* `errno_range`: a failed CQE yields `errno ∈ [1, 2^31]`.
* `bufferId_range`: `buffer_id` is `-1` or the high 16 flag bits.
* `connAssert_fails_open`: the debug assertion `Int(conn_id) <= Int(_CONN_MASK)`
  compares in signed 64-bit, so it accepts `conn_id ≥ 2^63` (which `pack`
  then truncates). Debug-only and unreachable with slot indices; recorded
  under "Checked, not a bug".
-/
namespace Flare.L1.UringTag

set_option linter.unusedSimpArgs false

/-- mirrors flare/runtime/_uring_optag.mojo:57-58 @59bda50 -/
def CONN_MASK : UInt64 := 0x00FFFFFFFFFFFFFF

/-- mirrors flare/runtime/_uring_optag.mojo:62-78 @59bda50 (asserts separate) -/
def pack (op conn : UInt64) : UInt64 := (op <<< 56) ||| (conn &&& CONN_MASK)

/-- mirrors flare/runtime/_uring_optag.mojo:82-84 @59bda50 -/
def unpackOp (u : UInt64) : UInt64 := (u >>> 56) &&& 0xFF

/-- mirrors flare/runtime/_uring_optag.mojo:88-90 @59bda50 -/
def unpackConn (u : UInt64) : UInt64 := u &&& CONN_MASK

/-- The `debug_assert` on `conn_id`: `Int(conn_id) <= Int(_CONN_MASK)` with
Mojo's 64-bit signed `Int`. mirrors flare/runtime/_uring_optag.mojo:68-72 @59bda50 -/
def connAssert (conn : UInt64) : Bool := decide (conn.toInt64 ≤ CONN_MASK.toInt64)

theorem and_low (v m : UInt64) (k : Nat) (hm : m.toNat = 2 ^ k - 1) (h : v.toNat < 2 ^ k) :
    v &&& m = v := by
  apply UInt64.toNat_inj.mp
  rw [UInt64.toNat_and, hm, Nat.and_two_pow_sub_one_eq_mod]
  exact Nat.mod_eq_of_lt h

theorem unpackOp_pack (op conn : UInt64) : unpackOp (pack op conn) = op &&& 0xFF := by
  unfold unpackOp pack CONN_MASK; bit_blast

theorem unpackConn_pack (op conn : UInt64) : unpackConn (pack op conn) = conn &&& CONN_MASK := by
  unfold unpackConn pack CONN_MASK; bit_blast

theorem unpack_pack (op conn : UInt64) (hop : op.toNat < 2 ^ 8) (hc : conn.toNat < 2 ^ 56) :
    unpackOp (pack op conn) = op ∧ unpackConn (pack op conn) = conn := by
  rw [unpackOp_pack, unpackConn_pack]
  exact ⟨and_low op 0xFF 8 rfl hop, and_low conn CONN_MASK 56 rfl hc⟩

theorem pack_inj (op conn op' conn' : UInt64) (hop : op.toNat < 2 ^ 8) (hc : conn.toNat < 2 ^ 56)
    (hop' : op'.toNat < 2 ^ 8) (hc' : conn'.toNat < 2 ^ 56) (h : pack op conn = pack op' conn') :
    op = op' ∧ conn = conn' := by
  obtain ⟨a1, a2⟩ := unpack_pack op conn hop hc
  obtain ⟨b1, b2⟩ := unpack_pack op' conn' hop' hc'
  rw [h] at a1 a2
  exact ⟨a1.symm.trans b1, a2.symm.trans b2⟩

theorem pack_unpack (u : UInt64) : pack (unpackOp u) (unpackConn u) = u := by
  unfold pack unpackOp unpackConn CONN_MASK; bit_blast

theorem connAssert_fails_open :
    connAssert 0x8000000000000000 = true ∧ unpackConn (pack 1 0x8000000000000000) = 0 := by
  decide

/-! ## CQE decoding -/

/-- Sign extension of the raw `res` word.
mirrors flare/runtime/io_uring_sqe.mojo:976-982 @59bda50 -/
def cqeRes (raw : UInt32) : Int32 :=
  if (raw.toNat : Int) ≥ 0x80000000 then Int32.ofInt ((raw.toNat : Int) - 0x100000000)
  else Int32.ofInt raw.toNat

theorem cqeRes_toInt (raw : UInt32) :
    (cqeRes raw).toInt = if raw.toNat < 2 ^ 31 then (raw.toNat : Int) else raw.toNat - 2 ^ 32 := by
  have := raw.toNat_lt
  unfold cqeRes
  by_cases h : raw.toNat < 2 ^ 31
  · rw [if_neg (by omega), if_pos h, Int32.toInt_ofInt_of_le (by omega) (by omega)]
  · rw [if_pos (by omega), if_neg h, Int32.toInt_ofInt_of_le (by omega) (by omega)]; rfl

theorem cqeRes_eq_toInt32 (raw : UInt32) : cqeRes raw = raw.toInt32 := by
  apply Int32.toInt_inj.mp
  rw [cqeRes_toInt]
  show _ = raw.toBitVec.toInt
  rw [BitVec.toInt_eq_toNat_cond]
  have : raw.toBitVec.toNat = raw.toNat := rfl
  rw [this]
  have := raw.toNat_lt
  by_cases h : raw.toNat < 2 ^ 31
  · rw [if_pos h, if_pos (by omega)]
  · rw [if_neg h, if_neg (by omega)]; simp

/-- mirrors flare/runtime/io_uring_sqe.mojo:932-939 @59bda50 -/
def errno (res : Int32) : Int := if res.toInt ≥ 0 then 0 else -res.toInt

theorem errno_range (raw : UInt32) (h : (cqeRes raw).toInt < 0) :
    1 ≤ errno (cqeRes raw) ∧ errno (cqeRes raw) ≤ 2 ^ 31 ∧
      errno (cqeRes raw) = 2 ^ 32 - raw.toNat := by
  have := raw.toNat_lt
  unfold errno
  rw [cqeRes_toInt] at h ⊢
  by_cases h1 : raw.toNat < 2 ^ 31
  · rw [if_pos h1] at h; omega
  · rw [if_neg h1] at h ⊢; rw [if_neg (by omega)]; omega

/-- `IORING_CQE_F_BUFFER`. -/
def F_BUFFER : UInt32 := 1

/-- mirrors flare/runtime/io_uring_sqe.mojo:948-958 @59bda50 -/
def bufferId (flags : UInt32) : Int :=
  if flags &&& F_BUFFER = 0 then -1 else ((flags >>> 16).toNat &&& 0xFFFF : Nat)

theorem bufferId_range (flags : UInt32) :
    (flags &&& F_BUFFER = 0 ∧ bufferId flags = -1) ∨
      (flags &&& F_BUFFER ≠ 0 ∧ bufferId flags = (flags.toNat / 2 ^ 16 : Nat) ∧
        bufferId flags < 2 ^ 16) := by
  unfold bufferId
  have hlt := flags.toNat_lt
  have e : (flags >>> 16).toNat &&& 0xFFFF = flags.toNat / 2 ^ 16 := by
    rw [UInt32.toNat_shiftRight, show (0xFFFF : Nat) = 2 ^ 16 - 1 from rfl,
      Nat.and_two_pow_sub_one_eq_mod, Nat.shiftRight_eq_div_pow,
      show (16 : UInt32).toNat % 32 = 16 from rfl]
    exact Nat.mod_eq_of_lt (by omega)
  by_cases h : flags &&& F_BUFFER = 0
  · exact Or.inl ⟨h, by rw [if_pos h]⟩
  · refine Or.inr ⟨h, ?_, ?_⟩ <;> rw [if_neg h, e] <;> omega

end Flare.L1.UringTag
