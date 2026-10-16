import Flare.Core
import Flare.L1_Encoding.Bits
import Flare.L1_Encoding.Utf8
/-!
# `ByteReader` / `ByteWriter` (`io/byte_cursor.mojo`) and the protobuf
length-delimited guard (`grpc/proto.mojo`)

`ByteReader` is `{buf, pos : Int}`; every read calls `_need(n)`, which
raises unless `n ≥ 0 ∧ pos + n ≤ len(buf)`. The check is
`n < 0 or n > len(buf) - pos`, which cannot overflow in Mojo `Int`
(`Int64`). `ProtoReader.read_bytes` / `ProtoReader.skip` in
`grpc/proto.mojo`, where `n` is a 64-bit varint taken from the wire, use
the same check.

* `guardFixed_iff`: the guard is exact for every `n`.
* `Inv` (`0 ≤ pos ≤ len`) is preserved by every operation that passes the
  shipped guard (`skip_inv`, `readBytes_spec`), and every read touches only
  `[pos, pos + k)`.
* Read-after-write round trips for all six integer widths, and
  `readUtf8_wf`: `read_utf8` only ever returns RFC 3629 well-formed bytes.
-/
namespace Flare.L1.ByteCursor
open Flare.Bytes (getD)

set_option linter.unusedSimpArgs false

/-! ## Int64 arithmetic facts -/

theorem add_toInt_of_fits (a b : Int64) (h1 : -2 ^ 63 ≤ a.toInt + b.toInt)
    (h2 : a.toInt + b.toInt < 2 ^ 63) : (a + b).toInt = a.toInt + b.toInt := by
  rw [Int64.toInt_add]; exact Int.bmod_eq_of_le (by omega) (by omega)

theorem sub_toInt_of_fits (a b : Int64) (h1 : -2 ^ 63 ≤ a.toInt - b.toInt)
    (h2 : a.toInt - b.toInt < 2 ^ 63) : (a - b).toInt = a.toInt - b.toInt := by
  rw [Int64.toInt_sub]; exact Int.bmod_eq_of_le (by omega) (by omega)

/-- `len(buf)` as a Mojo `Int` (lists shorter than `2^63`). -/
def lenI (b : Bytes) : Int64 := Int64.ofNat b.length

theorem lenI_toInt (b : Bytes) (h : b.length < 2 ^ 63) : (lenI b).toInt = b.length :=
  Int64.toInt_ofNat_of_lt h

/-! ## The bounds guard -/

/-- `n < 0 or n > len - pos` is *false* (the guard does not raise); `len - pos`
cannot overflow when `0 ≤ pos ≤ len`. `ByteReader._need` and the
`grpc/proto.mojo` reader both use it. -/
def guardFixed (pos n : Int64) (len : Nat) : Bool :=
  !(decide (n < 0) || decide (n > Int64.ofNat len - pos))

/-- Cursor invariant: `0 ≤ pos ≤ len(buf)`, and the buffer fits in a Mojo `Int`. -/
def PosInv (pos : Int64) (len : Nat) : Prop := 0 ≤ pos.toInt ∧ pos.toInt ≤ len ∧ len < 2 ^ 63

/-- The guard is exact for every `n`. -/
theorem guardFixed_iff (pos n : Int64) (len : Nat) (hI : PosInv pos len) :
    guardFixed pos n len = true ↔ 0 ≤ n.toInt ∧ pos.toInt + n.toInt ≤ len := by
  obtain ⟨h0, h1, h2⟩ := hI
  have hl : (Int64.ofNat len).toInt = len := Int64.toInt_ofNat_of_lt h2
  simp only [guardFixed, Bool.not_eq_true', Bool.or_eq_false_iff, decide_eq_false_iff_not,
    Int64.lt_iff_toInt_lt, gt_iff_lt, Int64.toInt_zero]
  rw [sub_toInt_of_fits _ _ (by rw [hl]; omega) (by rw [hl]; omega), hl]
  omega

/-- Advancing by an accepted amount preserves the invariant. -/
theorem advance_inv (pos n : Int64) (len : Nat) (hI : PosInv pos len)
    (h : guardFixed pos n len = true) : PosInv (pos + n) len ∧ (pos + n).toInt = pos.toInt + n.toInt := by
  rw [guardFixed_iff pos n len hI] at h
  obtain ⟨h0, h1, h2⟩ := hI
  have e := add_toInt_of_fits pos n (by omega) (by omega)
  exact ⟨⟨by omega, by omega, h2⟩, e⟩

/-! ## `ByteReader` -/

structure Reader where
  buf : Bytes
  pos : Int64

namespace Reader

/-- `self.buf[self.pos + k]` (only evaluated after the guard passed). -/
def byteAt (r : Reader) (k : Nat) : UInt8 := getD r.buf (r.pos.toInt.toNat + k)

/-- mirrors flare/io/byte_cursor.mojo#ByteReader._need sha=b7a4079b051e at=dadf0801 (fixed, ENC-04): `_need` raises
iff `n < 0 or n > len(buf) - pos`. -/
def need (r : Reader) (n : Int64) : Bool := guardFixed r.pos n r.buf.length

def adv (r : Reader) (n : Int64) : Reader := { r with pos := r.pos + n }

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.read_u8 sha=dca64841f691 at=dadf0801 (fixed, ENC-04) -/
def readU8 (r : Reader) : Option (UInt8 × Reader) :=
  if r.need 1 then some (r.byteAt 0, r.adv 1) else none

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.read_u16_be sha=854684464d32 at=dadf0801 (fixed, ENC-04) -/
def readU16be (r : Reader) : Option (UInt16 × Reader) :=
  if r.need 2 then some (((r.byteAt 0).toUInt16 <<< 8) ||| (r.byteAt 1).toUInt16, r.adv 2) else none

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.read_u16_le sha=e15a8729a0bc at=dadf0801 (fixed, ENC-04) -/
def readU16le (r : Reader) : Option (UInt16 × Reader) :=
  if r.need 2 then some ((r.byteAt 0).toUInt16 ||| ((r.byteAt 1).toUInt16 <<< 8), r.adv 2) else none

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.read_u32_be sha=0302a88c8cd9 at=dadf0801 (fixed, ENC-04) -/
def readU32be (r : Reader) : Option (UInt32 × Reader) :=
  if r.need 4 then
    some (((r.byteAt 0).toUInt32 <<< 24) ||| ((r.byteAt 1).toUInt32 <<< 16) |||
      ((r.byteAt 2).toUInt32 <<< 8) ||| (r.byteAt 3).toUInt32, r.adv 4)
  else none

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.read_u32_le sha=a615b935f924 at=dadf0801 (fixed, ENC-04) -/
def readU32le (r : Reader) : Option (UInt32 × Reader) :=
  if r.need 4 then
    some ((r.byteAt 0).toUInt32 ||| ((r.byteAt 1).toUInt32 <<< 8) |||
      ((r.byteAt 2).toUInt32 <<< 16) ||| ((r.byteAt 3).toUInt32 <<< 24), r.adv 4)
  else none

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.read_u64_be sha=bc05acbcad97 at=dadf0801 (fixed, ENC-04) -/
def readU64be (r : Reader) : Option (UInt64 × Reader) :=
  if r.need 8 then
    some ((List.range 8).foldl (fun v k => (v <<< 8) ||| (r.byteAt k).toUInt64) 0, r.adv 8)
  else none

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.read_u64_le sha=733cfebdd71a at=dadf0801 (fixed, ENC-04) -/
def readU64le (r : Reader) : Option (UInt64 × Reader) :=
  if r.need 8 then
    some ((List.range 8).foldl (fun v k => v ||| ((r.byteAt k).toUInt64 <<< (k.toUInt64 * 8))) 0, r.adv 8)
  else none

/-- The `n` bytes at the cursor. -/
def slice (r : Reader) (n : Int64) : Bytes := (r.buf.drop r.pos.toInt.toNat).take n.toInt.toNat

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.read_bytes sha=c28da49b2b80 at=dadf0801 (fixed, ENC-04) -/
def readBytes (r : Reader) (n : Int64) : Option (Bytes × Reader) :=
  if r.need n then some (r.slice n, r.adv n) else none

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.read_utf8 sha=b6e0d57fc0ce at=dadf0801 (fixed, ENC-04) -/
def readUtf8 (r : Reader) (n : Int64) : Option (Bytes × Reader) :=
  if r.need n then
    if Flare.L1.Utf8.isValidUtf8 (r.slice n) then some (r.slice n, r.adv n) else none
  else none

/-- mirrors flare/io/byte_cursor.mojo#ByteReader.skip sha=32d2038ee69f at=dadf0801 (fixed, ENC-04) -/
def skip (r : Reader) (n : Int64) : Option Reader :=
  if r.need n then some (r.adv n) else none

def Inv (r : Reader) : Prop := PosInv r.pos r.buf.length

end Reader

/-- `skip` preserves `0 ≤ pos ≤ len` for every `n`. -/
theorem skip_inv (r r' : Reader) (n : Int64) (hI : r.Inv) (h : r.skip n = some r') :
    r'.Inv := by
  unfold Reader.skip at h
  unfold Reader.need at h
  split at h
  · next hg => cases h; exact (advance_inv _ _ _ hI hg).1
  · cases h

/-- The shipped `read_bytes(n)` returns exactly the bytes
`buf[pos : pos + n]` (all in bounds) and preserves the invariant, for every `n`. -/
theorem readBytes_spec (r : Reader) (n : Int64) (s : Bytes) (r' : Reader) (hI : r.Inv)
    (h : r.readBytes n = some (s, r')) :
    r'.Inv ∧ r'.pos.toInt = r.pos.toInt + n.toInt ∧ r.pos.toInt + n.toInt ≤ r.buf.length ∧
      s.length = n.toInt.toNat ∧
      ∀ j, j < s.length → s[j]? = r.buf[r.pos.toInt.toNat + j]? := by
  unfold Reader.readBytes Reader.need at h
  split at h
  · next hg =>
    simp only [Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h
    have hb := (guardFixed_iff _ _ _ hI).mp hg
    obtain ⟨h1, h2⟩ := advance_inv _ _ _ hI hg
    obtain ⟨i0, i1, i2⟩ := hI
    refine ⟨h1, h2, hb.2, ?_, ?_⟩
    · simp only [Reader.slice, List.length_take, List.length_drop]; omega
    · intro j hj
      simp only [Reader.slice, List.length_take, List.length_drop] at hj
      simp only [Reader.slice, List.getElem?_take, List.getElem?_drop, if_pos (show j < n.toInt.toNat by omega)]
  · cases h

/-- **`read_utf8` only returns well-formed UTF-8** (RFC 3629). -/
theorem readUtf8_wf (r : Reader) (n : Int64) (s : Bytes) (r' : Reader)
    (h : r.readUtf8 n = some (s, r')) : Flare.L1.Utf8.WF s := by
  unfold Reader.readUtf8 at h
  split at h
  · split at h
    · next hv =>
      simp only [Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, -⟩ := h
      exact (Flare.L1.Utf8.isValidUtf8_iff _).mp hv
    · cases h
  · cases h

/-! ## `ByteWriter` -/

/-- mirrors flare/io/byte_cursor.mojo#ByteWriter.write_u16_le sha=346f5741b6b5 at=59bda50f -/
def writeU16be (v : UInt16) : Bytes := [((v >>> 8) &&& 0xFF).toUInt8, (v &&& 0xFF).toUInt8]
/-- mirrors flare/io/byte_cursor.mojo#ByteWriter.write_u32_be sha=2a1a9564ad9a at=59bda50f -/
def writeU16le (v : UInt16) : Bytes := [(v &&& 0xFF).toUInt8, ((v >>> 8) &&& 0xFF).toUInt8]
/-- mirrors flare/io/byte_cursor.mojo#ByteWriter.write_u32_le sha=691009473dd0 at=59bda50f -/
def writeU32be (v : UInt32) : Bytes :=
  [((v >>> 24) &&& 0xFF).toUInt8, ((v >>> 16) &&& 0xFF).toUInt8, ((v >>> 8) &&& 0xFF).toUInt8,
   (v &&& 0xFF).toUInt8]
/-- mirrors flare/io/byte_cursor.mojo#ByteWriter.write_u64_be sha=9f33ac91fea0 at=59bda50f -/
def writeU32le (v : UInt32) : Bytes :=
  [(v &&& 0xFF).toUInt8, ((v >>> 8) &&& 0xFF).toUInt8, ((v >>> 16) &&& 0xFF).toUInt8,
   ((v >>> 24) &&& 0xFF).toUInt8]
/-- mirrors flare/io/byte_cursor.mojo#ByteWriter.write_u64_le sha=051e04191255 at=59bda50f -/
def writeU64be (v : UInt64) : Bytes :=
  (List.range 8).map fun k => ((v >>> (56 - k * 8).toUInt64) &&& 0xFF).toUInt8
/-- mirrors flare/io/byte_cursor.mojo#ByteWriter.write_bytes sha=ece1d8e76e27 at=59bda50f -/
def writeU64le (v : UInt64) : Bytes :=
  (List.range 8).map fun k => ((v >>> (k * 8).toUInt64) &&& 0xFF).toUInt8

/-- A reader positioned at the start of `x` inside `pre ++ x ++ suf`. -/
def readerAt (pre x suf : Bytes) : Reader := ⟨pre ++ x ++ suf, Int64.ofNat pre.length⟩

theorem readerAt_need (pre x suf : Bytes) (h : (pre ++ x ++ suf).length < 2 ^ 63) :
    (readerAt pre x suf).need (Int64.ofNat x.length) = true ∧
    (readerAt pre x suf).adv (Int64.ofNat x.length) =
      ⟨pre ++ x ++ suf, Int64.ofNat (pre.length + x.length)⟩ := by
  simp only [List.length_append] at h
  have hp : (Int64.ofNat pre.length).toInt = pre.length := Int64.toInt_ofNat_of_lt (by omega)
  have hx : (Int64.ofNat x.length).toInt = x.length := Int64.toInt_ofNat_of_lt (by omega)
  have hI : PosInv (Int64.ofNat pre.length) (pre ++ x ++ suf).length := by
    simp only [PosInv, hp, List.length_append]; omega
  refine ⟨?_, ?_⟩
  · simp only [Reader.need, readerAt]
    rw [guardFixed_iff _ _ _ hI, hp, hx]; simp; omega
  · simp only [Reader.adv, readerAt, Reader.mk.injEq, true_and]
    rw [Int64.ofNat_add]

theorem readerAt_at (pre x suf : Bytes) (h : (pre ++ x ++ suf).length < 2 ^ 63) (k : Nat)
    (hk : k < x.length) : (readerAt pre x suf).byteAt k = getD x k := by
  simp only [List.length_append] at h
  have hp : (Int64.ofNat pre.length).toInt = pre.length := Int64.toInt_ofNat_of_lt (by omega)
  simp only [Reader.byteAt, readerAt, hp, Int.toNat_natCast, getD]
  rw [List.append_assoc, List.getElem?_append_right (by omega), Nat.add_sub_cancel_left,
    List.getElem?_append_left hk]

macro "rt_tac" : tactic => `(tactic| (
  simp only [List.range_succ, List.range_zero, List.nil_append, List.map_cons, List.map_nil,
    List.cons_append, List.foldl_cons, List.foldl_nil, List.foldl_append, getD,
    List.getElem?_cons_zero, List.getElem?_cons_succ, Option.getD_some, Nat.reduceMul,
    Nat.reduceSub, Nat.reduceAdd]
  bit_blast))

theorem readU16be_write (v : UInt16) (pre suf : Bytes) (h : (pre ++ writeU16be v ++ suf).length < 2 ^ 63) :
    (readerAt pre (writeU16be v) suf).readU16be =
      some (v, ⟨pre ++ writeU16be v ++ suf, Int64.ofNat (pre.length + 2)⟩) := by
  obtain ⟨hn, ha⟩ := readerAt_need pre (writeU16be v) suf h
  have hat := readerAt_at pre (writeU16be v) suf h
  have hl : (writeU16be v).length = 2 := by simp [writeU16be]
  have e : (2 : Int64) = Int64.ofNat (writeU16be v).length := by rw [hl]; rfl
  unfold Reader.readU16be
  rw [e, hn, if_pos rfl, ha, hl]
  try simp only [List.range_succ, List.range_zero, List.nil_append, List.foldl_cons, List.foldl_nil,
    List.foldl_append]
  rw [hat 0 (by rw [hl]; decide), hat 1 (by rw [hl]; decide)]
  simp only [Option.some.injEq, Prod.mk.injEq, and_true]
  simp only [writeU16be, getD, List.range_succ, List.range_zero, List.nil_append, List.map_cons,
    List.map_nil, List.cons_append, List.getElem?_cons_zero, List.getElem?_cons_succ,
    Option.getD_some, Nat.reduceMul, Nat.reduceSub, Nat.reduceAdd, List.map_append]
  bit_blast

theorem readU16le_write (v : UInt16) (pre suf : Bytes) (h : (pre ++ writeU16le v ++ suf).length < 2 ^ 63) :
    (readerAt pre (writeU16le v) suf).readU16le =
      some (v, ⟨pre ++ writeU16le v ++ suf, Int64.ofNat (pre.length + 2)⟩) := by
  obtain ⟨hn, ha⟩ := readerAt_need pre (writeU16le v) suf h
  have hat := readerAt_at pre (writeU16le v) suf h
  have hl : (writeU16le v).length = 2 := by simp [writeU16le]
  have e : (2 : Int64) = Int64.ofNat (writeU16le v).length := by rw [hl]; rfl
  unfold Reader.readU16le
  rw [e, hn, if_pos rfl, ha, hl]
  try simp only [List.range_succ, List.range_zero, List.nil_append, List.foldl_cons, List.foldl_nil,
    List.foldl_append]
  rw [hat 0 (by rw [hl]; decide), hat 1 (by rw [hl]; decide)]
  simp only [Option.some.injEq, Prod.mk.injEq, and_true]
  simp only [writeU16le, getD, List.range_succ, List.range_zero, List.nil_append, List.map_cons,
    List.map_nil, List.cons_append, List.getElem?_cons_zero, List.getElem?_cons_succ,
    Option.getD_some, Nat.reduceMul, Nat.reduceSub, Nat.reduceAdd, List.map_append]
  bit_blast

theorem readU32be_write (v : UInt32) (pre suf : Bytes) (h : (pre ++ writeU32be v ++ suf).length < 2 ^ 63) :
    (readerAt pre (writeU32be v) suf).readU32be =
      some (v, ⟨pre ++ writeU32be v ++ suf, Int64.ofNat (pre.length + 4)⟩) := by
  obtain ⟨hn, ha⟩ := readerAt_need pre (writeU32be v) suf h
  have hat := readerAt_at pre (writeU32be v) suf h
  have hl : (writeU32be v).length = 4 := by simp [writeU32be]
  have e : (4 : Int64) = Int64.ofNat (writeU32be v).length := by rw [hl]; rfl
  unfold Reader.readU32be
  rw [e, hn, if_pos rfl, ha, hl]
  try simp only [List.range_succ, List.range_zero, List.nil_append, List.foldl_cons, List.foldl_nil,
    List.foldl_append]
  rw [hat 0 (by rw [hl]; decide), hat 1 (by rw [hl]; decide), hat 2 (by rw [hl]; decide), hat 3 (by rw [hl]; decide)]
  simp only [Option.some.injEq, Prod.mk.injEq, and_true]
  simp only [writeU32be, getD, List.range_succ, List.range_zero, List.nil_append, List.map_cons,
    List.map_nil, List.cons_append, List.getElem?_cons_zero, List.getElem?_cons_succ,
    Option.getD_some, Nat.reduceMul, Nat.reduceSub, Nat.reduceAdd, List.map_append]
  bit_blast

theorem readU32le_write (v : UInt32) (pre suf : Bytes) (h : (pre ++ writeU32le v ++ suf).length < 2 ^ 63) :
    (readerAt pre (writeU32le v) suf).readU32le =
      some (v, ⟨pre ++ writeU32le v ++ suf, Int64.ofNat (pre.length + 4)⟩) := by
  obtain ⟨hn, ha⟩ := readerAt_need pre (writeU32le v) suf h
  have hat := readerAt_at pre (writeU32le v) suf h
  have hl : (writeU32le v).length = 4 := by simp [writeU32le]
  have e : (4 : Int64) = Int64.ofNat (writeU32le v).length := by rw [hl]; rfl
  unfold Reader.readU32le
  rw [e, hn, if_pos rfl, ha, hl]
  try simp only [List.range_succ, List.range_zero, List.nil_append, List.foldl_cons, List.foldl_nil,
    List.foldl_append]
  rw [hat 0 (by rw [hl]; decide), hat 1 (by rw [hl]; decide), hat 2 (by rw [hl]; decide), hat 3 (by rw [hl]; decide)]
  simp only [Option.some.injEq, Prod.mk.injEq, and_true]
  simp only [writeU32le, getD, List.range_succ, List.range_zero, List.nil_append, List.map_cons,
    List.map_nil, List.cons_append, List.getElem?_cons_zero, List.getElem?_cons_succ,
    Option.getD_some, Nat.reduceMul, Nat.reduceSub, Nat.reduceAdd, List.map_append]
  bit_blast

theorem readU64be_write (v : UInt64) (pre suf : Bytes) (h : (pre ++ writeU64be v ++ suf).length < 2 ^ 63) :
    (readerAt pre (writeU64be v) suf).readU64be =
      some (v, ⟨pre ++ writeU64be v ++ suf, Int64.ofNat (pre.length + 8)⟩) := by
  obtain ⟨hn, ha⟩ := readerAt_need pre (writeU64be v) suf h
  have hat := readerAt_at pre (writeU64be v) suf h
  have hl : (writeU64be v).length = 8 := by simp [writeU64be]
  have e : (8 : Int64) = Int64.ofNat (writeU64be v).length := by rw [hl]; rfl
  unfold Reader.readU64be
  rw [e, hn, if_pos rfl, ha, hl]
  try simp only [List.range_succ, List.range_zero, List.nil_append, List.foldl_cons, List.foldl_nil,
    List.foldl_append]
  rw [hat 0 (by rw [hl]; decide), hat 1 (by rw [hl]; decide), hat 2 (by rw [hl]; decide), hat 3 (by rw [hl]; decide), hat 4 (by rw [hl]; decide), hat 5 (by rw [hl]; decide), hat 6 (by rw [hl]; decide), hat 7 (by rw [hl]; decide)]
  simp only [Option.some.injEq, Prod.mk.injEq, and_true]
  simp only [writeU64be, getD, List.range_succ, List.range_zero, List.nil_append, List.map_cons,
    List.map_nil, List.cons_append, List.getElem?_cons_zero, List.getElem?_cons_succ,
    Option.getD_some, Nat.reduceMul, Nat.reduceSub, Nat.reduceAdd, List.map_append]
  bit_blast

theorem readU64le_write (v : UInt64) (pre suf : Bytes) (h : (pre ++ writeU64le v ++ suf).length < 2 ^ 63) :
    (readerAt pre (writeU64le v) suf).readU64le =
      some (v, ⟨pre ++ writeU64le v ++ suf, Int64.ofNat (pre.length + 8)⟩) := by
  obtain ⟨hn, ha⟩ := readerAt_need pre (writeU64le v) suf h
  have hat := readerAt_at pre (writeU64le v) suf h
  have hl : (writeU64le v).length = 8 := by simp [writeU64le]
  have e : (8 : Int64) = Int64.ofNat (writeU64le v).length := by rw [hl]; rfl
  unfold Reader.readU64le
  rw [e, hn, if_pos rfl, ha, hl]
  try simp only [List.range_succ, List.range_zero, List.nil_append, List.foldl_cons, List.foldl_nil,
    List.foldl_append]
  rw [hat 0 (by rw [hl]; decide), hat 1 (by rw [hl]; decide), hat 2 (by rw [hl]; decide), hat 3 (by rw [hl]; decide), hat 4 (by rw [hl]; decide), hat 5 (by rw [hl]; decide), hat 6 (by rw [hl]; decide), hat 7 (by rw [hl]; decide)]
  simp only [Option.some.injEq, Prod.mk.injEq, and_true]
  simp only [writeU64le, getD, List.range_succ, List.range_zero, List.nil_append, List.map_cons,
    List.map_nil, List.cons_append, List.getElem?_cons_zero, List.getElem?_cons_succ,
    Option.getD_some, Nat.reduceMul, Nat.reduceSub, Nat.reduceAdd, List.map_append]
  bit_blast

/-! ## `ProtoReader` (`grpc/proto.mojo`): length-delimited fields

The protobuf reader keeps `{data, pos : Int}` and guards `read_bytes` and
the `WIRE_LEN` branch of `skip` with the same expression as `_need`, where
`n = Int(varint)` comes straight off the wire. -/

structure PReader where
  data : Bytes
  pos : Int64

namespace PReader

/-- mirrors flare/grpc/proto.mojo#ProtoReader.has_more+ProtoReader._raw_varint sha=5a368cd2df77 at=59bda50f (`_raw_varint`) -/
def rawVarint (r : PReader) : Option (UInt64 × PReader) := go r.pos 0 0
where
  go (pos : Int64) (shift : Nat) (acc : UInt64) : Option (UInt64 × PReader) :=
    if pos ≥ Int64.ofNat r.data.length then none
    else if h : shift ≥ 64 then none
    else
      let byte := getD r.data pos.toInt.toNat
      let acc := acc ||| ((byte &&& 0x7F).toUInt64 <<< shift.toUInt64)
      if byte &&& 0x80 == 0 then some (acc, { r with pos := pos + 1 })
      else go (pos + 1) (shift + 7) acc
  termination_by 64 - shift

/-- mirrors flare/grpc/proto.mojo#ProtoReader.__init__+ProtoReader.has_more sha=11e19654112b at=59bda50f (`has_more`) -/
def hasMore (r : PReader) : Bool := decide (r.pos < Int64.ofNat r.data.length)

/-- mirrors flare/grpc/proto.mojo#ProtoReader._raw_varint+ProtoReader.read_tag sha=327bfd8a5e1d at=59bda50f (`read_tag`) -/
def readTag (r : PReader) : Option ((Int64 × Int64) × PReader) :=
  match rawVarint r with
  | none => none
  | some (key, r) =>
    let field := (key >>> 3).toInt64
    let wire := (key &&& 7).toInt64
    if field ≤ 0 then none else some ((field, wire), r)

/-- mirrors flare/grpc/proto.mojo#ProtoReader.skip sha=9f68870e0dcc at=ee6671c5 (fixed, ENC-03) (`skip`, `WIRE_LEN` branch):
`n < 0 or n > len(data) - pos` raises, otherwise `pos += n`. -/
def skipLen (r : PReader) : Option PReader :=
  match rawVarint r with
  | none => none
  | some (v, r) =>
    let n := v.toInt64
    if guardFixed r.pos n r.data.length then some { r with pos := r.pos + n } else none

/-- mirrors flare/grpc/proto.mojo#ProtoReader.read_bytes sha=bb73626186d5 at=ee6671c5 (fixed, ENC-03) (`read_bytes`) -/
def readBytes (r : PReader) : Option (Bytes × PReader) :=
  match rawVarint r with
  | none => none
  | some (v, r) =>
    let n := v.toInt64
    if guardFixed r.pos n r.data.length then
      some ((r.data.drop r.pos.toInt.toNat).take n.toInt.toNat, { r with pos := r.pos + n })
    else none

def Inv (r : PReader) : Prop := PosInv r.pos r.data.length

end PReader

theorem rawVarint_go_inv (r : PReader) (shift : Nat) (pos : Int64) (acc : UInt64) (v : UInt64)
    (r' : PReader) (hI : PosInv pos r.data.length) (h : PReader.rawVarint.go r pos shift acc = some (v, r')) :
    r'.data = r.data ∧ PosInv r'.pos r'.data.length := by
  induction hk : 64 - shift using Nat.strongRecOn generalizing shift pos acc with
  | ind k ih =>
  rw [PReader.rawVarint.go] at h
  obtain ⟨h0, h1, h2⟩ := hI
  have hl : (Int64.ofNat r.data.length).toInt = r.data.length := Int64.toInt_ofNat_of_lt h2
  split at h
  · cases h
  · next hlt =>
    simp only [ge_iff_le, Int64.le_iff_toInt_le, hl, Int.not_le] at hlt
    have e := add_toInt_of_fits pos 1 (by simp; omega) (by simp; omega)
    simp only [Int64.toInt_one] at e
    have hI' : PosInv (pos + 1) r.data.length := ⟨by omega, by omega, h2⟩
    split at h
    · cases h
    · next hs =>
      dsimp only at h
      split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨-, rfl⟩ := h
        exact ⟨rfl, hI'⟩
      · exact ih _ (by omega) (shift + 7) (pos + 1) _ hI' h rfl

theorem rawVarint_inv (r : PReader) (v : UInt64) (r' : PReader) (hI : r.Inv)
    (h : r.rawVarint = some (v, r')) : r'.data = r.data ∧ r'.Inv :=
  rawVarint_go_inv r 0 r.pos 0 v r' hI h

/-- Skipping a length-delimited field preserves
`0 ≤ pos ≤ len(data)` for every wire input. -/
theorem skipLen_inv (r r' : PReader) (hI : r.Inv) (h : r.skipLen = some r') : r'.Inv := by
  unfold PReader.skipLen at h
  split at h
  · cases h
  · next v r1 hv =>
    obtain ⟨hd, hI1⟩ := rawVarint_inv r v r1 hI hv
    dsimp only at h
    split at h
    · next hg =>
      cases h
      exact (advance_inv _ _ _ hI1 hg).1
    · cases h

/-- Likewise for the shipped `read_bytes`: the cursor stays in `[0, len(data)]`. -/
theorem readBytes_inv (r r' : PReader) (b : Bytes) (hI : r.Inv) (h : r.readBytes = some (b, r')) :
    r'.Inv := by
  unfold PReader.readBytes at h
  split at h
  · cases h
  · next v r1 hv =>
    obtain ⟨hd, hI1⟩ := rawVarint_inv r v r1 hI hv
    dsimp only at h
    split at h
    · next hg =>
      cases h
      exact (advance_inv _ _ _ hI1 hg).1
    · cases h

end Flare.L1.ByteCursor
