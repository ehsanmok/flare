import Flare.Core
import Flare.L1_Encoding.Bits
/-!
# Raw struct buffers

flare fills kernel structs (`epoll_event`, `kevent`, io_uring SQEs/CQEs)
with per-byte `unsafe_write`s at fixed offsets. `writeBytes buf off bs` is
that loop (`for i in range(len(bs)): buf[off + i] = bs[i]`); `readBytes` is
the matching load loop. Generic lemmas: a read of the field just written
returns it, and writes do not disturb disjoint fields.

Little-endian word ↔ byte-list codecs (`le16/32/64`, `fromLE16/32/64`)
mirror the shift-and-mask expressions used throughout flare.
-/
namespace Flare.L1.Buf
open Flare.Bytes (getD)

/-- Per-byte `unsafe_write` loop. mirrors flare/runtime/io_uring_abi.mojo:407-408,425-428,445-446 @59bda50 -/
def writeBytes : Bytes → Nat → Bytes → Bytes
  | buf, _, [] => buf
  | buf, off, x :: xs => writeBytes (buf.set off x) (off + 1) xs

/-- Per-byte load loop. mirrors flare/runtime/io_uring_abi.mojo:462-463,477-479,495-496 @59bda50 -/
def readBytes (buf : Bytes) (off n : Nat) : Bytes := (List.range n).map fun i => getD buf (off + i)

theorem writeBytes_length (buf : Bytes) (off : Nat) (bs : Bytes) :
    (writeBytes buf off bs).length = buf.length := by
  induction bs generalizing buf off with
  | nil => rfl
  | cons x xs ih => simp [writeBytes, ih]

theorem getD_writeBytes (buf : Bytes) (off : Nat) (bs : Bytes) (j : Nat) :
    getD (writeBytes buf off bs) j =
      if off ≤ j ∧ j < off + bs.length ∧ j < buf.length then getD bs (j - off) else getD buf j := by
  induction bs generalizing buf off with
  | nil => simp [writeBytes]; omega
  | cons x xs ih =>
    simp only [writeBytes, ih, List.length_set, List.length_cons]
    by_cases h1 : off + 1 ≤ j ∧ j < off + 1 + xs.length ∧ j < buf.length
    · rw [if_pos h1, if_pos (by omega)]
      have : j - off = (j - (off + 1)) + 1 := by omega
      rw [this]; simp [getD]
    · rw [if_neg h1]
      simp only [getD, List.getElem?_set]
      by_cases h2 : off = j
      · subst h2; by_cases h3 : off < buf.length <;> simp [h3]
      · simp only [h2, if_false]
        by_cases h4 : off ≤ j ∧ j < off + (xs.length + 1) ∧ j < buf.length
        · exfalso; omega
        · rw [if_neg h4]

/-- Reading back the bytes just written. -/
theorem readBytes_writeBytes (buf : Bytes) (off : Nat) (bs : Bytes)
    (h : off + bs.length ≤ buf.length) : readBytes (writeBytes buf off bs) off bs.length = bs := by
  apply List.ext_getElem
  · simp [readBytes]
  · intro i h1 h2
    simp only [readBytes, List.getElem_map, List.getElem_range, getD_writeBytes]
    simp only [readBytes, List.length_map, List.length_range] at h1
    rw [if_pos (by omega)]
    simp [getD, show off + i - off = i by omega, List.getElem?_eq_getElem h2]

/-- Writes leave disjoint fields untouched. -/
theorem readBytes_writeBytes_disjoint (buf : Bytes) (off : Nat) (bs : Bytes) (off' n : Nat)
    (h : off' + n ≤ off ∨ off + bs.length ≤ off') :
    readBytes (writeBytes buf off bs) off' n = readBytes buf off' n := by
  apply List.ext_getElem
  · simp [readBytes]
  · intro i h1 h2
    simp only [readBytes, List.getElem_map, List.getElem_range, getD_writeBytes]
    simp only [readBytes, List.length_map, List.length_range] at h1
    rw [if_neg (by omega)]

/-! ## Little-endian word codecs -/

/-- mirrors flare/runtime/io_uring_abi.mojo:394-408 @59bda50 -/
def le16 (x : UInt16) : Bytes := [(x &&& 0xFF).toUInt8, ((x >>> 8) &&& 0xFF).toUInt8]
/-- mirrors flare/runtime/io_uring_abi.mojo:412-428 @59bda50 -/
def le32 (x : UInt32) : Bytes := (List.range 4).map fun i => ((x >>> (8 * i).toUInt32) &&& 0xFF).toUInt8
/-- mirrors flare/runtime/io_uring_abi.mojo:432-446 @59bda50 -/
def le64 (x : UInt64) : Bytes := (List.range 8).map fun i => ((x >>> (8 * i).toUInt64) &&& 0xFF).toUInt8

/-- mirrors flare/runtime/io_uring_abi.mojo:467-479 @59bda50 -/
def fromLE16 (bs : Bytes) : UInt16 := (getD bs 0).toUInt16 ||| ((getD bs 1).toUInt16 <<< 8)
/-- mirrors flare/runtime/io_uring_abi.mojo:450-463 @59bda50 -/
def fromLE32 (bs : Bytes) : UInt32 :=
  (List.range 4).foldl (fun v i => v ||| ((getD bs i).toUInt32 <<< (8 * i).toUInt32)) 0
/-- mirrors flare/runtime/io_uring_abi.mojo:483-496 @59bda50 -/
def fromLE64 (bs : Bytes) : UInt64 :=
  (List.range 8).foldl (fun v i => v ||| ((getD bs i).toUInt64 <<< (8 * i).toUInt64)) 0

theorem le16_length (x : UInt16) : (le16 x).length = 2 := rfl
theorem le32_length (x : UInt32) : (le32 x).length = 4 := by simp [le32]
theorem le64_length (x : UInt64) : (le64 x).length = 8 := by simp [le64]

theorem fromLE16_le16 (x : UInt16) : fromLE16 (le16 x) = x := by
  simp only [fromLE16, le16, getD, List.getElem?_cons_zero, List.getElem?_cons_succ,
    Option.getD_some]
  bit_blast

theorem fromLE32_le32 (x : UInt32) : fromLE32 (le32 x) = x := by
  simp only [fromLE32, le32, List.range_succ, List.range_zero, List.nil_append, List.map_append,
    List.map_cons, List.map_nil, List.foldl_append, List.foldl_cons, List.foldl_nil, getD,
    List.cons_append, List.getElem?_cons_zero, List.getElem?_cons_succ, Option.getD_some]
  bit_blast

theorem fromLE64_le64 (x : UInt64) : fromLE64 (le64 x) = x := by
  simp only [fromLE64, le64, List.range_succ, List.range_zero, List.nil_append, List.map_append,
    List.map_cons, List.map_nil, List.foldl_append, List.foldl_cons, List.foldl_nil, getD,
    List.cons_append, List.getElem?_cons_zero, List.getElem?_cons_succ, Option.getD_some]
  bit_blast

theorem le32_fromLE32 (bs : Bytes) (h : bs.length = 4) : le32 (fromLE32 bs) = bs := by
  match bs, h with
  | [a, b, c, d], _ =>
    simp only [le32, fromLE32, List.range_succ, List.range_zero, List.nil_append, List.map_append,
      List.map_cons, List.map_nil, List.foldl_append, List.foldl_cons, List.foldl_nil, getD,
      List.cons_append, List.getElem?_cons_zero, List.getElem?_cons_succ, Option.getD_some,
      List.cons.injEq, and_true]
    refine ⟨?_, ?_, ?_, ?_⟩ <;> bit_blast

end Flare.L1.Buf
