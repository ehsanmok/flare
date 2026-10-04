import Flare.L1_Encoding.Bits
/-!
# Byte order helpers (`_htons`, `_ntohs`, `_htonl`)

All flare targets are little-endian, so host→network conversion is a byte
swap. Spec: the network form of a 16/32-bit value is its big-endian byte
sequence; on a little-endian host the in-memory bytes of `htons x` must be
`[hi x, lo x]`, i.e. the byte order of `x` reversed.
-/
namespace Flare.L1.ByteOrder

/-- mirrors flare/net/_libc.mojo:176-183 @59bda50 -/
def htons (x : UInt16) : UInt16 := ((x &&& 0xFF) <<< 8) ||| (x >>> 8)

/-- mirrors flare/net/_libc.mojo:186-189 @59bda50 -/
def ntohs (x : UInt16) : UInt16 := htons x

/-- mirrors flare/net/_libc.mojo:192-200 @59bda50 -/
def htonl (x : UInt32) : UInt32 :=
  ((x &&& 0xFF) <<< 24) ||| (((x >>> 8) &&& 0xFF) <<< 16) |||
  (((x >>> 16) &&& 0xFF) <<< 8) ||| (x >>> 24)

/-- Spec: byte `i` in little-endian memory order of a word. -/
def byte16 (x : UInt16) (i : UInt16) : UInt8 := (x >>> (8 * i)).toUInt8
def byte32 (x : UInt32) (i : UInt32) : UInt8 := (x >>> (8 * i)).toUInt8

theorem ntohs_htons (x : UInt16) : ntohs (htons x) = x := by
  bit_blast [ntohs, htons]

theorem htons_ntohs (x : UInt16) : htons (ntohs x) = x := by
  bit_blast [ntohs, htons]

theorem htons_involutive (x : UInt16) : htons (htons x) = x := ntohs_htons x

/-- `htons` is exactly the byte swap. -/
theorem htons_bytes (x : UInt16) :
    byte16 (htons x) 0 = byte16 x 1 ∧ byte16 (htons x) 1 = byte16 x 0 := by
  constructor <;> bit_blast [byte16, htons]

/-- `htonl` is exactly the 4-byte reversal. -/
theorem htonl_bytes (x : UInt32) :
    byte32 (htonl x) 0 = byte32 x 3 ∧ byte32 (htonl x) 1 = byte32 x 2 ∧
    byte32 (htonl x) 2 = byte32 x 1 ∧ byte32 (htonl x) 3 = byte32 x 0 := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> bit_blast [byte32, htonl]

theorem htonl_involutive (x : UInt32) : htonl (htonl x) = x := by
  bit_blast [htonl]

theorem htons_injective {x y : UInt16} (h : htons x = htons y) : x = y := by
  rw [← htons_involutive x, ← htons_involutive y, h]

theorem htonl_injective {x y : UInt32} (h : htonl x = htonl y) : x = y := by
  rw [← htonl_involutive x, ← htonl_involutive y, h]

end Flare.L1.ByteOrder
