/-!
# Bytes

flare's byte buffers (`List[UInt8]`, `Span[UInt8]`) are modelled as
`List UInt8`. Lists keep proofs structural; performance is irrelevant here.
-/
namespace Flare

abbrev Bytes := List UInt8

namespace Bytes

/-- ASCII string → bytes (only used for literals in specs/counterexamples). -/
def ofString (s : String) : Bytes := s.toUTF8.toList

/-- Read byte `i`, or `0` out of bounds (mirrors an unchecked read only where
the model separately proves `i < len`). -/
def getD (b : Bytes) (i : Nat) : UInt8 := (b[i]?).getD 0

/-- Big-endian natural from a byte list. -/
def beNat : Bytes → Nat
  | [] => 0
  | b :: bs => b.toNat * 256 ^ bs.length + beNat bs

/-- Encode `n` big-endian into exactly `k` bytes (truncating high bits). -/
def toBe (k : Nat) (n : Nat) : Bytes :=
  (List.range k).reverse.map fun i => UInt8.ofNat (n / 256 ^ i % 256)

/-- Little-endian natural from a byte list. -/
def leNat : Bytes → Nat
  | [] => 0
  | b :: bs => b.toNat + 256 * leNat bs

/-- Encode `n` little-endian into exactly `k` bytes. -/
def toLe : Nat → Nat → Bytes
  | 0, _ => []
  | k + 1, n => UInt8.ofNat (n % 256) :: toLe k (n / 256)

theorem toLe_length (k n : Nat) : (toLe k n).length = k := by
  induction k generalizing n <;> simp [toLe, *]

theorem leNat_toLe (k n : Nat) (h : n < 256 ^ k) : leNat (toLe k n) = n := by
  induction k generalizing n with
  | zero => simp [toLe, leNat] at *; omega
  | succ k ih =>
    simp only [toLe, leNat]
    have h1 : n / 256 < 256 ^ k := by
      rw [Nat.pow_succ] at h; exact Nat.div_lt_of_lt_mul (by omega)
    rw [ih _ h1]
    have : (UInt8.ofNat (n % 256)).toNat = n % 256 := by
      simp
    rw [this]; omega

theorem leNat_lt (b : Bytes) : leNat b < 256 ^ b.length := by
  induction b with
  | nil => simp [leNat]
  | cons x xs ih =>
    simp only [leNat, List.length_cons, Nat.pow_succ]
    have := x.toNat_lt; omega

theorem toLe_leNat (b : Bytes) : toLe b.length (leNat b) = b := by
  induction b with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.length_cons, toLe, leNat]
    have hx := x.toNat_lt
    have e1 : (x.toNat + 256 * leNat xs) % 256 = x.toNat := by omega
    have e2 : (x.toNat + 256 * leNat xs) / 256 = leNat xs := by omega
    rw [e1, e2, ih]
    simp [UInt8.ofNat_toNat]

end Bytes
end Flare
