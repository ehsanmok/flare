import Flare.Core
/-!
# HPACK Huffman code table (http/hpack_huffman.mojo, RFC 7541 Appendix B)

`TBL` lists `(code, length)` for symbols 0..256 (256 = EOS). Codes are
`_hpack_table_code` (a switch, hpack_huffman.mojo:119-641, falling through
to EOS) and lengths are the hex string `_LEN_TABLE`
(hpack_huffman.mojo:660); the list below was transcribed mechanically
from the switch. `tableLengthImpl` is the actual `_LEN_TABLE` decoder over
the string's bytes and is proved equal to the lengths in `TBL`.
`HuffmanRfc.lean` proves `TBL` equal to an independent transcription of
RFC 7541 Appendix B.

Theorems (all finite checks by kernel `decide`):
* `table_size`, `fits`: 257 entries, lengths in `[5, 30]`, each code fits
  its length.
* `kraft`: `Σ 2^(30 - len) = 2^30`, the Kraft sum of a complete prefix code.
* `prefix_free`: no code is a prefix of another (pairwise over all
  257·256/2 pairs).
* `eos_all_ones`, `padding_not_code`, `ones_not_code`: EOS is 30 one-bits
  and no other code is a run of one-bits, so the encoder's 1-bit padding
  (RFC 7541 §5.2) never decodes as a symbol.
* `tableLengthImpl_eq`: the hex-string length decoder agrees with `TBL`.
* `canon_covers`: listed in canonical (length, code) order, the code
  intervals tile `[0, 2^30)` (completeness: every 30-bit string starts with
  a code).
-/
namespace Flare.L1.Huffman

set_option maxRecDepth 100000

/-- mirrors flare/http/hpack_huffman.mojo:119-641 and :660 @59bda50 -/
def TBL : List (Nat × Nat) := [
  (0x1FF8, 13),
  (0x7FFFD8, 23),
  (0xFFFFFE2, 28),
  (0xFFFFFE3, 28),
  (0xFFFFFE4, 28),
  (0xFFFFFE5, 28),
  (0xFFFFFE6, 28),
  (0xFFFFFE7, 28),
  (0xFFFFFE8, 28),
  (0xFFFFEA, 24),
  (0x3FFFFFFC, 30),
  (0xFFFFFE9, 28),
  (0xFFFFFEA, 28),
  (0x3FFFFFFD, 30),
  (0xFFFFFEB, 28),
  (0xFFFFFEC, 28),
  (0xFFFFFED, 28),
  (0xFFFFFEE, 28),
  (0xFFFFFEF, 28),
  (0xFFFFFF0, 28),
  (0xFFFFFF1, 28),
  (0xFFFFFF2, 28),
  (0x3FFFFFFE, 30),
  (0xFFFFFF3, 28),
  (0xFFFFFF4, 28),
  (0xFFFFFF5, 28),
  (0xFFFFFF6, 28),
  (0xFFFFFF7, 28),
  (0xFFFFFF8, 28),
  (0xFFFFFF9, 28),
  (0xFFFFFFA, 28),
  (0xFFFFFFB, 28),
  (0x14, 6),
  (0x3F8, 10),
  (0x3F9, 10),
  (0xFFA, 12),
  (0x1FF9, 13),
  (0x15, 6),
  (0xF8, 8),
  (0x7FA, 11),
  (0x3FA, 10),
  (0x3FB, 10),
  (0xF9, 8),
  (0x7FB, 11),
  (0xFA, 8),
  (0x16, 6),
  (0x17, 6),
  (0x18, 6),
  (0x0, 5),
  (0x1, 5),
  (0x2, 5),
  (0x19, 6),
  (0x1A, 6),
  (0x1B, 6),
  (0x1C, 6),
  (0x1D, 6),
  (0x1E, 6),
  (0x1F, 6),
  (0x5C, 7),
  (0xFB, 8),
  (0x7FFC, 15),
  (0x20, 6),
  (0xFFB, 12),
  (0x3FC, 10),
  (0x1FFA, 13),
  (0x21, 6),
  (0x5D, 7),
  (0x5E, 7),
  (0x5F, 7),
  (0x60, 7),
  (0x61, 7),
  (0x62, 7),
  (0x63, 7),
  (0x64, 7),
  (0x65, 7),
  (0x66, 7),
  (0x67, 7),
  (0x68, 7),
  (0x69, 7),
  (0x6A, 7),
  (0x6B, 7),
  (0x6C, 7),
  (0x6D, 7),
  (0x6E, 7),
  (0x6F, 7),
  (0x70, 7),
  (0x71, 7),
  (0x72, 7),
  (0xFC, 8),
  (0x73, 7),
  (0xFD, 8),
  (0x1FFB, 13),
  (0x7FFF0, 19),
  (0x1FFC, 13),
  (0x3FFC, 14),
  (0x22, 6),
  (0x7FFD, 15),
  (0x3, 5),
  (0x23, 6),
  (0x4, 5),
  (0x24, 6),
  (0x5, 5),
  (0x25, 6),
  (0x26, 6),
  (0x27, 6),
  (0x6, 5),
  (0x74, 7),
  (0x75, 7),
  (0x28, 6),
  (0x29, 6),
  (0x2A, 6),
  (0x7, 5),
  (0x2B, 6),
  (0x76, 7),
  (0x2C, 6),
  (0x8, 5),
  (0x9, 5),
  (0x2D, 6),
  (0x77, 7),
  (0x78, 7),
  (0x79, 7),
  (0x7A, 7),
  (0x7B, 7),
  (0x7FFE, 15),
  (0x7FC, 11),
  (0x3FFD, 14),
  (0x1FFD, 13),
  (0xFFFFFFC, 28),
  (0xFFFE6, 20),
  (0x3FFFD2, 22),
  (0xFFFE7, 20),
  (0xFFFE8, 20),
  (0x3FFFD3, 22),
  (0x3FFFD4, 22),
  (0x3FFFD5, 22),
  (0x7FFFD9, 23),
  (0x3FFFD6, 22),
  (0x7FFFDA, 23),
  (0x7FFFDB, 23),
  (0x7FFFDC, 23),
  (0x7FFFDD, 23),
  (0x7FFFDE, 23),
  (0xFFFFEB, 24),
  (0x7FFFDF, 23),
  (0xFFFFEC, 24),
  (0xFFFFED, 24),
  (0x3FFFD7, 22),
  (0x7FFFE0, 23),
  (0xFFFFEE, 24),
  (0x7FFFE1, 23),
  (0x7FFFE2, 23),
  (0x7FFFE3, 23),
  (0x7FFFE4, 23),
  (0x1FFFDC, 21),
  (0x3FFFD8, 22),
  (0x7FFFE5, 23),
  (0x3FFFD9, 22),
  (0x7FFFE6, 23),
  (0x7FFFE7, 23),
  (0xFFFFEF, 24),
  (0x3FFFDA, 22),
  (0x1FFFDD, 21),
  (0xFFFE9, 20),
  (0x3FFFDB, 22),
  (0x3FFFDC, 22),
  (0x7FFFE8, 23),
  (0x7FFFE9, 23),
  (0x1FFFDE, 21),
  (0x7FFFEA, 23),
  (0x3FFFDD, 22),
  (0x3FFFDE, 22),
  (0xFFFFF0, 24),
  (0x1FFFDF, 21),
  (0x3FFFDF, 22),
  (0x7FFFEB, 23),
  (0x7FFFEC, 23),
  (0x1FFFE0, 21),
  (0x1FFFE1, 21),
  (0x3FFFE0, 22),
  (0x1FFFE2, 21),
  (0x7FFFED, 23),
  (0x3FFFE1, 22),
  (0x7FFFEE, 23),
  (0x7FFFEF, 23),
  (0xFFFEA, 20),
  (0x3FFFE2, 22),
  (0x3FFFE3, 22),
  (0x3FFFE4, 22),
  (0x7FFFF0, 23),
  (0x3FFFE5, 22),
  (0x3FFFE6, 22),
  (0x7FFFF1, 23),
  (0x3FFFFE0, 26),
  (0x3FFFFE1, 26),
  (0xFFFEB, 20),
  (0x7FFF1, 19),
  (0x3FFFE7, 22),
  (0x7FFFF2, 23),
  (0x3FFFE8, 22),
  (0x1FFFFEC, 25),
  (0x3FFFFE2, 26),
  (0x3FFFFE3, 26),
  (0x3FFFFE4, 26),
  (0x7FFFFDE, 27),
  (0x7FFFFDF, 27),
  (0x3FFFFE5, 26),
  (0xFFFFF1, 24),
  (0x1FFFFED, 25),
  (0x7FFF2, 19),
  (0x1FFFE3, 21),
  (0x3FFFFE6, 26),
  (0x7FFFFE0, 27),
  (0x7FFFFE1, 27),
  (0x3FFFFE7, 26),
  (0x7FFFFE2, 27),
  (0xFFFFF2, 24),
  (0x1FFFE4, 21),
  (0x1FFFE5, 21),
  (0x3FFFFE8, 26),
  (0x3FFFFE9, 26),
  (0xFFFFFFD, 28),
  (0x7FFFFE3, 27),
  (0x7FFFFE4, 27),
  (0x7FFFFE5, 27),
  (0xFFFEC, 20),
  (0xFFFFF3, 24),
  (0xFFFED, 20),
  (0x1FFFE6, 21),
  (0x3FFFE9, 22),
  (0x1FFFE7, 21),
  (0x1FFFE8, 21),
  (0x7FFFF3, 23),
  (0x3FFFEA, 22),
  (0x3FFFEB, 22),
  (0x1FFFFEE, 25),
  (0x1FFFFEF, 25),
  (0xFFFFF4, 24),
  (0xFFFFF5, 24),
  (0x3FFFFEA, 26),
  (0x7FFFF4, 23),
  (0x3FFFFEB, 26),
  (0x7FFFFE6, 27),
  (0x3FFFFEC, 26),
  (0x3FFFFED, 26),
  (0x7FFFFE7, 27),
  (0x7FFFFE8, 27),
  (0x7FFFFE9, 27),
  (0x7FFFFEA, 27),
  (0x7FFFFEB, 27),
  (0xFFFFFFE, 28),
  (0x7FFFFEC, 27),
  (0x7FFFFED, 27),
  (0x7FFFFEE, 27),
  (0x7FFFFEF, 27),
  (0x7FFFFF0, 27),
  (0x3FFFFEE, 26),
  (0x3FFFFFFF, 30)]

/-- Neither code is a prefix of the other. -/
def NotPrefix (a b : Nat × Nat) : Prop :=
  if a.2 ≤ b.2 then b.1 >>> (b.2 - a.2) ≠ a.1 else a.1 >>> (a.2 - b.2) ≠ b.1

instance (a b : Nat × Nat) : Decidable (NotPrefix a b) := by unfold NotPrefix; infer_instance

theorem table_size : TBL.length = 257 := by decide +kernel

theorem fits : ∀ e ∈ TBL, 5 ≤ e.2 ∧ e.2 ≤ 30 ∧ e.1 < 2 ^ e.2 := by decide +kernel

theorem kraft : (TBL.map (fun e => 2 ^ (30 - e.2))).sum = 2 ^ 30 := by decide +kernel

theorem prefix_free : TBL.Pairwise NotPrefix := by decide +kernel

theorem eos_all_ones : TBL.getD 256 (0, 0) = (2 ^ 30 - 1, 30) := by decide +kernel

theorem padding_not_code : ∀ k, k < 8 → 0 < k → (2 ^ k - 1, k) ∉ TBL := by decide +kernel

theorem ones_not_code : ∀ k, k < 30 → 0 < k → (2 ^ k - 1, k) ∉ TBL := by decide +kernel

/-! ## `_hpack_table_length`: the `_LEN_TABLE` hex string -/

/-- ASCII bytes of `_LEN_TABLE` (hpack_huffman.mojo:660), two lowercase hex
digits per symbol. -/
def LEN_ASCII : List Nat := [
  48, 100, 49, 55, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 56, 49, 101, 49, 99,
  49, 99, 49, 101, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 101, 49, 99,
  49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 49, 99, 48, 54, 48, 97, 48, 97, 48, 99,
  48, 100, 48, 54, 48, 56, 48, 98, 48, 97, 48, 97, 48, 56, 48, 98, 48, 56, 48, 54, 48, 54, 48, 54,
  48, 53, 48, 53, 48, 53, 48, 54, 48, 54, 48, 54, 48, 54, 48, 54, 48, 54, 48, 54, 48, 55, 48, 56,
  48, 102, 48, 54, 48, 99, 48, 97, 48, 100, 48, 54, 48, 55, 48, 55, 48, 55, 48, 55, 48, 55, 48, 55,
  48, 55, 48, 55, 48, 55, 48, 55, 48, 55, 48, 55, 48, 55, 48, 55, 48, 55, 48, 55, 48, 55, 48, 55,
  48, 55, 48, 55, 48, 55, 48, 55, 48, 56, 48, 55, 48, 56, 48, 100, 49, 51, 48, 100, 48, 101, 48, 54,
  48, 102, 48, 53, 48, 54, 48, 53, 48, 54, 48, 53, 48, 54, 48, 54, 48, 54, 48, 53, 48, 55, 48, 55,
  48, 54, 48, 54, 48, 54, 48, 53, 48, 54, 48, 55, 48, 54, 48, 53, 48, 53, 48, 54, 48, 55, 48, 55,
  48, 55, 48, 55, 48, 55, 48, 102, 48, 98, 48, 101, 48, 100, 49, 99, 49, 52, 49, 54, 49, 52, 49, 52,
  49, 54, 49, 54, 49, 54, 49, 55, 49, 54, 49, 55, 49, 55, 49, 55, 49, 55, 49, 55, 49, 56, 49, 55,
  49, 56, 49, 56, 49, 54, 49, 55, 49, 56, 49, 55, 49, 55, 49, 55, 49, 55, 49, 53, 49, 54, 49, 55,
  49, 54, 49, 55, 49, 55, 49, 56, 49, 54, 49, 53, 49, 52, 49, 54, 49, 54, 49, 55, 49, 55, 49, 53,
  49, 55, 49, 54, 49, 54, 49, 56, 49, 53, 49, 54, 49, 55, 49, 55, 49, 53, 49, 53, 49, 54, 49, 53,
  49, 55, 49, 54, 49, 55, 49, 55, 49, 52, 49, 54, 49, 54, 49, 54, 49, 55, 49, 54, 49, 54, 49, 55,
  49, 97, 49, 97, 49, 52, 49, 51, 49, 54, 49, 55, 49, 54, 49, 57, 49, 97, 49, 97, 49, 97, 49, 98,
  49, 98, 49, 97, 49, 56, 49, 57, 49, 51, 49, 53, 49, 97, 49, 98, 49, 98, 49, 97, 49, 98, 49, 56,
  49, 53, 49, 53, 49, 97, 49, 97, 49, 99, 49, 98, 49, 98, 49, 98, 49, 52, 49, 56, 49, 52, 49, 53,
  49, 54, 49, 53, 49, 53, 49, 55, 49, 54, 49, 54, 49, 57, 49, 57, 49, 56, 49, 56, 49, 97, 49, 55,
  49, 97, 49, 98, 49, 97, 49, 97, 49, 98, 49, 98, 49, 98, 49, 98, 49, 98, 49, 99, 49, 98, 49, 98,
  49, 98, 49, 98, 49, 98, 49, 97, 49, 101]

/-- mirrors flare/http/hpack_huffman.mojo:670-678 @59bda50 -/
def hexDigitValue (c : Nat) : Nat :=
  if 48 ≤ c ∧ c ≤ 57 then c - 48
  else if 97 ≤ c ∧ c ≤ 102 then c - 97 + 10
  else if 65 ≤ c ∧ c ≤ 70 then c - 65 + 10
  else 0

/-- mirrors flare/http/hpack_huffman.mojo:643-667 @59bda50 -/
def tableLengthImpl (s : Nat) : Nat :=
  if 256 < s then 30
  else hexDigitValue (LEN_ASCII.getD (2 * s) 0) * 16 + hexDigitValue (LEN_ASCII.getD (2 * s + 1) 0)

theorem len_ascii_size : LEN_ASCII.length = 514 := by decide +kernel

theorem tableLengthImpl_eq : ∀ s, s < 257 → tableLengthImpl s = (TBL.getD s (0, 0)).2 := by
  decide +kernel

/-! ## Completeness: the canonical intervals tile `[0, 2^30)` -/

/-- `covers a l b`: the half-open intervals in `l` are consecutive, starting
at `a` and ending at `b`. -/
def covers : Nat → List (Nat × Nat) → Nat → Bool
  | a, [], b => a == b
  | a, (s, e) :: rest, b => s == a && covers e rest b

theorem covers_mem (a b v : Nat) (l : List (Nat × Nat)) (h : covers a l b = true)
    (h1 : a ≤ v) (h2 : v < b) : ∃ p ∈ l, p.1 ≤ v ∧ v < p.2 := by
  induction l generalizing a with
  | nil => simp [covers] at h; omega
  | cons p rest ih =>
    obtain ⟨s, e⟩ := p
    simp only [covers, Bool.and_eq_true, beq_iff_eq] at h
    by_cases hv : v < e
    · exact ⟨(s, e), List.mem_cons_self, by simp; omega, hv⟩
    · obtain ⟨q, hq, hq'⟩ := ih e h.2 (by omega)
      exact ⟨q, List.mem_cons_of_mem _ hq, hq'⟩

/-- Symbols in canonical (length, code) order. -/
def CANON : List Nat :=
  [48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51, 52, 53, 54, 55, 56,
  57, 61, 65, 95, 98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117, 58, 66, 67, 68, 69,
  70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113,
  118, 119, 120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39, 43, 124, 35, 62,
  0, 36, 64, 91, 93, 126, 94, 125, 60, 96, 123, 92, 195, 208, 128, 130, 131, 162, 184, 194,
  224, 226, 153, 161, 167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129, 132, 133,
  134, 136, 146, 154, 156, 160, 163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190,
  196, 198, 228, 232, 233, 1, 135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152,
  155, 157, 158, 165, 166, 168, 174, 175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142,
  144, 145, 148, 159, 171, 206, 215, 225, 236, 237, 199, 207, 234, 235, 192, 193, 200, 201,
  202, 205, 210, 213, 218, 219, 238, 240, 242, 243, 255, 203, 204, 211, 212, 214, 221, 222,
  223, 241, 244, 245, 246, 247, 248, 250, 251, 252, 253, 254, 2, 3, 4, 5, 6, 7, 8, 11, 12,
  14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 127, 220, 249, 10, 13,
  22, 256]

/-- The 30-bit interval of strings that start with symbol `s`'s code. -/
def ival (s : Nat) : Nat × Nat :=
  ((TBL.getD s (0, 0)).1 * 2 ^ (30 - (TBL.getD s (0, 0)).2),
   ((TBL.getD s (0, 0)).1 + 1) * 2 ^ (30 - (TBL.getD s (0, 0)).2))

theorem canon_lt : ∀ s ∈ CANON, s < 257 := by decide +kernel

theorem canon_covers : covers 0 (CANON.map ival) (2 ^ 30) = true := by decide +kernel

end Flare.L1.Huffman
