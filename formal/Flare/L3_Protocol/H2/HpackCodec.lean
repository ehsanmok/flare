import Flare.L3_Protocol.H2.HpackPeer
import Flare.L1_Encoding.HpackInt
import Flare.L1_Encoding.Huffman

/-!
# The HPACK layer on flare's own L1 codecs

`real` instantiates `Hpack.Codec` with the L1 transliterations: the prefix
integer codec (`Flare.L1.HpackInt`, hpack.mojo:101-153) and
`huffman_decode_simd` (`Flare.L1.Huffman.decodeSimdImpl`, with its
success/raise behaviour `okOnly`). `real_correct` discharges the HPACK
layer's codec hypotheses from the L1 theorems, and `real_huff` is the
Huffman round trip a peer's Huffman-coded literal relies on
(`Huffman.encode`, RFC 7541 Appendix B).
-/
namespace Flare.L3.H2.Hpack
open Flare.L1

/-- flare's codecs. mirrors flare/http2/hpack.mojo:101-153 @59bda50 (integers) and
flare/http/hpack_huffman_simd.mojo (`huffman_decode_simd`, via `Flare.L1.Huffman`) -/
def real : Codec where
  encInt p v hi := HpackInt.encode v p hi
  decInt l p := (HpackInt.decode l 0 p).map fun r => (r.1, l.drop r.2)
  huff b := Huffman.okOnly (Huffman.decodeSimdImpl b)

theorem hpackInt_off (buf : Bytes) (N v o : Nat) (h : HpackInt.decode buf 0 N = some (v, o)) :
    0 < o ∧ o ≤ buf.length := by
  unfold HpackInt.decode at h
  split at h
  · cases h
  · rename_i hl
    dsimp only at h
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨_, rfl⟩ := h; omega
    · have := HpackInt.go_bounds buf 1 _ 0 v o rfl (by decide) h
      omega

set_option maxRecDepth 8000 in
theorem high_bits : ∀ p, 4 ≤ p → p ≤ 7 → ∀ n, n < 256 →
    n &&& (0xFF - HpackInt.maxPrefix p) = n / 2 ^ p * 2 ^ p := by
  intro p h4 h7
  have : p = 4 ∨ p = 5 ∨ p = 6 ∨ p = 7 := by omega
  rcases this with rfl | rfl | rfl | rfl <;> decide

theorem real_correct : real.Correct where
  progress l p v r h := by
    simp only [real, Option.map_eq_some_iff] at h
    obtain ⟨⟨v', o⟩, hd, he⟩ := h
    simp only [Prod.mk.injEq] at he
    obtain ⟨rfl, rfl⟩ := he
    have := hpackInt_off l p v' o hd
    simp; omega
  roundtrip p v hi rest h4 h7 hv := by
    obtain ⟨b, bs, he, hf⟩ := HpackInt.encode_flags v p hi (by omega) (by omega)
    refine ⟨b, bs, he, ?_, ?_⟩
    · rw [high_bits p h4 h7 _ b.toNat_lt, high_bits p h4 h7 _ hi.toNat_lt] at hf
      exact Nat.eq_of_mul_eq_mul_right (Nat.two_pow_pos p) hf
    · have := HpackInt.decode_encode [] rest v p hi (by omega) (by omega) (by omega)
      simp only [List.nil_append, List.length_nil, Nat.zero_add] at this
      simp only [real, this, Option.map_some]
      simp

/-- A Huffman-coded literal decodes to its octets. -/
theorem real_huff (s : Bytes) : real.huff (Huffman.encode s) = some s := by
  simp only [real, Huffman.okOnly_decodeSimdImpl, Huffman.decode_encode]

end Flare.L3.H2.Hpack
