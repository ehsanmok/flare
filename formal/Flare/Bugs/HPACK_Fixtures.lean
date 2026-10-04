import Flare.L3_Protocol.H2.Hpack

/-!
# Shared fixture for the HPACK counterexamples

The HPACK decoder is parametric in the L1 prefix-integer and Huffman
codecs (`Codec`). The witnesses only need single-byte integers and no
Huffman, so `toy` decodes a prefix integer whose value fits in the
prefix (RFC 7541 §5.1, first case) and has no Huffman decoder.
-/
namespace Flare.Bugs.HPACK_Fixtures
open Flare Flare.L3.H2.Hpack

def toy : Codec where
  encInt p v hi := [hi ||| UInt8.ofNat v % UInt8.ofNat (2 ^ p)]
  decInt l p := match l with
    | [] => none
    | b :: r => if b.toNat % 2 ^ p < 2 ^ p - 1 then some (b.toNat % 2 ^ p, r) else none
  huff _ := none

/-- Literal string, no Huffman, length < 127. -/
def str (s : Bytes) : Bytes := UInt8.ofNat s.length :: s

/-- The fields a decode returned (`.inr`), or its error (`.inl`). -/
def result : Except DErr (Table × List Entry) → DErr ⊕ List Entry
  | .ok (_, hs) => .inr hs
  | .error e => .inl e

theorem run_of_foldlM (c : Bytes → Bytes) :
    ∀ (evs : List Ev) (j j' : Joint), evs.foldlM (jstep c) j = some j' → (jointLTS c).Run j evs j'
  | [], j, j', h => by
    simp only [List.foldlM, pure, Option.some.injEq] at h; subst h; exact .nil _
  | e :: es, j, j', h => by
    simp only [List.foldlM] at h
    cases hs : jstep c j e with
    | none => rw [hs] at h; cases h
    | some s =>
      rw [hs] at h
      exact .cons hs (run_of_foldlM c es s j' h)

end Flare.Bugs.HPACK_Fixtures
