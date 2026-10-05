import Flare.Bugs.HPACK_Fixtures
import Flare.L3_Protocol.H2.ConnHpack
import Flare.L3_Protocol.H2.HpackCodec

/-!
# HPACK-02: the decode budget never counts the last header

`HpackDecoder.decode` (flare/http2/hpack.mojo:356-441 @59bda50, modelled by `decodeOld`) checks the
budget at the *top* of each iteration and charges the previously decoded
field there (378-384). The field decoded in the last iteration is never
charged, so a block holding one large field passes any budget.

RFC 9113 §6.5.2 / §10.5.1 and RFC 7541 §7.3 let a decoder bound the
memory a header block may expand to; the budget is that bound (every
decoded field counts, RFC 7541 §4.1 sizes). `decode_budget_impl` proves
the exact guarantee of the shipped check (all fields but the last).

Witness (the repro's): one literal field `a: b×100` (133 octets) decodes
with no error under a budget of 50.

Status: resolved. `HpackDecoder.decode` now charges every field, the last included. HPACK-02 has no `Fix` flag: `Hpack.decode` / `decodeLoop` model the fixed decoder, and `decodeOld` / `decodeLoopOld` the pre-fix one (@59bda50) that `bug`, `counterexample` and `bug_real` use. `fixed_shipped` is the shipped behaviour.
-/
namespace Flare.Bugs.HPACK_02
open Flare Flare.L3.H2.Hpack Flare.Bugs.HPACK_Fixtures

def blk : Bytes := 0x00 :: str [0x61] ++ str (List.replicate 100 0x62)

theorem bug : result (decodeOld toy false Table.init blk 50) = .inr [⟨[0x61], List.replicate 100 0x62⟩] ∧
    tsize [⟨[0x61], List.replicate 100 0x62⟩] = 133 := by native_decide

theorem counterexample : ∃ t hs, decodeOld toy false Table.init blk 50 = .ok (t, hs) ∧ ¬ tsize hs ≤ 50 := by
  have h := bug.1
  unfold result at h
  split at h
  · rename_i t hs heq
    cases h
    exact ⟨t, _, heq, by native_decide⟩
  · cases h

theorem fixed_trace : result (decode toy false Table.init blk 50) = .inl .budget := by native_decide

/-- **Fixed**, and shipped: `decode` is now the model of the charge-each-field
check (charge each field right after it is decoded): for every
codec, table and block, whatever is decoded fits the budget. -/
theorem fixed (C : Codec) (ah : Bool) (budget : Nat) (hb : 0 < budget) (t : Table) (buf : Bytes)
    (t' : Table) (hs : List Entry) (h : decode C ah t buf budget = .ok (t', hs)) :
    tsize hs ≤ budget :=
  decode_budget_fixed C ah budget hb _ t [] 0 buf t' hs rfl (Nat.zero_le _) h

/-! ## On flare's real codecs, Huffman-coded literals -/

def blkR : Bytes := encRep real Flare.L1.Huffman.encode (.lit 0 [0x61] (List.replicate 100 0x62) true true)

theorem huffman_coded : blkR.length < 1 + 2 + 2 + 100 := by native_decide

theorem bug_real : result (decodeOld real true Table.init blkR 50) = .inr [⟨[0x61], List.replicate 100 0x62⟩] := by
  native_decide

theorem fixed_trace_real : result (decode real true Table.init blkR 50) = .inl .budget := by native_decide

/-- Shipped: `decode` models the fixed `HpackDecoder.decode`, so the one-field
block that passed a budget of 50 is refused, on the toy and the real codec. -/
theorem fixed_shipped : result (decode toy false Table.init blk 50) = .inl .budget ∧
    result (decode real true Table.init blkR 50) = .inl .budget := ⟨fixed_trace, fixed_trace_real⟩

end Flare.Bugs.HPACK_02
