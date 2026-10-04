import Flare.L3_Protocol.H3.Control

/-!
# H3-05: a second QPACK encoder/decoder stream and a client push stream are accepted

flare/http3/server.mojo:1045-1068 @59bda50 (`_classify_uni_kind`): only a
second control stream is rejected. A second QPACK encoder (0x02) or decoder
(0x03) stream overwrites `peer_qpack_encoder_stream_id` /
`peer_qpack_decoder_stream_id`; a push stream (0x01) is recorded and its
bytes dropped.

Spec clauses: RFC 9204 §4.2, "Receipt of a second instance of either stream
type MUST be treated as a connection error of type
H3_STREAM_CREATION_ERROR"; RFC 9114 §6.2.2, "If a server receives a
client-initiated push stream, this MUST be treated as a connection error of
type H3_STREAM_CREATION_ERROR."
-/
namespace Flare.Bugs.H3_05
open Flare.L3.H3 Flare.L3.H3.Control

/-- **Counterexample**: two encoder streams (ids 2 and 6) are both accepted. -/
theorem impl_accepts_second_encoder :
    (runClassify Fixes.none {} [(2, 0x02), (6, 0x02)]).toOption = some [.qpackEnc, .qpackEnc] := by
  decide

theorem impl_accepts_second_decoder :
    (runClassify Fixes.none {} [(2, 0x03), (6, 0x03)]).toOption = some [.qpackDec, .qpackDec] := by
  decide

theorem impl_accepts_push :
    (runClassify Fixes.none {} [(2, 0x01)]).toOption = some [.push] := by decide

/-- flare violates the uniqueness property the spec guarantees. -/
theorem violates_spec :
    ¬ (∀ ks, runClassify Fixes.none {} [(2, 0x02), (6, 0x02)] = .ok ks →
        ks.count .qpackEnc ≤ 1) := by
  intro h
  have := h [.qpackEnc, .qpackEnc] rfl
  simp at this

theorem spec_rejects :
    errOf (specClassify { enc := some 2 } 0x02 6) = some .streamCreation ∧
    errOf (specClassify { dec := some 2 } 0x03 6) = some .streamCreation ∧
    errOf (specClassify {} 0x01 2) = some .streamCreation := by decide

/-- Trace level, mirroring the repro (`feed_uni_stream_chunk` with the
one-byte stream type). -/
theorem trace_impl :
    errOf (feedUnis Fixes.none {} [(2, [0x02]), (6, [0x02])]) = none ∧
    errOf (feedUnis Fixes.none {} [(2, [0x03]), (6, [0x03])]) = none ∧
    errOf (feedUnis Fixes.none {} [(2, [0x01])]) = none := by native_decide

theorem trace_fixed :
    errOf (feedUnis Fixes.all {} [(2, [0x02]), (6, [0x02])]) = some .streamCreation ∧
    errOf (feedUnis Fixes.all {} [(2, [0x03]), (6, [0x03])]) = some .streamCreation ∧
    errOf (feedUnis Fixes.all {} [(2, [0x01])]) = some .streamCreation := by native_decide

/-- **The fix meets the spec** on every input ... -/
theorem classifyFixed_spec (u : UniState) (code sid : Nat) :
    classify Fixes.all u code sid = specClassify u code sid :=
  classifyFixed_eq_spec u code sid

/-- ... and so never accepts two critical streams of the same type or a push
stream, however many streams the client opens. -/
theorem fixed_unique (xs : List (Nat × Nat)) (ks : List UKind)
    (h : runClassify Fixes.all {} xs = .ok ks) :
    ks.count .control ≤ 1 ∧ ks.count .qpackEnc ≤ 1 ∧ ks.count .qpackDec ≤ 1 ∧
      ks.count .push = 0 :=
  runClassifyFixed_unique xs {} ks h

end Flare.Bugs.H3_05
