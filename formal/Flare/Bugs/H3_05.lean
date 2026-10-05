import Flare.L3_Protocol.H3.Control

/-!
# H3-05: a second QPACK encoder/decoder stream and a client push stream are accepted

flare/http3/server.mojo:1045-1068 @59bda50 (`_classify_uni_kind`, now 1152-1191): only a
second control stream is rejected. A second QPACK encoder (0x02) or decoder
(0x03) stream overwrites `peer_qpack_encoder_stream_id` /
`peer_qpack_decoder_stream_id`; a push stream (0x01) is recorded and its
bytes dropped.

Spec clauses: RFC 9204 §4.2, "Receipt of a second instance of either stream
type MUST be treated as a connection error of type
H3_STREAM_CREATION_ERROR"; RFC 9114 §6.2.2, "If a server receives a
client-initiated push stream, this MUST be treated as a connection error of
type H3_STREAM_CREATION_ERROR."

Counterexample: two encoder streams (ids 2 and 6), two decoder streams, or a
client push stream are all accepted (`implOld_*` / `trace_implOld`, which use
`Fixes.none`).

Status: resolved. `_classify_uni_kind` raises H3_STREAM_CREATION_ERROR for
a push stream and for a second QPACK encoder or decoder stream.
`Fixes.shipped` models flare with this fix (`impl_rejects`, `trace_shipped`);
`classifyFixed_spec` shows the fix equals the spec and `fixed_unique` that no
client can get two critical streams of one type or a push stream accepted.
Regression tests: tests/h3/test_h3_uni_streams.mojo
`test_second_qpack_stream_of_either_type_is_refused` and
`test_client_push_stream_is_refused` (the latter replaces
`test_push_uni_stream_tolerated`, which encoded the bug).
-/
namespace Flare.Bugs.H3_05
open Flare.L3.H3 Flare.L3.H3.Control

/-- **Counterexample**: two encoder streams (ids 2 and 6) are both accepted. -/
theorem implOld_accepts_second_encoder :
    (runClassify Fixes.none {} [(2, 0x02), (6, 0x02)]).toOption = some [.qpackEnc, .qpackEnc] := by
  decide

theorem implOld_accepts_second_decoder :
    (runClassify Fixes.none {} [(2, 0x03), (6, 0x03)]).toOption = some [.qpackDec, .qpackDec] := by
  decide

theorem implOld_accepts_push :
    (runClassify Fixes.none {} [(2, 0x01)]).toOption = some [.push] := by decide

/-- flare violates the uniqueness property the spec guarantees. -/
theorem implOld_violates_spec :
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
theorem trace_implOld :
    errOf (feedUnis Fixes.none {} [(2, [0x02]), (6, [0x02])]) = none ∧
    errOf (feedUnis Fixes.none {} [(2, [0x03]), (6, [0x03])]) = none ∧
    errOf (feedUnis Fixes.none {} [(2, [0x01])]) = none := by native_decide

/-- Shipped: all three are H3_STREAM_CREATION_ERROR. -/
theorem impl_rejects :
    errOf (classify Fixes.shipped { enc := some 2 } 0x02 6) = some .streamCreation ∧
    errOf (classify Fixes.shipped { dec := some 2 } 0x03 6) = some .streamCreation ∧
    errOf (classify Fixes.shipped {} 0x01 2) = some .streamCreation := by decide

theorem trace_shipped :
    errOf (feedUnis Fixes.shipped {} [(2, [0x02]), (6, [0x02])]) = some .streamCreation ∧
    errOf (feedUnis Fixes.shipped {} [(2, [0x03]), (6, [0x03])]) = some .streamCreation ∧
    errOf (feedUnis Fixes.shipped {} [(2, [0x01])]) = some .streamCreation := by native_decide

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
