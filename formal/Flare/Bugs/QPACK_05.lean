import Flare.L3_Protocol.Qpack.Ric

/-!
# QPACK-05: an undecodable or blocked field section is not a connection error

flare/qpack/dynamic.mojo:473-498 @59bda50 (`decode_field_section_dynamic`)
raises when the Required Insert Count cannot be decoded (with the shipped
table capacity 0, any non-zero encoded value: `decode_required_insert_count`,
188-209) and when it exceeds the table's insert count ("blocked on missing
inserts"). flare/http3/request_reader.mojo:276-284 turns the raise into
`on_protocol_error`, a flag on that one request stream;
`take_completed_streams` (flare/http3/server.mojo:820-851) then skips the
stream, nothing resets it, and nothing reads `stream_protocol_error`
(flare/quic/server.mojo never calls it). The connection stays open. The
QUIC server always builds `Http3Connection()` (flare/quic/server.mojo:1819,
1836), so the decoder advertises (by default) capacity 0 and
SETTINGS_QPACK_BLOCKED_STREAMS 0.

Spec clause: RFC 9204 §2.1.2: "If a decoder encounters more blocked streams
than it promised to support, it MUST treat this as a connection error of
type QPACK_DECOMPRESSION_FAILED"; §4.5.1.1: a Required Insert Count the
encoder could not have produced is QPACK_DECOMPRESSION_FAILED; §2.2.3: an
invalid dynamic reference is QPACK_DECOMPRESSION_FAILED. Within the blocked
budget, §2.2.1: the stream "becomes blocked" and resumes once the Insert
Count reaches the Required Insert Count.

Model: `dec` is the decoded Required Insert Count (`Ric.implDecode`,
already proved equal to the RFC decode), `ic` the insert count, `refsOk`
whether every field line resolves.
-/
namespace Flare.Bugs.QPACK_05
open Flare.L3.Qpack

inductive Res | headers | blocked | streamErr | connErr
  deriving DecidableEq, Repr

/-- mirrors flare/qpack/dynamic.mojo:480-498 and
flare/http3/request_reader.mojo:276-284 @59bda50 -/
def impl (dec : Option Nat) (ic : Nat) (refsOk : Bool) : Res :=
  match dec with
  | none => .streamErr
  | some r => if r > ic then .streamErr else if refsOk then .headers else .streamErr

/-- RFC 9204 §2.1.2, §2.2.1, §2.2.3, §4.5.1.1; `blocked` streams are already
blocked and `B` is the advertised SETTINGS_QPACK_BLOCKED_STREAMS. -/
def spec (dec : Option Nat) (ic : Nat) (refsOk : Bool) (blocked B : Nat) : Res :=
  match dec with
  | none => .connErr
  | some r =>
    if r > ic then (if blocked + 1 > B then .connErr else .blocked)
    else if refsOk then .headers else .connErr

/-- flare never raises a connection error for a field section. -/
theorem impl_never_connErr (dec : Option Nat) (ic : Nat) (ok : Bool) : impl dec ic ok ≠ .connErr := by
  unfold impl; split
  · simp
  · split
    · simp
    · split <;> simp

/-- With the shipped table (MaxEntries 0) every non-zero encoded Required
Insert Count fails to decode. -/
theorem shipped_rejects (enc ic : UInt64) (h : enc ≠ 0) : Ric.implDecode enc ic 0 = none := by
  simp [Ric.implDecode, h]

/-- **Counterexample (shipped server)**: the field section `01 00 80`
(encoded RIC 1, indexed dynamic line) on a server with capacity 0: the spec
closes the connection; flare drops only the stream. -/
theorem impl_counterexample :
    impl ((Ric.implDecode 1 0 0).map UInt64.toNat) 0 true = .streamErr ∧
    spec ((Ric.implDecode 1 0 0).map UInt64.toNat) 0 true 0 0 = .connErr := by decide

/-- **Counterexample (blocked budget)**: with SETTINGS_QPACK_BLOCKED_STREAMS
1 a section with RIC 1 over insert count 0 must wait; flare fails the stream
for good. (Unreachable from the shipped server, which advertises 0.) -/
theorem impl_drops_blockable :
    impl (some 1) 0 true = .streamErr ∧ spec (some 1) 0 true 0 1 = .blocked := by decide

/-- **Fix** for the shipped configuration (B = 0): turn every stream-level
QPACK failure into a connection error QPACK_DECOMPRESSION_FAILED. -/
def fixed (dec : Option Nat) (ic : Nat) (refsOk : Bool) : Res :=
  match impl dec ic refsOk with
  | .streamErr => .connErr
  | r => r

theorem fixed_spec (dec : Option Nat) (ic : Nat) (ok : Bool) (blocked : Nat) :
    fixed dec ic ok = spec dec ic ok blocked 0 := by
  unfold fixed impl spec
  cases dec with
  | none => rfl
  | some r =>
    simp only
    by_cases h : r > ic
    · simp [h]
    · simp only [h, ↓reduceIte]; cases ok <;> rfl

end Flare.Bugs.QPACK_05
