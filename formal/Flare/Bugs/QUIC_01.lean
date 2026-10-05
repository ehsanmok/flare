import Flare.L3_Protocol.Quic.FrameProps

/-!
# QUIC-01: an unknown frame's body is parsed as further frames

Status: resolved. `parse_frame_into` now raises FRAME_ENCODING_ERROR for a type
outside the v1 table (flare/quic/frame.mojo, fixed on QUIC-01). The counterexample
below is about the pre-fix parser, `parsePayloadOld` (`Fixes.none`); the shipped
`parsePayload` rejects the payload.

Pre-fix behaviour (flare/quic/frame.mojo:957-958 @59bda50): for a frame type
outside the v1 table `parse_frame_into` called `handler.on_unknown(raw_type)`
and returned the bytes consumed so far, i.e. only the type varint. The
connection-level handler (flare/quic/state.mojo:756-760) ignored it, and
`dispatch_frames` (state.mojo:842-858) re-entered the parser right after the
type byte, so the unknown frame's body was executed as frames.

Spec clause: RFC 9000 §12.4, "An endpoint MUST treat the receipt of a frame
of unknown type as a connection error of type FRAME_ENCODING_ERROR."

Counterexample: the payload `21 1c 00 00 00` parsed as `[unknown 0x21,
CONNECTION_CLOSE(0, 0, "")]`: the peer smuggled a CONNECTION_CLOSE (or any
other frame) inside an "ignored" extension frame.
-/
namespace Flare.Bugs.QUIC_01
open Flare.L3.Quic.Wire Flare.L3.Quic.Frame

/-- The raised error, if any (`Except` has no decidable equality). -/
def errOf {α : Type} : Except Err α → Option Err
  | .error e => some e
  | .ok _ => none

def payload : Bytes := [0x21, 0x1C, 0x00, 0x00, 0x00]

/-- The pre-fix drain loop: unknown types accepted (`Fixes.none`). -/
def parsePayloadOld (p : Bytes) : Except Err (List Frame) :=
  parsePayloadWith (parseFrameWith Fixes.none) p.length p

/-- Every accepted frame of a payload meets the frame-level RFC constraints. -/
def PayloadOk (r : Except Err (List Frame)) : Prop :=
  ∀ fs, r = .ok fs → ∀ f ∈ fs, RfcFrameOk f

/-- The pre-fix drain loop accepted the payload and ran a CONNECTION_CLOSE that
was the body of the unknown frame. -/
theorem smuggled_close :
    (parsePayloadOld payload).toOption = some [.unknown 0x21, .connectionClose false 0 0 []] := by
  native_decide

theorem ok_of_toOption {α : Type} {r : Except Err α} {a : α} (h : r.toOption = some a) :
    r = .ok a := by
  cases r <;> simp_all [Except.toOption]

theorem violates_spec : ¬ PayloadOk (parsePayloadOld payload) := by
  intro h
  exact h _ (ok_of_toOption smuggled_close) (.unknown 0x21) (by simp)

/-- The shipped parser rejects the payload at the unknown type. -/
theorem fixed_rejects :
    errOf (parsePayload payload) =
      some (.raise "FRAME_ENCODING_ERROR: unknown frame type") := by
  native_decide

/-- The shipped parser never returns an unknown frame, so no payload it accepts
contains one (and none is skipped by its type varint alone). -/
theorem fixed_meets_spec (p : Bytes) :
    ∀ fs, parsePayload p = .ok fs → ∀ f ∈ fs, f.kind ≠ .unknown :=
  parsePayload_not_unknown p

end Flare.Bugs.QUIC_01
