import Flare.L3_Protocol.Quic.FrameProps

/-!
# QUIC-01: an unknown frame's body is parsed as further frames

flare/quic/frame.mojo:957-958 @59bda50: for a frame type outside the v1
table `parse_frame_into` calls `handler.on_unknown(raw_type)` and returns
the bytes consumed so far, i.e. only the type varint. The connection-level
handler (flare/quic/state.mojo:756-760) ignores it, and `dispatch_frames`
(state.mojo:842-858) re-enters the parser right after the type byte, so the
unknown frame's body is executed as frames.

Spec clause: RFC 9000 §12.4, "An endpoint MUST treat the receipt of a frame
of unknown type as a connection error of type FRAME_ENCODING_ERROR."

Counterexample: the payload `21 1c 00 00 00` parses as `[unknown 0x21,
CONNECTION_CLOSE(0, 0, "")]`: the peer smuggles a CONNECTION_CLOSE (or any
other frame) inside an "ignored" extension frame.
-/
namespace Flare.Bugs.QUIC_01
open Flare.L3.Quic.Wire Flare.L3.Quic.Frame

/-- The raised error, if any (`Except` has no decidable equality). -/
def errOf {α : Type} : Except Err α → Option Err
  | .error e => some e
  | .ok _ => none

def payload : Bytes := [0x21, 0x1C, 0x00, 0x00, 0x00]

/-- Every accepted frame of a payload meets the frame-level RFC constraints. -/
def PayloadOk (r : Except Err (List Frame)) : Prop :=
  ∀ fs, r = .ok fs → ∀ f ∈ fs, RfcFrameOk f

/-- flare's drain loop accepts the payload and runs a CONNECTION_CLOSE that
was the body of the unknown frame. -/
theorem smuggled_close :
    (parsePayload payload).toOption = some [.unknown 0x21, .connectionClose false 0 0 []] := by
  native_decide

theorem ok_of_toOption {α : Type} {r : Except Err α} {a : α} (h : r.toOption = some a) :
    r = .ok a := by
  cases r <;> simp_all [Except.toOption]

theorem violates_spec : ¬ PayloadOk (parsePayload payload) := by
  intro h
  exact h _ (ok_of_toOption smuggled_close) (.unknown 0x21) (by simp)

/-- The fixed parser rejects the payload at the unknown type. -/
theorem fixed_rejects :
    errOf (parsePayloadFixed payload) =
      some (.raise "FRAME_ENCODING_ERROR: unknown frame type") := by
  native_decide

/-- The minimal fix meets the spec on every payload. -/
theorem fixed_meets_spec (p : Bytes) : PayloadOk (parsePayloadFixed p) :=
  fun fs h => parsePayloadFixed_ok p fs h

end Flare.Bugs.QUIC_01
