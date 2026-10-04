import Flare.L3_Protocol.Quic.FrameProps

/-!
# QUIC-03: an ACK reaching below packet number 0 is clamped, not rejected

flare/quic/frame.mojo:765-792 @59bda50 builds the AckFrame without checking
the ranges; flare/quic/state.mojo:400-427 (`expand_ack_ranges`) then clamps
`largest - first_ack_range` to 0 and `break`s when a gap would go negative.

Spec clause: RFC 9000 §19.3.1, "If any computed packet number is negative,
an endpoint MUST generate a connection error of type FRAME_ENCODING_ERROR."

Counterexample: `02 00 00 00 05` (ACK, largest 0, delay 0, no extra ranges,
first range 5): smallest = 0 - 5 < 0, yet the frame is accepted and the
state machine reports packet 0 acknowledged.
-/
namespace Flare.Bugs.QUIC_03
open Flare.L3.Quic.Wire Flare.L3.Quic.Frame

/-- The raised error, if any (`Except` has no decidable equality). -/
def errOf {α : Type} : Except Err α → Option Err
  | .error e => some e
  | .ok _ => none

def wire : Bytes := [0x02, 0x00, 0x00, 0x00, 0x05]

theorem accepted : (parseFrame wire).toOption = some (.ack 0 0 5 [] false, 5) := by native_decide

theorem violates_spec : ¬ RfcFrameOk (.ack 0 0 5 [] false) := by
  simp only [RfcFrameOk]; decide

theorem fixed_rejects :
    errOf (parseFrameFixed wire) = some (.raise "FRAME_ENCODING_ERROR: negative ack range") := by
  native_decide

/-- The minimal fix meets the spec on every input. -/
theorem fixed_meets_spec (b : Bytes) (f : Frame) (n : Nat) (h : parseFrameFixed b = .ok (f, n)) :
    RfcFrameOk f :=
  parseFrameFixed_ok b f n h

end Flare.Bugs.QUIC_03
