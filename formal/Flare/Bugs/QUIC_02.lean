import Flare.L3_Protocol.Quic.FrameProps

/-!
# QUIC-02: MAX_STREAMS / STREAMS_BLOCKED above 2^60 are accepted

flare/quic/frame.mojo:853-861 and 873-884 @59bda50 decode the
`maximum_streams` varint and hand it to the handler with no bound.

Spec clause: RFC 9000 §4.6 / §19.11, "If a max_streams transport parameter
or a MAX_STREAMS frame is received with a value greater than 2^60 ... the
connection MUST be closed immediately with a connection error of type
TRANSPORT_PARAMETER_ERROR or FRAME_ENCODING_ERROR, respectively";
§19.14 the same for STREAMS_BLOCKED.

Counterexample: `12 d0 00 00 00 00 00 00 01` (MAX_STREAMS bidi, value
2^60 + 1) and the same with type `16` (STREAMS_BLOCKED bidi) parse.
-/
namespace Flare.Bugs.QUIC_02
open Flare.L3.Quic.Wire Flare.L3.Quic.Frame

/-- The raised error, if any (`Except` has no decidable equality). -/
def errOf {α : Type} : Except Err α → Option Err
  | .error e => some e
  | .ok _ => none

def maxStreamsWire : Bytes := [0x12, 0xD0, 0, 0, 0, 0, 0, 0, 0x01]
def streamsBlockedWire : Bytes := [0x16, 0xD0, 0, 0, 0, 0, 0, 0, 0x01]

theorem max_streams_accepted :
    (parseFrame maxStreamsWire).toOption = some (.maxStreams false (2 ^ 60 + 1), 9) := by
  native_decide

theorem streams_blocked_accepted :
    (parseFrame streamsBlockedWire).toOption = some (.streamsBlocked false (2 ^ 60 + 1), 9) := by
  native_decide

theorem violates_spec :
    ¬ RfcFrameOk (.maxStreams false (2 ^ 60 + 1)) ∧
      ¬ RfcFrameOk (.streamsBlocked false (2 ^ 60 + 1)) := by
  constructor <;> (simp only [RfcFrameOk]; native_decide)

theorem fixed_rejects :
    errOf (parseFrameFixed maxStreamsWire) =
      some (.raise "FRAME_ENCODING_ERROR: MAX_STREAMS > 2^60") ∧
    errOf (parseFrameFixed streamsBlockedWire) =
      some (.raise "FRAME_ENCODING_ERROR: STREAMS_BLOCKED > 2^60") := by
  constructor <;> native_decide

/-- The minimal fix meets the spec on every input. -/
theorem fixed_meets_spec (b : Bytes) (f : Frame) (n : Nat) (h : parseFrameFixed b = .ok (f, n)) :
    RfcFrameOk f :=
  parseFrameFixed_ok b f n h

end Flare.Bugs.QUIC_02
