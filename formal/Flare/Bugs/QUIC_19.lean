import Flare.L3_Protocol.Quic.Streams

/-!
# QUIC-19: STOP_SENDING is never answered with RESET_STREAM

Status: resolved. `StateHandler.on_stop_sending` lists every STOP_SENDING whose
send half is not yet reset in `ConnectionEvents.stop_sending_resets`, and the
client's `_dispatch_frames` answers each with a RESET_STREAM (the STOP_SENDING's
error code, final size `send_offsets[stream]`) through `_answer_stop_sending`;
the listing is what `replyFixed` models, `shipped_replies` pins it. The server
has no stream-sending path of its own that tracks a final size, so only the
client answers (as in the report). The counterexample below is about the
pre-fix `replyImpl`.

Pre-fix behaviour: flare/quic/state.mojo:478-486 @59bda50 (`apply_stop_sending`) only sets the
stream state to RESET_SENT, and flare/quic/client.mojo:902-912
(`_dispatch_frames`) sends nothing in reply. The only RESET_STREAM flare
ever encodes is in `cancel_stream` (client.mojo:1406-1428); the server
never sends one.

Spec clause: RFC 9000 §3.5: "An endpoint that receives a STOP_SENDING frame
MUST send a RESET_STREAM frame if the stream is in the "Ready" or "Send"
state." §3.1: the RESET_STREAM moves the sending part to "Reset Sent".

What goes wrong: a client mid-upload that receives STOP_SENDING stops
sending (send_stream now raises) but never tells the peer the final size;
the peer's receive half never reaches a terminal state, and the
connection-level credit for the stream is never settled (§4.5).

Repro: formal/repro/QUIC-19_stop_sending_not_answered.mojo (client).
-/
namespace Flare.Bugs.QUIC_19
open Flare.L3.Quic.Streams

/-- Frames sent in reply to STOP_SENDING, given whether our send half was
already reset. mirrors flare/quic/client.mojo:902-912 @59bda50 -/
def replyImpl (_sendReset : Bool) : List Kind := []

/-- RFC 9000 §3.5: RESET_STREAM unless the send half is already reset (in
which case one was sent already). -/
def replySpec (sendReset : Bool) : List Kind := if sendReset then [] else [.resetStream]

/-- The fix: on STOP_SENDING, if the stream was not RESET_SENT before the
frame, send RESET_STREAM with the final size. -/
def replyFixed (stateBefore : St) : List Kind :=
  if stateBefore == .resetSent then [] else [.resetStream]

/-- **Counterexample**: a stream in "Send" gets STOP_SENDING, nothing is
sent. -/
theorem impl_silent : replyImpl false = [] ∧ replySpec false = [.resetStream] := by
  native_decide

/-- **Fix meets spec**: when the stream state is the send half's state
(the QUIC-18 split), the fixed reply is the spec's for every event
history. -/
theorem fixed_spec (evs : List Ev) :
    replyFixed (if (runHalves evs).sendReset then .resetSent else .open_) =
      replySpec (runHalves evs).sendReset := by
  unfold replyFixed replySpec
  cases (runHalves evs).sendReset <;> rfl

/-- **The shipped reply** (`stop_sending_resets` non-empty exactly when the
send half is not reset): RESET_STREAM for a stream in Send, nothing for one
already in Reset Sent. -/
theorem shipped_replies :
    replyFixed .open_ = [.resetStream] ∧ replyFixed .resetSent = [] := by
  native_decide

end Flare.Bugs.QUIC_19
