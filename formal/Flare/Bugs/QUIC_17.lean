import Flare.L3_Protocol.Quic.Streams

/-!
# QUIC-17: the client checks no stream id on any stream frame

Status: resolved. `check_stream_frame_id` (flare/quic/state.mojo) now runs in the
frame handlers for STREAM, RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA and
STREAM_DATA_BLOCKED on connections that set `check_stream_ids` (the client and
the server); the client advertises 16 streams of each kind (`_CLIENT_MAX_STREAMS`),
advances `next_local_bidi` / `next_local_uni` in `open_*_stream`, and ends the
connection on a rejected frame (`_fail_on_state_error`: CONNECTION_CLOSE,
`connection_closed`). The counterexample below is about the client before the
fix (`client false`); `clientShipped` is the shipped one.

Pre-fix behaviour: flare/quic/client.mojo:902-912 @59bda50 (`_dispatch_frames`) hands every
frame to the shared state machine (flare/quic/state.mojo:325-365,
454-486), which creates a stream on the first STREAM frame for any id and
applies RESET_STREAM / STOP_SENDING / MAX_STREAM_DATA to any known one.

Spec clauses (RFC 9000): §19.8 STREAM on a send-only stream or a locally
initiated stream not yet created; §19.4 RESET_STREAM on a send-only stream;
§19.5 / §19.10 STOP_SENDING / MAX_STREAM_DATA on a receive-only stream or a
locally initiated stream not yet created; §19.13 STREAM_DATA_BLOCKED on a
send-only stream: each MUST be STREAM_STATE_ERROR. §4.6: a stream above the
advertised limit (16 of each, flare/quic/client.mojo:210-211) MUST be
STREAM_LIMIT_ERROR.

Counterexamples (the client opened bidirectional stream 0 and its three
unidirectional streams 2, 6, 10): STREAM on stream 2 (its own control
stream, send-only), STREAM on stream 4 (not opened yet), RESET_STREAM on
stream 2, STOP_SENDING on stream 3 (server unidirectional, receive-only),
STREAM on server bidirectional stream 65 (the seventeenth).

Repro: formal/repro/QUIC-17_client_stream_frames_wrong_direction.mojo.
-/
namespace Flare.Bugs.QUIC_17
open Flare.L3.Quic.Streams

/-- bidirectional stream 0 and unidirectional 2, 6, 10 are open -/
def ctx : Ctx := ⟨fun sid => sid == 0 || sid == 2 || sid == 6 || sid == 10, 16, 16⟩

/-- **Counterexample** -/
theorem impl_accepts :
    client false ctx .stream 2 = none ∧ spec .client ctx .stream 2 = some .state ∧
    client false ctx .stream 4 = none ∧ spec .client ctx .stream 4 = some .state ∧
    client false ctx .resetStream 2 = none ∧ spec .client ctx .resetStream 2 = some .state ∧
    client false ctx .stopSending 3 = none ∧ spec .client ctx .stopSending 3 = some .state ∧
    client false ctx .stream 65 = none ∧ spec .client ctx .stream 65 = some .limit := by
  native_decide

/-- The legitimate cases stay accepted: data on the open request stream and
on a server unidirectional stream, STOP_SENDING on the request stream. -/
theorem spec_accepts :
    spec .client ctx .stream 0 = none ∧ spec .client ctx .stream 3 = none ∧
      spec .client ctx .stopSending 0 = none := by
  native_decide

/-- **The shipped client rejects all five** with the spec's error. -/
theorem shipped_rejects :
    client clientShipped ctx .stream 2 = some .state ∧
    client clientShipped ctx .stream 4 = some .state ∧
    client clientShipped ctx .resetStream 2 = some .state ∧
    client clientShipped ctx .stopSending 3 = some .state ∧
    client clientShipped ctx .stream 65 = some .limit := by
  native_decide

/-- **Fix meets spec** -/
theorem fixed_spec (c : Ctx) (k : Kind) (sid : Nat) :
    client true c k sid = spec .client c k sid := clientFixed_eq_spec c k sid

end Flare.Bugs.QUIC_17
