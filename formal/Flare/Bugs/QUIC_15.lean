import Flare.L3_Protocol.Quic.Streams

/-!
# QUIC-15: the server accepts stream frames that name the wrong direction

Status: resolved. `check_stream_frame_id` (flare/quic/state.mojo) runs in
`on_reset_stream`, `on_stop_sending`, `on_max_stream_data` and
`on_stream_data_blocked` when `Connection.is_server` is set; it closes with
STREAM_STATE_ERROR or STREAM_LIMIT_ERROR and raises, and the server answers with
a CONNECTION_CLOSE. The counterexample below is about the server before the fix
(`ServerFixes ⟨false, false⟩`); `ServerFixes.shipped` has the check.

Pre-fix behaviour: flare/quic/state.mojo:454-486, 712-722 @59bda50 (`apply_max_stream_data`,
`apply_reset_stream`, `apply_stop_sending`, `on_stream_data_blocked`) reached
from flare/quic/_server_types.mojo:559-579 (`QuicConnection.dispatch_plaintext`).
The only stream-id check on the server is for STREAM, in
`_route_http3_stream_chunks` (flare/quic/server.mojo:1407-1430); the other
stream frames are applied (or ignored) whatever their stream id.

Spec clauses (RFC 9000): §19.4 RESET_STREAM for a send-only stream, §19.5
STOP_SENDING for a receive-only stream or a locally initiated stream not
yet created, §19.10 MAX_STREAM_DATA for the same two, §19.13
STREAM_DATA_BLOCKED for a send-only stream: each MUST be a connection error
of type STREAM_STATE_ERROR. §4.6: a frame naming a peer stream above the
advertised limit MUST be STREAM_LIMIT_ERROR.

Counterexamples (the server opens no stream of its own): RESET_STREAM and
STREAM_DATA_BLOCKED on stream 3 (server unidirectional, send-only),
STOP_SENDING and MAX_STREAM_DATA on stream 2 (client unidirectional,
receive-only), STOP_SENDING on stream 1 (server bidirectional, never
opened), and STOP_SENDING on client bidirectional stream 400 when 100 are
allowed.

Repro: formal/repro/QUIC-15_server_stream_frames_wrong_direction.mojo.
-/
namespace Flare.Bugs.QUIC_15
open Flare.L3.Quic.Streams

def ctx : Ctx := ⟨fun _ => false, 100, 3⟩

/-- **Counterexample**: flare's server accepts all six, the spec rejects
each one. -/
theorem impl_accepts :
    server ⟨false, false⟩ ctx .resetStream 3 = none ∧ spec .server ctx .resetStream 3 = some .state ∧
    server ⟨false, false⟩ ctx .streamDataBlocked 3 = none ∧
      spec .server ctx .streamDataBlocked 3 = some .state ∧
    server ⟨false, false⟩ ctx .stopSending 2 = none ∧ spec .server ctx .stopSending 2 = some .state ∧
    server ⟨false, false⟩ ctx .maxStreamData 2 = none ∧ spec .server ctx .maxStreamData 2 = some .state ∧
    server ⟨false, false⟩ ctx .stopSending 1 = none ∧ spec .server ctx .stopSending 1 = some .state ∧
    server ⟨false, false⟩ ctx .stopSending 400 = none ∧ spec .server ctx .stopSending 400 = some .limit := by
  native_decide

/-- **The shipped server rejects all six** with the spec's error. -/
theorem shipped_rejects :
    server ServerFixes.shipped ctx .resetStream 3 = some .state ∧
    server ServerFixes.shipped ctx .streamDataBlocked 3 = some .state ∧
    server ServerFixes.shipped ctx .stopSending 2 = some .state ∧
    server ServerFixes.shipped ctx .maxStreamData 2 = some .state ∧
    server ServerFixes.shipped ctx .stopSending 1 = some .state ∧
    server ServerFixes.shipped ctx .stopSending 400 = some .limit := by
  native_decide

/-- **Fix meets spec**: with the check on every stream frame (and the
QUIC-16 limit) the server's verdict is the spec's, for every frame kind
and stream id, given that it opens no stream of its own. -/
theorem fixed_spec (c : Ctx) (hc : ServerOpensNone c) (k : Kind) (sid : Nat) :
    server ⟨true, true⟩ c k sid = spec .server c k sid := serverFixed_eq_spec c hc k sid

end Flare.Bugs.QUIC_15
