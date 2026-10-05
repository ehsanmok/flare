import Flare.L3_Protocol.Quic.Conn

/-!
# QUIC-09: the server accepts HANDSHAKE_DONE from the client

Status: resolved. `Connection` has an `is_server` flag (set by `QuicConnection`)
and `on_handshake_done` closes with PROTOCOL_VIOLATION and raises when it is
set (flare/quic/state.mojo). The counterexample below is about the pre-fix,
role-unaware step `implStepPre`; the shipped `Conn.implStep` equals the spec on
every role, state and event (`fixed_meets_spec`).

Pre-fix behaviour: flare/quic/state.mojo:744-746 and 489-494 @59bda50: `on_handshake_done`
applies the frame with no role check; the sans-I/O `Connection` has no
role at all. The server's per-connection driver
(flare/quic/_server_types.mojo:559-578, `QuicConnection.dispatch_plaintext`,
called from flare/quic/server.mojo:823/849/897) runs 1-RTT payloads through
`dispatch_frames` with `before_1rtt = False`, so a client-sent
HANDSHAKE_DONE is applied: the server's state becomes ESTABLISHED and the
`handshake_done` event fires. (At Initial/Handshake level the frame is
already refused by `frame_allowed_before_1rtt`, state.mojo:804-822.)

Spec clause: RFC 9000 §19.20, "A server MUST treat receipt of a
HANDSHAKE_DONE frame as a connection error of type PROTOCOL_VIOLATION."
-/
namespace Flare.Bugs.QUIC_09
open Flare.L3.Quic.Frame Flare.L3.Quic.Conn

/-- The step before the fix: role-unaware, so every role behaved like the client. -/
def implStepPre (_role : Role) (s : CState) (e : Ev) : Option CState := implStep .client s e

/-- Pre-fix flare (server role): HANDSHAKE_DONE in HANDSHAKE succeeds and yields
ESTABLISHED. -/
theorem server_accepts : implStepPre .server .handshake (.frame .handshakeDone) = some .established :=
  rfl

/-- The spec requires a connection error. -/
theorem spec_rejects : specStep .server .handshake (.frame .handshakeDone) = none := rfl

theorem violates_spec :
    implStepPre .server .handshake (.frame .handshakeDone) ≠
      specStep .server .handshake (.frame .handshakeDone) := by
  rw [server_accepts, spec_rejects]; simp

/-- The shipped step rejects HANDSHAKE_DONE on the server in every non-closed state. -/
theorem fixed_rejects (s : CState) (hs : s ≠ .closed) :
    implStep .server s (.frame .handshakeDone) = none := by
  cases s <;> first | exact absurd rfl hs | rfl

/-- **The shipped step meets the spec** on every role, state and event. -/
theorem fixed_meets_spec (role : Role) (s : CState) (e : Ev) :
    implStep role s e = specStep role s e :=
  implStep_eq_spec role s e

end Flare.Bugs.QUIC_09
