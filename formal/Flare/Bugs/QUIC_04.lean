import Flare.L3_Protocol.Quic.Conn

/-!
# QUIC-04: HANDSHAKE_DONE moves a closing/draining connection back to ESTABLISHED

Status: resolved. `apply_handshake_done` now acts only in HANDSHAKE
(flare/quic/state.mojo, fixed on QUIC-04). The counterexample below is about
the pre-fix step `implStepOld`; the shipped `implStep` keeps closing, draining
and closed absorbing (`fixed_absorbing`) and equals the spec for the client
role (`fixed_refines`).

Pre-fix behaviour (flare/quic/state.mojo:489-494 @59bda50): `apply_handshake_done`
set `conn.state = CONN_STATE_ESTABLISHED` with no test of the current state
(`mark_handshake_complete`, 869, does test for HANDSHAKE). `handle_frame_buf`
(782) only drops frames once the state is CLOSED, so a CLOSING or DRAINING
connection still dispatched HANDSHAKE_DONE.

Spec clause: RFC 9000 §10.2: the closing and draining states only lead to
closed; an endpoint in the draining state "MUST NOT send any packets" and a
connection that received CONNECTION_CLOSE never becomes usable again
(`Flare.L3.Quic.Conn.spec_closing_absorbing`).

Counterexample: the payload `1c 00 00 00 1e` (CONNECTION_CLOSE, then
HANDSHAKE_DONE) took a fresh connection HANDSHAKE → DRAINING → ESTABLISHED.
The same happened from CLOSING (after a local `connection_close`).
-/
namespace Flare.Bugs.QUIC_04
open Flare.L3.Quic.Frame Flare.L3.Quic.Conn

/-- The pre-fix frame effect: HANDSHAKE_DONE always sets ESTABLISHED. -/
def frameEffectOld (s : CState) : Frame → CState
  | .connectionClose .. => .draining
  | .handshakeDone => .established
  | _ => s

/-- The pre-fix step (`handle_frame_buf` drops frames only in CLOSED). -/
def implStepOld (_role : Role) (s : CState) : Ev → Option CState
  | .frame f => if s = .closed then some s else some (frameEffectOld s f)
  | .tlsDone => some (markHandshakeComplete s)
  | .localClose => some (localClose s)

/-- Single step: DRAINING + HANDSHAKE_DONE = ESTABLISHED (either role). -/
theorem reopens (role : Role) :
    implStepOld role .draining (.frame .handshakeDone) = some .established := rfl

theorem reopens_closing (role : Role) :
    implStepOld role .closing (.frame .handshakeDone) = some .established := rfl

def payload : Bytes := [0x1C, 0x00, 0x00, 0x00, 0x1E]

/-- The repro's payload decodes to CONNECTION_CLOSE then HANDSHAKE_DONE. -/
theorem payload_frames :
    (parsePayload payload).toOption = some [.connectionClose false 0 0 [], .handshakeDone] := by
  native_decide

/-- Trace: from HANDSHAKE, the payload ended in ESTABLISHED (client role, as
in the repro, which drives the role-less `dispatch_frames` directly). -/
theorem trace :
    run implStepOld .client .handshake (frames [.connectionClose false 0 0 [], .handshakeDone])
      = some .established := rfl

/-- The spec keeps the connection draining. -/
theorem spec_trace :
    run specStep .client .handshake (frames [.connectionClose false 0 0 [], .handshakeDone])
      = some .draining := rfl

/-- The pre-fix step violated the absorbing-state property of the spec. -/
theorem violates_spec :
    ¬ ∀ role s s' e, s.terminal = true → implStepOld role s e = some s' → s'.terminal = true :=
  fun h => absurd (h .client .draining .established (.frame .handshakeDone) rfl rfl) (by decide)

/-- The shipped step equals the spec (client role; the server role differs only in
QUIC-09's HANDSHAKE_DONE rejection). -/
theorem fixed_refines (s : CState) (e : Ev) :
    implStep .client s e = specStep .client s e :=
  implStep_client_eq_spec s e

theorem fixed_trace :
    run implStep .client .handshake (frames [.connectionClose false 0 0 [], .handshakeDone])
      = some .draining := rfl

/-- Hence the shipped step never leaves closing/draining/closed, for either role. -/
theorem fixed_absorbing (role : Role) (s s' : CState) (e : Ev) (hs : s.terminal = true)
    (h : implStep role s e = some s') : s'.terminal = true :=
  implStep_absorbing role s s' e hs h

end Flare.Bugs.QUIC_04
