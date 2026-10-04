import Flare.L3_Protocol.Quic.Conn

/-!
# QUIC-04: HANDSHAKE_DONE moves a closing/draining connection back to ESTABLISHED

flare/quic/state.mojo:489-494 @59bda50: `apply_handshake_done` sets
`conn.state = CONN_STATE_ESTABLISHED` with no test of the current state
(`mark_handshake_complete`, 869, does test for HANDSHAKE). `handle_frame_buf`
(782) only drops frames once the state is CLOSED, so a CLOSING or DRAINING
connection still dispatches HANDSHAKE_DONE.

Spec clause: RFC 9000 §10.2: the closing and draining states only lead to
closed; an endpoint in the draining state "MUST NOT send any packets" and a
connection that received CONNECTION_CLOSE never becomes usable again
(`Flare.L3.Quic.Conn.spec_closing_absorbing`).

Counterexample: the payload `1c 00 00 00 1e` (CONNECTION_CLOSE, then
HANDSHAKE_DONE) takes a fresh connection HANDSHAKE → DRAINING → ESTABLISHED.
The same happens from CLOSING (after a local `connection_close`).
-/
namespace Flare.Bugs.QUIC_04
open Flare.L3.Quic.Frame Flare.L3.Quic.Conn

/-- Single step: DRAINING + HANDSHAKE_DONE = ESTABLISHED (either role). -/
theorem reopens (role : Role) :
    implStep role .draining (.frame .handshakeDone) = some .established := rfl

theorem reopens_closing (role : Role) :
    implStep role .closing (.frame .handshakeDone) = some .established := rfl

def payload : Bytes := [0x1C, 0x00, 0x00, 0x00, 0x1E]

/-- The repro's payload decodes to CONNECTION_CLOSE then HANDSHAKE_DONE. -/
theorem payload_frames :
    (parsePayload payload).toOption = some [.connectionClose false 0 0 [], .handshakeDone] := by
  native_decide

/-- Trace: from HANDSHAKE, the payload ends in ESTABLISHED (client role, as
in the repro, which drives the role-less `dispatch_frames` directly). -/
theorem trace :
    run implStep .client .handshake (frames [.connectionClose false 0 0 [], .handshakeDone])
      = some .established := rfl

/-- The spec keeps the connection draining. -/
theorem spec_trace :
    run specStep .client .handshake (frames [.connectionClose false 0 0 [], .handshakeDone])
      = some .draining := rfl

/-- flare violates the absorbing-state property of the spec. -/
theorem violates_spec :
    ¬ ∀ role s s' e, s.terminal = true → implStep role s e = some s' → s'.terminal = true :=
  fun h => absurd (h .client .draining .established (.frame .handshakeDone) rfl rfl) (by decide)

/-- The fix refines the spec (it is equal to it on every step). -/
theorem fixed_refines (role : Role) (s : CState) (e : Ev) :
    implStepFixed role s e = specStep role s e :=
  implStepFixed_eq_spec role s e

theorem fixed_trace :
    run implStepFixed .client .handshake (frames [.connectionClose false 0 0 [], .handshakeDone])
      = some .draining := rfl

/-- Hence the fix never leaves closing/draining/closed. -/
theorem fixed_absorbing (role : Role) (s s' : CState) (e : Ev) (hs : s.terminal = true)
    (h : implStepFixed role s e = some s') : s'.terminal = true :=
  spec_closing_absorbing role s s' e hs (by rw [← implStepFixed_eq_spec]; exact h)

end Flare.Bugs.QUIC_04
