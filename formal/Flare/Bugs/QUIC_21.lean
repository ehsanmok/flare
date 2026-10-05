import Flare.L3_Protocol.Quic.Timers

/-!
# QUIC-21: the client has no idle timeout

Status: resolved. The client runs the same idle timer as the server
(QUIC-20): `_dispatch_frames` moves `last_activity_us` with the monotonic
clock for every processed packet, `_note_ack_eliciting_send` restarts it on the
first ack-eliciting send after one, `_apply_peer_transport_params` reads the
server's `max_idle_timeout`, and `poll` calls `_check_idle`, which closes the
connection (CLOSED, not established, `connection_closed`) once the effective
timeout has elapsed. The counterexample below is about the pre-fix
`clientStep`; `fixedStep` is the shipped timer.

Pre-fix behaviour (flare/quic/client.mojo:557-608 @59bda50): `poll` never checks an idle
timer, and `_dispatch_frames` (902-912) passes `now_us = 0` to
`handle_frame_buf`, so `Connection.last_activity_us` never moves.
`is_idle_timeout_expired` (flare/quic/state.mojo:876-887) is exported but
called nowhere, and would return False anyway while `last_activity_us` is 0.

Spec clause: RFC 9000 §10.1: "the connection is silently closed and its
state is discarded when it remains idle for longer than the minimum of the
max_idle_timeout value advertised by both endpoints."

What goes wrong: when the server goes away without a CONNECTION_CLOSE (which
flare's server never sends, QUIC-22) the client keeps the connection
"established" for ever; requests on it are sent into the void and wait for
their own timeouts.
-/
namespace Flare.Bugs.QUIC_21
open Flare.L3.Quic.Timers

/-- The client's idle state never changes, on any run. -/
theorem impl_never_closes (s : IImpl) (es : List IEv) :
    (run clientStep s es).closed = s.closed := by
  rw [client_never]

/-- **Counterexample**: both sides advertise 1000 ms and nothing arrives for
5000 ms: the spec has closed; the client has not. -/
theorem impl_counterexample :
    (run clientStep ⟨1000, false⟩ [.tick 5000]).closed = false ∧
    (run (ispecStep ⟨1000, 1000, 100⟩) (ispecInit 0) [.tick 5000]).closed = true := by decide

/-- **Fix**: the same fixed timer as the server's (QUIC-20) meets the spec. -/
theorem fixed_spec (p : IdleParams) (t0 : Nat) (es : List IEv) :
    (run (fixedStep p) (fixedInit p t0) es).closed = (run (ispecStep p) (ispecInit t0) es).closed :=
  fixed_closed_eq_spec p t0 es

end Flare.Bugs.QUIC_21
