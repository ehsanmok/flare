import Flare.L3_Protocol.Quic.Timers

/-!
# QUIC-20: the server's idle timer uses the wrong timeout and restarts on the wrong events

Status: resolved. The server re-arms the idle timer only for packets that were
processed successfully (`_handle_inbound`) and for the first ack-eliciting
packet sent after one (`_build_1rtt_response`), and arms it at
`_effective_idle_ms` (the minimum of the two non-zero values, at least 3×PTO,
nothing when both are 0) via `schedule_idle_timeout`; the client's value is
read in `_client_params_ok`. The counterexamples below are about the pre-fix
`serverStep`; `fixedStep` is the shipped timer.

Pre-fix behaviour (flare/quic/server.mojo:724-782 @59bda50, `_handle_inbound`): `processed_any`
is set for every packet walked in the datagram, whether or not it decrypted,
and `schedule_idle_timeout` (2874-2898) then re-arms the idle timer at
`config.max_idle_timeout_ms`. That value is the server's own only (the
client's transport parameters are never read, see QUIC-11), it is not raised
to 3×PTO, and 0 is clamped to 1 ms by the timer wheel
(flare/runtime/timer_wheel.mojo:136). Sending never re-arms the timer.

Spec clause: RFC 9000 §10.1: the effective value "is computed as the minimum
of the two advertised values (or the sole advertised value, if only one
endpoint advertises a non-zero value)"; "An endpoint restarts its idle timer
when a packet from its peer is received and processed successfully. An
endpoint also restarts its idle timer when sending an ack-eliciting packet
if no other ack-eliciting packets have been sent since last receiving and
processing a packet"; "endpoints MUST increase the idle timeout period to be
at least three times the current Probe Timeout (PTO)". §18.2: idle timeout is
disabled when both endpoints omit the parameter or specify 0.

What goes wrong: anyone who sees the connection ID can keep a connection
alive with undecryptable datagrams; a client that advertised a shorter
timeout is held for the server's full 30 s; a configured 0 closes every
connection at the next timer advance; a server that sends after a quiet
period still times out from the last receipt.
-/
namespace Flare.Bugs.QUIC_20
open Flare.L3.Quic.Timers

def p1 : IdleParams := ⟨1000, 1000, 100⟩

/-- **Counterexample 1**: an undecryptable datagram at 900 ms keeps the slot
open past the 1000 ms timeout. -/
theorem impl_unauth_restarts :
    (run (serverStep 1000) (serverInit 1000 0) [.recv 900 false, .tick 1500]).closed = false ∧
    (run (ispecStep p1) (ispecInit 0) [.recv 900 false, .tick 1500]).closed = true := by decide

/-- **Counterexample 2**: the client advertised 1000 ms; the server (30000 ms)
is still open at 2000 ms. -/
theorem impl_ignores_peer :
    (run (serverStep 30000) (serverInit 30000 0) [.tick 2000]).closed = false ∧
    (run (ispecStep ⟨30000, 1000, 100⟩) (ispecInit 0) [.tick 2000]).closed = true := by decide

/-- **Counterexample 3**: with both values 0 there is no idle timeout, but the
server closes at the first millisecond. -/
theorem impl_zero_closes :
    (run (serverStep 0) (serverInit 0 0) [.tick 1]).closed = true ∧
    ∀ es, (run (ispecStep ⟨0, 0, 100⟩) (ispecInit 0) es).closed = false :=
  ⟨by decide, fun es => spec_none_never _ rfl es _⟩

/-- **Counterexample 4**: an ack-eliciting send at 800 ms restarts the spec
timer; the server still closes at 1200 ms. -/
theorem impl_no_send_restart :
    (run (serverStep 1000) (serverInit 1000 0) [.sendAE 800, .tick 1200]).closed = true ∧
    (run (ispecStep p1) (ispecInit 0) [.sendAE 800, .tick 1200]).closed = false := by decide

/-- **Counterexample 5**: 100 ms advertised by both, PTO 100 ms: the period
must be at least 300 ms; the server closes at 150 ms. -/
theorem impl_no_pto_floor :
    (run (serverStep 100) (serverInit 100 0) [.tick 150]).closed = true ∧
    (run (ispecStep ⟨100, 100, 100⟩) (ispecInit 0) [.tick 150]).closed = false := by decide

/-- The shipped `_effective_idle_ms` is the spec's effective timeout, and the
cases of the counterexamples come out right: 1000/30000 gives 1000 (above the
floor), 0/0 gives none, and 100/100 with PTO 100 is raised to 300. -/
theorem fixed_effective :
    effectiveMs 30000 1000 100 = 1000 ∧ effectiveMs 0 0 100 = 0 ∧ effectiveMs 100 100 100 = 300 ∧
    ∀ l p pto, effective ⟨l, p, pto⟩ = if effectiveMs l p pto = 0 then none else some (effectiveMs l p pto) :=
  ⟨by decide, by decide, by decide, effectiveMs_spec⟩

/-- **Fix**: arm from the effective timeout, re-arm on authenticated receipts
and the first ack-eliciting send after one; then the server closes exactly
when RFC 9000 §10.1 says, on every run. -/
theorem fixed_spec (p : IdleParams) (t0 : Nat) (es : List IEv) :
    (run (fixedStep p) (fixedInit p t0) es).closed = (run (ispecStep p) (ispecInit t0) es).closed :=
  fixed_closed_eq_spec p t0 es

end Flare.Bugs.QUIC_20
