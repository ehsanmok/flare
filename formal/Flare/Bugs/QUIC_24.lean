import Flare.L3_Protocol.Quic.Timers

/-!
# QUIC-24: the client keeps sending after the server's CONNECTION_CLOSE

Status: resolved. `_build_1rtt` (and the Initial, Handshake and 0-RTT builders)
return no datagram when the connection state is DRAINING (flare/quic/client.mojo)
and `send_stream` raises, so polls, PTO probes, keep-alives and `shutdown` send
nothing after the peer's CONNECTION_CLOSE. `Timers.cliStepNow` is the shipped
client and `shipped_silent` proves it; the counterexample below is about the
pre-fix `cliStep`.

Pre-fix behaviour: flare/quic/state.mojo:430-445 @59bda50 moves the client's connection to
DRAINING on CONNECTION_CLOSE, but nothing in flare/quic/client.mojo reads
the state before sending: `_drain_egress` (1035-1085) sends owed ACKs,
`_check_pto` (688-706) sends probes, and `keepalive` (1619-1634) and
`send_stream` send on request.

Spec clause: RFC 9000 §10.2.2: "an endpoint in the draining state MUST NOT
send any packets."

The client's own close is conforming: `shutdown` (1758-1778) sends
CONNECTION_CLOSE and closes the socket, which RFC 9000 §10.2 allows to end
the closing state early (`cli_close_ok`).
-/
namespace Flare.Bugs.QUIC_24
open Flare.L3.Quic.Timers

/-- **Counterexample**: in draining, every send the client has (an ACK, a
PTO probe, a keepalive, stream data) goes out. -/
theorem impl_sends_draining (u t : Nat) (out : List Pkt) :
    (cliStep ⟨.draining u, out⟩ (.want t)).out = .other :: out := rfl

theorem impl_trace :
    run cliStep ⟨.opened, []⟩ [.peerClose 0, .want 1, .want 2] =
      ⟨.draining 0, [.other, .other]⟩ := by decide

/-- **Fix**: send nothing once draining (`cspecStep`). -/
theorem fixed_spec (pto u : Nat) (out : List Pkt) (e : CEv) :
    (cspecStep pto ⟨.draining u, out⟩ e).out = out :=
  spec_draining_silent pto u out e

/-- **The shipped client** sends nothing in draining, for every event. -/
theorem shipped_silent (u : Nat) (out : List Pkt) (e : CEv) :
    (cliStepNow ⟨.draining u, out⟩ e).out = out :=
  cliNow_draining_silent u out e

theorem shipped_trace :
    run cliStepNow ⟨.opened, []⟩ [.peerClose 0, .want 1, .want 2] =
      ⟨.draining 0, []⟩ := by decide

/-- The client's own close already conforms. -/
theorem close_ok (t : Nat) (out : List Pkt) :
    cliStep ⟨.opened, out⟩ (.localClose t) = ⟨.gone, .cc :: out⟩ :=
  cli_close_ok t out

end Flare.Bugs.QUIC_24
