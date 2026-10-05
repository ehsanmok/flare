import Flare.L3_Protocol.Quic.Timers

/-!
# QUIC-23: the server keeps sending after the client's CONNECTION_CLOSE

Status: resolved. `_build_1rtt_response` returns no datagram and `_drain_and_send`
returns at once when the connection state is DRAINING (flare/quic/server.mojo), so
no ACK, response, PTO probe or delayed-ACK flush leaves a draining server.
`Timers.srvStepNow` is the shipped server and `shipped_silent` proves it sends
nothing in draining; the counterexample below is about the pre-fix `srvStep`.

Pre-fix behaviour: flare/quic/state.mojo:430-445 @59bda50 (`apply_connection_close`) moves the
connection to DRAINING, but the server's `alive` flag is set False only by
its own close paths (flare/quic/server.mojo:1261, 2180, 2969, 3011) and the
idle timer. `_drain_and_send` (2033-2038) and `_drain_1rtt_coalesced`
(2210-2433) check only `alive` and the 1-RTT keys, and frames are still
dispatched in DRAINING (state.mojo:766-791 drops them only once CLOSED), so
the server keeps sending ACKs, flow-control credit and responses.

Spec clause: RFC 9000 §10.2.2: "an endpoint in the draining state MUST NOT
send any packets"; "An endpoint that receives a CONNECTION_CLOSE frame MAY
send a single packet containing a CONNECTION_CLOSE frame before entering
the draining state ... An endpoint MUST NOT send further packets."
-/
namespace Flare.Bugs.QUIC_23
open Flare.L3.Quic.Timers

/-- **Counterexample**: after the peer's CONNECTION_CLOSE, any egress the
driver has (an ACK, a response) is sent. -/
theorem impl_sends_draining (u t : Nat) (out : List Pkt) :
    (srvStep ⟨.draining u, true, out⟩ (.want t)).out = .other :: out := rfl

theorem impl_trace :
    run srvStep ⟨.opened, true, []⟩ [.peerClose 0, .want 1] = ⟨.draining 0, true, [.other]⟩ := by
  decide

/-- **Fix**: stop all egress once draining; that is `cspecStep`, which sends
nothing in draining for any event. -/
theorem fixed_spec (pto u : Nat) (out : List Pkt) (e : CEv) :
    (cspecStep pto ⟨.draining u, out⟩ e).out = out :=
  spec_draining_silent pto u out e

/-- **The shipped server** sends nothing in draining, for every event
(`Timers.srvNow_draining_silent`), and after the peer's close at 0 the want at
1 sends nothing. -/
theorem shipped_silent (pto u : Nat) (al : Bool) (out : List Pkt) (e : CEv) :
    (srvStepNow pto ⟨.draining u, al, out⟩ e).out = out :=
  srvNow_draining_silent pto u al out e

theorem shipped_trace (pto : Nat) :
    run (srvStepNow pto) ⟨.opened, true, []⟩ [.peerClose 0, .want 1] =
      ⟨.draining 0, true, []⟩ := by
  simp [run, srvStepNow]

end Flare.Bugs.QUIC_23
