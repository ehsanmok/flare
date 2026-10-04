import Flare.L3_Protocol.Quic.Timers

/-!
# QUIC-23: the server keeps sending after the client's CONNECTION_CLOSE

flare/quic/state.mojo:430-445 @59bda50 (`apply_connection_close`) moves the
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

end Flare.Bugs.QUIC_23
