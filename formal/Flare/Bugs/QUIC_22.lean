import Flare.L3_Protocol.Quic.Timers

/-!
# QUIC-22: the server never sends CONNECTION_CLOSE

flare/quic/server.mojo:2177-2180 @59bda50 (`_close_for`), and the other
local-close sites (1255-1262, 2965-2971, 3006-3012), set the state to
CLOSING and `alive := False`; `_drain_and_send` (2033-2038) then returns
before building any packet, and nothing else encodes a CONNECTION_CLOSE on
the server. The slot is reclaimed when any of its timers next fires
(2925-2938), which can be an ACK-delay or PTO timer a few milliseconds
later.

Spec clause: RFC 9000 §11.1: connection errors "MUST be signaled using a
CONNECTION_CLOSE frame"; §10.2.1: "An endpoint in the closing state sends a
packet containing a CONNECTION_CLOSE frame in response to any incoming
packet that it attributes to the connection"; §10.2: the closing and
draining states "SHOULD persist for at least three times the current PTO
interval", and "Servers that retain an open socket for accepting new
connections SHOULD NOT end the closing or draining state early."

What goes wrong: every connection error the server detects (stream-id,
stream-limit and flow-control violations, an ACK of an unsent packet,
CRYPTO overflow, the QUIC-11/15/16 fixes) is silent: the client never learns
the connection is gone or why, and keeps sending until its own idle timeout,
which flare's client does not have (QUIC-21).
-/
namespace Flare.Bugs.QUIC_22
open Flare.L3.Quic.Timers

/-- **Counterexample**: a local close sends nothing, and a packet arriving in
the closing state is not answered. -/
theorem impl_no_cc (t u t' : Nat) (out : List Pkt) :
    (srvStep ⟨.opened, true, out⟩ (.localClose t)).out = out ∧
    (srvStep ⟨.closing u, false, out⟩ (.recvPkt t')).out = out := ⟨rfl, rfl⟩

/-- The spec sends CONNECTION_CLOSE on the close and in answer to a packet
in the closing state. -/
theorem spec_answers (pto t : Nat) (hp : 0 < pto) (out : List Pkt) :
    (cspecStep pto ⟨.opened, out⟩ (.localClose t)).out = .cc :: out ∧
    (run (cspecStep pto) ⟨.opened, out⟩ [.localClose t, .recvPkt t]).out =
      .cc :: .cc :: out := by
  refine ⟨rfl, ?_⟩
  have : t < t + 3 * pto := by omega
  simp [run, cspecStep, this]

/-- **Counterexample (period)**: a timer of the slot firing 1 ms after the
close reclaims it; with PTO 100 ms the spec is still closing. -/
theorem impl_short_period :
    (run srvStep ⟨.opened, true, []⟩ [.localClose 0, .tick 1]).phase = .gone ∧
    (run (cspecStep 100) ⟨.opened, []⟩ [.localClose 0, .tick 1]).phase = .closing 300 := by decide

/-- **Fix**: send CONNECTION_CLOSE when closing and in answer to packets
during a closing period of 3×PTO, then reclaim; that is `cspecStep`, which
meets §10.2, §10.2.1 and §11.1. -/
theorem fixed_spec (pto u t : Nat) (out : List Pkt) (e : CEv) (ht : t < u) :
    (cspecStep pto ⟨.opened, out⟩ (.localClose t)).out = .cc :: out ∧
    ((cspecStep pto ⟨.closing u, out⟩ e).out = out ∨
      (cspecStep pto ⟨.closing u, out⟩ e).out = .cc :: out) ∧
    (cspecStep pto ⟨.closing u, out⟩ (.tick t)).phase = .closing u :=
  ⟨spec_cc_on_close pto t out, spec_closing_only_cc pto u out e,
    (spec_tick_before pto u t out ht).1⟩

end Flare.Bugs.QUIC_22
