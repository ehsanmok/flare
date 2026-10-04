import Flare.L3_Protocol.Quic.Streams

/-!
# QUIC-18: one state for both stream halves loses a reset

flare/quic/state.mojo:467-486 @59bda50: `apply_reset_stream` sets the
stream's single `state` to RESET_RECVD and `apply_stop_sending` sets it to
RESET_SENT, each overwriting the other; `cancel_stream`
(flare/quic/client.mojo:1406-1428) also writes RESET_SENT. The client reads
the receive half through `stream_reset` (state == RESET_RECVD,
client.mojo:1455-1460) and the send half through `send_stream` (refuses only
in RESET_SENT, client.mojo:1357-1362).

Spec clause: RFC 9000 §3 keeps a sending part (§3.1) and a receiving part
(§3.2) per bidirectional stream; RESET_STREAM moves the receiving part to
"Reset Recvd" and STOP_SENDING / our own RESET_STREAM moves the sending
part to "Reset Sent", independently. §3.1: once in "Reset Sent" no more
STREAM frames are sent.

What goes wrong:
* RESET_STREAM then STOP_SENDING (a server abandoning a request answers
  with both): `stream_reset` is false, so the HTTP/3 client
  (flare/http3/client.mojo:465) does not fail the response and waits.
* `cancel_stream` then the peer's RESET_STREAM: the state is RESET_RECVD,
  `send_stream` accepts more data on a stream we reset.

Repro: formal/repro/QUIC-18_stream_reset_state_overwritten.mojo.
-/
namespace Flare.Bugs.QUIC_18
open Flare.L3.Quic.Streams

/-- **Counterexample**: both orders lose an event. -/
theorem impl_loses :
    resetSeen (runImpl [.resetIn, .stopIn]) = false ∧ (runHalves [.resetIn, .stopIn]).recvReset = true ∧
    sendRefused (runImpl [.resetOut, .resetIn]) = false ∧
      (runHalves [.resetOut, .resetIn]).sendReset = true := by
  native_decide

/-- **Fix meets spec**: with the halves kept apart, a reset received is
seen, and a send half reset or stopped stays refused, for every event
sequence. -/
theorem fixed_spec (evs : List Ev) :
    (runHalves evs).recvReset = evs.contains .resetIn ∧
      (runHalves evs).sendReset = (evs.contains .stopIn || evs.contains .resetOut) :=
  ⟨halves_reset_iff evs, halves_stop_iff evs⟩

end Flare.Bugs.QUIC_18
