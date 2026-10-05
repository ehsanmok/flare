import Flare.L3_Protocol.Ws.Recv

/-!
# WS-03: `WsClient` accepts masked frames from the server

* flare file: `flare/ws/client.mojo:717-763` @59bda50 (`_recv_one` decodes
  and returns; the server's `_recv_one` at `flare/ws/server.mojo:558-562`
  has the mirror-image check).
* Spec clause: RFC 6455 §5.1: "A client MUST close a connection if it
  detects a masked frame."
* What goes wrong: any masked TEXT frame from the server is unmasked and
  returned as data.
* Fix (`clientAccept`, the shipped `_recv_one`): refuse a decoded frame
  whose MASK bit is set. `clientAccept_safe` proves the fix; `server_safe` is
  the server-side analogue, which already holds. The counterexample is about
  `clientAcceptOld`, the pre-fix `_recv_one`.

Status: resolved. `WsClient._recv_one` raises `WsProtocolError` on a masked
server frame.
-/
namespace Flare.Bugs.WS_03
open Flare Flare.L3.Ws

def frameHi : Frame := ⟨true, false, 1, false, [104, 105]⟩  -- "hi"
def key : Key := ⟨0x11, 0x22, 0x33, 0x44⟩

/-- The client decodes a masked server frame (any masked frame, by the
round-trip theorem). -/
theorem client_accepts_masked :
    clientAcceptOld (2 ^ 20) (encode frameHi true key) =
      .ok { frameHi with masked := true } (encode frameHi true key).length := by
  have := decode_encode false (2 ^ 20) frameHi true key [] (by decide) (by decide) (by decide)
    (by decide) (by decide)
  simpa [clientAcceptOld] using this

theorem counterexample : ¬ ClientSafe (clientAcceptOld (2 ^ 20)) := by
  intro h
  have := h _ _ _ client_accepts_masked
  simp at this

theorem fixed_client_safe (maxP : Nat) : ClientSafe (clientAccept maxP) := clientAccept_safe maxP

end Flare.Bugs.WS_03
