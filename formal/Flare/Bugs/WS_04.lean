import Flare.L3_Protocol.Ws.Handshake

/-!
# WS-04: `WsClient` accepts a 101 that is not a WebSocket handshake

* flare file: `flare/ws/client.mojo:562-603` (TLS) and `609-646` (TCP)
  @59bda50: the status line must start `HTTP/1.1 101` and the last
  `Sec-WebSocket-Accept` must match; no other field is read.
* Spec clause: RFC 6455 §4.1: the client MUST fail the connection if the
  101 lacks `Upgrade: websocket` or a `Connection` token `upgrade`, or
  names a subprotocol or extension the client did not request.
* What goes wrong: a 101 with only the right accept and
  `Sec-WebSocket-Protocol: chat` is taken as a WebSocket connection, for
  every SHA-1.
* Fix (`clientFixed`): check the whole §4.1 list. `clientFixed_ok` proves it
  decides exactly `ClientOK`.
-/
namespace Flare.Bugs.WS_04
open Flare Flare.L3.Ws.Handshake

/-- `dGhlIHNhbXBsZSBub25jZQ==` (RFC 6455 §1.3). -/
def key : Bytes :=
  [100, 71, 104, 108, 73, 72, 78, 104, 98, 88, 66, 115, 90, 83, 66, 117, 98, 50, 53, 106, 90, 81,
    61, 61]
def PROTOCOL_CAP : Bytes :=
  [83, 101, 99, 45, 87, 101, 98, 83, 111, 99, 107, 101, 116, 45, 80, 114, 111, 116, 111, 99, 111, 108]
def CHAT : Bytes := [99, 104, 97, 116]

def resp (sha1 : Sha1) : Fields := [(ACCEPT_CAP, acceptOf sha1 key), (PROTOCOL_CAP, CHAT)]

theorem shipped_accepts (sha1 : Sha1) : clientAccepts sha1 key SWITCHING (resp sha1) = true := by
  simp (config := { decide := true }) [clientAccepts, resp, lastVal, vals_cons, vals_nil]

theorem fixed_refuses (sha1 : Sha1) : clientFixed sha1 key SWITCHING (resp sha1) = false := by
  simp (config := { decide := true }) [clientFixed, resp, vals_cons, vals_nil]

theorem counterexample (sha1 : Sha1) :
    clientAccepts sha1 key SWITCHING (resp sha1) = true ∧ ¬ ClientOK sha1 key SWITCHING (resp sha1) :=
  ⟨shipped_accepts sha1, fun h => by
    rw [← clientFixed_ok, fixed_refuses] at h; cases h⟩

theorem fixed_ok (sha1 : Sha1) (k st : Bytes) (fs : Fields) :
    clientFixed sha1 k st fs = true ↔ ClientOK sha1 k st fs := clientFixed_ok sha1 k st fs

end Flare.Bugs.WS_04
