import Flare.L3_Protocol.Ws.Handshake

/-!
# WS-05: the standalone `WsServer` handshake checks almost nothing

* flare file: `flare/ws/server.mojo:188-261` (`_parse_ws_upgrade_bytes`)
  and `264-321` (`_read_upgrade_request`) @59bda50: the request line is
  read and dropped, `Connection` is tested by substring, the key only for
  being non-empty, and `Sec-WebSocket-Version` not at all.
* Spec clause: RFC 6455 §4.2.1: a GET, HTTP/1.1 or higher, `Upgrade`
  containing `websocket`, a `Connection` token `upgrade`, a key that
  decodes to 16 bytes, and version 13 (§4.2.2 point 4 otherwise:
  426 with the supported version); §11.3.1/§11.3.5: those fields once.
* What goes wrong: `POST / HTTP/1.0`, `Connection: noupgrade`,
  `Sec-WebSocket-Key: x`, `Sec-WebSocket-Version: 8` is upgraded.
* Fix (`srvFixed`): `srvFixed_ok`.
-/
namespace Flare.Bugs.WS_05
open Flare Flare.L3.Ws.Handshake

def POST : Bytes := [80, 79, 83, 84]
def NOUPGRADE : Bytes := [110, 111, 117, 112, 103, 114, 97, 100, 101]

def req : Req :=
  { method := POST, target := [47], version := HTTP10,
    fields := [(UPGRADE_CAP, WEBSOCKET), (CONNECTION_CAP, NOUPGRADE), (KEY_CAP, [120]),
      (VERSION_CAP, [56])] }

theorem shipped_upgrades : srvShipped req = some [120] := by native_decide

theorem counterexample : srvShipped req = some [120] ∧ ¬ ServerOK req [120] :=
  ⟨shipped_upgrades, fun h => absurd h.1 (by native_decide)⟩

theorem key_invalid : ¬ KeyOK [120] := by
  rw [← keyOk_iff]; native_decide

theorem fixed_refuses : srvFixed req = none := by native_decide

theorem fixed_ok {r : Req} {k : Bytes} (h : srvFixed r = some k) : ServerOK r k := srvFixed_ok h

end Flare.Bugs.WS_05
