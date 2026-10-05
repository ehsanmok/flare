import Flare.L3_Protocol.Ws.Handshake

/-!
# WS-07: the reactor upgrade tests Connection by substring and never decodes the key

* flare file: `flare/http/_reactor/conn_handle.mojo:1512-1523`
  (`_handle_ws_upgrade`) @59bda50. The 426 check before it
  (`conn_handle.mojo:143-152`, 835-855) does enforce version 13
  (`reactorOld_upgrade_v13`).
* Spec clause: RFC 6455 §4.2.1 points 4 and 5: a `Connection` token
  `upgrade` and a key that is base64 of 16 bytes.
* What goes wrong: GET with `Connection: noupgrade` and
  `Sec-WebSocket-Key: x` gets `101 Switching Protocols`.
* Fix (`reactor`, the shipped decision): `reactor_ok`. The counterexample is
  about `reactorOld`, the pre-fix reactor.

Status: resolved. `_handle_ws_upgrade` qualifies a request with
`_ws_handshake_problem`, the rule the standalone server uses too (WS-05).
-/
namespace Flare.Bugs.WS_07
open Flare Flare.L3.Ws.Handshake

def NOUPGRADE : Bytes := [110, 111, 117, 112, 103, 114, 97, 100, 101]

def req : Req :=
  { method := GET, target := [47], version := HTTP11,
    fields := [(UPGRADE_CAP, WEBSOCKET), (CONNECTION_CAP, NOUPGRADE), (KEY_CAP, [120]),
      (VERSION_CAP, V13)] }

theorem old_upgrades : reactorOld req = .upgrade [120] := by native_decide

theorem no_conn_token :
    (vals req.fields N_CONNECTION).any (fun v => hasTok v UPGRADE) = false := by native_decide

theorem counterexample : reactorOld req = .upgrade [120] ∧ ¬ ServerOK req [120] :=
  ⟨old_upgrades, fun h => by
    have := h.2.2.2.1
    rw [no_conn_token] at this
    cases this⟩

theorem fixed_refuses : reactor req = .http := by native_decide

theorem fixed_ok {r : Req} {k : Bytes} (h : reactor r = .upgrade k) : ServerOK r k :=
  reactor_ok h

end Flare.Bugs.WS_07
