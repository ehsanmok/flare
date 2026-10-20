import Oracle.Codec
import Flare.Kernels.WsProtocol
/-!
# Oracle target: the WebSocket server protocol core

`ws_protocol.trace` runs `Flare.Kernels.WsProtocol.run` from a fresh session
over a trace of client frames, as `formal/difftest/drivers/dt_ws.mojo` does
with the real `WsProtocol` on the same frames encoded for the wire.

Input layout:
* byte 0: `max_message = byte0 % 8 + 1`, and `max_outbox` is
  `[4, 16, 64, 2^20]` at index `(byte0 >> 3) % 4`.
* then one event per header byte `e`: kind `e % 8` (0 TEXT, 1 BINARY,
  2 CONTINUATION, 3 PING, 4 PONG, 5 CLOSE, 6 a frame with RSV2 set, 7 a
  frame declaring `max_message + 1` bytes); FIN is bit 3, forced on control
  frames; the payload is the next `min((e >> 4) % 8, max_message)` bytes
  (kinds 0-5); the frame is unmasked iff `e >> 4 = 15`.

Output: `OK:<events>|<frames queued for the peer>|<outbox length>`.
-/
namespace Oracle.Ws

open Flare
open Flare.Kernels.WsProtocol

def opOf : Nat → Op
  | 0 => .text | 1 => .binary | 2 => .cont | 3 => .ping | 4 => .pong | _ => .close

def parse (m : Nat) : Nat → Bytes → List In
  | 0, _ => []
  | _, [] => []
  | fuel + 1, e :: r =>
    let k := e.toNat % 8
    if k = 6 then .bad false :: parse m fuel r
    else if k = 7 then .bad true :: parse m fuel r
    else
      let l := min (e.toNat / 16 % 8) m
      let fin := e.toNat / 8 % 2 = 1 || k ≥ 3
      let f : Frame := ⟨opOf k, fin, e.toNat / 16 ≠ 15, r.take l⟩
      .frame f :: parse m fuel (r.drop l)

def renderEvent : Out → String
  | .deliver t p => (if t then "T" else "B") ++ toHex p ++ "."
  | .ended c => s!"E{c}."
  | _ => ""

def renderSend : Out → String
  | .sendPong p => "P" ++ toHex p ++ "."
  | .sendClose none => "C."
  | .sendClose (some c) => s!"C{c}."
  | _ => ""

def trace : Bytes → String
  | [] => "ERR"
  | b0 :: rest =>
    let m := b0.toNat % 8 + 1
    let mo := [4, 16, 64, 1 <<< 20].getD (b0.toNat / 8 % 4) 0
    let r := run m mo St.init (parse m rest.length rest)
    "OK:" ++ String.join (r.2.map renderEvent) ++ "|" ++ String.join (r.2.map renderSend) ++
      "|" ++ toString r.1.queued

end Oracle.Ws
