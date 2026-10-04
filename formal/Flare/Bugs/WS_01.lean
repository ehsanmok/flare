import Flare.L3_Protocol.Ws.Recv

/-!
# WS-01: `decode_one` accepts reserved opcodes

* flare file: `flare/ws/frame.mojo:395-508` @59bda50 (`opcode = byte0 & 0x0F`
  is never checked).
* Spec clause: RFC 6455 §5.2: opcodes 0x3-0x7 and 0xB-0xF are reserved; "if
  an unknown opcode is received, the receiving endpoint MUST _Fail the
  WebSocket Connection_".
* What goes wrong: `[0x83, 0x00]` decodes to a FIN frame with opcode 3, and
  `WsConnection.recv` / `WsClient.recv` return it to the application.
* Fix (`decodeKnown`): reject the frame unless the opcode is 0x0-0x2 or
  0x8-0xA. `decodeKnown_safe` proves the fix, and `decodeKnown_encode`
  proves it still round-trips every frame with a defined opcode.
-/
namespace Flare.Bugs.WS_01
open Flare Flare.L3.Ws

theorem decodes_reserved :
    decode false (2 ^ 20) [0x83, 0x00] = .ok ⟨true, false, 3, false, []⟩ 2 := by native_decide

theorem decodes_reserved_control :
    decode false (2 ^ 20) [0x8B, 0x00] = .ok ⟨true, false, 11, false, []⟩ 2 := by native_decide

theorem counterexample : ¬ OpcodeSafe (decode false (2 ^ 20)) := by
  intro h
  have := h _ _ _ decodes_reserved
  exact absurd this (by native_decide)

theorem fixed_known_opcode (maxP : Nat) : OpcodeSafe (decodeKnown false maxP) :=
  decodeKnown_safe false maxP

theorem fixed_rejects : decodeKnown false (2 ^ 20) [0x83, 0x00] = .error := by native_decide

end Flare.Bugs.WS_01
