import Flare.L3_Protocol.Ws.Close

/-!
# WS-06: `WsConnection` does not take part in the closing handshake

* flare file: `flare/ws/server.mojo` @59bda50: `recv` (514-536) hands a
  CLOSE to the caller without answering it; `close()` (600-616) writes a
  CLOSE and keeps no state (its docstring says it waits for the reply; it
  does not); `send_text`/`send_binary`/`send_frame` (473-512) never check.
  The documented handler (660-671) breaks on CLOSE, and `__deinit__`
  closes the socket with no CLOSE written.
* Spec clause: RFC 6455 §5.5.1: an endpoint that receives a CLOSE and has
  not sent one MUST send one in response, and after sending a CLOSE MUST
  NOT send more data; §7.4.1, §7.1.7: a 1-byte body, an invalid code or a
  non-UTF-8 reason is a protocol error (1002).
* What goes wrong: a client's CLOSE 1000 gets EOF; a 1-byte CLOSE body gets
  EOF, not 1002; `close()` followed by `send_text` puts a TEXT frame after
  the CLOSE.
* Fix (`fixStep`, a `close_sent` flag): `fixed_closeOK`.

Status: resolved. The counterexamples are about the pre-fix endpoint
`oldStep`; `fixed_ok` is about the shipped `fixStep`.
-/
namespace Flare.Bugs.WS_06
open Flare Flare.L3.Ws.Close

theorem counterexample_no_echo : ¬ CloseOK oldStep () := by
  intro h
  have := h [.recv 8 [3, 232]]
  simp [outs, Good, oldStep] at this

theorem counterexample_invalid_payload : ¬ CloseOK oldStep () := by
  intro h
  have := h [.recv 8 [3]]
  simp [outs, Good, oldStep] at this

theorem counterexample_data_after_close : ¬ CloseOK oldStep () := by
  intro h
  have := h [.close 1000, .sendText [108]]
  simp [outs, Good, oldStep, isCloseOut, isDataOut] at this

theorem reply_1002 : closeReply [3] = [3, 234] := by native_decide

theorem fixed_ok : CloseOK fixStep false := fixed_closeOK

end Flare.Bugs.WS_06
