import Flare.L3_Protocol.Ws.Recv

/-!
# WS-02: `WsClient.recv_message` returns a fragment, or a PONG, as a message

* flare file: `flare/ws/client.mojo:765-794` @59bda50 ("TEXT or anything
  else: return as text").
* Spec clause: RFC 6455 §5.4 (a message is a TEXT/BINARY frame plus
  CONTINUATIONs up to FIN, control frames interleaved; its payload is the
  concatenation) and §5.5.3 (an unsolicited PONG is allowed and is not a
  message). `recv_message` is documented as "the next complete message".
* What goes wrong: `TEXT(fin=0,"hel") CONT(fin=1,"lo")` is delivered as
  "hel" and then "lo"; `PONG("x") TEXT("a")` is delivered as text "x". A
  code point split across fragments makes the per-frame UTF-8 check raise
  on a valid message.
* Fix (`nextMessage`): skip PING/PONG, start a message only on TEXT/BINARY,
  append CONTINUATIONs to FIN, and check UTF-8 on the whole message.
  `nextMessage_delivered` proves it meets `Delivered`.
-/
namespace Flare.Bugs.WS_02
open Flare Flare.L3.Ws

def tHel : Frame := ⟨false, false, 1, false, Bytes.ofString "hel"⟩
def cLo : Frame := ⟨true, false, 0, false, Bytes.ofString "lo"⟩
def pongX : Frame := ⟨true, false, 10, false, Bytes.ofString "x"⟩
def tA : Frame := ⟨true, false, 1, false, Bytes.ofString "a"⟩

theorem impl_fragment : recvMessage [tHel, cLo] = some (.text (Bytes.ofString "hel"), [cLo]) := by
  native_decide

theorem impl_pong : recvMessage [pongX, tA] = some (.text (Bytes.ofString "x"), [tA]) := by
  native_decide

theorem fixed_fragment :
    nextMessage [tHel, cLo] = some (.text (Bytes.ofString "hello"), []) := by native_decide

theorem fixed_pong : nextMessage [pongX, tA] = some (.text (Bytes.ofString "a"), []) := by native_decide

theorem counterexample_fragment : ¬ Delivered recvMessage := by
  intro h
  obtain ⟨c, e, hM⟩ := h _ _ _ _ impl_fragment rfl
  have hc : c = [tHel] := by
    have : [tHel] ++ [cLo] = c ++ [cLo] := e
    exact (List.append_cancel_right this).symm
  subst hc
  obtain ⟨d, rest, hd, -, hcase⟩ := hM
  have hfil : [tHel].filter isData = [tHel] := by native_decide
  rw [hfil] at hd
  simp only [List.cons.injEq] at hd
  obtain ⟨rfl, rfl⟩ := hd
  rcases hcase with ⟨hf, -⟩ | ⟨-, b', hC, -⟩
  · exact absurd hf (by native_decide)
  · cases hC

theorem counterexample_pong : ¬ Delivered recvMessage := by
  intro h
  obtain ⟨c, e, hM⟩ := h _ _ _ _ impl_pong rfl
  have hc : c = [pongX] := by
    have : [pongX] ++ [tA] = c ++ [tA] := e
    exact (List.append_cancel_right this).symm
  subst hc
  obtain ⟨d, rest, hd, -⟩ := hM
  have hfil : [pongX].filter isData = [] := by native_decide
  rw [hfil] at hd
  cases hd

theorem fixed_meets_spec : Delivered nextMessage := nextMessage_delivered

end Flare.Bugs.WS_02
