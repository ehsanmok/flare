import Flare.Bugs.DOC_01

/-!
# DOC-02: an unmasked client frame is refused without the promised CLOSE 1002

Status: resolved. `WsConnection._recv_one` (`flare/ws/server.mojo:776-834`)
now writes CLOSE 1002 before it raises on an unmasked client frame; regression
test `tests/ws/test_ws_server_close_handshake.mojo`
`test_unmasked_client_frame_is_refused_with_close_1002`. `Flare.Bugs.DOC_01.recv`
is the shipped model; the counterexample is about `recvOld`, the pre-fix
behaviour.

* flare file (pre-fix): `flare/ws/server.mojo:558-562` @59bda50 (`_recv_one`
  raised `WsProtocolError("client sent unmasked frame")` and wrote nothing; the
  only close it ever wrote was 1009, server.mojo:587-598).
* Doc clause: `docs/threat-model.md:60` "`WsConnection.recv` enforces the RFC
  6455 §5.1 client-side mask requirement; unmasked frames are rejected with
  1002." RFC 6455 §5.1: the server MUST close the connection and MAY send a
  Close frame with status 1002. The refusal itself holds
  (`Flare.L3.Ws.server_safe`); the 1002 the doc names is never sent.
* What goes wrong: `recv` on an unmasked TEXT frame fails the connection
  having written no CLOSE frame.
* Fix (`recv`): write CLOSE 1002 before raising.
-/
namespace Flare.Bugs.DOC_02
open Flare Flare.L3.Ws Flare.Bugs.DOC_01

/-- The doc's promise: a decodable frame without the MASK bit is refused with
CLOSE 1002. -/
def MaskSpec (maxP : Nat) (r : Bytes → Step) : Prop :=
  ∀ d f n, decode false maxP d = .ok f n → f.masked = false → r d = .fail [1002]

def frameHi : Frame := ⟨true, false, 1, false, [104, 105]⟩

theorem decodes_hi :
    decode false (2 ^ 20) (encode frameHi false key) =
      .ok { frameHi with masked := false } (encode frameHi false key).length := by
  have := decode_encode false (2 ^ 20) frameHi false key [] (by decide) (by decide) (by decide)
    (by decide) (by decide)
  simpa using this

/-- The repro's frame: refused, with nothing written. -/
theorem bug : recvOld (2 ^ 20) (encode frameHi false key) = .fail [] := by
  rw [recvOld, decodes_hi]
  rfl

theorem counterexample : ¬ MaskSpec (2 ^ 20) (recvOld (2 ^ 20)) := by
  intro h
  have := h _ _ _ decodes_hi rfl
  rw [bug] at this
  simp at this

theorem fixed (maxP : Nat) : MaskSpec maxP (recv maxP) := by
  intro d f n hd hm
  simp [recv, hd, hm]

/-- The fix still never delivers an unmasked frame. -/
theorem fixed_server_safe (maxP : Nat) (d : Bytes) (f : Frame) (h : recv maxP d = .deliver f) :
    f.masked = true := by
  unfold recv at h
  repeat' split at h
  all_goals first | (cases h; assumption) | cases h

end Flare.Bugs.DOC_02
