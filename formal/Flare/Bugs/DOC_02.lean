import Flare.Bugs.DOC_01

/-!
# DOC-02: an unmasked client frame is refused without the promised CLOSE 1002

* flare file: `flare/ws/server.mojo:558-562` @59bda50 (`_recv_one` raises
  `WsProtocolError("client sent unmasked frame")` and writes nothing; the only
  close it ever writes is 1009, server.mojo:587-598).
* Doc clause: `docs/threat-model.md:60` "`WsConnection.recv` enforces the RFC
  6455 §5.1 client-side mask requirement; unmasked frames are rejected with
  1002." RFC 6455 §5.1: the server MUST close the connection and MAY send a
  Close frame with status 1002. The refusal itself holds
  (`Flare.L3.Ws.server_safe`); the 1002 the doc names is never sent.
* What goes wrong: `recv` on an unmasked TEXT frame fails the connection
  having written no CLOSE frame.
* Fix (`recvFixed`): write CLOSE 1002 before raising.
-/
namespace Flare.Bugs.DOC_02
open Flare Flare.L3.Ws Flare.Bugs.DOC_01

/-- The doc's promise: a decodable frame without the MASK bit is refused with
CLOSE 1002. -/
def MaskSpec (maxP : Nat) (r : Bytes → Step) : Prop :=
  ∀ d f n, decode false maxP d = .ok f n → f.masked = false → r d = .fail [1002]

def recvFixed (maxP : Nat) (d : Bytes) : Step :=
  match decode false maxP d with
  | .ok f _ => if f.masked then .deliver f else .fail [1002]
  | .error => .fail []
  | .needMore => .wait

def frameHi : Frame := ⟨true, false, 1, false, [104, 105]⟩

theorem decodes_hi :
    decode false (2 ^ 20) (encode frameHi false key) =
      .ok { frameHi with masked := false } (encode frameHi false key).length := by
  have := decode_encode false (2 ^ 20) frameHi false key [] (by decide) (by decide) (by decide)
    (by decide) (by decide)
  simpa using this

/-- The repro's frame: refused, with nothing written. -/
theorem bug : recv (2 ^ 20) (encode frameHi false key) = .fail [] := by
  rw [recv, decodes_hi]
  rfl

theorem counterexample : ¬ MaskSpec (2 ^ 20) (recv (2 ^ 20)) := by
  intro h
  have := h _ _ _ decodes_hi rfl
  rw [bug] at this
  simp at this

theorem fixed (maxP : Nat) : MaskSpec maxP (recvFixed maxP) := by
  intro d f n hd hm
  simp [recvFixed, hd, hm]

/-- The fix still never delivers an unmasked frame. -/
theorem fixed_server_safe (maxP : Nat) (d : Bytes) (f : Frame) (h : recvFixed maxP d = .deliver f) :
    f.masked = true := by
  unfold recvFixed at h
  split at h
  · split at h
    · cases h; assumption
    · cases h
  · cases h
  · cases h

end Flare.Bugs.DOC_02
