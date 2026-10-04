import Flare.L3_Protocol.Ws.Recv

/-!
# DOC-01: `WsConnection.recv` delivers TEXT frames that are not valid UTF-8

* flare file: `flare/ws/server.mojo:514-536` @59bda50 (`recv` returns every
  frame `_recv_one`, 538-598, decodes); the validator
  (`_is_valid_utf8`, `flare/ws/frame.mojo:553`) is only reached through
  `text_payload` (frame.mojo:522-536), after delivery, and
  `WsCloseCode.INVALID_PAYLOAD` (frame.mojo:68) is never sent.
* Doc clause: `docs/threat-model.md:61` "Frame-level UTF-8 validator runs on
  every TEXT payload; invalid sequences trigger 1007"; `docs/security.md:16`;
  `docs/features.md:552`. RFC 6455 §8.1: invalid UTF-8 in a text message
  "MUST _Fail the WebSocket Connection_"; §7.4.1: status 1007.
* What goes wrong: a masked, final TEXT frame with payload `C3 28` is handed
  to the handler; no CLOSE is written.
* Fix (`recvFixed`): fail a final TEXT frame whose payload is not well formed,
  after writing CLOSE 1007. Unfragmented frames only: the server has no
  continuation reassembly (`fin = false` frames are passed through as is).
-/
namespace Flare.Bugs.DOC_01
open Flare Flare.L3.Ws

/-- One `recv` call: hand a frame to the handler, fail the connection after
writing the listed CLOSE status codes, or wait for more bytes. -/
inductive Step
  | deliver (f : Frame)
  | fail (closes : List Nat)
  | wait
  deriving DecidableEq, Repr

/-- Data frames only: the PING auto-reply loop and the 1009 close for an
oversized frame (server.mojo:587-598) are outside this model, so every other
decode error is `.fail []`.
mirrors flare/ws/server.mojo:514-536,553-575 @59bda50 -/
def recv (maxP : Nat) (d : Bytes) : Step :=
  match decode false maxP d with
  | .ok f _ => if f.masked then .deliver f else .fail []
  | .error => .fail []
  | .needMore => .wait

/-- The doc's promise: an accepted (masked) final TEXT frame whose payload is
not well-formed UTF-8 fails the connection with CLOSE 1007. -/
def Utf8Spec (maxP : Nat) (r : Bytes → Step) : Prop :=
  ∀ d f n, decode false maxP d = .ok f n → f.masked = true → f.opcode = 1 → f.fin = true →
    Flare.L1.Utf8.isValidUtf8 f.payload = false → r d = .fail [1007]

def recvFixed (maxP : Nat) (d : Bytes) : Step :=
  match decode false maxP d with
  | .ok f _ =>
    if f.masked then
      if f.opcode = 1 && f.fin && !Flare.L1.Utf8.isValidUtf8 f.payload then .fail [1007]
      else .deliver f
    else .fail []
  | .error => .fail []
  | .needMore => .wait

def frameBad : Frame := ⟨true, false, 1, false, [0xC3, 0x28]⟩
def key : Key := ⟨0x11, 0x22, 0x33, 0x44⟩

theorem bad_not_utf8 : Flare.L1.Utf8.isValidUtf8 frameBad.payload = false := by native_decide

theorem decodes_bad :
    decode false (2 ^ 20) (encode frameBad true key) =
      .ok { frameBad with masked := true } (encode frameBad true key).length := by
  have := decode_encode false (2 ^ 20) frameBad true key [] (by decide) (by decide) (by decide)
    (by decide) (by decide)
  simpa using this

/-- The repro's frame is delivered to the handler. -/
theorem bug : recv (2 ^ 20) (encode frameBad true key) = .deliver { frameBad with masked := true } := by
  rw [recv, decodes_bad]
  rfl

theorem counterexample : ¬ Utf8Spec (2 ^ 20) (recv (2 ^ 20)) := by
  intro h
  have := h _ _ _ decodes_bad rfl rfl rfl bad_not_utf8
  rw [bug] at this
  simp at this

theorem fixed (maxP : Nat) : Utf8Spec maxP (recvFixed maxP) := by
  intro d f n hd hm ho hf hv
  simp [recvFixed, hd, hm, ho, hf, hv]

/-- The fix delivers every accepted frame that is not an ill-formed final TEXT
frame, so it rejects nothing else. -/
theorem fixed_keeps (maxP : Nat) (d : Bytes) (f : Frame) (n : Nat)
    (hd : decode false maxP d = .ok f n) (hm : f.masked = true)
    (hok : ¬ (f.opcode = 1 ∧ f.fin = true ∧ Flare.L1.Utf8.isValidUtf8 f.payload = false)) :
    recvFixed maxP d = .deliver f := by
  have : (f.opcode = 1 && f.fin && !Flare.L1.Utf8.isValidUtf8 f.payload) = false := by
    cases h1 : decide (f.opcode = 1) <;> cases h2 : f.fin <;>
      cases h3 : Flare.L1.Utf8.isValidUtf8 f.payload <;> simp_all
  simp [recvFixed, hd, hm, this]

end Flare.Bugs.DOC_01
