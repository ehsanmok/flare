import Flare.L3_Protocol.Ws.Recv

/-!
# DOC-01: `WsConnection.recv` delivers TEXT frames that are not valid UTF-8

Status: resolved. `WsConnection.recv` (`flare/ws/server.mojo:695-759`) now
writes CLOSE 1007 and raises on a final TEXT frame whose payload is not valid
UTF-8; regression test `tests/ws/test_ws_server_close_handshake.mojo`
`test_invalid_utf8_text_frame_is_refused_with_close_1007`. `recv` below is the
shipped model; `recvOld` is the pre-fix behaviour the counterexample is about.

* flare file (pre-fix): `flare/ws/server.mojo:514-536` @59bda50 (`recv` returned
  every frame `_recv_one`, 538-598, decodes); the validator
  (`_is_valid_utf8`, `flare/ws/frame.mojo:553`) was only reached through
  `text_payload` (frame.mojo:522-536), after delivery, and
  `WsCloseCode.INVALID_PAYLOAD` (frame.mojo:68) was never sent.
* Doc clause: `docs/threat-model.md:61` "Frame-level UTF-8 validator runs on
  every TEXT payload; invalid sequences trigger 1007"; `docs/security.md:16`;
  `docs/features.md:552`. RFC 6455 §8.1: invalid UTF-8 in a text message
  "MUST _Fail the WebSocket Connection_"; §7.4.1: status 1007.
* What goes wrong: a masked, final TEXT frame with payload `C3 28` is handed
  to the handler; no CLOSE is written.
* Fix (`recv`; the unmasked branch is DOC-02's): fail a final TEXT frame whose payload is not well formed,
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

/-- The pre-fix `recv` (DOC-01 and DOC-02 both unfixed). Data frames only: the
PING auto-reply loop and the 1009 close for an oversized frame are outside this
model, so every other decode error is `.fail []`.
mirrors flare/ws/server.mojo:514-536,553-575 @59bda50 -/
def recvOld (maxP : Nat) (d : Bytes) : Step :=
  match decode false maxP d with
  | .ok f _ => if f.masked then .deliver f else .fail []
  | .error => .fail []
  | .needMore => .wait

/-- The doc's promise: an accepted (masked) final TEXT frame whose payload is
not well-formed UTF-8 fails the connection with CLOSE 1007. -/
def Utf8Spec (maxP : Nat) (r : Bytes → Step) : Prop :=
  ∀ d f n, decode false maxP d = .ok f n → f.masked = true → f.opcode = 1 → f.fin = true →
    Flare.L1.Utf8.isValidUtf8 f.payload = false → r d = .fail [1007]

/-- The shipped `recv`: a final TEXT frame that is not UTF-8 fails with CLOSE 1007
(DOC-01), and an unmasked frame fails with CLOSE 1002 (DOC-02).
mirrors flare/ws/server.mojo:695-759,776-834 (fixed, DOC-01, DOC-02) -/
def recv (maxP : Nat) (d : Bytes) : Step :=
  match decode false maxP d with
  | .ok f _ =>
    if f.masked then
      if f.opcode = 1 && f.fin && !Flare.L1.Utf8.isValidUtf8 f.payload then .fail [1007]
      else .deliver f
    else .fail [1002]
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

/-- The repro's frame was delivered to the handler by the pre-fix `recv`. -/
theorem bug : recvOld (2 ^ 20) (encode frameBad true key) = .deliver { frameBad with masked := true } := by
  rw [recvOld, decodes_bad]
  rfl

theorem counterexample : ¬ Utf8Spec (2 ^ 20) (recvOld (2 ^ 20)) := by
  intro h
  have := h _ _ _ decodes_bad rfl rfl rfl bad_not_utf8
  rw [bug] at this
  simp at this

theorem fixed (maxP : Nat) : Utf8Spec maxP (recv maxP) := by
  intro d f n hd hm ho hf hv
  simp [recv, hd, hm, ho, hf, hv]

/-- The fix delivers every accepted frame that is not an ill-formed final TEXT
frame, so it rejects nothing else. -/
theorem fixed_keeps (maxP : Nat) (d : Bytes) (f : Frame) (n : Nat)
    (hd : decode false maxP d = .ok f n) (hm : f.masked = true)
    (hok : ¬ (f.opcode = 1 ∧ f.fin = true ∧ Flare.L1.Utf8.isValidUtf8 f.payload = false)) :
    recv maxP d = .deliver f := by
  have : (f.opcode = 1 && f.fin && !Flare.L1.Utf8.isValidUtf8 f.payload) = false := by
    cases h1 : decide (f.opcode = 1) <;> cases h2 : f.fin <;>
      cases h3 : Flare.L1.Utf8.isValidUtf8 f.payload <;> simp_all
  simp [recv, hd, hm, this]

end Flare.Bugs.DOC_01
