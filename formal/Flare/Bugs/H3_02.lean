import Flare.L3_Protocol.H3.Grammar

/-!
# H3-02: HTTP/2-reserved frame types are ignored on request streams

flare/http3/request_reader.mojo:308-327 @59bda50 rejects the control-stream
frame types (CANCEL_PUSH, SETTINGS, PUSH_PROMISE, GOAWAY, MAX_PUSH_ID) on a
request stream but sends every other type, including 0x02, 0x06, 0x08 and
0x09, to `on_unknown_frame`, so the stream continues.

Spec clause: RFC 9114 §7.2.8 / §11.2.1: the frame types used by HTTP/2
PRIORITY (0x02), PING (0x06), WINDOW_UPDATE (0x08) and CONTINUATION (0x09)
are reserved; "their receipt MUST be treated as a connection error of type
H3_FRAME_UNEXPECTED". In the request-stream grammar `specStep` they are
rejections.

`Flare.L3.H3.run_accept_impl` / `run_reject_impl` show flare matches the
grammar on every sequence without these types; this file shows the
remaining gap and that the minimal fix closes it with no side condition.
-/
namespace Flare.Bugs.H3_02
open Flare.L3.H3

variable {Hdrs : Type}

/-- flare reports a reserved type as an ignorable unknown frame, in any state. -/
theorem impl_ignores_reserved (qd : Bytes → Option Hdrs) (r : Reader) (t : Nat) (p : Bytes)
    (ht : t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09) :
    (stepFrame qd r t p).2.isError = false ∧ (stepFrame qd r t p).1 = r := by
  rcases ht with rfl | rfl | rfl | rfl <;>
    simp [stepFrame, T_HEADERS, T_DATA, isControlType, T_SETTINGS, T_GOAWAY, T_MAX_PUSH_ID,
      T_CANCEL_PUSH, T_PUSH_PROMISE, Ev.isError]

/-- The grammar rejects them in every state. -/
theorem spec_rejects (q : Q) (t : Nat) (ht : t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09) :
    specStep q t = none := by
  rcases ht with rfl | rfl | rfl | rfl <;> simp [specStep]

/-- Concretely: a HEADERS-then-PING request stream is accepted by flare but
rejected by the spec. -/
theorem violates_spec (qd : Bytes → Option Hdrs) (r : Reader) (h : Hdrs) (p : Bytes)
    (hr : r.st = .init) (hp : p.length ≤ r.maxField) (hq : qd p = some h) :
    specRun .q0 [0x01, 0x06] = none ∧
      ∀ e ∈ (runFrames (stepFrame qd) r [(0x01, p), (0x06, [])]).2, e.isError = false := by
  refine ⟨by simp [specRun, specStep], ?_⟩
  have hp' : ¬ p.length > r.maxField := by omega
  simp [runFrames, stepFrame, T_HEADERS, T_DATA, hr, hp', hq, isControlType, T_SETTINGS,
    T_GOAWAY, T_MAX_PUSH_ID, T_CANCEL_PUSH, T_PUSH_PROMISE, Ev.isError]

/-- The minimal fix: reject the reserved types next to the control types. -/
def stepFrameFixed (qd : Bytes → Option Hdrs) (r : Reader) (t : Nat) (p : Bytes) :
    Reader × Ev Hdrs :=
  if isH2Reserved t then ({ r with st := .done }, .error .controlType) else stepFrame qd r t p

theorem stepFrameFixed_agrees (qd : Bytes → Option Hdrs) (r : Reader) (t : Nat) (p : Bytes)
    (hg : GoodFrame qd r.maxField (t, p)) : StepAgrees (stepFrameFixed qd) r t p := by
  by_cases h : isH2Reserved t = true
  · have hs : ∀ q, specStep q t = none := fun q => spec_rejects q t ((isH2Reserved_iff t).1 h)
    unfold StepAgrees stepFrameFixed
    rw [if_pos h]
    refine ⟨rfl, fun q _ => ⟨fun q' hq' => ?_, fun _ => rfl⟩⟩
    rw [hs q] at hq'; cases hq'
  · have h' : isH2Reserved t = false := by simpa using h
    have := stepFrame_agrees qd r t p hg h'
    unfold StepAgrees stepFrameFixed at *
    simpa only [h', Bool.false_eq_true, ↓reduceIte] using this

/-- **The fix meets the RFC 9114 §4.1 grammar** on every sequence of good
frames, with no restriction on frame types: spec-accepted sequences raise no
error and track the spec state; spec-rejected ones raise an error. -/
theorem runFixed_spec (qd : Bytes → Option Hdrs) (fs : List (Nat × Bytes)) (r : Reader) (q : Q)
    (hq : absQ r.st = some q) (hgood : ∀ f ∈ fs, GoodFrame qd r.maxField f) :
    (∀ q', specRun q (fs.map Prod.fst) = some q' →
      (∀ e ∈ (runFrames (stepFrameFixed qd) r fs).2, e.isError = false) ∧
        absQ (runFrames (stepFrameFixed qd) r fs).1.st = some q') ∧
    (specRun q (fs.map Prod.fst) = none →
      ∃ e ∈ (runFrames (stepFrameFixed qd) r fs).2, e.isError = true) :=
  ⟨fun q' hacc => runFrames_accept (P := fun _ => True) qd (stepFrameFixed qd)
      (fun r t p hg _ => stepFrameFixed_agrees qd r t p hg) fs r q q' hq hgood
      (fun _ _ => trivial) hacc,
   fun hrej => runFrames_reject (P := fun _ => True) qd (stepFrameFixed qd)
      (fun r t p hg _ => stepFrameFixed_agrees qd r t p hg) fs r q hq hgood
      (fun _ _ => trivial) hrej⟩

end Flare.Bugs.H3_02
