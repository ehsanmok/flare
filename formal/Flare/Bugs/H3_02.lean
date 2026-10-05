import Flare.L3_Protocol.H3.Grammar

/-!
# H3-02: HTTP/2-reserved frame types are ignored on request streams

flare/http3/request_reader.mojo:308-327 @59bda50 (pre-fix) rejected the control-stream
frame types (CANCEL_PUSH, SETTINGS, PUSH_PROMISE, GOAWAY, MAX_PUSH_ID) on a
request stream but sent every other type, including 0x02, 0x06, 0x08 and
0x09, to `on_unknown_frame`, so the stream continued.

Spec clause: RFC 9114 §7.2.8 / §11.2.1: the frame types used by HTTP/2
PRIORITY (0x02), PING (0x06), WINDOW_UPDATE (0x08) and CONTINUATION (0x09)
are reserved; "their receipt MUST be treated as a connection error of type
H3_FRAME_UNEXPECTED". In the request-stream grammar `specStep` they are
rejections.

Status: resolved. `feed_into` now rejects the four reserved types with the
control-stream types (`isControlType t || isH2Reserved t`), so
`Flare.L3.H3.run_accept_impl` / `run_reject_impl` show the shipped reader
matches the grammar on every sequence, with no side condition on frame types.
`stepFrameOld` below is the pre-fix dispatch (the counterexamples are about
it); `runFixed_spec` restates the guarantee for the shipped `stepFrame`.
Regression tests: tests/h3/test_request_reader.mojo
`test_h2_reserved_frame_types_are_refused`.
-/
namespace Flare.Bugs.H3_02
open Flare.L3.H3

variable {Hdrs : Type}

/-- PRE-FIX dispatch: the HTTP/2-reserved types fall through to `unknown`.
mirrors flare/http3/request_reader.mojo:261-327 @59bda50 (pre-fix) -/
def stepFrameOld (qd : Bytes → Option Hdrs) (r : Reader) (t : Nat) (p : Bytes) :
    Reader × Ev Hdrs :=
  if t = T_HEADERS then
    if r.st = .trailers then ({r with st := .done}, .error .headersAfterTrailers)
    else if p.length > r.maxField then ({r with st := .done}, .error .fieldTooBig)
    else match qd p with
      | none => ({r with st := .done}, .error .qpack)
      | some h =>
        if r.st = .init then ({r with st := .body}, .headers h)
        else ({r with st := .trailers}, .trailers h)
  else if t = T_DATA then
    if r.st ≠ .body then ({r with st := .done}, .error .dataOutside)
    else ({r with bodyBytes := r.bodyBytes + p.length}, .data p)
  else if isControlType t then ({r with st := .done}, .error .controlType)
  else (r, .unknown t)

/-- The pre-fix reader reports a reserved type as an ignorable unknown frame,
in any state. -/
theorem implOld_ignores_reserved (qd : Bytes → Option Hdrs) (r : Reader) (t : Nat) (p : Bytes)
    (ht : t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09) :
    (stepFrameOld qd r t p).2.isError = false ∧ (stepFrameOld qd r t p).1 = r := by
  rcases ht with rfl | rfl | rfl | rfl <;>
    simp [stepFrameOld, T_HEADERS, T_DATA, isControlType, T_SETTINGS, T_GOAWAY, T_MAX_PUSH_ID,
      T_CANCEL_PUSH, T_PUSH_PROMISE, Ev.isError]

/-- The grammar rejects them in every state. -/
theorem spec_rejects (q : Q) (t : Nat) (ht : t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09) :
    specStep q t = none := by
  rcases ht with rfl | rfl | rfl | rfl <;> simp [specStep]

/-- Concretely: a HEADERS-then-PING request stream was accepted by the pre-fix
reader but is rejected by the spec. -/
theorem violates_spec (qd : Bytes → Option Hdrs) (r : Reader) (h : Hdrs) (p : Bytes)
    (hr : r.st = .init) (hp : p.length ≤ r.maxField) (hq : qd p = some h) :
    specRun .q0 [0x01, 0x06] = none ∧
      ∀ e ∈ (runFrames (stepFrameOld qd) r [(0x01, p), (0x06, [])]).2, e.isError = false := by
  refine ⟨by simp [specRun, specStep], ?_⟩
  have hp' : ¬ p.length > r.maxField := by omega
  simp [runFrames, stepFrameOld, T_HEADERS, T_DATA, hr, hp', hq, isControlType, T_SETTINGS,
    T_GOAWAY, T_MAX_PUSH_ID, T_CANCEL_PUSH, T_PUSH_PROMISE, Ev.isError]

/-- The shipped dispatch rejects every reserved type, in any state. -/
theorem implRejects_reserved (qd : Bytes → Option Hdrs) (r : Reader) (t : Nat) (p : Bytes)
    (ht : t = 0x02 ∨ t = 0x06 ∨ t = 0x08 ∨ t = 0x09) :
    (stepFrame qd r t p).2.isError = true ∧ (stepFrame qd r t p).1.st = .done := by
  rcases ht with rfl | rfl | rfl | rfl <;>
    simp [stepFrame, T_HEADERS, T_DATA, isControlType, T_SETTINGS, T_GOAWAY, T_MAX_PUSH_ID,
      T_CANCEL_PUSH, T_PUSH_PROMISE, isH2Reserved, Ev.isError]

/-- **The fix meets the RFC 9114 §4.1 grammar** on every sequence of good
frames, with no restriction on frame types: spec-accepted sequences raise no
error and track the spec state; spec-rejected ones raise an error. -/
theorem runFixed_spec (qd : Bytes → Option Hdrs) (fs : List (Nat × Bytes)) (r : Reader) (q : Q)
    (hq : absQ r.st = some q) (hgood : ∀ f ∈ fs, GoodFrame qd r.maxField f) :
    (∀ q', specRun q (fs.map Prod.fst) = some q' →
      (∀ e ∈ (runFrames (stepFrame qd) r fs).2, e.isError = false) ∧
        absQ (runFrames (stepFrame qd) r fs).1.st = some q') ∧
    (specRun q (fs.map Prod.fst) = none →
      ∃ e ∈ (runFrames (stepFrame qd) r fs).2, e.isError = true) :=
  ⟨fun q' hacc => run_accept_impl qd fs r q q' hq hgood hacc,
   fun hrej => run_reject_impl qd fs r q hq hgood hrej⟩

end Flare.Bugs.H3_02
