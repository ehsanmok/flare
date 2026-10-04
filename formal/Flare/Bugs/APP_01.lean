import Flare.L4_App.ConnSM

/-!
# APP-01: the 426 WebSocket-version answer says `Connection: close` but the connection stays open

flare/http/_reactor/conn_handle.mojo:846-856 @59bda50 (the
`_is_ws_version_mismatch` branch of `on_readable`) returns
`self._finalise_response(r426^, True)`. `_finalise_response`
(conn_handle.mojo:718-756) uses `close_after = True` only to pick the
`Connection: close` header; it never sets `should_close`, and the branch
skips `_apply_keepalive_policy`. After the flush `on_writable`
(conn_handle.mojo:1365-1375) sees `should_close = False` and returns to
STATE_READING, so the next request on the connection is served.

Spec (RFC 9112 §9.6): a server that sends the `close` connection option
MUST initiate closure after that response and MUST NOT process further
requests on the connection. In the model: `Flare.L4.ConnSM.CloseHonoured`
(a queued `Connection: close` response implies `should_close`).

Witness machine: requests are single bytes, byte `1` is a WebSocket
handshake with an unsupported version, byte `0` a plain request.
-/
namespace Flare.Bugs.APP_01

open Flare.L4.ConnSM

/-- A concrete framing oracle and configuration (keep-alive on, cap 100). -/
def P0 : Params Bool where
  frame b := match b with
    | [] => .needMore
    | c :: _ => .complete (c == 1) 1
  hasBuf b := !b.isEmpty
  ser _ := [7]
  closeAfter _ := false
  wsMismatch r := r
  handlerOk _ := true
  maxKA := 100
  keepAlive := true
  cap := 1000

theorem P0_wf : Oracle.WF P0 where
  complete_le b r n h := by
    cases b with
    | nil => simp [P0] at h
    | cons c cs => simp only [P0, Frame.complete.injEq] at h; simp [← h.2]
  complete_self b r n h := by
    cases b with
    | nil => simp [P0] at h
    | cons c cs => simp only [P0, Frame.complete.injEq] at h; obtain ⟨rfl, rfl⟩ := h; simp [P0]
  complete_buf b r n h := by
    cases b with
    | nil => simp [P0] at h
    | cons c cs => simp [P0]

/-- The handshake with the bad version, its 426 fully flushed. -/
def s1 : St Bool := run false P0 init [.arrive [1], .readable false, .writable 10]

/-- Then a plain request arrives on the same connection. -/
def s2 : St Bool := run false P0 s1 [.arrive [0], .readable false]

/-- Counterexample: the 426 carries `Connection: close`, yet after it is
flushed the connection is back in STATE_READING (not done) and the next
request is dispatched. -/
theorem ws426_close_header_but_kept_open :
    (∃ o ∈ s1.log, o.kind = .ws426 ∧ o.keepAlive = false) ∧
      s1.phase = .reading ∧ s1.done = false ∧ s1.segs.length = 1 ∧ s2.segs.length = 2 := by
  native_decide

/-- `¬ spec (impl x)`: the reachable state `s1` violates `CloseHonoured`. -/
theorem violates_spec : ¬ CloseHonoured s1 := by
  intro h
  have : s1.shouldClose = false := by native_decide
  have hl : (⟨some true, .ws426, false⟩ : Out Bool) ∈ s1.log := by native_decide
  rw [h _ hl rfl] at this; cases this

/-- `s1` is reachable in the shipped machine. -/
theorem s1_reachable : (lts false P0).Reachable s1 := reachable_run false P0 _

/-- Fix (`self.should_close = True` before `_finalise_response(r426^, True)`):
in every reachable state of the fixed machine, for every framing oracle and
configuration, `CloseHonoured` holds and no request is dispatched after a
`Connection: close` response has been queued. -/
theorem fixed_close_header_implies_close {Req : Type} (P : Params Req) (hP : Oracle.WF P)
    (s : St Req) (h : (lts true P).Reachable s) :
    CloseHonoured s ∧
      ∀ o ∈ s.log, o.keepAlive = false → ∀ es, (run true P s es).segs = s.segs :=
  fixed_no_request_after_close_header P hP s h

/-- On the witness trace the fixed machine closes after the 426. -/
theorem fixed_on_example :
    (run true P0 init [.arrive [1], .readable false, .writable 10]).done = true ∧
    (run true P0 init [.arrive [1], .readable false, .writable 10, .arrive [0],
      .readable false]).segs.length = 1 := by
  native_decide

end Flare.Bugs.APP_01
