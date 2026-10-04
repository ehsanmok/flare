import Flare.L5_Concurrency.Watchdog

/-!
# CONC-02: arm on a still-armed slot fires the old deadline into the new cell

`watchdog_arm` (flare/runtime/watchdog.mojo:98-111 @59bda50) settles the
slot, stores the new cancel-cell address (:106), computes the deadline
(:107) and only then CASes the deadline in (:110). If the slot still holds
the previous request's deadline, the poller (:157-177) can claim that old
deadline between the address store and the CAS, load the *new* address
(:166) and write `TIMEOUT` into the new request's cell (:172-175). The new
request is cancelled although its own deadline is far in the future, and
its `disarm` (:114-132) then returns `False` ("not fired").

Spec clause (`Flare.L5.Watchdog.Safe`, `DisarmCorrect`): a cell write
targets the current request and uses the deadline that request armed;
`disarm` returns `True` exactly when the request's cell was cancelled.

Latent: no caller in flare re-arms without a disarm. The watchdog has no
production call site at 59bda50 (only `watchdog.mojo` itself and
`tests/runtime/test_watchdog.mojo`, whose re-arm happens after the fire
has completed). The arm docstring does not state the precondition.

Fix: begin `watchdog_arm` with the disarm loop (CAS the current deadline to
0, waiting out FIRING), then store the address and CAS `0 → deadline`
(`Cfg.disarmFirst`). `Flare.L5.Watchdog.fixed_safe` and
`disarmFirst_safe` below prove it safe even when callers re-arm.
-/
namespace Flare.Bugs.CONC_02
open Flare.L5.Watchdog

/-- The code at 59bda50 with positive budgets, when a caller re-arms a slot
without disarming it first. -/
def cfgRearm : Cfg := { cfgImpl with allowRearm := true }

/-- Request 1 armed with budget 0 (deadline 1 = now, already expired); the
poller loads it; the worker re-arms for request 2 and stores cell 2's
address; the poller's CAS claims the old deadline and it loads address 2. -/
def traceA : List Lbl :=
  [.w 0, .w 0, .w 0, .w 0, .w 0, .w 0, .p, .p, .rearm, .w 0, .w 0, .p, .p]

/-- Continue: the poller writes TIMEOUT into cell 2 and releases; request 2
arms its 60 s deadline, finishes, and disarms. -/
def traceB : List Lbl :=
  traceA ++ [.p, .p, .w 60000, .w 0, .w 0, .w 0, .w 0, .w 0]

theorem traceA_result :
    (exec cfgRearm s0 traceA).map (fun s => (s.p, s.claimReq, s.cur)) =
      some (PPc.write 2, 1, 2) := by
  decide

theorem traceB_result :
    (exec cfgRearm s0 traceB).map (fun s => (s.cancelled 2, s.ret, s.fired, s.cur, s.w, s.reqDl)) =
      some (true, false, true, 2, WPc.idle, 60001) := by
  decide

/-- Headline counterexample: a reachable state in which the poller is about
to write into request 2's cell on the strength of request 1's claim. -/
theorem rearm_hits_new_cell :
    ∃ s, (lts cfgRearm).Reachable s ∧ s.p = .write 2 ∧ s.cur = 2 ∧ s.claimReq = 1 ∧ ¬ Safe s := by
  cases h : exec cfgRearm s0 traceA with
  | none => have := traceA_result; rw [h] at this; cases this
  | some s =>
    have hr := traceA_result
    rw [h] at hr
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨e1, e2, e3⟩ := hr
    refine ⟨s, ⟨s0, traceA, s0_init, run_of_exec _ _ _ _ h⟩, e1, e3, e2, ?_⟩
    intro hs
    have := (hs 2 e1 (by decide)).2.1
    rw [e2, e3] at this
    cases this

/-- The same run ends with request 2's cell cancelled while `disarm`
reported "not fired", and request 2's deadline (60001 ms) never expired. -/
theorem rearm_disarm_wrong :
    ∃ s, (lts cfgRearm).Reachable s ∧ s.cancelled 2 = true ∧ s.reqDl = 60001 ∧ ¬ DisarmCorrect s := by
  cases h : exec cfgRearm s0 traceB with
  | none => have := traceB_result; rw [h] at this; cases this
  | some s =>
    have hr := traceB_result
    rw [h] at hr
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨e1, e2, e3, e4, e5, e6⟩ := hr
    refine ⟨s, ⟨s0, traceB, s0_init, run_of_exec _ _ _ _ h⟩, e1, e6, ?_⟩
    intro hd
    have := hd e5 (by rw [e4]; decide)
    rw [e2, e3] at this
    cases this

/-- The disarm-first arm alone (no clamp, positive budgets) is safe even
when callers re-arm a still-armed slot. -/
theorem disarmFirst_safe :
    ∀ s, (lts { cfgRearm with disarmFirst := true }).Reachable s →
      Safe s ∧ DisarmCorrect s ∧ FiringOwned s :=
  safe_of_cfg _ (fun _ => rfl) deadlinePos_impl

/-- The full fix (disarm-first + clamp) meets the spec for every budget and
with re-arming allowed. -/
theorem implFixed_safe :
    ∀ s, (lts cfgFixed).Reachable s → Safe s ∧ DisarmCorrect s ∧ FiringOwned s :=
  fixed_safe

end Flare.Bugs.CONC_02
