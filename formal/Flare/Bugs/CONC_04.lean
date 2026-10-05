import Flare.L5_Concurrency.Scheduler

/-!
# CONC-04: `Scheduler.drain` leaks the joined workers' listeners

When any worker is detached, the stuck-worker branch of `drain`
(flare/runtime/scheduler.mojo:890-897 @59bda50) runs
`self._per_worker_listener_addrs.clear()`, dropping every per-worker
listener from the list `_free_resources` (:726-733) frees, not only the
stuck worker's. The listeners of workers that returned and were joined stay
open and bound for the life of the process; the kernel keeps hashing new
connections to `SO_REUSEPORT` listeners nobody accepts on.

Spec clause (`Flare.L5.Scheduler.NoLeak`): after drain only the detached
workers' context, stats cell and listeners are left allocated (drain
docstring, :799-803).

Fix: in that branch drop only the stuck workers' entries (primary `i` and
its extras `n_workers + i*n_extra + j`), i.e. `Cfg.fixLis`.
`implFixed_noLeak` proves it suffices.

Status: resolved. The shipped drain is `cfgShipped` (both the CONC-03 and
CONC-04 fixes); the counterexample is about the explicitly pre-fix
`cfgImpl`. Regression tests: tests/runtime/test_scheduler.mojo::
test_drain_closes_the_joined_workers_listeners and
test_drain_closes_the_joined_workers_extra_listeners.
-/
namespace Flare.Bugs.CONC_04
open Flare.L5.Scheduler

/-- Worker 0 enters a long handler; drain signals; worker 1 sees the flag
and returns; drain samples (0: not done, 1: done), detaches worker 0, joins
worker 1, reports and frees. -/
def trace : List Lbl :=
  [.w 0, .w 0, .m, .w 1, .w 1, .w 1, .w 1, .sample 0, .sample 1, .m, .m, .m, .m, .m, .m]

theorem trace_result :
    (exec cfgImpl (init 2) trace).map
      (fun s => (s.m, s.ws.map fun w => [w.joined, w.detached, w.ctxF, w.statsF, w.lisF])) =
      some (MPc.fin, [[false, true, false, false, false], [true, false, true, true, false]]) := by
  decide

/-- Headline counterexample: drain has finished, worker 1 was joined (not
detached), its context and stats cell were freed, its listener was not. -/
theorem drain_leaks_joined_listener :
    ∃ s, (lts cfgImpl 2).Reachable s ∧ s.m = .fin ∧
      (∃ w ∈ s.ws, w.joined = true ∧ w.detached = false ∧ w.lisF = false) ∧ ¬ NoLeak s := by
  cases h : exec cfgImpl (init 2) trace with
  | none => have := trace_result; rw [h] at this; cases this
  | some s =>
    have hr := trace_result
    rw [h] at hr
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨e1, e2⟩ := hr
    have hw : ∃ w ∈ s.ws, w.joined = true ∧ w.detached = false ∧ w.lisF = false := by
      have hm : [true, false, true, true, false] ∈
          s.ws.map fun w => [w.joined, w.detached, w.ctxF, w.statsF, w.lisF] := by
        rw [e2]; simp
      obtain ⟨w, hw, hwe⟩ := List.mem_map.mp hm
      simp only [List.cons.injEq] at hwe
      exact ⟨w, hw, hwe.1, hwe.2.1, hwe.2.2.2.2.1⟩
    refine ⟨s, reachable_of_exec _ _ _ _ h, e1, hw, fun hn => ?_⟩
    obtain ⟨w, hwm, -, hd, hl⟩ := hw
    have := ((hn e1).1 w hwm hd).2.2
    rw [hl] at this; cases this

/-- The CONC-04 fix alone (the shipped drain also has the CONC-03 fix). -/
def cfgFixLis : Cfg := { cfgImpl with fixLis := true }

/-- The shipped drain has the CONC-04 fix. -/
theorem shipped_has_fixLis : cfgShipped.fixLis = true := rfl

/-- The fix suffices (shipped drain): for any number of workers and every
interleaving, drain leaves allocated only the detached workers' resources
(and the stop flag only when some worker was detached). -/
theorem implFixed_noLeak (n : Nat) : ∀ s, (lts cfgShipped n).Reachable s → NoLeak s :=
  noLeak_of_cfg cfgShipped (Or.inl rfl) n

/-- The CONC-04 fix alone also suffices for `NoLeak`. -/
theorem fixLis_alone_noLeak (n : Nat) : ∀ s, (lts cfgFixLis n).Reachable s → NoLeak s :=
  noLeak_of_cfg cfgFixLis (Or.inl rfl) n

/-- With both fixes (the shipped drain) it is memory safe and leak free. -/
theorem implFixed_full (n : Nat) :
    ∀ s, (lts cfgShipped n).Reachable s → MemSafe s ∧ LiveRefsAllocated s ∧ NoLeak s :=
  fixed_safe n

end Flare.Bugs.CONC_04
