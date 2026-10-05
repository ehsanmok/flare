import Flare.L5_Concurrency.Scheduler

/-!
# CONC-03: `Scheduler.drain` frees the stop flag under a detached worker

`drain(timeout_ms > 0)` detaches a worker that has not returned by the
deadline (flare/runtime/scheduler.mojo:846-855 @59bda50, pre-fix). The stuck-worker
carve-out (:887-897) keeps that worker's context and stats cell allocated,
but then `_free_resources` (:900, :741-744) frees the shared stop-flag cell.
The detached worker re-reads that cell on every serve-loop iteration
(`_worker.mojo:114-116,150-155`, the frontend's `load_stop_flag`): a
use-after-free. In the repro the allocator reissues the byte, the next
owner stores `False`, and the worker keeps serving after drain returned.

Spec clause (`Flare.L5.Scheduler.MemSafe`, `LiveRefsAllocated`): nothing a
live worker can reference is freed, as the drain docstring (:799-803)
promises for the detached worker.

Fix: in the `if len(stuck) > 0:` block also leak the stop flag
(`self._stopping_addr = 0` before `_free_resources`), i.e. `Cfg.fixStop`.
`implFixed_safe` proves it suffices for any number of workers.

Status: resolved. The shipped drain is `cfgShipped` (= `cfgFixStop`); the
counterexamples below are about the explicitly pre-fix `cfgImpl`.
Regression test: tests/runtime/test_scheduler.mojo::
test_drain_keeps_the_stop_flag_allocated_for_a_detached_worker.
-/
namespace Flare.Bugs.CONC_03
open Flare.L5.Scheduler

/-- One worker enters a long handler; drain signals, samples DONE = 0,
times out, detaches it, reports and frees; the handler returns and the
serve loop re-reads the stop flag. -/
def traceFree : List Lbl := [.w 0, .w 0, .m, .sample 0, .m, .m, .m, .m, .m]
def traceUaf : List Lbl := traceFree ++ [.w 0, .w 0]

/-- The detached worker is still live (inside `serve`) when drain finishes,
and the stop flag is freed. -/
theorem traceFree_result :
    (exec cfgImpl (init 1) traceFree).map (fun s => (s.ws.map (·.pc), s.stopF, s.m)) =
      some ([WPc.serve], true, MPc.fin) := by
  decide

theorem traceUaf_result : (exec cfgImpl (init 1) traceUaf).map (·.uaf) = some true := by
  decide

/-- At the end of drain a live worker references a freed cell. -/
theorem drain_frees_live_ref :
    ∃ s, (lts cfgImpl 1).Reachable s ∧ s.m = .fin ∧ ¬ LiveRefsAllocated s := by
  cases h : exec cfgImpl (init 1) traceFree with
  | none => have := traceFree_result; rw [h] at this; cases this
  | some s =>
    have hr := traceFree_result
    rw [h] at hr
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨e1, e2, e3⟩ := hr
    refine ⟨s, reachable_of_exec _ _ _ _ h, e3, fun hl => ?_⟩
    have hne : s.ws ≠ [] := by intro he; rw [he] at e1; cases e1
    obtain ⟨w, hw⟩ := List.exists_mem_of_ne_nil _ hne
    have hpc : w.pc = .serve := by
      have := List.mem_map_of_mem (f := (·.pc)) hw
      rw [e1] at this; simpa using this
    have := (hl w hw (by rw [hpc]; decide)).2
    rw [e2] at this; cases this

/-- Headline counterexample: the detached worker dereferences the freed
stop flag. -/
theorem drain_uaf : ∃ s, (lts cfgImpl 1).Reachable s ∧ ¬ MemSafe s := by
  cases h : exec cfgImpl (init 1) traceUaf with
  | none => have := traceUaf_result; rw [h] at this; cases this
  | some s =>
    have hr := traceUaf_result
    rw [h] at hr
    simp only [Option.map_some, Option.some.injEq] at hr
    exact ⟨s, reachable_of_exec _ _ _ _ h, fun hm => by unfold MemSafe at hm; rw [hr] at hm; cases hm⟩

/-- The CONC-03 fix alone: this is the shipped drain. -/
def cfgFixStop : Cfg := { cfgImpl with fixStop := true }

theorem shipped_eq_fixStop : cfgShipped = cfgFixStop := rfl

/-- **Fix meets spec**: for the shipped drain, any number of workers and
every interleaving, no freed cell is dereferenced and nothing a live worker
can reference is freed; a detached worker reads `True` from the
still-allocated flag. -/
theorem implFixed_safe (n : Nat) :
    ∀ s, (lts cfgShipped n).Reachable s → MemSafe s ∧ LiveRefsAllocated s :=
  safe_of_cfg cfgShipped (Or.inl rfl) n

theorem implFixed_detached_sees_stop (n : Nat) :
    ∀ s, (lts cfgShipped n).Reachable s → s.m = .fin → ∀ w ∈ s.ws, w.pc ≠ .term →
      s.stop = true ∧ s.stopF = false :=
  detached_sees_stop cfgShipped (Or.inl rfl) n

/-- Bounded (3 workers, exhaustive, `native_decide`): the fully fixed drain
meets the specification; the explorer finds the violation in the code at
59bda50 with 2 workers as well. -/
theorem bounded_fixed_3 : check cfgFixed 3 specB 20000 = true := by native_decide
theorem bounded_impl_2_fails : check cfgImpl 2 specB 4000 = false := by native_decide

end Flare.Bugs.CONC_03
