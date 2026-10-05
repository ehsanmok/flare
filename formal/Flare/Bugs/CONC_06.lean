import Flare.L5_Concurrency.Lifecycle

/-!
# CONC-06: `Scheduler.start`'s rollback leaks every per-worker listener

In the default listener mode (per-worker `SO_REUSEPORT`, and always with
extra addresses or a frontend that requires it), `start` binds and
heap-stores one listener per worker, plus the extras, before spawning
(flare/runtime/scheduler.mojo:511-543 @59bda50). When `pthread_create`
fails for worker `k`, the rollback (:591-633) joins the spawned workers and
frees the worker array, the contexts, the stats cells, the shared listener
and the stop flag, but never `s._per_worker_listener_addrs`. `Scheduler`
has no destructor, so once the `Error` propagates those listeners stay open
and bound for the life of the process: the port stays held and the kernel
keeps hashing connections to sockets nobody accepts on.

Spec clause: `start`'s docstring (:337-343) ("partially-started workers are
best-effort joined before re-raising"); a failed constructor leaves nothing
behind (`Lifecycle.H.empty`).

Status: resolved. The rollback now calls `_free_per_worker_listeners` (the
helper `_free_resources` uses); the shipped rollback is
`rollbackShipped`. The counterexamples are about the explicitly pre-fix
`rollbackPreFix`. Regression test:
tests/runtime/test_scheduler_start_rollback.mojo::
test_failed_start_releases_the_per_worker_listeners.

Fix: free and clear `_per_worker_listener_addrs` in the rollback, as
`_free_resources` does (`startFail true`). `fixed_rollback_clean` proves the
fixed rollback leaves nothing allocated, frees nothing twice, frees nothing
under a running worker and joins every spawned worker, for every worker
count, listener count and failing spawn index.
-/
namespace Flare.Bugs.CONC_06
open Flare.L5.Lifecycle

/-- Headline counterexample (pre-fix `rollbackPreFix`), general: for every
`n`, every listener count `L` and failing spawn `k`, the rollback leaves
every per-worker listener allocated. -/
theorem rollback_leaks_listeners (n L k i : Nat) (hi : i < L) :
    (startFail rollbackPreFix true n L k).cnt (.pwl i) = 1 :=
  impl_rollback_leaks n L k i hi

/-- The concrete run of the repro: two workers, two listeners, spawn 1
fails (worker 0 was spawned and is joined). -/
theorem repro_instance :
    (startFail rollbackPreFix true 2 2 1).cnt (.pwl 0) = 1 ∧
      (startFail rollbackPreFix true 2 2 1).cnt (.pwl 1) = 1 ∧
      (startFail rollbackPreFix true 2 2 1).thr = 0 :=
  ⟨impl_rollback_leaks 2 2 1 0 (by decide), impl_rollback_leaks 2 2 1 1 (by decide),
    by rw [startFail_eq]⟩

/-- Everything else is released correctly, already in flare. -/
theorem rollback_rest_ok (fix pre : Bool) (n L k : Nat) :
    (startFail fix pre n L k).thr = 0 ∧ (startFail fix pre n L k).dbl = false ∧
      (startFail fix pre n L k).uaf = false := by
  rw [startFail_eq]; exact ⟨rfl, rfl, rfl⟩

/-- Fix meets spec (the shipped rollback `rollbackShipped`). -/
theorem fixed_rollback_clean (pre : Bool) (n L k : Nat) :
    startFail rollbackShipped pre n L k = H.empty :=
  Flare.L5.Lifecycle.fixed_rollback_clean pre n L k

end Flare.Bugs.CONC_06
