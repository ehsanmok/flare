import Flare.L2_Machine.Blocking

/-!
# RT-07: one fail-open acquire raises the blocking-pool cap permanently

flare/runtime/blocking.mojo:177-206 @59bda50.

Spec (comment at :116-122): at most `MAX_POOL_SIZE` (32) pool slots are
held at once, whatever transient errors occur.

What goes wrong: `_pool_try_acquire` returns `True` without decrementing
when `sem_open` fails (fail-open), but the paired `_pool_release` posts
whenever its own `sem_open` succeeds. One acquire made while `sem_open`
fails (e.g. EMFILE under fd exhaustion, the overload the cap exists for)
followed by a normal release leaves the semaphore at 33; the cap is
raised for the rest of the process, and each repetition raises it again.

On macOS this is masked by RT-06 (`sem_open` never succeeds there).

Repro: formal/repro/RT-07_pool_semaphore_fail_open_drift.mojo.
-/
namespace Flare.Bugs.RT_07
open Flare.L2.Blocking

/-- one failed-`sem_open` acquire, its normal release, then 33 normal
acquires -/
def trace : List Op := .acq false :: .rel true :: List.replicate 33 (.acq true)

/-- **Counterexample**: after the trace, 33 slots are held (cap 32). -/
theorem failOpen_breaks_cap : (run Sem.init trace).held = 33 ∧ MAX_POOL_SIZE < 33 := by
  native_decide

/-- **Fix meets spec**: with a fail-closed acquire, at most 32 slots are
held after any sequence of operations and any pattern of `sem_open`
failures. -/
theorem fixed_cap_invariant (ops : List Op) : (runFixed Sem.init ops).held ≤ MAX_POOL_SIZE :=
  fixed_cap_from_init ops

end Flare.Bugs.RT_07
