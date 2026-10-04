import Flare.L2_Machine.UringWakeup

/-!
# RT-03: UringReactor.poll can block with no wakeup read armed

flare/runtime/uring_reactor.mojo:739-846,926-946 @59bda50.

Spec (`wakeup` / `poll` docstrings): a cross-thread `wakeup()` releases a
blocked `poll`; so whenever `poll` blocks in phase 3
(`submit_and_wait(need)`) the eventfd read that turns the wakeup into a
CQE must be armed.

What goes wrong: `poll` arms the read lazily before phase 1. If the SQ is
full, `_arm_wakeup_recv` raises, the exception is swallowed (:799-804) and
`_wake_armed` stays false. Phase 1 flushes the SQ but nothing retries the
arm, so phase 3 can block with no read on the eventfd and a `wakeup()` is
not seen until some unrelated completion arrives.

Repro: formal/repro/RT-03_uring_poll_blocks_unarmed.mojo (PLATFORM linux;
not run here, the host is macOS).
-/
namespace Flare.Bugs.RT_03
open Flare.L2.UringWakeup

/-- SQ (8 entries) full of committed SQEs, wakeup enabled but not armed, and a
wakeup already signalled (`ev = 1`). -/
def sqFull : W := ⟨true, false, 8, 8, false, false, 1, []⟩

theorem sqFull_inv : Inv sqFull := by intro h; cases h

/-- Counterexample: `poll(1)` blocks in phase 3 with no read on the eventfd,
although the invariant holds and a wakeup is pending. -/
theorem poll_blocks_unarmed :
    ¬ NeverBlocksUnarmed (poll false sqFull 1 64) sqFull := by
  intro h; have := h rfl (by decide); revert this; decide

/-- The same state under the fixed poll: armed when it blocks. -/
theorem pollFixed_on_sqFull : (poll true sqFull 1 64).blocked = true ∧
    (poll true sqFull 1 64).armedAtBlock = true := by decide

/-- The fix meets the liveness spec from every invariant state. -/
theorem pollFixed_never_blocks_unarmed (s : W) (mn mx : Nat) (h : Inv s) (hcap : 0 < s.cap) :
    NeverBlocksUnarmed (poll true s mn mx) s :=
  Flare.L2.UringWakeup.pollFixed_never_blocks_unarmed s mn mx h hcap

end Flare.Bugs.RT_03
