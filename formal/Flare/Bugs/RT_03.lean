import Flare.L2_Machine.UringWakeup

/-!
# RT-03: UringReactor.poll can block with no wakeup read armed

flare/runtime/uring_reactor.mojo `poll` (pre-fix lines 739-846,926-946).

Status: resolved. `poll` now calls `_try_arm_wakeup()` a second time right
after phase 1 (the SQ is empty there), so phase 3 never blocks with no read
on the eventfd (test_uring_reactor.mojo::test_wakeup_rearmed_after_full_sq_flushed).
The counterexample below is about the pre-fix definition `pollOld`.

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
now prints OK in the Linux container).
-/
namespace Flare.Bugs.RT_03
open Flare.L2.UringWakeup

/-- SQ (8 entries) full of committed SQEs, wakeup enabled but not armed, and a
wakeup already signalled (`ev = 1`). -/
def sqFull : W := ⟨true, false, 8, 8, false, false, 1, []⟩

theorem sqFull_inv : Inv sqFull := by intro h; cases h

/-- Counterexample (pre-fix `pollOld`): `poll(1)` blocks in phase 3 with no read
on the eventfd, although the invariant holds and a wakeup is pending. -/
theorem poll_blocks_unarmed :
    ¬ NeverBlocksUnarmed (pollOld sqFull 1 64) sqFull := by
  intro h; have := h rfl (by decide); revert this; unfold pollOld pollWith; decide

/-- The same state under the shipped poll: armed when it blocks. -/
theorem poll_on_sqFull : (poll sqFull 1 64).blocked = true ∧
    (poll sqFull 1 64).armedAtBlock = true := by
  unfold poll pollWith; decide

/-- The shipped `poll` meets the liveness spec from every invariant state. -/
theorem poll_never_blocks_unarmed (s : W) (mn mx : Nat) (h : Inv s) (hcap : 0 < s.cap) :
    NeverBlocksUnarmed (poll s mn mx) s :=
  Flare.L2.UringWakeup.poll_never_blocks_unarmed s mn mx h hcap

end Flare.Bugs.RT_03
