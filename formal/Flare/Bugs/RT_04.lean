import Flare.L2_Machine.Handoff

/-!
# RT-04: `peek_idle_worker` returns a peer whose queue is full

flare/runtime/handoff.mojo `peek_idle_worker` (pre-fix lines 312-334).

Status: resolved. The scan now starts at `best_size = capacity`, so only peers
strictly below capacity qualify (tests: tests/runtime/test_handoff.mojo::
test_peek_idle_skips_peer_whose_queue_is_full, ::test_peek_idle_prefers_non_full_peer_over_full_one,
::test_choose_target_never_picks_full_peer). The counterexample below is about
the pre-fix `peekIdleOld`.

Spec (`peek_idle_worker` docstring): "Returns -1 when the policy is
disabled or no peer queue is below capacity"; a returned peer therefore
has a queue strictly below capacity.

What goes wrong: the scan starts from `best_size = capacity + 1` and keeps
any peer with `size < best_size`, so a peer holding exactly `capacity`
tokens qualifies. `choose_handoff_target` (:336-365) can then pick it and
the following `try_handoff` fails; the caller falls back to the local
accept path, so the cost is a wasted handoff attempt.

Repro: formal/repro/RT-04_handoff_peek_returns_full_peer.mojo (now prints OK).
-/
namespace Flare.Bugs.RT_04
open Flare.L2.Handoff

/-- **Counterexample** (pre-fix `peekIdleOld`): two workers, capacity 1, worker 1's queue full
(size 1), called from worker 0: worker 1 is returned. -/
theorem peek_returns_full_peer :
    peekIdleOld true 1 [0, 1] 0 = 1 ∧ ¬ ((1 : Nat) < 1) := by decide

/-- **Shipped code meets spec**: starting from `best_size = capacity`, the result is
-1 or a peer other than the caller with a queue strictly below capacity,
and -1 (handoff enabled, ≥ 2 workers) only when every peer queue is full. -/
theorem peek_below_capacity (cap : Nat) (sizes : List Nat) (excl : Int) (en : Bool) :
    let r := peekIdle en cap sizes excl
    (r = -1 ∨ ∃ k, ∃ hk : k < sizes.length, r = k ∧ (k : Int) ≠ excl ∧ sizes[k] < cap) ∧
    (en = true → 2 ≤ sizes.length → r = -1 →
      ∀ k (hk : k < sizes.length), (k : Int) ≠ excl → cap ≤ sizes[k]) :=
  Flare.L2.Handoff.peek_below_capacity cap sizes excl en

end Flare.Bugs.RT_04
