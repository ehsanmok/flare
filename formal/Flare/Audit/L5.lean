import Flare.L5_Concurrency
/-! L5 concurrency: axiom footprint of the headline theorems. Expected:
`propext`, `Quot.sound`, `Classical.choice`. -/

-- Watchdog
#print axioms Flare.L5.Watchdog.inv_inductive
#print axioms Flare.L5.Watchdog.shipped_safe
-- AsyncRT task cell
#print axioms Flare.L5.AsyncRT.inv_inductive
#print axioms Flare.L5.AsyncRT.free_at_most_once
#print axioms Flare.L5.AsyncRT.no_use_after_free
#print axioms Flare.L5.AsyncRT.chain_before_free
#print axioms Flare.L5.AsyncRT.join_returns_after_done
#print axioms Flare.L5.AsyncRT.freed_exactly_once
#print axioms Flare.L5.AsyncRT.progress
#print axioms Flare.L5.AsyncRT.calls_after_zero_are_noops
#print axioms Flare.L5.AsyncRT.step_iff_stepFn
#print axioms Flare.L5.AsyncRT.ar1_load_bearing
#print axioms Flare.L5.AsyncRT.guard_load_bearing
-- ThreadHandle
#print axioms Flare.L5.Thread.inv_inductive
#print axioms Flare.L5.Thread.at_most_one_effect
#print axioms Flare.L5.Thread.no_posix_ub
#print axioms Flare.L5.Thread.zeroed_noop
#print axioms Flare.L5.Thread.alias_double_join
#print axioms Flare.L5.Thread.pin_after_join_hazard
-- Scheduler lifecycle
#print axioms Flare.L5.Scheduler.core_inductive
#print axioms Flare.L5.Scheduler.coreSI_inductive
#print axioms Flare.L5.Scheduler.safe_of_cfg
#print axioms Flare.L5.Scheduler.noLeak_of_cfg
#print axioms Flare.L5.Scheduler.detached_sees_stop
#print axioms Flare.L5.Scheduler.soft_join_bounded
#print axioms Flare.L5.Scheduler.shutdown_safe
#print axioms Flare.L5.Scheduler.drain_safe
#print axioms Flare.L5.Scheduler.check_sound
#print axioms Flare.L5.Scheduler.bounded_drain
#print axioms Flare.L5.Scheduler.bounded_shutdown
-- CONC-01
-- CONC-02
-- CONC-03
-- CONC-04
-- Shared-listener mode
#print axioms Flare.L5.SharedListener.inv_inductive
#print axioms Flare.L5.SharedListener.noStale
#print axioms Flare.L5.SharedListener.closedAtEnd
#print axioms Flare.L5.SharedListener.stop_exits
-- Lifecycle: start rollback, stuck-branch indices, pthread return codes
#print axioms Flare.L5.Lifecycle.rollback_clean
#print axioms Flare.L5.Lifecycle.abandon_clean
#print axioms Flare.L5.Lifecycle.popStuck_keeps_joined
#print axioms Flare.L5.Lifecycle.freed_iff_not_detached
#print axioms Flare.L5.Lifecycle.live_handle_calls
#print axioms Flare.L5.Lifecycle.impl_freed_under_live_iff
#print axioms Flare.L5.Lifecycle.impl_safe_of_external_caller
#print axioms Flare.L5.Lifecycle.self_shutdown_frees_caller
#print axioms Flare.L5.Lifecycle.self_drain_keeps_caller
#print axioms Flare.L5.Lifecycle.fixed_never_frees_live
-- CONC-05
-- CONC-06
-- Timed teardown (clock, poll cap, fairness)
#print axioms Flare.L5.Timed.pollTimeout_le_cap
#print axioms Flare.L5.Timed.pollTimeout_pos
#print axioms Flare.L5.Timed.J_inductive
#print axioms Flare.L5.Timed.worker_done_by
#print axioms Flare.L5.Timed.teardown_done_by
#print axioms Flare.L5.Timed.drain_joins_all
#print axioms Flare.L5.Timed.bound_epoll
#print axioms Flare.L5.Timed.bound_tight
-- io_uring worker and the shared listener
#print axioms Flare.L5.UringShared.uring_never_shared
#print axioms Flare.L5.UringShared.probe_skew_shared
#print axioms Flare.L5.UringShared.sim_step
#print axioms Flare.L5.UringShared.sim_reachable
#print axioms Flare.L5.UringShared.uring_fixed_noStale
#print axioms Flare.L5.UringShared.uring_fixed_closedAtEnd
-- CONC-07
