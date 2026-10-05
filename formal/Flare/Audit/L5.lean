import Flare.L5_Concurrency
/-! L5 concurrency: axiom footprint of the headline theorems. Expected:
`propext`, `Quot.sound`, `Classical.choice`; the two `bounded_*` theorems
in `Flare.Bugs.CONC_03` use `native_decide`, which Lean 4.33 reports as a
per-theorem auxiliary axiom `<thm>._native.native_decide.ax_1_1`. -/

-- Watchdog
#print axioms Flare.L5.Watchdog.inv_inductive
#print axioms Flare.L5.Watchdog.safe_of_cfg
#print axioms Flare.L5.Watchdog.impl_safe
#print axioms Flare.L5.Watchdog.fixed_safe
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
#print axioms Flare.L5.Scheduler.fixed_safe
#print axioms Flare.L5.Scheduler.check_sound
#print axioms Flare.L5.Scheduler.bounded_fixed
#print axioms Flare.L5.Scheduler.bounded_shutdown
#print axioms Flare.L5.Scheduler.bounded_impl_fails
-- CONC-01
#print axioms Flare.Bugs.CONC_01.arm_firing_sentinel
#print axioms Flare.Bugs.CONC_01.stuck_closed
#print axioms Flare.Bugs.CONC_01.implFixed_safe
#print axioms Flare.Bugs.CONC_01.clampOnly_safe
-- CONC-02
#print axioms Flare.Bugs.CONC_02.rearm_hits_new_cell
#print axioms Flare.Bugs.CONC_02.rearm_disarm_wrong
#print axioms Flare.Bugs.CONC_02.disarmFirst_safe
#print axioms Flare.Bugs.CONC_02.implFixed_safe
-- CONC-03
#print axioms Flare.Bugs.CONC_03.drain_frees_live_ref
#print axioms Flare.Bugs.CONC_03.drain_uaf
#print axioms Flare.Bugs.CONC_03.implFixed_safe
#print axioms Flare.Bugs.CONC_03.implFixed_detached_sees_stop
#print axioms Flare.Bugs.CONC_03.bounded_fixed_3
#print axioms Flare.Bugs.CONC_03.bounded_impl_2_fails
-- CONC-04
#print axioms Flare.Bugs.CONC_04.drain_leaks_joined_listener
#print axioms Flare.Bugs.CONC_04.implFixed_noLeak
#print axioms Flare.Bugs.CONC_04.fixLis_alone_noLeak
#print axioms Flare.Bugs.CONC_04.implFixed_full
-- Shared-listener mode
#print axioms Flare.L5.SharedListener.inv_inductive
#print axioms Flare.L5.SharedListener.fixed_noStale
#print axioms Flare.L5.SharedListener.fixed_closedAtEnd
#print axioms Flare.L5.SharedListener.stop_exits
-- Lifecycle: start rollback, stuck-branch indices, pthread return codes
#print axioms Flare.L5.Lifecycle.startFail_eq
#print axioms Flare.L5.Lifecycle.impl_rollback_leaks
#print axioms Flare.L5.Lifecycle.fixed_rollback_clean
#print axioms Flare.L5.Lifecycle.impl_rollback_clean_shared
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
#print axioms Flare.Bugs.CONC_05.shutdown_stale_accept
#print axioms Flare.Bugs.CONC_05.drain_closes_live_listener
#print axioms Flare.Bugs.CONC_05.implFixed_safe
#print axioms Flare.Bugs.CONC_05.implFixed_noLeak
-- CONC-06
#print axioms Flare.Bugs.CONC_06.rollback_leaks_listeners
#print axioms Flare.Bugs.CONC_06.repro_instance
#print axioms Flare.Bugs.CONC_06.rollback_rest_ok
#print axioms Flare.Bugs.CONC_06.fixed_rollback_clean
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
#print axioms Flare.L5.UringShared.uring_trace_shutdown_safe
#print axioms Flare.L5.UringShared.uring_late_arm_stale
-- CONC-07
#print axioms Flare.Bugs.CONC_07.shutdown_never_returns
#print axioms Flare.Bugs.CONC_07.not_pollReturns
#print axioms Flare.Bugs.CONC_07.drain_detaches_idle
#print axioms Flare.Bugs.CONC_07.fixed_meets_spec
