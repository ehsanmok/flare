import Flare.L5_Concurrency.SharedListener

/-!
# CONC-05: shared-listener teardown closes the fd number under live workers

In shared-listener mode (`FLARE_REUSEPORT_WORKERS=0`) every worker holds the
listener's bare fd number. `shutdown` and `drain` start with
`_signal_and_close_listener` (flare/runtime/scheduler.mojo:655-668 @59bda50),
which closes that number right after storing the stop flag, before any
worker has observed the flag or been joined. A worker already past its
`load_stop_flag` check (flare/http/_server_reactor_epoll.mojo:163) still
calls `_accept_loop_fd(listener_fd, ...)` for the listener event of the batch
it polled (:184-193); if the process reused the number meanwhile (any
`open`/`socket`/`accept` takes the lowest free number), that worker accepts
on, or registers, an unrelated file. A worker starting up registers the
number with `register_exclusive` (:155-156) and can hit the same window.
For `drain` with a detached worker the window is unbounded: the worker
keeps running after drain returned, and `_free_resources` (:713-724) also
frees the shared `TcpListener` under it.

Spec clause (`Flare.L5.SharedListener.NoStaleUse`): no worker uses the
number after it stopped naming the listener. Drain's docstring (:799-803)
promises that a detached worker's listeners "are left allocated, since the
thread may still be using them".

Fix (`cfgFixed`): no close in `_signal_and_close_listener`; close the number
once in `_free_resources`, after every worker was joined; when a worker was
detached, leak the shared listener (`self._shared_listener_addr = 0` in the
stuck-worker branch). Liveness does not need the early close: the poll
timeout is capped at 100 ms (`_reactor/lifecycle.mojo:31-47`), after which
the worker re-checks the flag (`SharedListener.stop_exits`).
-/
namespace Flare.Bugs.CONC_05
open Flare.L5.SharedListener

/-- `shutdown()` with one worker: the worker registers and passes its stop
check (it polled a listener event); shutdown stores the flag and closes the
number; the process opens an unrelated file, which gets the number; the
worker accepts on it. -/
def traceShutdown : List Lbl := [.w 0, .w 0, .m, .reuse, .w 0]

theorem traceShutdown_result :
    (exec cfgShutdown (init 1) traceShutdown).map (fun s => (s.stale, s.fd, s.stop)) =
      some (true, Fd.other, true) := by
  decide

/-- Headline counterexample (narrow window, `shutdown`): a reachable state
in which a worker used the listener's number after it named another file. -/
theorem shutdown_stale_accept :
    ∃ s, (lts cfgShutdown 1).Reachable s ∧ ¬ NoStaleUse s := by
  cases h : exec cfgShutdown (init 1) traceShutdown with
  | none => have := traceShutdown_result; rw [h] at this; cases this
  | some s =>
    have hr := traceShutdown_result
    rw [h] at hr
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hr
    exact ⟨s, reachable_of_exec _ _ _ _ h, fun hn => by rw [NoStaleUse, hr.1] at hn; cases hn⟩

/-- `drain` with one worker in a handler past the deadline: drain signals
and closes, detaches the worker, frees and returns; the number is reused;
the worker finishes its handler and accepts on the reused number. -/
def traceDrain : List Lbl := [.w 0, .w 0, .m, .m, .m, .m, .reuse, .w 0]

theorem traceDrain_result :
    (exec cfgDrain (init 1) traceDrain).map
      (fun s => (s.m, s.ws.map (·.detached), s.stale)) =
      some (MPc.fin, [true], true) := by
  decide

/-- Headline counterexample (long window, `drain`): drain has returned, the
worker was detached, and it then used the number while another file held it. -/
theorem drain_closes_live_listener :
    ∃ s, (lts cfgDrain 1).Reachable s ∧ s.m = .fin ∧ anyDet s = true ∧ ¬ NoStaleUse s := by
  cases h : exec cfgDrain (init 1) traceDrain with
  | none => have := traceDrain_result; rw [h] at this; cases this
  | some s =>
    have hr := traceDrain_result
    rw [h] at hr
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨e1, e2, e3⟩ := hr
    refine ⟨s, reachable_of_exec _ _ _ _ h, e1, ?_, fun hn => by rw [NoStaleUse, e3] at hn; cases hn⟩
    have hm : true ∈ s.ws.map (·.detached) := by rw [e2]; simp
    obtain ⟨w, hw, hwd⟩ := List.mem_map.mp hm
    simp only [anyDet, List.any_eq_true]
    exact ⟨w, hw, hwd⟩

/-- The fix suffices, for `shutdown` and `drain`, any number of workers and
every interleaving with unrelated fd allocations. -/
theorem implFixed_safe (hard : Bool) (n : Nat) :
    ∀ s, (lts (cfgFixed hard) n).Reachable s → NoStaleUse s :=
  fun s h => fixed_noStale hard n s h

/-- …and it does not leak the listener when every worker was joined. -/
theorem implFixed_noLeak (hard : Bool) (n : Nat) :
    ∀ s, (lts (cfgFixed hard) n).Reachable s → ClosedAtEnd s :=
  fun s h => fixed_closedAtEnd hard n s h

end Flare.Bugs.CONC_05
