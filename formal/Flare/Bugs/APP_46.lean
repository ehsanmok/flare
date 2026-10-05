import Flare.L4_App.Drain

/-!
# APP-46: single-worker `drain(timeout_ms)` is a hard stop

flare/http/server.mojo:1694-1755 @59bda50. `drain` closes the listener and
sets `_stopping` at once; `timeout_ms` is never read. The reactor loop on
the serving thread sees the flag within one poll (at most 100 ms) and
closes every live connection (flare/http/_unified_reactor_impl.mojo:
1000-1046), so a response still being written is cut, exactly as with
`close()`, which its docstring calls the hard stop and for which it
recommends `drain(timeout_ms)` as the graceful alternative.

Status: resolved. `drain` now closes the listener, waits out `timeout_ms`
(1 ms sleeps against the monotonic clock), then sets `_stopping`; the
shipped delay is `stopDelayFixed`. The counterexample is about the pre-fix
`stopDelay`.

Repro: formal/repro/APP-46_drain_is_hard_stop.mojo.
-/
namespace Flare.Bugs.APP_46

open Flare.L4.Drain

/-- Counterexample about the pre-fix `stopDelay`: 1000 bytes pending, peer takes 1 byte/ms, 5000 ms
timeout, the reactor notices the flag after the full 100 ms poll cap. -/
theorem cut_example : delivered (stopDelay 5000) 100 1 1000 = 100 := by native_decide

theorem violates_spec : ¬ GracefulSpec stopDelay := by
  intro h
  have := h 5000 100 1 1000 (by decide) (by decide)
  rw [cut_example] at this
  exact absurd this (by decide)

/-- Fix meets spec: the shipped delay `stopDelayFixed`. -/
theorem fixed_meets_spec : GracefulSpec stopDelayFixed := fixed_graceful

theorem fixed_on_example : delivered (stopDelayFixed 5000) 100 1 1000 = 1000 := by native_decide

end Flare.Bugs.APP_46
