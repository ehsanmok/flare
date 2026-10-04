import Flare.Core

/-!
# Single-worker `HttpServer.drain`

Model of `HttpServer.drain(timeout_ms)` (flare/http/server.mojo:1694-1755)
and of what the single-worker reactor does once the stop flag is set
(flare/http/_unified_reactor_impl.mojo:1103-1170 and 1000-1046).

`drain` closes the listener, sets `_stopping` and returns a
`ShutdownReport` with every count zero. There is no wait: the comment at
:1743-1752 says the wait is "capped at 1ms", but no sleep call follows
(`drain_ignores_timeout`, `drain_report_zero`). The zero counts are
documented (the "Returns" paragraph, :1712-1718, and
examples/intermediate/drain.mojo), so they are a documentation gap only.

The ignored timeout is a bug (APP-46). `serve` runs on another thread, and
the reactor re-reads the stop flag at least every 100 ms (the poll cap in
`_poll_timeout_ms`, flare/http/_reactor/lifecycle.mojo:31). On exit it
closes every live connection, whether or not its response is fully
written. So a response still in flight when `drain` is called gets at
most `pollCap` more milliseconds of writing, whatever `timeout_ms` is.
`close()` (:1680-1689) is documented as the hard stop that may cut
in-flight writes and points to `drain(timeout_ms)` for a graceful
tear-down; `drain` promises to wait up to `timeout_ms` for in-flight
events to flush (:1697-1701, :1729-1731).

The timed model: an in-flight response has `pending` bytes left and the
peer accepts `rate` bytes per millisecond. `stopDelay` is the time between
the `drain` call and the stop flag being set; the reactor sees the flag
`lag ≤ pollCap` ms later and closes the connection. Bytes delivered:
`min pending (rate * (stopDelay + lag))`. The multi-worker
`Scheduler.drain` (runtime/scheduler.mojo:778) belongs to L5.
-/
namespace Flare.L4.Drain

structure Report where
  drained : Nat
  timedOut : Nat
  inFlightAtDeadline : Nat
  crashed : Nat
deriving DecidableEq

structure Srv where
  listenerOpen : Bool
  stopping : Bool

/-- `HttpServer.drain`.
mirrors flare/http/server.mojo:1694-1755 @59bda50 -/
def drain (s : Srv) (_timeoutMs : Int) : Srv × Report :=
  ({ s with listenerOpen := false, stopping := true }, ⟨0, 0, 0, 0⟩)

theorem drain_ignores_timeout (s : Srv) (t1 t2 : Int) : drain s t1 = drain s t2 := rfl

theorem drain_report_zero (s : Srv) (t : Int) : (drain s t).2 = ⟨0, 0, 0, 0⟩ := rfl

theorem drain_stops (s : Srv) (t : Int) :
    (drain s t).1.listenerOpen = false ∧ (drain s t).1.stopping = true := ⟨rfl, rfl⟩

/-! ## Timed model -/

/-- The reactor re-reads the stop flag at least this often (ms).
mirrors flare/http/_reactor/lifecycle.mojo:31-48 @59bda50 -/
def pollCap : Nat := 100

/-- Bytes of an in-flight response delivered when the stop flag is set
`stopDelay` ms after the `drain` call and the reactor notices it `lag` ms
later, then closes every live connection.
mirrors flare/http/_unified_reactor_impl.mojo:1103-1170,1000-1046 @59bda50 -/
def delivered (stopDelay lag rate pending : Nat) : Nat :=
  min pending (rate * (stopDelay + lag))

/-- Delay between the `drain` call and `_stopping := True` in the current
code: none.
mirrors flare/http/server.mojo:1733-1755 @59bda50 -/
def stopDelay (_timeoutMs : Int) : Nat := 0

/-- Fix: after closing the listener, wait out `timeout_ms` (negative
clamps to 0) before setting `_stopping`. -/
def stopDelayFixed (timeoutMs : Int) : Nat := timeoutMs.toNat

/-- Graceful-drain contract: a response the peer can absorb within the
timeout is delivered in full, whatever the poll lag. -/
def GracefulSpec (delay : Int → Nat) : Prop :=
  ∀ (t : Int) (lag rate pending : Nat), lag ≤ pollCap →
    pending ≤ rate * t.toNat → delivered (delay t) lag rate pending = pending

theorem stopDelay_ignores_timeout (t1 t2 : Int) : stopDelay t1 = stopDelay t2 := rfl

/-- Current code: whatever the timeout, at most `rate * pollCap` more
bytes go out. -/
theorem delivered_le_pollCap (t : Int) (lag rate pending : Nat) (hl : lag ≤ pollCap) :
    delivered (stopDelay t) lag rate pending ≤ rate * pollCap := by
  unfold delivered stopDelay
  have : rate * (0 + lag) ≤ rate * pollCap := Nat.mul_le_mul_left _ (by omega)
  exact Nat.le_trans (Nat.min_le_right _ _) this

/-- `drain(0)` under the fix is the same as `close()`: the flag is set at once. -/
theorem fixed_zero_is_hard_stop (t : Int) (ht : t ≤ 0) : stopDelayFixed t = stopDelay t := by
  unfold stopDelayFixed stopDelay; omega

theorem fixed_graceful : GracefulSpec stopDelayFixed := by
  intro t lag rate pending _ hp
  unfold delivered stopDelayFixed
  have : rate * t.toNat ≤ rate * (t.toNat + lag) := Nat.mul_le_mul_left _ (by omega)
  exact Nat.min_eq_left (Nat.le_trans hp this)

/-- The fix never delivers less than the current code. -/
theorem fixed_ge (t : Int) (lag rate pending : Nat) :
    delivered (stopDelay t) lag rate pending ≤ delivered (stopDelayFixed t) lag rate pending := by
  unfold delivered stopDelay stopDelayFixed
  have : rate * (0 + lag) ≤ rate * (t.toNat + lag) := Nat.mul_le_mul_left _ (by omega)
  omega

end Flare.L4.Drain
