import Flare.Core

/-!
# Single-worker `HttpServer.drain`

Model of `HttpServer.drain(timeout_ms)` (flare/http/server.mojo:1697-1760)
and of what the single-worker reactor does once the stop flag is set
(flare/http/_unified_reactor_impl.mojo:1103-1170 and 1000-1046).

`drain` closes the listener, then waits out `timeout_ms` before setting
`_stopping` (APP-46). `serve` runs on another thread, and
the reactor re-reads the stop flag at least every 100 ms (the poll cap in
`_poll_timeout_ms`, flare/http/_reactor/lifecycle.mojo:31). On exit it
closes every live connection, whether or not its response is fully
written. So once the flag is set, a response still in flight gets at most `pollCap`
more milliseconds of writing.
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

/-! ## Timed model -/

/-- The reactor re-reads the stop flag at least this often (ms).
mirrors flare/http/_reactor/lifecycle.mojo#_poll_timeout_ms sha=daa578780fe3 at=59bda50f -/
def pollCap : Nat := 100

/-- Bytes of an in-flight response delivered when the stop flag is set
`stopDelay` ms after the `drain` call and the reactor notices it `lag` ms
later, then closes every live connection.
mirrors flare/http/_unified_reactor_impl.mojo#_run_unified_loop_for_fd+_drain_remaining_conns_unified sha=5270acd9b3ff at=59bda50f -/
def delivered (stopDelay lag rate pending : Nat) : Nat :=
  min pending (rate * (stopDelay + lag))

/-- After closing the listener, `drain` waits out `timeout_ms`
(negative clamps to 0) before setting `_stopping`.
mirrors flare/http/server.mojo#HttpServer.drain sha=387b49a4a202 at=2348b24b (fixed, APP-46) -/
def stopDelay (timeoutMs : Int) : Nat := timeoutMs.toNat

/-- Graceful-drain contract: a response the peer can absorb within the
timeout is delivered in full, whatever the poll lag. -/
def GracefulSpec (delay : Int → Nat) : Prop :=
  ∀ (t : Int) (lag rate pending : Nat), lag ≤ pollCap →
    pending ≤ rate * t.toNat → delivered (delay t) lag rate pending = pending

/-- `drain(0)` is the same as `close()`: the flag is set at once. -/
theorem stopDelay_nonpos (t : Int) (ht : t ≤ 0) : stopDelay t = 0 := by
  unfold stopDelay; omega

theorem graceful : GracefulSpec stopDelay := by
  intro t lag rate pending _ hp
  unfold delivered stopDelay
  have : rate * t.toNat ≤ rate * (t.toNat + lag) := Nat.mul_le_mul_left _ (by omega)
  exact Nat.min_eq_left (Nat.le_trans hp this)

end Flare.L4.Drain
