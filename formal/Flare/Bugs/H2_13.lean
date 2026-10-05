import Flare.Bugs.H2_Fixtures
import Flare.L3_Protocol.H2.StreamTable

/-!
# H2-13: client `send_data` sends on a CLOSED stream and reopens it

flare/http2/client.mojo:869-908 @59bda50 (`send_data`) has no CLOSED check:
after the server reset the stream (or the client cancelled it), an
end-of-stream call queues a DATA frame on the closed stream and moves the
state back to HALF_CLOSED_LOCAL. `finish_upload` (650-667) guards this
case; `send_data` is reached unguarded from `grpc/streaming.mojo:229,240`.

RFC 9113 §5.1 closed: "An endpoint MUST NOT send frames other than
PRIORITY on a closed stream." A closed stream never leaves "closed".

Status: resolved. `send_data` returns without sending when the stream is closed (it also drops any stashed body). `Fix.shipped` carries `h2_13`; `counterexample` and `bug` stay about `Fix.none` (the pre-fix code); `fixed_shipped` is the shipped behaviour.
-/
namespace Flare.Bugs.H2_13
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { isClient := true }

def tr : List Ev := [.frame settings0, .openLocal 1 false, .frame (rstF 1), .endLocal 1 true]

/-- Shipped: the stream was CLOSED by RST_STREAM and is HALF_CLOSED_LOCAL
after the local END_STREAM (the repro shows the DATA frame queued). -/
theorem bug : stateOf Fix.none init (tr.take 3) 1 = some .closed ∧
    stateOf Fix.none init tr 1 = some .hcl := by native_decide

theorem counterexample : stateOf Fix.none init tr 1 ≠ some .closed := by rw [bug.2]; simp

theorem fixed_trace : stateOf { h2_13 := true } init tr 1 = some .closed := by native_decide

/-- **Fixed**: a local END_STREAM leaves a closed stream untouched. -/
theorem fixed (fx : Fix) (c : Conn) (k : Nat) (s : Stream) (e : Bool) (hfx : fx.h2_13 = true)
    (hg : get c k = some s) (hs : s.state = .closed) : endLocal fx c k e = c := by
  simp [endLocal, hg, hs, hfx]

/-- Shipped (`Fix.shipped` has `h2_13`): the stream stays closed. -/
theorem fixed_shipped : stateOf Fix.shipped init tr 1 = some .closed := by native_decide

end Flare.Bugs.H2_13
