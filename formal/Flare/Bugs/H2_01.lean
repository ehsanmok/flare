import Flare.Bugs.H2_Fixtures

/-!
# H2-01: the connection-level receive window is never enforced

flare/http2/state.mojo:1340-1512 @59bda50 (DATA branch) debits only the
*stream* receive window. The connection field `recv_window`
(state.mojo:446) is initialised to 65535 and never read. Server side,
connection credit is returned for every DATA frame until
`_MAX_BUFFERED_REQUEST_BYTES` (64 MiB) are buffered, and is then withheld
(1492-1511). A peer that ignores the withheld credit keeps sending, and
flare keeps buffering, past both the window and the cap.

RFC 9113 §6.9.1: "A receiver MUST treat the receipt of a frame that
exceeds the flow-control window as a connection error (Section 5.4.1) of
type FLOW_CONTROL_ERROR". `ConnWindowOK` is that rule as a monitor on the
input/reply trace (it tracks the window the peer was granted from the
WINDOW_UPDATE(0) frames flare actually emitted).

Status: resolved. `recv_window` is debited by every DATA payload
(connection error FLOW_CONTROL_ERROR when it would go negative) and
credited by every WINDOW_UPDATE(0) through `_conn_window_update`; the
counterexample below is about `Fix.none`, the code before the fix, and
`fixed_shipped` is the fix-meets-spec statement about `Fix.shipped`.

Trace `tr` (the repro's): SETTINGS, then 7 POST streams; streams 1..11
carry 640 DATA frames of 16384 octets, stream 13 carries 264. That is
4104 DATA frames. Without the fix nothing is refused: the peer's window
ends at -65537, `buffered` at 67239936 > 64 MiB, `withheld` at 131072,
exactly the numbers the repro prints.
-/
namespace Flare.Bugs.H2_01
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def tr : List Ev :=
  [.frame settings0] ++
  ((List.range 7).flatMap fun i =>
    .frame (hdrs (2 * i + 1) false 5) ::
      List.replicate (if i < 6 then 640 else 264) (.frame (dataF (2 * i + 1) 16384 false)))

/-- Final peer window, buffered octets, withheld credit, GOAWAY sent. -/
def summary (fx : Fix) : Option (Int × Nat × Nat × Bool) :=
  (run fx dec {} tr).map fun r => (peerW 65535 r.2, r.1.buffered, r.1.withheld, r.1.goawaySent)

theorem bug : summary Fix.none = some (-65537, 67239936, 131072, false) := by native_decide

theorem counterexample : ¬ ConnWindowOK (trace Fix.none {} tr) := by
  unfold ConnWindowOK; native_decide

theorem fixed_trace : ConnWindowOK (trace { h2_01 := true } {} tr) ∧
    (summary { h2_01 := true }).map (·.2.2.2) = some true := by
  unfold ConnWindowOK; exact ⟨by native_decide, by native_decide⟩

/-- **Fixed** (debit `recv_window` on DATA, connection error when it would
go negative, credit it with every WINDOW_UPDATE(0) emitted): every run
from a fresh connection, under any HPACK outcomes and any interleaving of
local actions, satisfies the §6.9.1 monitor. -/
theorem fixed (fx : Fix) (h1 : fx.h2_01 = true) (dec : Dec) (c : Conn) (hF : Fresh c)
    (es : List Ev) (c' : Conn) (t : List (Ev × List Out)) (hr : run fx dec c es = some (c', t)) :
    ConnWindowOK t :=
  h2_01_fixed fx h1 dec c hF es c' t hr

/-- The shipped model carries the H2-01 fix, so the shipped code meets
the §6.9.1 monitor on every run from a fresh connection. -/
theorem fixed_shipped (dec : Dec) (c : Conn) (hF : Fresh c)
    (es : List Ev) (c' : Conn) (t : List (Ev × List Out))
    (hr : run Fix.shipped dec c es = some (c', t)) : ConnWindowOK t :=
  fixed Fix.shipped rfl dec c hF es c' t hr

end Flare.Bugs.H2_01
