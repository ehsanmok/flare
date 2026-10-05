import Flare.Bugs.H2_Fixtures

/-!
# H2-09: credit for discarded DATA is never returned to the connection window

flare/http2/state.mojo:1374-1383 (stream window overrun) and 1457-1470
(content-length mismatch at END_STREAM) @59bda50 reset the stream and
return without a WINDOW_UPDATE on stream 0. The other reset paths in the
DATA branch (1384-1447) do send it. Each such reset permanently shrinks
the connection window the peer sees by the frame's length, and four
16 KiB requests with a wrong content-length close it for good.

RFC 9113 §6.9: flow control counts every DATA frame against the
connection window whether or not it is processed; a receiver that
discards a frame still consumed its window and has to give that credit
back, or the sender stalls (§6.9.1: "the receiver MUST ... account for
its contribution against the connection flow-control window"). As a
requirement on replies (`h2_09_fixed`): while no GOAWAY has been sent,
the peer's view of the connection window plus the credit flare
deliberately withholds equals the initial 65535.

Status: resolved. Both reset paths (stream-window overrun and
content-length mismatch at END_STREAM) now append WINDOW_UPDATE(0, len)
through `_conn_window_update`. The counterexample is about `Fix.none`
(the code before the fix); `fixed_shipped` is about `Fix.shipped`.

Trace: SETTINGS, then four POST requests with `content-length: 100000`,
each with one END_STREAM DATA frame (16384, 16384, 16384, 16383 octets),
65535 octets in total.
-/
namespace Flare.Bugs.H2_09
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def tr : List Ev :=
  [.frame settings0, .frame (hdrs 1 false 3), .frame (dataF 1 16384 true),
   .frame (hdrs 3 false 3), .frame (dataF 3 16384 true), .frame (hdrs 5 false 3),
   .frame (dataF 5 16384 true), .frame (hdrs 7 false 3), .frame (dataF 7 16383 true)]

/-- Any GOAWAY emitted, and the peer's window plus withheld credit. -/
def credit (fx : Fix) : Option (Bool × Int) :=
  (run fx dec {} tr).map fun r => (r.2.any (fun p => hasGoaway p.2), peerW 65535 r.2 + r.1.withheld)

theorem bug : outs Fix.none {} tr =
    some [[.settingsAck], [], [.rst 1 ePROTOCOL], [], [.rst 3 ePROTOCOL], [], [.rst 5 ePROTOCOL], [],
      [.rst 7 ePROTOCOL]] ∧
    credit Fix.none = some (false, 0) := by native_decide

theorem counterexample : ∃ c' t, run Fix.none dec {} tr = some (c', t) ∧
    t.any (fun p => hasGoaway p.2) = false ∧ peerW 65535 t + c'.withheld ≠ 65535 := by
  have hs : (run Fix.none dec {} tr).isSome = true := by native_decide
  obtain ⟨⟨c', t⟩, hr⟩ := Option.isSome_iff_exists.mp hs
  have hc := bug.2
  simp only [credit, hr, Option.map_some, Option.some.injEq, Prod.mk.injEq] at hc
  exact ⟨c', t, hr, hc.1, by omega⟩

theorem fixed_trace : credit { h2_01 := true, h2_09 := true } = some (false, 65535) := by
  native_decide

/-- **Fixed** (WINDOW_UPDATE(0, len) on both reset paths; stated with
the H2-01 fix, which makes `recvW` the window the peer sees): every run
from a fresh connection conserves connection credit until a GOAWAY. -/
theorem fixed (fx : Fix) (h1 : fx.h2_01 = true) (h9 : fx.h2_09 = true) (dec : Dec) (c : Conn)
    (hF : Fresh c) (es : List Ev) (c' : Conn) (t : List (Ev × List Out))
    (hr : run fx dec c es = some (c', t)) (hno : t.any (fun p => hasGoaway p.2) = false) :
    peerW 65535 t + c'.withheld = 65535 :=
  h2_09_fixed fx h1 h9 dec c hF es c' t hr hno

/-- The shipped model (H2-01 and H2-09 fixes): connection credit is
conserved on every run from a fresh connection until a GOAWAY. -/
theorem fixed_shipped (dec : Dec) (c : Conn) (hF : Fresh c) (es : List Ev) (c' : Conn)
    (t : List (Ev × List Out)) (hr : run Fix.shipped dec c es = some (c', t))
    (hno : t.any (fun p => hasGoaway p.2) = false) : peerW 65535 t + c'.withheld = 65535 :=
  fixed Fix.shipped rfl rfl dec c hF es c' t hr hno

theorem shipped_trace : credit Fix.shipped = some (false, 65535) := by native_decide

end Flare.Bugs.H2_09
