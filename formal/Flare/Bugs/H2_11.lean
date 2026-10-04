import Flare.Bugs.H2_Fixtures

/-!
# H2-11: SETTINGS_MAX_CONCURRENT_STREAMS = 0 means "unlimited"

flare/http2/state.mojo:1289-1298 @59bda50 refuses a new stream only when
`self.max_concurrent_streams > 0` and the active count reached it. A
server configured with a limit of 0 accepts every stream.

RFC 9113 §5.1.2: "Endpoints MUST NOT exceed the limit set by their peer.
An endpoint that receives a HEADERS frame that causes its advertised
concurrent stream limit to be exceeded MUST treat this as a stream error
(Section 5.4.2) of type PROTOCOL_ERROR or REFUSED_STREAM." §6.5.2: "A
value of 0 for SETTINGS_MAX_CONCURRENT_STREAMS SHOULD NOT be treated as
special by endpoints."
-/
namespace Flare.Bugs.H2_11
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { maxConcurrent := 0 }

def tr : List Ev := [.frame settings0, .frame (hdrs 1 true 1)]

theorem bug : lastOut Fix.none init tr = some [] ∧ stateOf Fix.none init tr 1 = some .hcr := by
  native_decide

/-- No RST_STREAM(REFUSED_STREAM / PROTOCOL_ERROR) for the stream over the limit. -/
theorem counterexample : ∀ o, lastOut Fix.none init tr = some o →
    Out.rst 1 eREFUSED ∉ o ∧ Out.rst 1 ePROTOCOL ∉ o := by
  intro o h; rw [bug.1] at h; cases h; simp

theorem fixed_trace : lastOut { h2_11 := true } init tr = some [.rst 1 eREFUSED] := by native_decide

/-- **Fixed** (drop the `> 0` conjunct): for every server state, a new
stream id that arrives with the active count at or above the limit
(any limit, 0 included) is refused. -/
theorem fixed (fx : Fix) (c : Conn) (f : Fr) (h11 : fx.h2_11 = true)
    (hs : c.isClient = false) (hm : mem c f.sid = false) (hge : c.maxConcurrent ≤ activeCount c) :
    headersRefuse fx c f 0 = eREFUSED :=
  refuse_at_limit fx c f h11 hs hm hge

end Flare.Bugs.H2_11
