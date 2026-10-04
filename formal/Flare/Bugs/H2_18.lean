import Flare.Bugs.H2_Fixtures

/-!
# H2-18: client raises on an oversized frame instead of FRAME_SIZE_ERROR

flare/http2/client.mojo:404-414 @59bda50 raises
`Error("h2 client: frame exceeds advertised maximum size")` from `feed`
when a frame header declares more than the advertised
SETTINGS_MAX_FRAME_SIZE. The error propagates to the caller; no GOAWAY is
queued (same class as H2-06).

RFC 9113 §4.2: "An endpoint MUST send an error code of FRAME_SIZE_ERROR if
a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE [...]"; a
frame that could alter the connection state "MUST be treated as a
connection error (Section 5.4.1)".
-/
namespace Flare.Bugs.H2_18
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { isClient := true }

def big : Fr := { ty := tDATA, sid := 1, plen := 16385 }

def tr : List Ev := [.frame settings0, .openLocal 1 true, .frame big]

/-- The run raises (`none`): no reply, no GOAWAY. -/
theorem bug : outs Fix.none init tr = none := by native_decide

theorem fixed_trace : lastOut { h2_18 := true } init tr = some [.goaway 0 eFRAME_SIZE] := by
  native_decide

/-- **Fixed**: in client role an oversized frame is GOAWAY(FRAME_SIZE_ERROR). -/
theorem fixed (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (hfx : fx.h2_18 = true)
    (hc : c.isClient = true) (hl : f.plen > c.localMaxFrame) :
    step fx dec c (.frame f) = .ok (connErr c eFRAME_SIZE) := by
  simp [step, hc, driveClient, hl, hfx]

/-- Without the fix the step raises. -/
theorem shipped_raises (dec : Dec) (c : Conn) (f : Fr) (hc : c.isClient = true)
    (hl : f.plen > c.localMaxFrame) :
    step Fix.none dec c (.frame f) = .error "h2 client: frame exceeds advertised maximum size" := by
  simp [step, hc, driveClient, hl, Fix.none]

end Flare.Bugs.H2_18
