import Flare.Bugs.H2_Fixtures
import Flare.L3_Protocol.H2.StreamTable

/-!
# H2-14: client accepts HEADERS on a HALF_CLOSED_REMOTE stream

flare/http2/state.mojo:1275-1281 @59bda50 refuses HEADERS on a
HALF_CLOSED_REMOTE stream only in server role (`not self.is_client and`).
After the server ended its response with END_STREAM, a client accepts a
further HEADERS block on the same stream and appends its fields to the
response.

RFC 9113 §5.1 half-closed (remote): "If an endpoint receives additional
frames, other than WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream
that is in this state, it MUST respond with a stream error (Section
5.4.2) of type STREAM_CLOSED."
-/
namespace Flare.Bugs.H2_14
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { isClient := true }

def tr : List Ev :=
  [.frame settings0, .openLocal 1 false, .frame (hdrs 1 true 4), .frame (hdrs 1 true 7)]

theorem bug : outs Fix.none init tr = some [[.settingsAck], [], [], []] ∧
    stateOf Fix.none init tr 1 = some .hcr := by native_decide

theorem counterexample :
    ∀ o, lastOut Fix.none init tr = some o → ¬ IsConnError o eSTREAM_CLOSED := by
  intro o h
  have : lastOut Fix.none init tr = some [] := by native_decide
  rw [this] at h; cases h; exact not_connError_nil _

theorem fixed_trace : lastOut { h2_14 := true } init tr = some [.goaway 0 eSTREAM_CLOSED] := by
  native_decide

/-- **Fixed**: in either role, HEADERS on a HALF_CLOSED_REMOTE stream is
refused with STREAM_CLOSED before anything else is looked at. -/
theorem fixed (fx : Fix) (c : Conn) (f : Fr) (s : Stream) (hfx : fx.h2_14 = true)
    (hg : get c f.sid = some s) (hs : s.state = .hcr) :
    headersPre fx c f = .inl (connErr c eSTREAM_CLOSED) := by
  simp [headersPre, hg, hs, hfx]

end Flare.Bugs.H2_14
