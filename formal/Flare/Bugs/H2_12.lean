import Flare.Bugs.H2_Fixtures
import Flare.L3_Protocol.H2.StreamTable

/-!
# H2-12: client END_STREAM on a HALF_CLOSED_REMOTE stream leaves it HALF_CLOSED_LOCAL

flare/http2/client.mojo:584 @59bda50 (`_emit_body_span`, last chunk) sets
`HALF_CLOSED_LOCAL` whatever the state; only the empty-DATA path
(client.mojo:885-901) moves HALF_CLOSED_REMOTE to CLOSED. After the server
finished its response (END_STREAM) and the client then sends its last body
chunk, the stream is HALF_CLOSED_LOCAL instead of CLOSED, so a further
server DATA frame is accepted and credited instead of drawing
STREAM_CLOSED.

RFC 9113 §5.1: "half-closed (remote) [...] If an endpoint [...] sends a
frame with the END_STREAM flag set [...] the stream transitions to
'closed'." §5.1 closed: "An endpoint that receives any frame other than
PRIORITY after receiving a RST_STREAM MUST treat that as a stream error
[...] STREAM_CLOSED"; half-closed (remote) / closed after END_STREAM:
DATA "MUST respond with a stream error (Section 5.4.2) of type
STREAM_CLOSED" — flare's handler escalates that to a connection error.

Status: resolved. `_emit_body_span` now closes a HALF_CLOSED_REMOTE stream on the last chunk's END_STREAM, as the empty-body path does. `Fix.shipped` carries `h2_12`; `counterexample` and `bug` stay about `Fix.none` (the pre-fix code); `fixed_shipped` is the shipped behaviour.
-/
namespace Flare.Bugs.H2_12
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { isClient := true }

def tr : List Ev :=
  [.frame settings0, .openLocal 1 false, .frame (hdrs 1 true 4), .endLocal 1 false,
   .frame (dataF 1 1 true)]

/-- Shipped: after the client's END_STREAM the stream is HALF_CLOSED_LOCAL,
and the late DATA is accepted and credited back. -/
theorem bug : stateOf Fix.none init (tr.take 4) 1 = some .hcl ∧
    lastOut Fix.none init tr = some [.wu 1 1, .wu 0 1] := by native_decide

theorem counterexample :
    stateOf Fix.none init (tr.take 4) 1 ≠ some .closed ∧
    ∀ o, lastOut Fix.none init tr = some o → ¬ IsConnError o eSTREAM_CLOSED := by
  refine ⟨by rw [bug.1]; simp, ?_⟩
  intro o h; rw [bug.2] at h; cases h; rintro ⟨_, h⟩; simp at h

theorem fixed_trace : stateOf { h2_12 := true } init (tr.take 4) 1 = some .closed ∧
    lastOut { h2_12 := true } init tr = some [.goaway 0 eSTREAM_CLOSED] := by native_decide

/-- **Fixed**: the client's END_STREAM on a HALF_CLOSED_REMOTE stream closes it,
on either send path. -/
theorem fixed (fx : Fix) (c : Conn) (k : Nat) (s : Stream) (e : Bool) (hfx : fx.h2_12 = true)
    (hg : get c k = some s) (hs : s.state = .hcr) :
    get (endLocal fx c k e) k = some { s with state := .closed } := by
  simp [endLocal, hg, hs, hfx]

/-- Shipped (`Fix.shipped` has `h2_12`): the stream is closed and the late
DATA is a STREAM_CLOSED connection error. -/
theorem fixed_shipped : stateOf Fix.shipped init (tr.take 4) 1 = some .closed ∧
    lastOut Fix.shipped init tr = some [.goaway 0 eSTREAM_CLOSED] := by native_decide

end Flare.Bugs.H2_12
