import Flare.Bugs.H2_Fixtures

/-!
# H2-02: a refused stream id can be reused to open a new request

flare/http2/state.mojo:1123 @59bda50 rejects a HEADERS frame whose id is
*below* `last_peer_stream_id` and not in the table (`sid < last`), but
not one *equal* to it. A stream refused with RST_STREAM(REFUSED_STREAM)
is not kept in the table, so a second HEADERS with the same id is
accepted and opens a new request.

RFC 9113 §5.1.1: "The identifier of a newly established stream MUST be
numerically greater than all streams that the initiating endpoint has
opened or reserved. [...] An endpoint that receives an unexpected stream
identifier MUST respond with a connection error (Section 5.4.1) of type
PROTOCOL_ERROR."

Trace (`max_concurrent_streams = 1`): SETTINGS; HEADERS(1) without
END_STREAM; HEADERS(3, END_STREAM) is refused (`RST_STREAM(3,
REFUSED_STREAM)`); RST_STREAM(1); HEADERS(3, END_STREAM) again. flare
answers nothing and stream 3 is a fresh half-closed (remote) request.
-/
namespace Flare.Bugs.H2_02
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { maxConcurrent := 1 }

def tr : List Ev :=
  [.frame settings0, .frame (hdrs 1 false 1), .frame (hdrs 3 true 1), .frame (rstF 1),
   .frame (hdrs 3 true 1)]

theorem bug : outs Fix.none init tr = some [[.settingsAck], [], [.rst 3 eREFUSED], [], []] ∧
    stateOf Fix.none init tr 3 = some .hcr := by native_decide

theorem counterexample : ∀ o, lastOut Fix.none init tr = some o → ¬ IsConnError o ePROTOCOL := by
  intro o h
  have e : lastOut Fix.none init tr = some [] := by native_decide
  rw [e] at h; cases h; exact not_connError_nil _

theorem fixed_trace : lastOut { h2_02 := true } init tr = some [.goaway 3 ePROTOCOL] ∧
    IsConnError [.goaway 3 ePROTOCOL] ePROTOCOL := ⟨by native_decide, ⟨3, rfl⟩⟩

/-- **Fixed** (`sid ≤ last` at line 1123): for every server state, a
HEADERS frame whose id is at most the highest one seen and that is not a
live stream is answered with GOAWAY(PROTOCOL_ERROR). -/
theorem fixed (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (hfx : fx.h2_02 = true)
    (hc : c.continuing = 0) (hs : c.isClient = false) (ht : f.ty = tHEADERS)
    (hl : f.plen ≤ c.localMaxFrame) (hle : f.sid ≤ c.lastPeer) (hm : mem c f.sid = false) :
    handle fx dec c f = .ok (connErr c ePROTOCOL) :=
  handle_reuse fx dec c f hfx hc hs ht hl hle hm

end Flare.Bugs.H2_02
