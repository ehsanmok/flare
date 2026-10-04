import Flare.Bugs.H2_Fixtures

/-!
# H2-04: client accepts HEADERS on streams it never opened

flare/http2/state.mojo:1257-1333 @59bda50 (HEADERS branch) creates the
stream through `_ensure_stream` whatever the role. A client that has
opened no stream accepts HEADERS from the server on stream 2 (even, which
only PUSH_PROMISE may reserve; push is disabled) and on stream 3 (odd,
client-initiated by definition), and reports a response as ready.

RFC 9113 §5.1.1: "Streams initiated by a client MUST use odd-numbered
stream identifiers; those initiated by the server MUST use even-numbered
stream identifiers. [...] An endpoint that receives an unexpected stream
identifier MUST respond with a connection error (Section 5.4.1) of type
PROTOCOL_ERROR." §8.4: a client that disabled push must not see
server-initiated streams.
-/
namespace Flare.Bugs.H2_04
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { isClient := true }

def tr : List Ev := [.frame settings0, .frame (hdrs 2 true 4), .frame (hdrs 3 true 4)]

theorem bug : outs Fix.none init tr = some [[.settingsAck], [], []] ∧
    stateOf Fix.none init tr 2 = some .hcr ∧ stateOf Fix.none init tr 3 = some .hcr := by
  native_decide

theorem counterexample :
    ∀ os, outs Fix.none init tr = some os → ¬ IsConnError (os.getD 1 []) ePROTOCOL := by
  intro os h; rw [bug.1] at h; cases h; exact not_connError_nil _

theorem fixed_trace : outs { h2_04 := true } init tr = some [[.settingsAck], [.goaway 0 ePROTOCOL], []] :=
  by native_decide

/-- **Fixed**: for every client state, HEADERS on a stream id the client
does not have is GOAWAY(PROTOCOL_ERROR). -/
theorem fixed (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (hfx : fx.h2_04 = true)
    (hc : c.continuing = 0) (hcl : c.isClient = true) (ht : f.ty = tHEADERS) (h0 : f.sid ≠ 0)
    (hl : f.plen ≤ c.localMaxFrame) (hm : mem c f.sid = false) :
    handle fx dec c f = .ok (connErr c ePROTOCOL) :=
  handle_client_unopened fx dec c f hfx hc hcl ht h0 hl hm

end Flare.Bugs.H2_04
