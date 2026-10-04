import Flare.Bugs.H2_Fixtures

/-!
# H2-06: HEADERS on stream 0 raises instead of a connection error

flare/http2/state.mojo:1258-1259 @59bda50 raises
`Error("h2: HEADERS on stream 0")`. The raise escapes `handle_frame` and
`Http2Connection.feed` (flare/http2/server.mojo:358-438) without queuing
a GOAWAY. The id check at state.mojo:1120-1126 catches stream 0 first
(`0 < last_peer_stream_id`) once any request was seen, so the raise is
reached on a fresh server connection, or in client role.

RFC 9113 §6.2: "If a HEADERS frame is received whose Stream Identifier
field is 0x00, the recipient MUST respond with a connection error
(Section 5.4.1) of type PROTOCOL_ERROR."
-/
namespace Flare.Bugs.H2_06
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def tr : List Ev := [.frame settings0, .frame (hdrs 0 true 1)]

/-- The run raises (`none`): no reply, no GOAWAY. -/
theorem bug : outs Fix.none {} tr = none := by native_decide

def raises : Res → Bool
  | .error e => e == "h2: HEADERS on stream 0"
  | .ok _ => false

/-- The offending frame on a fresh connection raises the Mojo error. -/
theorem counterexample : raises (step Fix.none dec {} (.frame (hdrs 0 true 1))) = true := by
  native_decide

theorem fixed_trace : lastOut { h2_06 := true } {} tr = some [.goaway 0 ePROTOCOL] := by native_decide

/-- **Fixed**: whenever the stream-0 HEADERS reaches the HEADERS branch,
the reply is GOAWAY(PROTOCOL_ERROR); without the fix the step raises. -/
theorem fixed (fx : Fix) (dec : Dec) (c : Conn) (f : Fr)
    (hc : c.continuing = 0) (ht : f.ty = tHEADERS) (h0 : f.sid = 0) (hl : f.plen ≤ c.localMaxFrame)
    (hlp : c.isClient = true ∨ c.lastPeer = 0) (h02 : fx.h2_02 = false) :
    handle fx dec c f =
      if fx.h2_06 then .ok (connErr c ePROTOCOL) else .error "h2: HEADERS on stream 0" :=
  handle_headers0 fx dec c f hc ht h0 hl hlp h02

end Flare.Bugs.H2_06
