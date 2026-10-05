import Flare.Bugs.H2_Fixtures

/-!
# H2-07: a GOAWAY shorter than 8 octets is accepted

flare/http2/state.mojo:1063-1065 @59bda50 checks only the stream id of a
GOAWAY frame; the GOAWAY branch (1514-1516) then sets
`goaway_received` without looking at the payload. A 0- or 4-octet GOAWAY
is accepted silently.

RFC 9113 §6.8: the GOAWAY payload carries a 31-bit last-stream-id and a
32-bit error code (8 octets at least); §4.2: "An endpoint MUST send an
error code of FRAME_SIZE_ERROR if a frame [...] is too small to contain
mandatory frame data." A frame-size error in a frame that affects
connection state is a connection error.

Status: resolved. The frame-shape check rejects `plen < 8` with FRAME_SIZE_ERROR before the GOAWAY branch. `Fix.shipped` carries `h2_07`; `counterexample` and `bug` stay about `Fix.none` (the pre-fix code); `fixed_shipped` is the shipped behaviour.
-/
namespace Flare.Bugs.H2_07
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def tr (n : Nat) : List Ev := [.frame settings0, .frame { ty := tGOAWAY, plen := n }]

theorem bug : lastOut Fix.none {} (tr 0) = some [] ∧ lastOut Fix.none {} (tr 4) = some [] := by
  native_decide

theorem counterexample : ∀ o, lastOut Fix.none {} (tr 0) = some o → ¬ IsConnError o eFRAME_SIZE := by
  intro o h; rw [bug.1] at h; cases h; exact not_connError_nil _

theorem fixed_trace : lastOut { h2_07 := true } {} (tr 0) = some [.goaway 0 eFRAME_SIZE] ∧
    lastOut { h2_07 := true } {} (tr 4) = some [.goaway 0 eFRAME_SIZE] := by native_decide

/-- **Fixed**: in every state, a GOAWAY on stream 0 with fewer than 8
payload octets is a FRAME_SIZE_ERROR connection error. -/
theorem fixed (fx : Fix) (dec : Dec) (c : Conn) (f : Fr)
    (hc : c.continuing = 0) (ht : f.ty = tGOAWAY) (h0 : f.sid = 0) (hfx : fx.h2_07 = true)
    (hs : f.plen < 8) : handle fx dec c f = .ok (connErr c eFRAME_SIZE) :=
  handle_goaway_short fx dec c f hc ht h0 hfx hs

/-- Shipped (`Fix.shipped` has `h2_07`): the short GOAWAYs draw the
FRAME_SIZE_ERROR connection error. -/
theorem fixed_shipped : lastOut Fix.shipped {} (tr 0) = some [.goaway 0 eFRAME_SIZE] ∧
    lastOut Fix.shipped {} (tr 4) = some [.goaway 0 eFRAME_SIZE] := by native_decide

end Flare.Bugs.H2_07
