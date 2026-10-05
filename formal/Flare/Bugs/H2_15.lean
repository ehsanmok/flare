import Flare.Bugs.H2_Fixtures

/-!
# H2-15: server treats an even, never-opened stream as closed

flare/http2/state.mojo:1099,1238,1351 @59bda50 call a stream absent from
the table "idle" only when its id is above `last_peer_stream_id`. In
server role an even id is server-initiated; with push disabled the server
never opens one, so every even id is idle. Below the high-water mark the
server instead treats it as closed: WINDOW_UPDATE and RST_STREAM are
ignored and DATA draws STREAM_CLOSED.

RFC 9113 §5.1 idle: "Receiving any frame other than HEADERS or PRIORITY on
a stream in this state MUST be treated as a connection error (Section
5.4.1) of type PROTOCOL_ERROR."

Status: resolved. `_idle_id` now also treats every even id as idle in server role. `Fix.shipped` carries `h2_15`; `counterexample` and `bug` stay about `Fix.none` (the pre-fix code); `fixed_shipped` is the shipped behaviour.
-/
namespace Flare.Bugs.H2_15
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def tr (f : Fr) : List Ev := [.frame settings0, .frame (hdrs 3 true 1), .frame f]

theorem bug : lastOut Fix.none {} (tr (wuF 2 1)) = some [] ∧
    lastOut Fix.none {} (tr (rstF 2)) = some [] ∧
    lastOut Fix.none {} (tr (dataF 2 1 false)) = some [.goaway 3 eSTREAM_CLOSED] := by
  native_decide

theorem counterexample : ∀ o, lastOut Fix.none {} (tr (wuF 2 1)) = some o → ¬ IsConnError o ePROTOCOL := by
  intro o h; rw [bug.1] at h; cases h; exact not_connError_nil _

theorem fixed_trace : lastOut { h2_15 := true } {} (tr (wuF 2 1)) = some [.goaway 3 ePROTOCOL] ∧
    lastOut { h2_15 := true } {} (tr (rstF 2)) = some [.goaway 3 ePROTOCOL] ∧
    lastOut { h2_15 := true } {} (tr (dataF 2 1 false)) = some [.goaway 3 ePROTOCOL] := by
  native_decide

/-- **Fixed**: in server role every even id is idle when absent, so the
RST_STREAM / WINDOW_UPDATE / DATA idle checks fire. -/
theorem fixed (fx : Fix) (c : Conn) (k : Nat) (hfx : fx.h2_15 = true) (hs : c.isClient = false)
    (he : k % 2 = 0) : isIdleId fx c k = true := by
  simp [isIdleId, hfx, hs, he]

/-- With the fix the RST_STREAM idle check answers GOAWAY(PROTOCOL_ERROR). -/
theorem fixed_rst (fx : Fix) (c : Conn) (f : Fr) (hfx : fx.h2_15 = true) (hs : c.isClient = false)
    (ht : f.ty = tRST) (h0 : f.sid ≠ 0) (he : f.sid % 2 = 0) (hp : f.plen = 4)
    (hm : mem c f.sid = false) : shapeCheck fx c f = some (connErr c ePROTOCOL) := by
  have hi := fixed fx c f.sid hfx hs he
  simp [shapeCheck, ht, h0, hp, hm, hi, tRST, tPING, tGOAWAY, tSETTINGS, tPRIORITY]

/-- Shipped (`Fix.shipped` has `h2_15`): all three frames on the even,
never-opened stream 2 are PROTOCOL_ERROR. -/
theorem fixed_shipped : lastOut Fix.shipped {} (tr (wuF 2 1)) = some [.goaway 3 ePROTOCOL] ∧
    lastOut Fix.shipped {} (tr (rstF 2)) = some [.goaway 3 ePROTOCOL] ∧
    lastOut Fix.shipped {} (tr (dataF 2 1 false)) = some [.goaway 3 ePROTOCOL] := by
  native_decide

end Flare.Bugs.H2_15
