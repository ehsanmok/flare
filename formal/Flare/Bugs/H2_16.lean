import Flare.Bugs.H2_Fixtures

/-!
# H2-16: RST_STREAM on an idle stream; the later request's body is swallowed

flare/http2/state.mojo:1078-1092 (PRIORITY self-dependency) and
1213-1222 (WINDOW_UPDATE increment 0) @59bda50 answer with RST_STREAM even
when the stream is idle, and record the id in `reset_by_us`. When the
client then opens that stream, its DATA frames hit the `reset_by_us`
check (1340-1347) and are dropped (only connection credit is returned):
the request never completes.

RFC 9113 §5.1 idle: "Receiving any frame other than HEADERS or PRIORITY on
a stream in this state MUST be treated as a connection error [...]
PROTOCOL_ERROR"; §5.4.2 / §6.4: RST_STREAM "MUST NOT be sent for a stream
in the 'idle' state". §5.3.1: a self-dependent PRIORITY is a stream error,
which on an idle stream cannot be signalled with RST_STREAM.

Status: resolved. PRIORITY self-dependency and zero-increment WINDOW_UPDATE on an idle stream are now connection errors. `Fix.shipped` carries `h2_16`; `counterexample` and `bug` stay about `Fix.none` (the pre-fix code); `fixed_shipped` is the shipped behaviour.
-/
namespace Flare.Bugs.H2_16
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def prio : Fr := { ty := tPRIORITY, sid := 1, plen := 5, word := 1 }

def tr : List Ev :=
  [.frame settings0, .frame prio, .frame (hdrs 1 false 5),
   .frame { dataF 1 3 true with frag := [97, 98, 99] }]

/-- Shipped: RST_STREAM on idle stream 1; after HEADERS opened it, the
END_STREAM DATA is dropped and the stream stays OPEN. -/
theorem bug : outs Fix.none {} tr = some [[.settingsAck], [.rst 1 ePROTOCOL], [], [.wu 0 3]] ∧
    stateOf Fix.none {} tr 1 = some .open_ := by native_decide

theorem bug_wu : outs Fix.none {} [.frame settings0, .frame (wuF 1 0)] =
    some [[.settingsAck], [.rst 1 ePROTOCOL]] := by native_decide

theorem counterexample : stateOf Fix.none {} tr 1 ≠ some .hcr := by rw [bug.2]; simp

theorem fixed_trace : outs { h2_16 := true } {} tr = some [[.settingsAck], [.goaway 0 ePROTOCOL], [], []] ∧
    outs { h2_16 := true } {} [.frame settings0, .frame (wuF 1 0)] =
      some [[.settingsAck], [.goaway 0 ePROTOCOL]] := by native_decide

/-- **Fixed**: a self-dependent PRIORITY on an idle stream is a connection
error, never an RST_STREAM. -/
theorem fixed (fx : Fix) (c : Conn) (f : Fr) (hfx : fx.h2_16 = true) (ht : f.ty = tPRIORITY)
    (h0 : f.sid ≠ 0) (hp : f.plen = 5) (hd : f.word % 2147483648 = f.sid)
    (hm : mem c f.sid = false) (hi : isIdleId fx c f.sid = true) :
    shapeCheck fx c f = some (connErr c ePROTOCOL) := by
  simp [shapeCheck, ht, h0, hp, hd, hm, hi, hfx, tPRIORITY, tPING, tGOAWAY, tSETTINGS]

/-- **Fixed**: WINDOW_UPDATE with increment 0 on an idle stream is a
connection error. -/
theorem fixed_wu (fx : Fix) (c : Conn) (f : Fr) (hfx : fx.h2_16 = true)
    (h0 : f.sid ≠ 0) (hw : f.word % 2147483648 = 0)
    (hm : mem c f.sid = false) (hi : isIdleId fx c f.sid = true) :
    wuH fx c f = connErr c ePROTOCOL := by
  simp [wuH, h0, hw, hm, hi, hfx]

/-- Shipped (`Fix.shipped` has `h2_16`): both triggers draw
GOAWAY(PROTOCOL_ERROR), never RST_STREAM, on the idle stream. -/
theorem fixed_shipped : outs Fix.shipped {} tr = some [[.settingsAck], [.goaway 0 ePROTOCOL], [], []] ∧
    outs Fix.shipped {} [.frame settings0, .frame (wuF 1 0)] =
      some [[.settingsAck], [.goaway 0 ePROTOCOL]] := by native_decide

end Flare.Bugs.H2_16
