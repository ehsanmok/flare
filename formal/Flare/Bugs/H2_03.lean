import Flare.Bugs.H2_Fixtures

/-!
# H2-03: client treats a late frame on a stream it closed as a protocol error

flare/http2/state.mojo:1099 (RST_STREAM) and 1236-1240 (WINDOW_UPDATE)
@59bda50 treat an id absent from the table as *idle* when it is above
`last_peer_stream_id`. In client role that counter only tracks
server-initiated ids and stays 0, while `take_response`
(flare/http2/client.mojo:1021) drops finished streams from the table. A
WINDOW_UPDATE or RST_STREAM the server sends after its final response
therefore draws GOAWAY(PROTOCOL_ERROR).

RFC 9113 §5.1 (closed): "WINDOW_UPDATE or RST_STREAM frames can be
received in this state for a short period after a DATA or HEADERS frame
containing an END_STREAM flag is sent." Such frames must not be a
connection error.

Traces (client): SETTINGS; open stream 1 with END_STREAM; response
HEADERS(1, END_STREAM); `take_response(1)`; then WINDOW_UPDATE(1) (or
RST_STREAM(1)).
-/
namespace Flare.Bugs.H2_03
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { isClient := true }

def pre : List Ev := [.frame settings0, .openLocal 1 true, .frame (hdrs 1 true 4), .pop 1]

def trWU : List Ev := pre ++ [.frame (wuF 1 100)]
def trRST : List Ev := pre ++ [.frame (rstF 1)]

theorem bug : lastOut Fix.none init trWU = some [.goaway 0 ePROTOCOL] ∧
    lastOut Fix.none init trRST = some [.goaway 0 ePROTOCOL] := by native_decide

theorem counterexample : ∃ o, lastOut Fix.none init trWU = some o ∧ hasGoaway o = true :=
  ⟨_, bug.1, rfl⟩

theorem fixed_trace : lastOut { h2_03 := true } init trWU = some [] ∧
    lastOut { h2_03 := true } init trRST = some [] := by native_decide

/-- **Fixed** (client role: an id is idle only if it is even or above our
own highest stream id): for every client state, a late WINDOW_UPDATE on
an odd id we opened is ignored, and a late RST_STREAM goes to the normal
RST_STREAM branch instead of the idle-stream error. -/
theorem fixed :
    (∀ (fx : Fix) (dec : Dec) (c : Conn) (f : Fr), fx.h2_03 = true → c.isClient = true →
      c.continuing = 0 → f.ty = tWU → f.plen = 4 → f.plen ≤ c.localMaxFrame →
      f.word % 2147483648 ≠ 0 → f.sid ≠ 0 → f.sid % 2 = 1 → f.sid ≤ c.maxLocalSid →
      get c f.sid = none → handle fx dec c f = .ok (c, [])) ∧
    (∀ (fx : Fix) (dec : Dec) (c : Conn) (f : Fr), fx.h2_03 = true → c.isClient = true →
      c.continuing = 0 → f.ty = tRST → f.plen = 4 → f.plen ≤ c.localMaxFrame →
      f.sid ≠ 0 → f.sid % 2 = 1 → f.sid ≤ c.maxLocalSid → handle fx dec c f = .ok (rstH c f)) :=
  ⟨handle_client_late_wu, handle_client_late_rst⟩

end Flare.Bugs.H2_03
