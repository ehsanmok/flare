import Flare.Bugs.H2_Fixtures

/-!
# H2-20: DATA on a stream the peer reset draws PROTOCOL_ERROR, not STREAM_CLOSED

flare/http2/state.mojo:1340-1512 @59bda50 tests the client's
"headers not complete" condition (PROTOCOL_ERROR) before the stream's
state, so DATA on a stream that is closed (the server reset it before
any response HEADERS) or half-closed (remote) draws GOAWAY(PROTOCOL_ERROR).

RFC 9113 §5.1, closed: "An endpoint that receives any frame other than
PRIORITY after receiving a RST_STREAM MUST treat that as a stream error
(Section 5.4.2) of type STREAM_CLOSED"; half-closed (remote): "If an
endpoint receives additional frames, other than WINDOW_UPDATE, PRIORITY,
or RST_STREAM, for a stream that is in this state, it MUST respond with
a stream error (Section 5.4.2) of type STREAM_CLOSED." flare answers both
with a connection error (allowed, §5.4.1), but with the wrong code.

Witness (the repro's): client; SETTINGS; request on stream 1 with
END_STREAM; the server's RST_STREAM(1); DATA(1, 1 octet).
-/
namespace Flare.Bugs.H2_20
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { isClient := true }

def tr : List Ev := [.frame settings0, .openLocal 1 true, .frame (rstF 1), .frame (dataF 1 1 false)]

/-- Shipped: stream 1 is CLOSED and the DATA draws GOAWAY(PROTOCOL_ERROR). -/
theorem bug : stateOf Fix.none init (tr.take 3) 1 = some .closed ∧
    lastOut Fix.none init tr = some [.goaway 0 ePROTOCOL] := by native_decide

theorem counterexample : ∀ o, lastOut Fix.none init tr = some o → ¬ IsConnError o eSTREAM_CLOSED := by
  intro o h; rw [bug.2] at h; cases h; rintro ⟨_, h⟩; cases h

theorem fixed_trace : lastOut { h2_20 := true } init tr = some [.goaway 0 eSTREAM_CLOSED] := by native_decide

/-- **Fixed**: with the H2-20 fix, DATA on a closed or half-closed (remote)
stream that we did not reset is a STREAM_CLOSED connection error, in
either role. -/
theorem fixed (fx : Fix) (hfx : fx.h2_20 = true) (c : Conn) (f : Fr) (s : Stream)
    (hr : f.sid ∉ c.resetByUs) (hg : get c f.sid = some s) (hs : s.state = .closed ∨ s.state = .hcr) :
    dataH fx c f = connErr c eSTREAM_CLOSED := by
  unfold dataH
  rw [if_neg hr, hg]
  simp only [hfx, Bool.true_and]
  rw [if_pos (by rcases hs with h | h <;> simp [h])]

end Flare.Bugs.H2_20
