import Flare.Bugs.H2_Fixtures
import Flare.L3_Protocol.H2.StreamTable

/-!
# H2-19: WINDOW_UPDATE sent on a stream the DATA frame just closed

flare/http2/state.mojo:1492-1494 @59bda50 queues `WINDOW_UPDATE(sid,
credit)` for every DATA frame with a payload, after 1470-1478 has already
moved a client stream that was HALF_CLOSED_LOCAL to CLOSED on END_STREAM.
That is the ordinary path for every bodiless client request: the HEADERS
ends the request, the response's last DATA frame ends the stream.

RFC 9113 §5.1, closed: "An endpoint MUST NOT send frames other than
PRIORITY on a closed stream."

Witness (the repro's): client; SETTINGS; request on stream 1 with
END_STREAM; response HEADERS(:status 200); DATA(1, 3 octets, END_STREAM).

Status: resolved. The DATA branch no longer queues a stream-level WINDOW_UPDATE for a stream the frame closed. `Fix.shipped` carries `h2_19`; `bug` and `counterexample` stay about `Fix.none` (the pre-fix code); `fixed_shipped` is the shipped behaviour.
-/
namespace Flare.Bugs.H2_19
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def init : Conn := { isClient := true }

def tr : List Ev :=
  [.frame settings0, .openLocal 1 true, .frame { hdrs 1 false 4 with eh := true },
   .frame (dataF 1 3 true)]

/-- Shipped: stream 1 is CLOSED and the reply carries `WINDOW_UPDATE(1, 3)`. -/
theorem bug : stateOf Fix.none init tr 1 = some .closed ∧
    lastOut Fix.none init tr = some [.wu 1 3, .wu 0 3] := by native_decide

theorem counterexample : ∃ o, lastOut Fix.none init tr = some o ∧
    stateOf Fix.none init tr 1 = some .closed ∧ (∃ n, Out.wu 1 n ∈ o) :=
  ⟨_, bug.2, bug.1, 3, by simp⟩

theorem fixed_trace : stateOf { h2_19 := true } init tr 1 = some .closed ∧
    lastOut { h2_19 := true } init tr = some [.wu 0 3] := by native_decide

/-- **Fixed**: with the H2-19 fix, the DATA tail never queues a stream
WINDOW_UPDATE for a stream it closes. -/
theorem fixed (fx : Fix) (hfx : fx.h2_19 = true) (c : Conn) (f : Fr) (s : Stream) (cr : Nat)
    (hc : c.isClient = true) (hk : f.sid ≠ 0) (he : f.f1 = true) (hs : s.state = .hcl)
    (hcl : ¬ (f.f1 = true ∧ (0 : Int) ≤ s.contentLength ∧ (s.received : Int) ≠ s.contentLength)) :
    ∀ n, Out.wu f.sid n ∉ (dataFinish fx c f s cr).2 := by
  intro n hn
  unfold dataFinish at hn
  rw [if_neg (by simpa [he] using hcl)] at hn
  simp only [hfx, he, hc, hs, Bool.true_and, beq_self_eq_true, ite_true] at hn
  unfold dataCredit at hn
  split at hn
  · simp only [Nat.lt_irrefl, ite_false, List.nil_append] at hn
    split at hn
    · simp at hn
    · simp at hn; exact hk hn.1
  · simp at hn

/-- Shipped (`Fix.shipped` has `h2_19`): the stream is closed and only the
connection-level `WINDOW_UPDATE` is sent. -/
theorem fixed_shipped : stateOf Fix.shipped init tr 1 = some .closed ∧
    lastOut Fix.shipped init tr = some [.wu 0 3] := by native_decide

end Flare.Bugs.H2_19
