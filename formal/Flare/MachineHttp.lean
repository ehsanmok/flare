import Flare.Machine
import Flare.L4_App.ConnSM

/-!
# The worker loop running the HTTP/1.1 connection state machine

`Flare.Machine` is generic over the per-connection model; this file plugs in
`Flare.L4.ConnSM` (the model of `ConnHandle`) and lifts its invariant to every
live connection of every reachable worker state.

The `StepResult` is read off the handle's state: reading arms the idle timer,
writing the write timer, done cancels
(flare/http/_reactor/conn_handle.mojo:618-689,1319-1374 @59bda50; the
request-budget variant of the reading timer, :669-689, is approximated by
`idle`). The theorems below do not depend on these timer values.
-/
namespace Flare.MachineHttp
open Flare.L4

variable {Req : Type}

/-- mirrors flare/http/_reactor/conn_handle.mojo `StepResult` construction
@59bda50 (`want_read` in STATE_READING, `want_write` in STATE_WRITING). -/
def stepResult (idle write : Nat) (s : ConnSM.St Req) : Machine.StepResult :=
  { wantRead := decide (s.phase = .reading)
    wantWrite := decide (s.phase = .writing)
    done := s.done
    idleMs := if s.done then 0 else if s.phase = .writing then write else idle }

/-- `ConnHandle` as the worker loop's per-connection model. `fix = true` is
the APP-01-fixed handle. -/
def http (fix : Bool) (P : ConnSM.Params Req) (idle write : Nat) : Machine.ConnModel where
  S := ConnSM.St Req
  I := ConnSM.Ev
  init := ConnSM.init
  onEvent s e := (ConnSM.step fix P s e, stepResult idle write (ConnSM.step fix P s e))
  idleMs := idle

/-- **The connection invariant holds inside the server.** In every reachable
worker state (any accept / poll / dispatch / timer interleaving, any fd
reuse), every live connection satisfies `ConnSM.Inv`. -/
theorem server_conns_inv (fix : Bool) (P : ConnSM.Params Req) (hP : ConnSM.Oracle.WF P)
    (idle write : Nat) (MP : Machine.Params) (c : Machine.Cfg (http fix P idle write).S)
    (hr : (Machine.lts (http fix P idle write) MP).Reachable c) :
    ∀ f l, c.conns f = some l → ConnSM.Inv P l.st :=
  Machine.conn_invariant_lifts (http fix P idle write) MP (ConnSM.Inv P) (ConnSM.inv_init P)
    (fun s e h => ConnSM.inv_step fix P hP s e h) c hr

/-- **One response per request, in order, on every live connection.** The
requests answered by queued responses are exactly the dispatched requests,
each the framing oracle's reading of exactly its own bytes, and the bytes on
the wire are a prefix of the queued responses. -/
theorem server_responses_fifo (fix : Bool) (P : ConnSM.Params Req) (hP : ConnSM.Oracle.WF P)
    (idle write : Nat) (MP : Machine.Params) (c : Machine.Cfg (http fix P idle write).S)
    (hr : (Machine.lts (http fix P idle write) MP).Reachable c) (f : Machine.Fd)
    (l : Machine.Live (http fix P idle write).S) (hf : c.conns f = some l) :
    l.st.log.filterMap ConnSM.Out.req = l.st.segs.map Prod.snd ∧
    (∀ p ∈ l.st.segs, P.frame p.1 = .complete p.2 p.1.length) ∧
    l.st.wire <+: ConnSM.flat P l.st.log := by
  have hi := server_conns_inv fix P hP idle write MP c hr f l hf
  exact ⟨hi.answers, hi.segs_ok, ConnSM.Inv.wire_prefix P l.st hi⟩

/-- **Keep-alive bound on every live connection.** -/
theorem server_ka_bound (fix : Bool) (P : ConnSM.Params Req) (hP : ConnSM.Oracle.WF P)
    (idle write : Nat) (MP : Machine.Params) (c : Machine.Cfg (http fix P idle write).S)
    (hr : (Machine.lts (http fix P idle write) MP).Reachable c) (f : Machine.Fd)
    (l : Machine.Live (http fix P idle write).S) (hf : c.conns f = some l) :
    l.st.ka ≤ max P.maxKA 1 :=
  (server_conns_inv fix P hP idle write MP c hr f l hf).ka_le

/-- **No stale idle close, with HTTP connections.** Every idle close the
server performs hits the connection that armed the timer. -/
theorem server_no_stale_timer (fix : Bool) (P : ConnSM.Params Req) (idle write : Nat)
    (MP : Machine.Params) (hP : MP.cancelOnCleanup = true)
    (c : Machine.Cfg (http fix P idle write).S)
    (hr : (Machine.lts (http fix P idle write) MP).Reachable c) :
    ∀ k ∈ c.kills, k.victim = k.armer :=
  Machine.no_stale_timer (http fix P idle write) MP hP c hr

end Flare.MachineHttp
