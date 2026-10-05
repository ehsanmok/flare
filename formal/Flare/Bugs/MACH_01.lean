import Flare.Machine

/-!
# MACH-01: a client accepted on fd 0 shares the listener's reactor token

flare/http/_unified_reactor_impl.mojo:1086-1130 registered the listener with
token 0 (pre-fix lines) and handed every token-0 event to the accept drainer;
clients are registered with token = fd (:722). `accept` returns the lowest
free fd, so once fd 0 is free (stdin closed at runtime) the next client
landed on token 0 and none of its events reached its connection.

Status: resolved. The listener is now registered under `LISTENER_TOKEN` (2^40,
flare/runtime/event.mojo), which no fd can take, in the unified loop and in
the four loops of `_server_reactor_epoll.mojo` (tests:
tests/http/test_listener_token_fd0.mojo). The counterexamples below are about
the pre-fix machine `stdinClosedOldP` (listener token 0).
Repro: formal/repro/MACH-01_client_on_fd0_never_served.mojo.
-/
namespace Flare.Bugs.MACH_01
open Flare.Machine

/-- Buggy: with fd 0 free the worker loop reaches a state with a live
connection on fd 0. -/
theorem client_on_fd0 :
    ∃ c, (lts counter stdinClosedOldP).Reachable c ∧ (c.conns 0).isSome :=
  fd0_reachable_old

/-- Buggy: that connection's readiness event is consumed by the accept
drainer; no dispatch step for it exists. -/
theorem fd0_event_lost (fin : Bool) :
    (runSteps counter stdinClosedOldP initCfg fd0TraceOld).bind
      (fun c => step counter stdinClosedOldP c (.dispatch fin)) = none :=
  fd0_event_not_dispatched_old fin

/-- Buggy, in general: with the listener on token 0, no step ever changes a
connection living on fd 0. -/
theorem fd0_frozen (M : ConnModel) (P : Params) (hT : P.listenerTok = 0)
    (c c' : Cfg M.S) (lab : Label M.I)
    (hs : step M P c lab = some c') (l l' : Live M.S)
    (h0 : c.conns 0 = some l) (h0' : c'.conns 0 = some l') : l' = l :=
  fd0_never_served_old M P hT c c' lab hs l l' h0 h0'

/-- Shipped code meets spec: with stdin closed, the client accepted on fd 0
is served: its event is dispatched and its connection advances. -/
theorem client_on_fd0_served :
    (runSteps counter stdinClosedP initCfg fd0Trace).map
      (fun c => ((c.conns 0).map (·.st), c.batch)) = some (some 1, []) :=
  fd0_served

/-- Shipped code meets spec: the listener's token is above every fd, so no
reachable state, for any per-connection model and with or without stdin, has
a connection on it. -/
theorem no_conn_on_listener_token (M : ConnModel) (P : Params)
    (hP : fdLimit ≤ P.listenerTok) (c : Cfg M.S) (hr : (lts M P).Reachable c) :
    c.conns P.listenerTok = none :=
  routing_ok M P (Or.inl hP) c hr

end Flare.Bugs.MACH_01
