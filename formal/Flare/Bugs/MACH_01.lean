import Flare.Machine

/-!
# MACH-01: a client accepted on fd 0 shares the listener's reactor token

flare/http/_unified_reactor_impl.mojo:1086-1130 @59bda50 registers the
listener with token 0 and hands every token-0 event to the accept drainer;
clients are registered with token = fd (:722). `accept` returns the lowest
free fd, so once fd 0 is free (stdin closed at runtime) the next client
lands on token 0 and none of its events reach its connection.
Repro: formal/repro/MACH-01_client_on_fd0_never_served.mojo.
-/
namespace Flare.Bugs.MACH_01
open Flare.Machine

/-- Buggy: with fd 0 free the worker loop reaches a state with a live
connection on fd 0. -/
theorem client_on_fd0 :
    ∃ c, (lts counter stdinClosedP).Reachable c ∧ (c.conns 0).isSome :=
  fd0_reachable

/-- Buggy: that connection's readiness event is consumed by the accept
drainer; no dispatch step for it exists. -/
theorem fd0_event_lost (fin : Bool) :
    (runSteps counter stdinClosedP initCfg fd0Trace).bind
      (fun c => step counter stdinClosedP c (.dispatch fin)) = none :=
  fd0_event_not_dispatched fin

/-- Buggy, in general: no step ever changes a connection living on fd 0. -/
theorem fd0_frozen (M : ConnModel) (P : Params) (c c' : Cfg M.S) (lab : Label M.I)
    (hs : step M P c lab = some c') (l l' : Live M.S)
    (h0 : c.conns 0 = some l) (h0' : c'.conns 0 = some l') : l' = l :=
  fd0_never_served M P c c' lab hs l l' h0 h0'

/-- Fixed (no client ever takes the listener's token; modelled as the accept
guard `fd ≠ 0`): no reachable state has a connection on token 0, for every
per-connection model. -/
theorem fixed_no_conn_on_listener_token (M : ConnModel) (P : Params)
    (hP : P.stdinOpen = true) (c : Cfg M.S) (hr : (lts M P).Reachable c) :
    c.conns 0 = none :=
  routing_ok M P hP c hr

end Flare.Bugs.MACH_01
