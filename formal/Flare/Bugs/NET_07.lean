import Flare.L2_Machine.UdsListener

/-!
# NET-07: `UnixListener.bind` unlinks a live socket when the probe fails with EACCES

Status: resolved. `bind_with_options` now probes with `_socket_path_is_stale`
and only a refusal (`ECONNREFUSED`/`ENOENT`) makes a socket stale; the
model's `prep` mirrors it and the counterexample below is about the
pre-fix `prepOld`.

Pre-fix code: flare/uds/listener.mojo:163-184 @59bda50.

Spec (docstring 146-153): `unlink_existing` removes "a stale socket at
`path` ...: one no process is listening on. A live socket raises
`AddressInUse`".

What goes wrong: liveness is probed with `UnixStream.connect(path)` inside
`try: ... except: pass`; every probe failure counts as "stale". `connect`
also fails with `EACCES` when the caller may not write the socket file,
which says nothing about liveness. A server whose socket is mode 0600
under another user (in a directory the caller can write), or mode 0, gets
its path unlinked and taken over; it keeps running but is unreachable.

Repro: formal/repro/NET-07_uds_takeover_unlinks_live_socket.mojo.
-/
namespace Flare.Bugs.NET_07
open Flare.L2.UdsListener

/-- **Counterexample** (pre-fix `prepOld`): listening peer, unwritable socket file, probe
`EACCES` (allowed by `ConnectFacts`); flare chooses unlink-then-bind. -/
theorem takeover_unlinks_live :
    ConnectFacts ⟨true, false⟩ (.err EACCES) ∧ prepOld (.sock 1 2) (.err EACCES) = .unlinkBind :=
  ⟨Flare.L2.UdsListener.takeover_unlinks_live.1, Flare.L2.UdsListener.takeover_unlinks_live.2.1⟩

/-- **Fix meets spec** (shipped `prep`): unlink only after a refused probe; then a live
socket is never unlinked, and stale (refusing) sockets are still taken
over. -/
theorem prep_safe (k : Kind) (p : Peer) (c : Conn) (hc : ConnectFacts p c) :
    (prep k c = .unlinkBind → p.listening = false) ∧
    (∀ d i, k = .sock d i → c = .refused → prep k c = .unlinkBind) :=
  Flare.L2.UdsListener.prep_safe k p c hc

end Flare.Bugs.NET_07
