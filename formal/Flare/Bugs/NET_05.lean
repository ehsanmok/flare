import Flare.L2_Machine.Socket

/-!
# NET-05: accepted fd leaks if the peer address fails to decode

`TcpListener.accept` and `accept_fd` (flare/tcp/listener.mojo:190-201,
271-282) call `_sockaddr_to_socket_addr(peer_buf)` *before* wrapping
`client_fd` in a `RawSocket`. If the decode raises, no object owns the fd
and it is never closed. Latent: the decode raises only when `inet_ntop`
fails, which it does not for the AF_INET/AF_INET6 buffers `accept(2)`
fills. Spec: once `accept(2)` returns a client fd, a `TcpStream` owns it
or it is closed before the error propagates. Severity: info/low.
Repro: formal/repro/NET-05_accept_fd_leak_on_decode_error.mojo, by fault
injection (an interposed `inet_ntop`; DYLD_INSERT_LIBRARIES on macOS,
LD_PRELOAD on Linux): the accepted fd stays open after `accept` raises.
-/
namespace Flare.Bugs.NET_05
open Flare.L2.Socket

/-- Counterexample: a successful accept whose decode raises leaks the fd. -/
theorem accept_leaks_on_decode_error : ¬ AcceptSpec (acceptImpl 5 false true) := by
  unfold AcceptSpec acceptImpl; decide

/-- Minimal fix: wrap `client_fd` in a `RawSocket` first, then decode; a
raise after wrapping runs the destructor, which closes the fd.
mirrors flare/tcp/listener.mojo:165-201 @59bda50 (with the minimal fix) -/
def acceptFixed (fd : Int) (decodeOk nodelayOk : Bool) : AcceptOut :=
  if fd < 0 then .noFd
  else if ¬ decodeOk then .closed
  else if ¬ nodelayOk then .closed
  else .owned

theorem acceptFixed_spec (fd : Int) (d n : Bool) : AcceptSpec (acceptFixed fd d n) := by
  unfold AcceptSpec acceptFixed
  repeat' split
  all_goals simp

/-- The fix changes nothing on the success path. -/
theorem acceptFixed_agrees (fd : Int) (n : Bool) : acceptFixed fd true n = acceptImpl fd true n := by
  simp [acceptFixed, acceptImpl]

end Flare.Bugs.NET_05
