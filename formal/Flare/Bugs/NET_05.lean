import Flare.L2_Machine.Socket

/-!
# NET-05: accepted fd leaks if the peer address fails to decode

Status: resolved. `TcpListener.accept` and `accept_fd` now go through
`_adopt_accepted` (flare/tcp/listener.mojo:62-77), which wraps the fd in a
`RawSocket` before decoding the peer address; `Flare.L2.Socket.acceptImpl`
mirrors the shipped code and the counterexample below is about the pre-fix
`acceptImplOld`.

Pre-fix code: `TcpListener.accept` and `accept_fd` (flare/tcp/listener.mojo:
190-201, 271-282 @59bda50) called `_sockaddr_to_socket_addr(peer_buf)`
*before* wrapping `client_fd` in a `RawSocket`. If the decode raised, no
object owned the fd and it was never closed. Latent: the decode raises only
when `inet_ntop` fails, which it does not for the AF_INET/AF_INET6 buffers
`accept(2)` fills. Spec: once `accept(2)` returns a client fd, a `TcpStream`
owns it or it is closed before the error propagates. Severity: info/low.
Repro: formal/repro/NET-05_accept_fd_leak_on_decode_error.mojo, by fault
injection (an interposed `inet_ntop`; DYLD_INSERT_LIBRARIES on macOS,
LD_PRELOAD on Linux): the accepted fd stayed open after `accept` raised.
-/
namespace Flare.Bugs.NET_05
open Flare.L2.Socket

/-- **Counterexample** (pre-fix order): a successful accept whose decode
raises leaks the fd. -/
theorem accept_leaks_on_decode_error : ¬ AcceptSpec (acceptImplOld 5 false true) := by
  unfold AcceptSpec acceptImplOld; decide

/-- **Fix meets spec**: the shipped accept (wrap first, then decode) never
leaks, whatever the decode and `nodelay` do. -/
theorem accept_spec (fd : Int) (d n : Bool) : AcceptSpec (acceptImpl fd d n) :=
  accept_never_leaks fd d n

/-- on the counterexample input the fd is now closed by the destructor -/
theorem accept_closes_on_decode_error : acceptImpl 5 false true = .closed := by decide

/-- The fix changes nothing on the success path. -/
theorem accept_agrees (fd : Int) (n : Bool) : acceptImpl fd true n = acceptImplOld fd true n :=
  acceptImpl_agrees fd n

end Flare.Bugs.NET_05
