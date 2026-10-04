import Flare.L2_Machine.Udp

/-!
# NET-01: `UdpSocket.recv_from` reports the wrong sender for IPv6 peers

flare/udp/socket.mojo:279-283,330-334 @59bda50 (buffer and `addrlen`),
flare/net/_libc.mojo:366-397 @59bda50 (IPv6 decoder).

Spec (POSIX `recvfrom(2)`): `src_addr` receives the sender's address,
truncated to `*addrlen` bytes; `recv_from` must return that address.

What goes wrong: `recv_from` passes a 16-byte (`sockaddr_in`) buffer and
`addrlen = 16` even on an IPv6 socket. The kernel writes only the first 16
of the 28 bytes of the `sockaddr_in6`, but the decoder reads `sin6_addr` at
offsets 8..23: the last 8 address bytes come from beyond the buffer (stack
contents), so the reported sender is wrong and the read is out of bounds.

Repro: formal/repro/NET-01_udp_recvfrom_ipv6_sender.mojo.
-/
namespace Flare.Bugs.NET_01
open Flare.L2.Udp

/-- the sender `[::1]:61854` as a `sockaddr_in6` (port 0xF19E at 2..3,
`sin6_addr` = ::1 at 8..23) -/
def loopback6 : Nat → UInt8 := fun i =>
  if i = 2 then 0xF1 else if i = 3 then 0x9E else if i = 23 then 1 else 0

/-- The decoder reads 8 bytes past the 16-byte buffer. -/
theorem reads_past_buffer :
    (addr6Offsets.filter (implBufLen ≤ ·)) = [16, 17, 18, 19, 20, 21, 22, 23] :=
  impl_reads_past_buffer

/-- **Counterexample**: whenever the stack byte at offset 23 is not `1`
(e.g. zero), `recv_from` reports a sender address other than `::1`. -/
theorem recvFrom_ipv6_wrong_sender (stack mem : Nat → UInt8) (hs : stack 23 ≠ 1)
    (h : RecvfromFills implBufLen sockaddrIn6Size loopback6 stack mem) :
    readAddr6 mem ≠ readAddr6 loopback6 := by
  rw [impl_addr6 h]
  intro heq
  have := congrArg (fun l => l[15]?) heq
  simp [readAddr6, loopback6] at this
  exact hs this

/-- **Fix meets spec**: with a `sockaddr_in6`-sized buffer and `addrlen`,
the decoded address and port are the sender's, for every sender. -/
theorem recvFromFixed_correct {sa stack mem : Nat → UInt8}
    (h : RecvfromFills fixedBufLen sockaddrIn6Size sa stack mem) :
    readAddr6 mem = readAddr6 sa ∧ readPort mem = readPort sa :=
  fixed_addr6 h

end Flare.Bugs.NET_01
