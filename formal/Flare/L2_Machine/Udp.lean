import Flare.Core

/-!
# UDP `recv_from` / `try_recv_from`: decoding the sender address

`flare/udp/socket.mojo:269-352` hands `recvfrom(2)` a zeroed stack buffer
of `SOCKADDR_IN_SIZE` (16) bytes with `addrlen = 16`, then decodes it with
`_sockaddr_to_socket_addr` (`net/socket.mojo:561-585`), which for
`AF_INET6` calls `_read_ipv6_from_sockaddr` (`net/_libc.mojo:366-397`):
`inet_ntop` over the 16 bytes at offset 8 (`sin6_addr`).

Memory is modelled as a function `Nat → UInt8` over offsets from the start
of `peer_buf`; offsets at or past the buffer size are whatever the stack
holds there (`stack`). The kernel's behaviour is the hypothesis
`RecvfromFills` (POSIX `recvfrom`: the stored address is truncated to
`addrlen`; nothing past `addrlen` is written).

Not modelled: `inet_ntop`'s text form (the model compares the 16 raw
address bytes it would format), and the family-byte layout difference
between Linux and macOS (both decoders read the family from inside the
first 16 bytes, so it is decoded correctly either way).
-/
namespace Flare.L2.Udp

/-- `SOCKADDR_IN_SIZE` and `SOCKADDR_IN6_SIZE` (`net/_libc.mojo:88-89`). -/
def sockaddrInSize : Nat := 16
def sockaddrIn6Size : Nat := 28

/-- Environment hypothesis (POSIX `recvfrom(2)`): with a buffer of `bufLen`
bytes, zeroed by the caller, and a sender sockaddr `sa` of `saLen` bytes,
afterwards byte `i` of the buffer is `sa i` for `i < min bufLen saLen`, still
`0` for the rest of the buffer, and memory past the buffer is untouched. -/
def RecvfromFills (bufLen saLen : Nat) (sa stack mem : Nat → UInt8) : Prop :=
  ∀ i, mem i = if i < min bufLen saLen then sa i else if i < bufLen then 0 else stack i

/-- `_read_port_from_sockaddr`: big-endian `sin_port` / `sin6_port` at 2..3.
mirrors flare/net/_libc.mojo:303-321 @59bda50 -/
def readPort (mem : Nat → UInt8) : Nat := (mem 2).toNat * 256 + (mem 3).toNat

/-- the 16 bytes `_read_ipv6_from_sockaddr` passes to `inet_ntop`
(`sin6_addr`, offset 8).
mirrors flare/net/_libc.mojo:366-397 @59bda50 -/
def readAddr6 (mem : Nat → UInt8) : List UInt8 := (List.range 16).map fun i => mem (8 + i)

/-- the 4 bytes `_read_ip_from_sockaddr` passes to `inet_ntop` (`sin_addr`,
offset 4).
mirrors flare/net/_libc.mojo:325-363 @59bda50 -/
def readAddr4 (mem : Nat → UInt8) : List UInt8 := (List.range 4).map fun i => mem (4 + i)

/-- buffer size `recv_from` allocates (and passes as `addrlen`).
mirrors flare/udp/socket.mojo:279-283,330-334 @59bda50 -/
def implBufLen : Nat := sockaddrInSize

/-- the minimal fix: a `sockaddr_in6`-sized buffer and `addrlen` -/
def fixedBufLen : Nat := sockaddrIn6Size

/-- the offsets the IPv6 decoder reads -/
def addr6Offsets : List Nat := (List.range 16).map (8 + ·)

/-- **Out-of-bounds read**: the IPv6 decoder reads 8 bytes past the end of
the 16-byte buffer (offsets 16..23). -/
theorem impl_reads_past_buffer :
    (addr6Offsets.filter (implBufLen ≤ ·)) = [16, 17, 18, 19, 20, 21, 22, 23] := by decide

/-- With the 16-byte buffer the decoded IPv6 address is the first 8 bytes of
`sin6_addr` followed by 8 bytes of stack memory: it never depends on the
last 8 address bytes the kernel delivered. -/
theorem impl_addr6 {sa stack mem : Nat → UInt8} (h : RecvfromFills implBufLen sockaddrIn6Size sa stack mem) :
    readAddr6 mem = (List.range 16).map fun i => if i < 8 then sa (8 + i) else stack (8 + i) := by
  unfold readAddr6
  apply List.map_congr_left
  intro i hi
  rw [List.mem_range] at hi
  rw [h]
  unfold implBufLen sockaddrInSize sockaddrIn6Size
  by_cases hi8 : i < 8
  · rw [if_pos (by omega), if_pos hi8]
  · rw [if_neg (by omega), if_neg (by omega), if_neg hi8]

/-- The port (offsets 2..3) is inside the buffer, so it is decoded correctly
even by the buggy code (matching the observed repro output). -/
theorem impl_port {sa stack mem : Nat → UInt8} (h : RecvfromFills implBufLen sockaddrIn6Size sa stack mem) :
    readPort mem = readPort sa := by
  unfold readPort; rw [h 2, h 3]; rfl

/-- **Fix**: with a 28-byte buffer an IPv6 sender's address and port are
decoded exactly, whatever the stack holds. -/
theorem fixed_addr6 {sa stack mem : Nat → UInt8} (h : RecvfromFills fixedBufLen sockaddrIn6Size sa stack mem) :
    readAddr6 mem = readAddr6 sa ∧ readPort mem = readPort sa := by
  refine ⟨?_, ?_⟩
  · unfold readAddr6
    apply List.map_congr_left
    intro i hi
    rw [List.mem_range] at hi
    rw [h]; unfold fixedBufLen sockaddrIn6Size; rw [if_pos (by omega)]
  · unfold readPort; rw [h 2, h 3]; rfl

/-- IPv4 senders are decoded correctly with either buffer size. -/
theorem addr4_ok (bufLen : Nat) (hb : 16 ≤ bufLen) {sa stack mem : Nat → UInt8}
    (h : RecvfromFills bufLen sockaddrInSize sa stack mem) :
    readAddr4 mem = readAddr4 sa ∧ readPort mem = readPort sa := by
  refine ⟨?_, ?_⟩
  · unfold readAddr4
    apply List.map_congr_left
    intro i hi
    rw [List.mem_range] at hi
    rw [h]; unfold sockaddrInSize; rw [if_pos (by omega)]
  · unfold readPort; rw [h 2, h 3]; unfold sockaddrInSize; rw [if_pos (by omega), if_pos (by omega)]

end Flare.L2.Udp
