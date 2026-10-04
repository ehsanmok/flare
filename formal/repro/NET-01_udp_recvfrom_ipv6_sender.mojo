# PLATFORM: any
"""NET-01: UdpSocket.recv_from / try_recv_from report the wrong IPv6 sender.

Lean: Flare.Bugs.NET_01.recvFrom_ipv6_wrong_sender (counterexample) and
Flare.Bugs.NET_01.recvFromFixed_correct (fix meets spec).
flare/udp/socket.mojo:279-352 @59bda50.

Expected: recv_from on an IPv6 socket returns the sender's real address
and port ([::1]:<tx port>).
Actual: the sockaddr buffer handed to recvfrom(2) is SOCKADDR_IN_SIZE
(16) bytes. The kernel truncates the 28-byte sockaddr_in6 to 16 bytes
(family, port, flowinfo, first 8 address bytes) and
_read_ipv6_from_sockaddr then reads sin6_addr from bytes 8..23, i.e. 8
bytes past the end of the stack buffer. The reported address is wrong
(and the read is out of bounds).

Minimal fix: allocate SOCKADDR_IN6_SIZE (28) bytes for peer_buf and
pass SOCKADDR_IN6_SIZE as peer_len in both recv_from and try_recv_from.
"""

from flare.net import SocketAddr
from flare.udp import UdpSocket


def main() raises:
    var rx = UdpSocket.bind(SocketAddr.parse("[::1]:0"))
    var tx = UdpSocket.bind(SocketAddr.parse("[::1]:0"))
    var msg = String("ping")
    _ = tx.send_to(msg.as_bytes(), rx.local_addr())
    var buf = List[UInt8](length=64, fill=UInt8(0))
    var got = rx.recv_from(Span[UInt8, _](buf))
    var want = tx.local_addr()
    var seen = got[1]
    if got[0] != 4 or seen != want:
        print(
            "BUG REPRODUCED: recv_from reported sender",
            String(seen),
            "but the datagram came from",
            String(want),
        )
        raise Error("NET-01")
    print("OK: recv_from reported the IPv6 sender", String(seen))
