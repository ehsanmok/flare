"""Example 11: UDP datagrams with flare.udp.UdpSocket.

Demonstrates:
  - ``UdpSocket.bind()`` with an OS-assigned port
  - ``send_to()`` / ``recv_from()`` round-trip over loopback
  - Reading back the sender address from ``recv_from()``
  - Datagram size limits (``DatagramTooLarge``)

Run:
    pixi run example-udp
"""

from flare.net import SocketAddr
from flare.udp import UdpSocket, DatagramTooLarge


def zero_buf(n: Int) -> List[UInt8]:
    var b = List[UInt8]()
    b.resize(n, 0)
    return b^


def main() raises:
    print("=== flare Example 11: UDP ===")
    print()

    # ── 1. Bind two UDP sockets on loopback ──────────────────────────────────
    print("── 1. Bind two sockets ──")
    var server = UdpSocket.bind(SocketAddr.localhost(0))
    var client = UdpSocket.bind(SocketAddr.localhost(0))
    var server_port = server.local_addr().port
    var client_port = client.local_addr().port
    print("  server listening on 127.0.0.1:" + String(server_port))
    print("  client bound    on 127.0.0.1:" + String(client_port))
    print()

    # ── 2. Send + receive a datagram ─────────────────────────────────────────
    print("── 2. send_to -> recv_from ──")
    var msg = String("hello over UDP")
    var payload = msg.as_bytes()
    var sent = client.send_to(
        Span[UInt8](payload), SocketAddr.localhost(server_port)
    )
    print("  client sent " + String(sent) + " bytes")

    var buf = zero_buf(128)
    var received = server.recv_from(Span[UInt8](buf))
    var n = received[0]
    var sender = received[1]
    var text = String(unsafe_from_utf8=buf[:n])
    print("  server got  " + String(n) + " bytes: '" + text + "'")
    print("  sender addr: " + String(sender))
    print()

    # ── 3. Oversized datagram rejected locally before any syscall ───────────
    print("── 3. Oversized datagram raises DatagramTooLarge ──")
    var huge = List[UInt8]()
    huge.resize(100_000, UInt8(0))  # UDP max payload is ~65 KB
    try:
        _ = client.send_to(Span[UInt8](huge), SocketAddr.localhost(server_port))
        print("  [UNEXPECTED] oversized send returned OK")
    except e:
        print("  raised:", String(e))
    print()

    server.close()
    client.close()
    print("=== Example 11 complete ===")
