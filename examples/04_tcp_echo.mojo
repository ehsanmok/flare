"""Example 04: TCP — TcpListener + TcpStream.

Demonstrates:
  - ``TcpListener.bind()`` and ``local_addr()``
  - Non-blocking connect + ``accept()`` over loopback
  - ``write_all()`` / ``read()`` round-trip
  - ``TcpStream`` options: ``set_nodelay()``, ``set_keepalive()``

Run:
    pixi run example-tcp
"""

from testing import assert_equal
from flare.tcp import TcpStream, TcpListener
from flare.net import SocketAddr


fn zero_buf(n: Int) -> List[UInt8]:
    var b = List[UInt8]()
    b.resize(n, 0)
    return b^


fn main() raises:
    print("=== flare Example 04: TCP ===")
    print()

    # ── 1. Bind listener on an OS-assigned port ───────────────────────────────
    print("── 1. Bind + accept ──")
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    print("  Listening on 127.0.0.1:" + String(port))

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()

    print("  client local addr : " + String(client.local_addr()))
    print("  server peer  addr : " + String(server.peer_addr()))
    print()

    # ── 2. Bidirectional ping-pong ─────────────────────────────────────────────
    print("── 2. Ping-pong round-trip ──")
    var msg = String("hello, flare!")
    var payload = msg.as_bytes()
    client.write_all(Span[UInt8](payload))
    print("  client → server: '" + msg + "'")

    var buf = zero_buf(64)
    var n = server.read(buf.unsafe_ptr(), len(buf))
    var received = String(unsafe_from_utf8=buf[:n])
    print("  server received : '" + received + "'")
    assert_equal(received, msg)

    server.write_all(Span[UInt8](buf[:n]))
    var echo_buf = zero_buf(64)
    var n2 = client.read(echo_buf.unsafe_ptr(), len(echo_buf))
    var echoed = String(unsafe_from_utf8=echo_buf[:n2])
    print("  client echo     : '" + echoed + "'")
    assert_equal(n2, n)
    print()

    # ── 3. Socket options ─────────────────────────────────────────────────────
    print("── 3. Socket options ──")
    client.set_nodelay(True)
    client.set_nodelay(False)
    client.set_keepalive(True)
    client.set_keepalive(False)
    print("  set_nodelay / set_keepalive: OK")
    print()

    # ── 4. Large payload (64 KiB) ─────────────────────────────────────────────
    print("── 4. Large payload (64 KiB) ──")
    var big = List[UInt8]()
    for i in range(65536):
        big.append(UInt8(i & 0xFF))
    client.write_all(Span[UInt8](big))

    var recv = zero_buf(65536)
    var total = 0
    while total < 65536:
        var chunk = zero_buf(4096)
        var got = server.read(chunk.unsafe_ptr(), len(chunk))
        if got == 0:
            break
        for i in range(got):
            recv[total + i] = chunk[i]
        total += got
    assert_equal(total, 65536)
    print("  transferred " + String(total) + " bytes OK")
    print()

    # ── Cleanup ───────────────────────────────────────────────────────────────
    client.close()
    server.close()
    listener.close()
    print("=== Example 04 complete ===")
