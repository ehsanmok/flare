"""Example 14: Direct Reactor usage (advanced).

Demonstrates:
  - Creating a ``Reactor`` (epoll on Linux, kqueue on macOS)
  - Registering a TCP listener with ``INTEREST_READ``
  - Driving a one-shot ``poll()`` to get a readable event
  - Handling the accept + byte round-trip
  - Tearing the reactor down cleanly

Most users will never touch ``flare.runtime`` directly; ``HttpServer``
and ``WsServer`` already use the reactor internally and expose a
friendlier request handler API. This example exists to make the Stage 1
architecture visible so you can build your own protocol on top of the
same event loop.

See also:
  - Example 08 (HttpServer) for the high-level HTTP-specific reactor.
  - ``flare/http/_server_reactor_impl.mojo`` for the production
    state-machine that handles many connections at once.

Run:
    pixi run example-reactor
"""

from flare.net import SocketAddr
from flare.runtime import Reactor, Event, INTEREST_READ
from flare.tcp import TcpStream, TcpListener


def main() raises:
    print("=== flare Example 14: Reactor ===")
    print()

    # ── 1. Create a reactor ───────────────────────────────────────────────────
    print("── 1. Create a reactor (platform: kqueue on macOS, epoll on Linux)")
    var reactor = Reactor()
    print(" registered_count =", reactor.registered_count())
    print()

    # ── 2. Register a TCP listener's fd with INTEREST_READ ───────────────────
    print("── 2. Register listener fd with INTEREST_READ ──")
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var listener_fd = listener._socket.fd
    var LISTENER_TOKEN = UInt64(1)
    reactor.register(listener_fd, LISTENER_TOKEN, INTEREST_READ)
    print(
        " listening on 127.0.0.1:"
        + String(port)
        + " token="
        + String(LISTENER_TOKEN)
    )
    print()

    # ── 3. Connect a client; poll expects a readable event on the listener ──
    print("── 3. poll() picks up the incoming connection ──")
    var client = TcpStream.connect(SocketAddr.localhost(port))

    var events = List[Event]()
    # Up to 100ms for the kernel to mark the listener readable.
    _ = reactor.poll(100, events)
    print(" events observed:", len(events))
    for i in range(len(events)):
        var ev = events[i]
        print(
            " token=" + String(ev.token),
            " readable=" + String(ev.is_readable()),
            " writable=" + String(ev.is_writable()),
            " hup=" + String(ev.is_hup()),
        )
    print()

    # ── 4. Accept + echo one byte so the example does real work ─────────────
    print("── 4. accept + one-byte round-trip ──")
    var server = listener.accept()
    var m = List[UInt8]()
    m.append(UInt8(ord("A")))
    client.write_all(Span[UInt8](m))
    var buf = List[UInt8]()
    buf.resize(1, UInt8(0))
    var n = server.read(buf.unsafe_ptr(), 1)
    print(" server read " + String(n) + " byte: '" + chr(Int(buf[0])) + "'")
    print()

    # ── 5. Unregister + teardown ────────────────────────────────────────────
    print("── 5. Unregister and close ──")
    reactor.unregister(listener_fd)
    print(" registered_count =", reactor.registered_count())
    client.close()
    server.close()
    listener.close()

    print()
    print("=== Example 14 complete ===")
