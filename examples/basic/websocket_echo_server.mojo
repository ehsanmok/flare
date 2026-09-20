"""A WebSocket echo server that keeps accepting connections.

The canonical WebSocket demonstration, and the server the Autobahn
test suite drives. `wstest -m fuzzingclient` opens several hundred
connections in sequence, each one probing a different corner of RFC
6455 and RFC 7692, and expects every data frame it sends to come back
byte for byte.

It is a `WsHandler` struct rather than a plain callback because the
connection budget has to survive between connections, which is exactly
what the struct variant of `WsServer.serve` is for.

Run bare, it serves itself: a forked child connects once, sends a
message, checks what comes back, and the server exits when its
connection budget is spent. So the example terminates, needs no
network, and still shows the real accept loop.

Environment:
    FLARE_WS_ECHO_PORT      : Listen port (default 9001, Autobahn's).
    FLARE_WS_ECHO_MAX_CONNS : Stop after this many connections. Default
                              1, with the self-test client. Set 0 to
                              serve until killed and skip the client,
                              which is what the conformance run does.

Its client-side counterpart is `websocket_echo.mojo`, which connects
to a server like this one.

Run:
    pixi run example-websocket-echo-server
    FLARE_WS_ECHO_MAX_CONNS=0 pixi run example-websocket-echo-server
"""

from std.os import getenv

from flare.net import SocketAddr
from flare.utils import exit, fork, usleep, waitpid
from flare.ws import (
    WsClient,
    WsCloseCode,
    WsConnection,
    WsHandler,
    WsOpcode,
    WsServer,
)


struct EchoHandler(Movable, WsHandler):
    """Echoes every data frame until the peer closes."""

    var served: Int
    """Connections completed so far."""

    var budget: Int
    """Stop after this many; ``0`` means never stop."""

    def __init__(out self, budget: Int):
        self.served = 0
        self.budget = budget

    def on_connection(mut self, mut conn: WsConnection) raises -> None:
        """Run one connection to completion, echoing as it goes.

        `recv` answers PING itself, so only TEXT, BINARY and CLOSE
        reach here. A fragmented message arrives reassembled, which is
        what lets the echo be a single send.
        """
        while True:
            var frame = conn.recv()
            if frame.opcode == WsOpcode.CLOSE:
                conn.close(WsCloseCode.NORMAL)
                break
            if frame.opcode == WsOpcode.TEXT:
                conn.send_text(frame.text_payload())
            elif frame.opcode == WsOpcode.BINARY:
                conn.send_binary(frame.payload.copy())

        self.served += 1
        if self.budget > 0 and self.served >= self.budget:
            print("echo: served", self.served, "connection(s); done")
            # `serve` has no way to be asked to stop, so leaving is the
            # only way out of its accept loop. Nothing is buffered at
            # this point: the CLOSE above has already gone out.
            exit()


def _self_test(port: UInt16) raises:
    """One round trip, from a forked child, so the example terminates."""
    usleep(300000)
    var c = WsClient.connect("ws://127.0.0.1:" + String(port) + "/")
    c.send_text("hello from the self-test")
    var echoed = c.recv().text_payload()
    c.close()
    if echoed != "hello from the self-test":
        print("echo: MISMATCH, got", echoed)
        exit()
    print("echo: round trip ok")


def main() raises:
    var port = UInt16(atol(getenv("FLARE_WS_ECHO_PORT", "9001")))
    var budget = atol(getenv("FLARE_WS_ECHO_MAX_CONNS", "1"))

    var srv = WsServer.bind(SocketAddr.localhost(port))
    var bound = srv.local_addr().port
    print("echo: listening on 127.0.0.1:" + String(bound))

    if budget <= 0:
        print("echo: serving until killed")
        srv.serve(EchoHandler(0))
        return

    print("echo: will stop after", budget, "connection(s)")
    var pid = fork()
    if pid == 0:
        try:
            _self_test(bound)
        except e:
            print("echo: self-test failed:", e)
        exit()
    srv.serve(EchoHandler(budget))
    waitpid(pid)
