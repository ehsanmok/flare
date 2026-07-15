"""Stateful WsHandler trait over WsServer.serve[H] (ws:// loopback).

A :trait:`WsHandler` struct carries per-connection state via ``mut self``
and is mounted with the ``WsServer.serve[H]`` overload. This forks a
server running a counting-echo handler and drives it with a real
``WsClient``: three text frames come back tagged with the handler's
running count, proving the ``mut self`` state threads through the trait
dispatch across ``recv`` calls within a connection.
"""

from std.testing import assert_equal, assert_true

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.ws import (
    WsClient,
    WsConnection,
    WsHandler,
    WsOpcode,
    WsServer,
)
from flare.net import SocketAddr


@fieldwise_init
struct _CountingEcho(Copyable, Movable, WsHandler):
    """Replies ``count=N`` where N is the running message count held on
    the handler (exercises mut-self state through the trait)."""

    var total: Int

    def on_connection(mut self, mut conn: WsConnection) raises:
        while True:
            var frame = conn.recv()
            if frame.opcode == WsOpcode.CLOSE:
                break
            if frame.opcode == WsOpcode.TEXT:
                self.total += 1
                conn.send_text(String("count=") + String(self.total))


def main() raises:
    print("test_ws_stateful_handler")
    var srv = WsServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var pid = fork()
    if pid == 0:
        try:
            srv.serve[_CountingEcho](_CountingEcho(0))
        except:
            pass
        exit()
    usleep(200_000)

    var replies = List[String]()
    var raised = False
    try:
        var url = String("ws://127.0.0.1:") + String(port) + String("/ws")
        var ws = WsClient.connect(url)
        ws.send_text("a")
        replies.append(ws.recv().text_payload())
        ws.send_text("b")
        replies.append(ws.recv().text_payload())
        ws.send_text("c")
        replies.append(ws.recv().text_payload())
    except e:
        print("ws stateful raised:", e)
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_true(not raised, "ws stateful handler raised")
    assert_equal(len(replies), 3)
    assert_equal(replies[0], "count=1")
    assert_equal(replies[1], "count=2")
    assert_equal(replies[2], "count=3")
    print("test_ws_stateful_handler: 1 passed")
