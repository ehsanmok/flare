"""Tests for :mod:`flare.http.streaming_server` (v0.9 A1).

Drives the ``StreamHandler`` lifecycle over a real in-process loopback
TCP connection via ``run_stream_connection``. Asserts that:

- the handler reaches its shared state as typed ``mut self`` fields
  (no ``Int``-as-pointer, no ``unsafe_from_address``),
- one handler instance shared across connections accumulates state,
- the per-connection id is delivered to the handler, and
- the lifecycle order is on_open -> on_writable* -> on_close with the
  bytes arriving at the client in order.
"""

from std.collections import Dict
from std.testing import assert_equal, assert_true

from flare.http.streaming_server import (
    StreamConn,
    StreamHandler,
    run_stream_connection,
)
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream


# A streaming front whose shared state is its own typed fields.
struct ChunkFront(Movable, StreamHandler):
    var opened: Int
    var closed: Int
    var seen_ids: List[Int]
    # Per-connection state keyed by conn.id(): how many chunks emitted.
    var per_conn_writes: Dict[Int, Int]

    def __init__(out self):
        self.opened = 0
        self.closed = 0
        self.seen_ids = List[Int]()
        self.per_conn_writes = Dict[Int, Int]()

    def on_open(mut self, mut conn: StreamConn) raises:
        self.opened += 1
        self.seen_ids.append(conn.id())
        self.per_conn_writes[conn.id()] = 0
        conn.send("open\n".as_bytes())

    def on_upstream(mut self, mut conn: StreamConn) raises:
        pass

    def on_writable(mut self, mut conn: StreamConn) raises:
        var sent = self.per_conn_writes[conn.id()]
        if sent < 3:
            conn.send(("chunk " + String(sent) + "\n").as_bytes())
            self.per_conn_writes[conn.id()] = sent + 1
        else:
            conn.request_close()

    def on_close(mut self, mut conn: StreamConn) raises:
        self.closed += 1
        # Framework-owned lifecycle: drop our per-connection entry.
        _ = self.per_conn_writes.pop(conn.id())


def _read_all(mut s: TcpStream) raises -> String:
    var out = List[UInt8]()
    var chunk = List[UInt8](capacity=4096)
    while True:
        chunk.resize(4096, 0)
        var n = s.read(chunk.unsafe_ptr(), 4096)
        if n == 0:
            break
        for i in range(n):
            out.append(chunk[i])
    return String(unsafe_from_utf8=Span[UInt8, _](out))


def _drive_one(mut handler: ChunkFront, id: Int) raises -> String:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var addr = listener.local_addr()
    var client = TcpStream.connect(addr)
    var server = listener.accept()
    run_stream_connection(handler, server^, id)
    var got = _read_all(client)
    client.close()
    return got


def test_single_connection_lifecycle() raises:
    var handler = ChunkFront()
    var got = _drive_one(handler, 7)
    assert_equal(got, "open\nchunk 0\nchunk 1\nchunk 2\n")
    assert_equal(handler.opened, 1)
    assert_equal(handler.closed, 1)
    # on_close dropped the per-connection entry.
    assert_true(7 not in handler.per_conn_writes)
    # The per-connection id reached the handler.
    assert_equal(len(handler.seen_ids), 1)
    assert_equal(handler.seen_ids[0], 7)


def test_shared_state_across_connections() raises:
    # One handler instance, two sequential connections: the typed
    # shared state (counters) accumulates across both.
    var handler = ChunkFront()
    var got1 = _drive_one(handler, 1)
    var got2 = _drive_one(handler, 2)
    assert_equal(got1, "open\nchunk 0\nchunk 1\nchunk 2\n")
    assert_equal(got2, "open\nchunk 0\nchunk 1\nchunk 2\n")
    assert_equal(handler.opened, 2)
    assert_equal(handler.closed, 2)
    assert_equal(len(handler.seen_ids), 2)
    assert_equal(handler.seen_ids[0], 1)
    assert_equal(handler.seen_ids[1], 2)


def main() raises:
    test_single_connection_lifecycle()
    test_shared_state_across_connections()
    print("test_streaming_server: 2 passed")
