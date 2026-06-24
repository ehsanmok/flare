"""End-to-end tests for ``HttpServer.serve_streaming`` (v0.9 A2).

Forks a child running the streaming reactor loop and drives it from the
parent with a real client socket. Asserts the reactor walks the
``StreamHandler`` lifecycle correctly: ``on_open`` queues a header,
``on_writable`` streams chunks with backpressure-correct draining, and
``request_close`` tears the connection down (client sees EOF) -- across
both a single connection and two sequential connections sharing one
handler instance.
"""

from std.collections import Dict
from std.testing import assert_equal

from flare.http import HttpServer
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


struct PushFront(Movable, StreamHandler):
    var n_chunks: Int
    var writes: Dict[Int, Int]

    def __init__(out self, n_chunks: Int):
        self.n_chunks = n_chunks
        self.writes = Dict[Int, Int]()

    def on_open(mut self, mut conn: StreamConn) raises:
        self.writes[conn.id()] = 0
        conn.send("HELLO\n".as_bytes())

    def on_upstream(mut self, mut conn: StreamConn) raises:
        pass

    def on_writable(mut self, mut conn: StreamConn) raises:
        var w = self.writes[conn.id()]
        if w < self.n_chunks:
            conn.send(("chunk " + String(w) + "\n").as_bytes())
            self.writes[conn.id()] = w + 1
        else:
            conn.request_close()

    def on_close(mut self, mut conn: StreamConn) raises:
        if conn.id() in self.writes:
            _ = self.writes.pop(conn.id())


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


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    var handler = PushFront(3)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_streaming(handler^)
        except:
            pass
        exit()
    usleep(250_000)

    var expected = String("HELLO\nchunk 0\nchunk 1\nchunk 2\n")

    # First connection.
    var c1 = TcpStream.connect(SocketAddr.localhost(port))
    var got1 = _read_all(c1)
    c1.close()

    # Second connection on the same server / handler instance.
    var c2 = TcpStream.connect(SocketAddr.localhost(port))
    var got2 = _read_all(c2)
    c2.close()

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_equal(got1, expected)
    assert_equal(got2, expected)
    print("test_streaming_server_reactor: 2 passed")
