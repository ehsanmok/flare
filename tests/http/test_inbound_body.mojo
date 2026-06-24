"""Incremental inbound body streaming to the handler (v0.9 B5).

A forked server runs a front that opts into front-owned inbound body
consumption (``enable_inbound``) and drains the request body in fixed
64 KiB chunks via ``read_body``, keeping only a running byte counter --
never the whole body. The parent streams a multi-megabyte body, half-
closes its write side, and reads back the byte count the server tallied.

Asserts the server received every byte while holding at most one chunk at
a time (peak memory independent of body size) -- the B5 acceptance.
"""

from std.collections import Dict
from std.testing import assert_equal, assert_true

from flare.http import HttpServer
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


struct CountBody(Movable, StreamHandler):
    """Counts inbound body bytes in bounded memory; on EOF it replies with
    the total and closes. ``max_chunk`` proves the per-read bound."""

    var totals: Dict[Int, Int]
    var max_chunk: Dict[Int, Int]

    def __init__(out self):
        self.totals = Dict[Int, Int]()
        self.max_chunk = Dict[Int, Int]()

    def on_open(mut self, mut conn: StreamConn) raises:
        conn.enable_inbound()
        self.totals[conn.id()] = 0
        self.max_chunk[conn.id()] = 0

    def on_upstream(mut self, mut conn: StreamConn) raises:
        pass

    def on_writable(mut self, mut conn: StreamConn) raises:
        var id = conn.id()
        var total = self.totals[id]
        var mx = self.max_chunk[id]
        var saw_eof = False
        while True:
            var p = conn.read_body(65536)
            if p.is_ready():
                var c = p.take_chunk()
                var n = len(c)
                total += n
                if n > mx:
                    mx = n
            elif p.is_eof():
                saw_eof = True
                break
            else:
                break  # pending: wait for the next readable edge
        self.totals[id] = total
        self.max_chunk[id] = mx
        if saw_eof:
            # Reply: "<total>:<max_chunk_seen>" then close.
            conn.send((String(total) + ":" + String(mx)).as_bytes())
            conn.request_close()

    def on_close(mut self, mut conn: StreamConn) raises:
        if conn.id() in self.totals:
            _ = self.totals.pop(conn.id())
        if conn.id() in self.max_chunk:
            _ = self.max_chunk.pop(conn.id())


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

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_streaming(CountBody())
        except:
            pass
        exit()

    usleep(200_000)

    var mb = 4
    var total_bytes = mb * 1024 * 1024
    var block = List[UInt8](capacity=65536)
    for j in range(65536):
        block.append(UInt8(48 + (j % 10)))

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var written = 0
    while written < total_bytes:
        client.write_all(Span[UInt8, _](block))
        written += 65536
    client.shutdown_write()  # signal end-of-body (clean FIN on write side)

    var reply = _read_all(client)
    client.close()

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    # reply == "<total>:<max_chunk>"
    var colon = reply.find(":")
    assert_true(colon > 0, "malformed reply: " + reply)
    var got_total = Int(reply[byte=0:colon])
    var got_max = Int(reply[byte = colon + 1 :])
    assert_equal(got_total, written)
    # Bounded memory: no single read exceeded the 64 KiB request size.
    assert_true(
        got_max <= 65536,
        "peak chunk exceeded the bound: " + String(got_max),
    )
    print(
        "test_inbound_body: passed (",
        written,
        "bytes, peak chunk ",
        got_max,
        ")",
    )
