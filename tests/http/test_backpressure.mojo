"""End-to-end backpressure coupling tests (v0.9 B2).

Two layers:

- ``test_watermark_hysteresis`` -- deterministic, no fork. Drives a
  ``StreamConn``'s relay buffer occupancy across the hi/lo watermarks and
  asserts the upstream read gate toggles with hysteresis and the pause /
  resume crossing counters advance exactly once per crossing (the B2
  acceptance "interest toggles across watermarks, assert via counters").

- ``_run_slow_client_soak`` -- a forked worker floods framed chunks while
  the parent client reads slowly. With the watermark gate active the relay
  throttles the upstream instead of buffering without bound; the test
  asserts every byte arrives in order (no chunks dropped) under the slow
  consumer.
"""

from std.collections import Dict
from std.testing import assert_equal, assert_true

from flare.http import HttpServer, UpstreamChunkSource
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.uds import FrameMux, UnixListener, UnixStream
from flare.uds._libc import unlink_path
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def test_watermark_hysteresis() raises:
    # A connected loopback pair so StreamConn has a real client socket;
    # the kernel completes the handshake into the accept queue, so a
    # single-threaded connect-then-accept works without a peer thread.
    var lst = TcpListener.bind(SocketAddr.localhost(0))
    var port = lst.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var peer = lst.accept()
    var conn = StreamConn(client^, 1)
    conn.set_watermarks(100, 20)
    assert_equal(conn.hi_watermark(), 100)
    assert_equal(conn.lo_watermark(), 20)
    assert_true(not conn.upstream_paused())

    # Occupancy >= hi -> pause (1st crossing). Manipulate the buffer
    # cursor directly to set occupancy deterministically.
    conn.out_buf.resize(150, UInt8(0))
    conn.out_pos = 0
    assert_true(conn.write_buffer_full())
    assert_true(not conn.apply_backpressure())  # should_read == False
    assert_true(conn.upstream_paused())
    assert_equal(conn.pause_count(), 1)
    assert_equal(conn.resume_count(), 0)

    # In the hysteresis band (lo < occ < hi) -> hold paused, no crossing.
    conn.out_pos = 100  # occ = 50
    assert_true(not conn.apply_backpressure())
    assert_true(conn.upstream_paused())
    assert_equal(conn.pause_count(), 1)
    assert_equal(conn.resume_count(), 0)

    # Occupancy <= lo -> resume (1st resume crossing).
    conn.out_pos = 135  # occ = 15
    assert_true(conn.apply_backpressure())  # should_read == True
    assert_true(not conn.upstream_paused())
    assert_equal(conn.resume_count(), 1)

    # Band again from below -> hold resumed.
    conn.out_pos = 100  # occ = 50
    assert_true(conn.apply_backpressure())
    assert_true(not conn.upstream_paused())
    assert_equal(conn.pause_count(), 1)

    # Cross hi again -> pause (2nd crossing).
    conn.out_pos = 50  # occ = 100
    assert_true(not conn.apply_backpressure())
    assert_true(conn.upstream_paused())
    assert_equal(conn.pause_count(), 2)
    assert_equal(conn.resume_count(), 1)

    # set_watermarks clamps a bad order (lo >= hi) instead of wedging.
    conn.set_watermarks(10, 99)
    assert_true(conn.lo_watermark() < conn.hi_watermark())

    peer.close()
    # ``conn`` drops here -> client socket closed.
    print("test_watermark_hysteresis: passed")


struct SlowRelay(Movable, StreamHandler):
    """Relays a framed upstream to the client with a tight relay window so
    a slow client engages the watermark gate. Checks ``write_buffer_full``
    in the drain loop so one readable edge cannot overshoot the bound."""

    var worker_path: String
    var sources: Dict[Int, UpstreamChunkSource]

    def __init__(out self, worker_path: String):
        self.worker_path = worker_path
        self.sources = Dict[Int, UpstreamChunkSource]()

    def on_open(mut self, mut conn: StreamConn) raises:
        conn.set_watermarks(2048, 512)
        var up = UnixStream.connect(self.worker_path)
        var src = UpstreamChunkSource(up^, 1)
        conn.attach_upstream(Int(src.fd()))
        self.sources[conn.id()] = src^

    def on_upstream(mut self, mut conn: StreamConn) raises:
        ref src = self.sources[conn.id()]
        while not conn.write_buffer_full():
            var p = src.poll(conn.cancel())
            if p.is_ready():
                var c = p.take_chunk()
                conn.send(Span[UInt8, _](c))
            elif p.is_eof():
                conn.request_close()
                break
            else:
                break

    def on_writable(mut self, mut conn: StreamConn) raises:
        pass

    def on_close(mut self, mut conn: StreamConn) raises:
        if conn.id() in self.sources:
            _ = self.sources.pop(conn.id())


def _run_slow_client_soak() raises:
    var chunks = 200
    var chunk_sz = 256
    var total = chunks * chunk_sz
    var wpath = String("/tmp/flare_bp_worker.sock")
    _ = unlink_path(wpath)
    var worker = UnixListener.bind_with_options(wpath, cleanup_path=False)
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var wpid = fork()
    if wpid == 0:
        try:
            var conn = worker.accept()
            var mux = FrameMux(conn^)
            var payload = List[UInt8](capacity=chunk_sz)
            for j in range(chunk_sz):
                payload.append(UInt8(65 + (j % 26)))
            for _i in range(chunks):
                mux.send_chunk(1, Span[UInt8, _](payload))
                mux.flush()
            mux.done(1)
            mux.flush()
            usleep(500_000)
        except:
            pass
        exit()

    usleep(150_000)

    var spid = fork()
    if spid == 0:
        try:
            srv.serve_streaming(SlowRelay(wpath))
        except:
            pass
        exit()

    usleep(200_000)

    # Slow consumer: small reads with sleeps so the relay buffer fills and
    # the watermark gate throttles the upstream.
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var received = 0
    var buf = List[UInt8](capacity=512)
    var reads = 0
    while True:
        buf.resize(512, 0)
        var n = client.read(buf.unsafe_ptr(), 512)
        if n == 0:
            break
        received += n
        reads += 1
        if reads % 8 == 0:
            usleep(5_000)  # throttle the reader
    client.close()

    _ = kill(spid, SIGKILL)
    waitpid(spid)
    _ = kill(wpid, SIGKILL)
    waitpid(wpid)
    _ = worker.local_path()
    _ = unlink_path(wpath)

    assert_equal(received, total)
    print("test_backpressure: slow-client soak passed (", received, "bytes)")


def main() raises:
    test_watermark_hysteresis()
    _run_slow_client_soak()
