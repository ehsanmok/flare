"""Loopback test for the reactor-integrated streaming source (v0.9 B1).

A forked worker emits N framed CHUNK frames with artificial gaps
(``usleep`` between them) and then a DONE frame. The parent consumes them
through an ``UpstreamChunkSource``:

- every chunk arrives, in order (correctness);
- during a gap ``poll`` returns ``pending(fd)`` and the consumer parks on
  the fd with ``poll(2)`` rather than spinning -- proven by an iteration
  counter that stays within a small bound (no busy-poll, B1 acceptance);
- the terminating DONE frame surfaces as ``eof``.

Also unit-checks the ``ChunkPoll`` tri-state factories.
"""

from std.collections import Dict
from std.ffi import c_int, c_uint
from std.memory import stack_allocation
from std.testing import assert_equal, assert_true

from flare.http import ChunkPoll, HttpServer, UpstreamChunkSource
from flare.http.cancel import Cancel
from flare.http.streaming_server import StreamConn, StreamHandler
from flare.net import SocketAddr
from flare.net._libc import _poll
from flare.tcp import TcpStream
from flare.uds import FrameMux, UnixListener, UnixStream
from flare.uds._libc import unlink_path
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime POLLIN: Int = 0x0001


def _park(fd: c_int, timeout_ms: Int) raises -> Int:
    """Block until ``fd`` is readable (or timeout). Returns poll(2)'s
    result. Builds one ``pollfd`` { int fd; short events; short revents }."""
    var pfd = stack_allocation[8, UInt8]()
    var fdv = Int(fd)
    pfd[0] = UInt8(fdv & 0xFF)
    pfd[1] = UInt8((fdv >> 8) & 0xFF)
    pfd[2] = UInt8((fdv >> 16) & 0xFF)
    pfd[3] = UInt8((fdv >> 24) & 0xFF)
    pfd[4] = UInt8(POLLIN & 0xFF)
    pfd[5] = UInt8((POLLIN >> 8) & 0xFF)
    pfd[6] = 0
    pfd[7] = 0
    return Int(_poll(pfd, c_uint(1), c_int(timeout_ms)))


def test_chunk_poll_tristate() raises:
    var r = ChunkPoll.ready(List[UInt8](capacity=0))
    assert_true(r.is_ready())
    assert_true(not r.is_pending())
    assert_true(not r.is_eof())

    var p = ChunkPoll.pending(c_int(7))
    assert_true(p.is_pending())
    assert_equal(Int(p.wait_fd()), 7)

    var e = ChunkPoll.eof()
    assert_true(e.is_eof())
    assert_equal(Int(e.wait_fd()), -1)


def test_chunk_poll_consume() raises:
    """F6: ``consume`` collapses ready -> Some / eof -> None and refuses
    to consume a pending poll (it must be parked, not drained)."""
    var bytes = List[UInt8]()
    bytes.append(UInt8(65))
    bytes.append(UInt8(66))
    var r = ChunkPoll.ready(bytes^)
    var got = r.consume()
    assert_true(got.__bool__())
    assert_equal(len(got.value()), 2)
    assert_equal(Int(got.value()[0]), 65)

    var e = ChunkPoll.eof()
    assert_true(not e.consume().__bool__())

    var raised = False
    var p = ChunkPoll.pending(c_int(7))
    try:
        _ = p.consume()
    except:
        raised = True
    assert_true(raised, "consume on a pending poll must raise")


struct RelayFront(Movable, StreamHandler):
    """A streaming front that relays an upstream framed source to the
    client with no bespoke reactor code: ``on_open`` connects the
    upstream and attaches its fd; ``on_upstream`` polls the source and
    sends ready chunks; ``request_close`` on EOF."""

    var worker_path: String
    var sources: Dict[Int, UpstreamChunkSource]

    def __init__(out self, worker_path: String):
        self.worker_path = worker_path
        self.sources = Dict[Int, UpstreamChunkSource]()

    def on_open(mut self, mut conn: StreamConn) raises:
        var up = UnixStream.connect(self.worker_path)
        var src = UpstreamChunkSource(up^, 1)
        conn.attach_upstream(Int(src.fd()))
        self.sources[conn.id()] = src^

    def on_upstream(mut self, mut conn: StreamConn) raises:
        ref src = self.sources[conn.id()]
        while True:
            var p = src.poll(conn.cancel())
            if p.is_ready():
                var c = p.take_chunk()
                conn.send(Span[UInt8, _](c))
            elif p.is_eof():
                conn.request_close()
                break
            else:
                break  # pending: park until the next readable edge

    def on_writable(mut self, mut conn: StreamConn) raises:
        pass

    def on_close(mut self, mut conn: StreamConn) raises:
        if conn.id() in self.sources:
            _ = self.sources.pop(conn.id())


def _read_all_tcp(mut s: TcpStream) raises -> String:
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


def _run_reactor_e2e() raises:
    """Acceptance #1: a handler streams a response sourced from a
    registered fd through ``serve_streaming`` with zero bespoke reactor
    code. A worker child emits framed chunks with gaps; a server child
    relays them to the parent TCP client via ``RelayFront``."""
    var M = 4
    var wpath = String("/tmp/flare_async_e2e_worker.sock")
    _ = unlink_path(wpath)
    var worker = UnixListener.bind_with_options(wpath, cleanup_path=False)
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var wpid = fork()
    if wpid == 0:
        try:
            var conn = worker.accept()
            var mux = FrameMux(conn^)
            for i in range(M):
                mux.send_chunk(1, ("frag" + String(i)).as_bytes())
                mux.flush()
                usleep(30_000)
            mux.done(1)
            mux.flush()
            usleep(300_000)
        except:
            pass
        exit()

    usleep(150_000)

    var spid = fork()
    if spid == 0:
        try:
            srv.serve_streaming(RelayFront(wpath))
        except:
            pass
        exit()

    usleep(200_000)

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var got = _read_all_tcp(client)
    client.close()

    _ = kill(spid, SIGKILL)
    waitpid(spid)
    _ = kill(wpid, SIGKILL)
    waitpid(wpid)
    _ = worker.local_path()
    _ = unlink_path(wpath)

    var expected = String("")
    for i in range(M):
        expected += "frag" + String(i)
    assert_equal(got, expected)
    print("test_async_chunk_source: reactor e2e passed (", M, "frags relayed)")


def main() raises:
    test_chunk_poll_tristate()
    test_chunk_poll_consume()

    var N = 5
    var path = String("/tmp/flare_async_src_test.sock")
    _ = unlink_path(path)
    # cleanup_path=False: the path lifecycle spans the fork (see
    # test_frame_mux for the rationale); the parent unlinks at the end.
    var listener = UnixListener.bind_with_options(path, cleanup_path=False)

    var pid = fork()
    if pid == 0:
        # Worker: accept, emit N framed chunks with gaps, then DONE.
        try:
            var conn = listener.accept()
            var mux = FrameMux(conn^)
            for i in range(N):
                mux.send_chunk(1, ("tok" + String(i)).as_bytes())
                mux.flush()
                usleep(40_000)  # artificial gap -> consumer must park
            mux.done(1)
            mux.flush()
            usleep(200_000)
        except:
            pass
        exit()

    usleep(150_000)

    var conn = UnixStream.connect(path)
    var src = UpstreamChunkSource(conn^, 1)
    var cancel = Cancel.never()

    var got = List[String]()
    var poll_calls = 0
    var guard = 0
    while guard < 100000:
        guard += 1
        poll_calls += 1
        var p = src.poll(cancel)
        if p.is_ready():
            var chunk = p.take_chunk()
            got.append(String(unsafe_from_utf8=Span[UInt8, _](chunk)))
        elif p.is_eof():
            break
        else:
            # Pending: park on the fd until readable. This is the
            # no-busy-poll contract -- we sleep in poll(2), not spin.
            _ = _park(p.wait_fd(), 2000)

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    _ = listener.local_path()
    _ = unlink_path(path)

    assert_equal(len(got), N)
    for i in range(N):
        assert_equal(got[i], "tok" + String(i))

    # No busy-poll: at most one ready + one pending per chunk, plus the
    # terminating eof -- comfortably under 4*N. A spin would be millions.
    assert_true(
        poll_calls <= 4 * N + 4,
        "async source busy-polled: "
        + String(poll_calls)
        + " poll() calls for "
        + String(N)
        + " chunks",
    )
    print(
        "test_async_chunk_source: passed (", N, "chunks, ", poll_calls, "polls)"
    )

    _run_reactor_e2e()
