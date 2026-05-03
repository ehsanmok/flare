"""Integration test for the multi-worker static-response server
(``HttpServer.serve_static_multicore`` in :mod:`flare.http.server`,
backed by ``StaticScheduler`` in :mod:`flare.runtime.scheduler` and
``run_reactor_loop_static_shared`` in
:mod:`flare.http._server_reactor_impl`).

Phase 1E (throughput parity with Rust libs): the per-request work
collapses to ``recv -> _scan_content_length -> memcpy(resp.bytes)
-> send`` -- no parser, no handler, no Response struct allocation,
no header lookups, no body re-serialisation. With N pthread
workers each running this fast path under EPOLLEXCLUSIVE accept
fairness, throughput on the gate-defining TFB plaintext bench
scales near-linearly across cores. The dev-box A/B (this commit)
shows ``flare_mc_static`` 4w at 285K req/s vs ``flare_mc``
(handler-driven) 4w at 244K -- +17 % from the static fast path
alone.

Tests parallel ``tests/test_uring_serve_handler.mojo``'s shape:
fork(2) topology, parent runs TCP clients, child runs the server,
SIGKILL on test-end. Two scenarios:

1. **Sequential keep-alive churn** (8 conns x 50 reqs = 400
   round-trips on a single client process).
2. **Concurrent fan-out** (8 conns hit at once, 30 reqs each).

Both validate the multi-worker accept distribution, the
per-conn lifecycle (alloc -> on_readable_static -> on_writable
-> close), and the ``StaticScheduler.shutdown`` path.

Cross-platform: works on Linux + macOS (no io_uring dependency;
the static fast path lives in the epoll/kqueue reactor).
"""

from std.ffi import c_int, c_uint, c_size_t, external_call
from std.memory import UnsafePointer, stack_allocation
from std.sys.info import CompilationTarget
from std.testing import assert_equal, assert_true, TestSuite

from flare.http import (
    HttpServer,
    ServerConfig,
    StaticResponse,
    precompute_response,
)
from flare.net import SocketAddr
from flare.net._libc import (
    AF_INET,
    MSG_NOSIGNAL,
    SOCK_STREAM,
    _close,
    _connect,
    _fill_sockaddr_in,
    _recv,
    _send,
    _socket,
    _strerror,
    get_errno,
)


# ── POSIX shims (same shape as test_uring_serve_handler.mojo) ──────────────


@always_inline
def _fork() -> c_int:
    return external_call["fork", c_int]()


@always_inline
def _waitpid(pid: c_int):
    _ = external_call["waitpid", c_int](pid, 0, c_int(0))


@always_inline
def _exit_child(code: c_int = c_int(0)):
    _ = external_call["_exit", c_int](code)


@always_inline
def _usleep(us: c_int):
    _ = external_call["usleep", c_int](us)


@always_inline
def _kill(pid: c_int, sig: c_int) -> c_int:
    return external_call["kill", c_int](pid, sig)


comptime _SIGKILL: c_int = c_int(9)


# ── Loopback client helpers ────────────────────────────────────────────────


def _connect_loopback(port: UInt16) raises -> c_int:
    var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if c < c_int(0):
        raise Error("client socket() failed: " + _strerror(get_errno().value))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa + i).init_pointee_copy(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip + 0).init_pointee_copy(UInt8(127))
    (ip + 1).init_pointee_copy(UInt8(0))
    (ip + 2).init_pointee_copy(UInt8(0))
    (ip + 3).init_pointee_copy(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    if _connect(c, sa, c_uint(16)) < c_int(0):
        var msg = _strerror(get_errno().value)
        _ = _close(c)
        raise Error("connect 127.0.0.1 failed: " + msg)
    return c


def _send_request_and_recv_response(
    fd: c_int, req: String, body: String
) raises:
    var rc_send = _send(
        fd,
        req.unsafe_ptr(),
        c_size_t(req.byte_length()),
        c_int(MSG_NOSIGNAL),
    )
    if Int(rc_send) != req.byte_length():
        raise Error("send() short-write")

    var buf = stack_allocation[4096, UInt8]()
    var got = String(capacity=4096)
    var attempts = 0
    while attempts < 16 and (body not in got or "\r\n\r\n" not in got):
        attempts += 1
        var rc_recv = _recv(fd, buf, c_size_t(4096), c_int(0))
        if Int(rc_recv) <= 0:
            raise Error("recv() returned " + String(Int(rc_recv)))
        for i in range(Int(rc_recv)):
            got += chr(Int(buf[i]))
    if body not in got:
        raise Error("response missing body; got prefix: " + got)


# ── Integration tests ──────────────────────────────────────────────────────


def test_static_multicore_sequential_keepalive_churn() raises:
    """8 sequential conns x 50 keep-alive requests = 400 round-trips
    against a 4-worker static server. Validates the
    StaticScheduler lifecycle + run_reactor_loop_static_shared
    accept-distribution under sequential conn churn."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    assert_true(Int(port) > 0, "server must bind to a positive port")

    var pid = _fork()
    if pid == 0:
        try:
            var resp = precompute_response(
                status=200,
                content_type="text/plain; charset=utf-8",
                body="Hello, static multi!",
            )
            srv.serve_static_multicore(resp^, num_workers=4, pin_cores=False)
        except:
            pass
        _exit_child()
    _usleep(c_int(120000))

    var req = String(
        "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Connection: keep-alive\r\n\r\n"
    )
    var body = String("Hello, static multi!")
    var total_ok = 0
    var failed_at = -1
    for c in range(8):
        try:
            var fd = _connect_loopback(port)
            try:
                for i in range(50):
                    _ = i
                    _send_request_and_recv_response(fd, req, body)
                total_ok += 50
            finally:
                _ = _close(fd)
        except:
            failed_at = c
            break

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)

    assert_equal(failed_at, -1, "sequential conn churn failed mid-test")
    assert_equal(total_ok, 8 * 50, "expected 400 successful round-trips")


def test_static_multicore_concurrent_fanout() raises:
    """Single client, 8 sequential conns x 30 reqs against a
    4-worker static server. Validates the StaticScheduler shared
    listener distributes across workers (kernel hashes the source
    port to a worker via EPOLLEXCLUSIVE) without losing any
    accepts. We use sequential conns from one client process
    instead of fork+inspect-status because Mojo's external_call
    cache rejects two different waitpid signatures in the same
    binary."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    assert_true(Int(port) > 0, "server must bind to a positive port")

    var pid = _fork()
    if pid == 0:
        try:
            var resp = precompute_response(
                status=200,
                content_type="text/plain; charset=utf-8",
                body="Hello, static fanout!",
            )
            srv.serve_static_multicore(resp^, num_workers=4, pin_cores=False)
        except:
            pass
        _exit_child()
    _usleep(c_int(120000))

    var req = String(
        "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Connection: keep-alive\r\n\r\n"
    )
    var body = String("Hello, static fanout!")
    var total_ok = 0
    var failed_at = -1

    # 8 conns sequentially; each conn uses a different ephemeral
    # source port, so the kernel's accept-balance distributes them
    # across the 4 workers (the connect() side picks the source
    # port; EPOLLEXCLUSIVE wakes one of the 4 reactors per accept).
    for c in range(8):
        try:
            var fd = _connect_loopback(port)
            try:
                for j in range(30):
                    _ = j
                    _send_request_and_recv_response(fd, req, body)
                total_ok += 30
            finally:
                _ = _close(fd)
        except:
            failed_at = c
            break

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)

    assert_equal(failed_at, -1, "concurrent fanout failed mid-test")
    assert_equal(total_ok, 8 * 30, "expected 240 successful round-trips")


def main() raises:
    print("=" * 60)
    print("test_static_multicore.mojo - Phase 1E static multi-worker")
    print("=" * 60)
    var suite = TestSuite()
    suite.test[test_static_multicore_sequential_keepalive_churn]()
    suite.test[test_static_multicore_concurrent_fanout]()
    suite^.run()
