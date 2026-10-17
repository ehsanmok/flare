"""Integration test for accept-time connection balancing
(``flare.runtime._balance``) behind ``HttpServer.serve(handler, num_workers=N)``.

Each worker owns a ``SO_REUSEPORT`` listener and the kernel picks one by
hashing the 4-tuple, which spreads a few dozen connections unevenly. The
scheduler's balancing group lets a worker that is clearly ahead hand a
freshly accepted stream to a lighter peer.

fork(2) topology as in ``test_static_multicore.mojo``: the child runs the
server, the parent runs the clients and SIGKILLs the child at the end.
The handler answers with the calling thread's id, so the client can see
which worker holds each connection. Scenarios:

1. **Spread**: 64 keep-alive connections end up within a few connections
   of each other across the 4 workers, every connection stays served by
   the worker that owns it, and every response is intact (this covers a
   handed-off stream being adopted and driven like any other).
2. **Churn on top of a loaded server**: with 40 connections held open
   (above the balancing floor), 100 short ``Connection: close`` requests
   all complete, so a hand-off never loses or double-serves a stream.
"""

from std.collections import Dict
from std.ffi import c_int, c_size_t, c_uint, external_call
from std.memory import stack_allocation
from std.testing import assert_equal, assert_true, TestSuite

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

from flare.http import HttpServer, Handler, Request, Response, ok
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

comptime _WORKERS = 4
comptime _TID_WIDTH = 8


# ── Handler: reply with the id of the thread that served the request ───────


@fieldwise_init
struct _TidHandler(Copyable, Handler):
    var unused: Int

    def serve(self, req: Request) raises -> Response:
        var tid = Int(external_call["gettid", c_int]())
        var s = String(tid)
        var padded = String("")
        for _ in range(_TID_WIDTH - s.byte_length()):
            padded += "0"
        padded += s
        return ok(padded)


# ── Loopback client helpers ────────────────────────────────────────────────


def _connect_loopback(port: UInt16) raises -> c_int:
    var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if c < c_int(0):
        raise Error("client socket() failed: " + _strerror(get_errno().value))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa.unsafe_offset(i)).unsafe_write(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip.unsafe_offset(0)).unsafe_write(UInt8(127))
    (ip.unsafe_offset(1)).unsafe_write(UInt8(0))
    (ip.unsafe_offset(2)).unsafe_write(UInt8(0))
    (ip.unsafe_offset(3)).unsafe_write(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    if _connect(c, sa, c_uint(16)) < c_int(0):
        var msg = _strerror(get_errno().value)
        _ = _close(c)
        raise Error("connect 127.0.0.1 failed: " + msg)
    return c


def _request(fd: c_int, req: String) raises -> Int:
    """Send ``req``, read one response, and return the worker thread id
    its body carries."""
    var rc_send = _send(
        fd,
        req.unsafe_ptr(),
        c_size_t(req.byte_length()),
        c_int(MSG_NOSIGNAL),
    )
    if Int(rc_send) != req.byte_length():
        raise Error("send() short-write")
    var buf = stack_allocation[4096, UInt8]()
    var got = String(capacity_bytes=4096)
    var attempts = 0
    while attempts < 32:
        attempts += 1
        var head_end = got.find("\r\n\r\n")
        if head_end >= 0 and got.byte_length() - (head_end + 4) >= _TID_WIDTH:
            return Int(got[byte = head_end + 4 : head_end + 4 + _TID_WIDTH])
        var rc_recv = _recv(fd, buf, c_size_t(4096), c_int(0))
        if Int(rc_recv) <= 0:
            raise Error("recv() returned " + String(Int(rc_recv)))
        for i in range(Int(rc_recv)):
            got += chr(Int(buf[unsafe_offset=i]))
    raise Error("response incomplete: " + got)


def _start_server() raises -> Tuple[Int, UInt16]:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    assert_true(Int(port) > 0, "server must bind to a positive port")
    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_TidHandler(0), num_workers=_WORKERS, pin_cores=False)
        except:
            pass
        exit()
    usleep(300000)
    return (pid, port)


comptime _KEEP_ALIVE = (
    "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection:"
    " keep-alive\r\n\r\n"
)
comptime _CLOSE = (
    "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
)


# ── Tests ──────────────────────────────────────────────────────────────────


def test_connections_spread_evenly_across_workers() raises:
    var started = _start_server()
    var pid = started[0]
    var port = started[1]
    var n_conns = 64
    var fds = List[c_int]()
    var tids = List[Int]()
    var failure = String("")
    try:
        for _ in range(n_conns):
            var fd = _connect_loopback(port)
            fds.append(fd)
            tids.append(_request(fd, String(_KEEP_ALIVE)))
        # Every connection keeps being served by the worker that owns it.
        for i in range(n_conns):
            var again = _request(fds[i], String(_KEEP_ALIVE))
            if again != tids[i]:
                failure = "connection moved between workers"
                break
    except e:
        failure = String(e)
    for i in range(len(fds)):
        _ = _close(fds[i])
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(failure, "")

    var per_worker = Dict[Int, Int]()
    for i in range(len(tids)):
        per_worker[tids[i]] = per_worker.get(tids[i], 0) + 1
    assert_equal(len(per_worker), _WORKERS, "every worker should hold some")
    var lo = n_conns
    var hi = 0
    for entry in per_worker.items():
        if entry.value < lo:
            lo = entry.value
        if entry.value > hi:
            hi = entry.value
    assert_true(
        hi - lo <= 3,
        "workers hold " + String(lo) + ".." + String(hi) + " connections",
    )


def test_short_connections_complete_while_workers_are_loaded() raises:
    var started = _start_server()
    var pid = started[0]
    var port = started[1]
    var held = List[c_int]()
    var ok_count = 0
    var failure = String("")
    try:
        for _ in range(40):
            var fd = _connect_loopback(port)
            held.append(fd)
            _ = _request(fd, String(_KEEP_ALIVE))
        for _ in range(100):
            var fd = _connect_loopback(port)
            try:
                _ = _request(fd, String(_CLOSE))
                ok_count += 1
            finally:
                _ = _close(fd)
        for i in range(len(held)):
            _ = _request(held[i], String(_KEEP_ALIVE))
    except e:
        failure = String(e)
    for i in range(len(held)):
        _ = _close(held[i])
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(failure, "")
    assert_equal(ok_count, 100)


def main() raises:
    print("=" * 60)
    print("test_accept_balance.mojo - accept-time connection balancing")
    print("=" * 60)
    TestSuite.discover_tests[__functions_in_module()]().run()
