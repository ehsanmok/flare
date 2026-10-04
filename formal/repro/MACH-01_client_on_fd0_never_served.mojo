# PLATFORM: any
"""MACH-01: a client accepted on fd 0 shares the listener's reactor token.

Lean: Flare.Machine.fd0_reachable / Flare.Machine.fd0_never_served
(counterexample), Flare.Machine.routing_ok (with fd 0 in use every live
connection has a token other than the listener's), Flare.Bugs.MACH_01.
flare/http/_unified_reactor_impl.mojo:1086-1089,1119-1130 @59bda50
(listener registered with token 0; every token-0 event goes to the accept
drainer) with :661-722 (client registered with token = its fd). The four
loops in flare/http/_server_reactor_epoll.mojo (155-194, 377-406,
599-625, 745-771) and flare/http/_reactor/lifecycle.mojo:236,292 repeat
the pattern.

Flip check: moving the listener token in _unified_reactor_impl.mojo to
1 << 40 makes this repro print OK.

Spec: every readiness event for a connection reaches that connection.

Expected: once something in the process closes fd 0 (stdin), the next
accepted client is still served.
Actual: accept() returns the lowest free fd, 0. The client is registered
with token 0, which is the listener's token, so each of its events is
handed to the accept drainer instead of the connection. The request is
never answered; the connection lingers until its idle timer closes it
(500 ms by default). Meanwhile its unread data keeps the fd readable, so
every poll returns at once and the worker spins: about 450 ms of server
CPU in those 500 ms, against about 5 ms for an idle connection without the
bug (measured on macOS with a variant whose second client sends nothing).

Minimal fix: use a listener token that no fd can take (for example the
listener fd + 1 << 32, or any value >= 2^31), or reject fd 0 at accept.

The handler below closes fd 0 on request; anything in the process doing
so (a library closing stdin, a daemonisation helper) has the same effect.
"""

from std.ffi import c_int, external_call
from std.time import perf_counter_ns

from flare.http import HttpServer, Request, Response, ok
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def _handler(req: Request) raises -> Response:
    if req.url == "/close-stdin":
        _ = external_call["close", c_int](c_int(0))
        return ok("closed")
    return ok("hello")


def _children_cpu_ms() -> Int:
    """User + system CPU of reaped children (``getrusage(RUSAGE_CHILDREN)``;
    ``struct rusage`` starts with two ``struct timeval``)."""
    var ru = List[Int64](length=32, fill=0)
    _ = external_call["getrusage", c_int](c_int(-1), ru.unsafe_ptr())
    # tv_usec is 32-bit on macOS (then padding), 64-bit on Linux.
    var us = (ru[1] & 0xFFFF_FFFF) + (ru[3] & 0xFFFF_FFFF)
    return Int((ru[0] + ru[2]) * 1000 + us // 1000)


def _get(port: UInt16, path: String) -> String:
    var got = String("")
    try:
        var s = TcpStream.connect(SocketAddr.localhost(port))
        s.set_recv_timeout(2000)
        var req = "GET " + path + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        _ = s.write(req.as_bytes())
        var buf = List[UInt8](length=4096, fill=0)
        while True:
            var n = s.read(buf.unsafe_ptr(), 4096)
            if n <= 0:
                break
            for i in range(n):
                got += chr(Int(buf[i]))
        s.close()
    except:
        pass
    return got


def main() raises:
    var fd0_open = external_call["fcntl", c_int](c_int(0), c_int(1), c_int(0)) >= c_int(0)
    if not fd0_open:
        raise Error("setup: run with stdin open (fd 0 must be in use)")
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_handler)
        except:
            pass
        exit()
    usleep(250000)
    var first = _get(port, "/close-stdin")
    var t0 = perf_counter_ns()
    var second = _get(port, "/")
    var wall_ms = Int((perf_counter_ns() - t0) // 1_000_000)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    if not first.startswith("HTTP/1.1 200"):
        raise Error("setup: first request failed: " + first)
    if not second.startswith("HTTP/1.1 200"):
        print(
            "BUG REPRODUCED: after fd 0 was freed, the next client got no",
            "response (",
            second.byte_length(),
            "bytes before the idle timer closed it); its token 0 routes its",
            "events to the accept drainer;",
            "server CPU",
            _children_cpu_ms(),
            "ms over its life, of which",
            wall_ms,
            "ms were spent waiting on that client",
        )
        raise Error("MACH-01")
    print("OK: the client after fd 0 was freed was served")
