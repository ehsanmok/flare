# PLATFORM: any (loopback TCP, forked server child)
"""DOC-05: `serve_cancellable`, `serve_view` and `serve_static` on a server
bound to several addresses serve only the first one; the extra listeners
stay bound (connections complete in the kernel backlog) but are never
accepted, and no error is raised.

Lean: Flare.Bugs.DOC_05.counterexample (counterexample) and
Flare.Bugs.DOC_05.fixed (fix meets spec).
flare/http/server.mojo @59bda50: `bind(List[SocketAddr])` (262-346) puts
every address after the first in `_extra_listener_fds`;
`_reject_tls_with_extra_listeners` (1009-1026) raises only when
`_tls_ctx` is set; serve_cancellable (1433-1444), serve_view (1475-1486)
and serve_static (1523-1528, 1539+) call it and then run a loop over
`self._listener` alone. `serve` and `serve_streaming` (1096, 1140) do
handle or reject the extras.

Doc claim: docs/features.md:80-82 "`serve_cancellable`, `serve_view` and
`serve_static` now raise when a TLS context or extra listeners are bound,
instead of silently ignoring both."

Trace, per method: bind two loopback addresses; a forked child calls the
method (exit 7 if it raised, 3 if it returned). After 300 ms the parent
checks whether the child exited, sends GET to the primary address
(precondition: 200), then GET to the extra address with a 1.5 s timeout.
Expected: the method raises (or, at the least, the extra address is
served). Actual: the method runs, the primary answers 200 and the extra
address never answers.

Minimal fix: at the top of each of the three methods,
`if len(self._extra_listener_fds) > 0: raise Error(...)`.
"""

from std.ffi import c_int, external_call

from flare.http import (
    FnHandler,
    HttpServer,
    Request,
    Response,
    WithCancel,
    ok,
    precompute_response,
)
from flare.http.handler import WithViewCancel
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep


def _hello(req: Request) raises -> Response:
    return ok("hello")


def _get(port: UInt16) -> String:
    var got = String("")
    try:
        var s = TcpStream.connect(SocketAddr.localhost(port))
        s.set_recv_timeout(1500)
        var req = String("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
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


def _exit_code(pid: Int) -> Int:
    """-1 while the child runs, else its exit status (WNOHANG poll)."""
    var st = List[c_int](length=1, fill=0)
    var r = external_call["waitpid", c_int](c_int(pid), st.unsafe_ptr(), c_int(1))
    if Int(r) != pid:
        return -1
    return (Int(st[0]) >> 8) & 0xFF


def _probe(method: Int) raises -> String:
    """'raised', 'served-extra', 'ignored', or 'inconclusive: ...'."""
    var addrs = List[SocketAddr]()
    addrs.append(SocketAddr.localhost(0))
    addrs.append(SocketAddr.localhost(0))
    var srv = HttpServer.bind(addrs^)
    var bound = srv.local_addrs()
    if len(bound) != 2:
        return "inconclusive: expected 2 bound addresses, got " + String(len(bound))
    var primary = UInt16(bound[0].port)
    var extra = UInt16(bound[1].port)
    var pid = fork()
    if pid == 0:
        try:
            if method == 0:
                srv.serve_cancellable(WithCancel(FnHandler(_hello)))
            elif method == 1:
                srv.serve_view(WithViewCancel(FnHandler(_hello)))
            else:
                srv.serve_static(precompute_response(200, "text/plain", "hello"))
        except:
            exit(7)
        exit(3)
    usleep(300000)
    var code = _exit_code(pid)
    if code == 7:
        return "raised"
    if code >= 0:
        return "inconclusive: child returned with code " + String(code)
    var p = _get(primary)
    var x = _get(extra)
    _ = kill(pid, SIGKILL)
    _ = _exit_code(pid)
    usleep(50000)
    _ = _exit_code(pid)
    if not p.startswith("HTTP/1.1 200"):
        return "inconclusive: primary address not served (" + String(p.byte_length()) + " bytes)"
    if x.startswith("HTTP/1.1 200"):
        return "served-extra"
    return "ignored"


def main() raises:
    var names = List[String]()
    names.append("serve_cancellable")
    names.append("serve_view")
    names.append("serve_static")
    var bad = List[String]()
    var all_ok = True
    for m in range(3):
        var r = _probe(m)
        print("  ", names[m], "->", r)
        if r.startswith("inconclusive"):
            print("inconclusive:", names[m], r)
            raise Error("setup")
        if r == "ignored":
            bad.append(names[m])
            all_ok = False
    if all_ok:
        print("OK: every serve variant raises on (or serves) the extra listener")
        return
    var joined = String("")
    for i in range(len(bad)):
        joined += (", " if i > 0 else "") + bad[i]
    print(
        "BUG REPRODUCED:",
        joined,
        "on a two-address server raised nothing, answered 200 on the primary",
        "address and left the extra address unanswered (silently ignored)",
    )
    raise Error("DOC-05")
