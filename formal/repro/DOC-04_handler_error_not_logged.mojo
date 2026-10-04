# PLATFORM: any (loopback TCP in-process; no external network)
"""DOC-04: a handler that raises gets a sanitised 500, but its message is
never logged, and the one sanitised error path that does log (extractor
400s) logs without the request id.

Lean: Flare.Bugs.DOC_04.counterexample (counterexample) and
Flare.Bugs.DOC_04.fixed (fix meets spec).
flare/http/_reactor/conn_handle.mojo:910-915 @59bda50 (handler error
branch of `on_readable`: `map_handler_error` then `_queue_error`, no log;
the same shape at conn_handle.mojo:1007, 1083, 1162, the HTTP/2 server
at flare/http/_h2_conn_handle.mojo:545 and 980, and HTTP/3 at
flare/http/server.mojo:86-100). `map_handler_error`
(flare/errors.mojo:276-301) only builds the status and reason.
flare/http/extract.mojo:879-880 + 914-919: `Extracted.serve` has the
request but passes only the error to `_bad_request_from_error`, which
prints "[flare:bad-request] <msg>" to stdout, with no request id.

Doc claims: docs/security.md:14 "Logs carry the full message + request
id"; docs/security.md:39-43 "The full message ... is logged with the
request id" and "500 (handler raise) is the same: fixed body, full
message logged with request id"; docs/features.md:672-674;
flare/http/_server/config.mojo:90-95 ("log the message ... to stderr").

Setup: fds 1 and 2 are redirected into a pipe; two ConnHandles are driven
in-process over loopback. Request A (X-Request-Id: doc04-rid-500) hits a
handler that raises Error("doc04-handler-secret"); request B
(X-Request-Id: doc04-rid-400) hits an `Extracted` handler whose
`QueryInt["n"]` fails on ?n=doc04-extract-secret. Preconditions: A drew a
500 and B a 400, neither body echoes its secret, and B's message reached
the pipe (proves the capture works).

Expected: the captured log holds "doc04-handler-secret" together with
"doc04-rid-500", and "doc04-extract-secret" together with "doc04-rid-400".
Actual: the handler message is absent and neither request id is logged.

Minimal fix: in both places, read `req.headers.get("x-request-id")`
before the request is consumed and log "[flare:<kind>] rid=<id> <msg>"
to stderr next to the existing response mapping.
"""

from std.ffi import c_int, external_call

from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener
from flare.http import Extracted, Handler, QueryInt, Request, Response, ok
from flare.http.server import ServerConfig
from flare.http.handler import FnHandler
from flare.http._server_reactor_impl import ConnHandle
from flare.utils import usleep


def _boom(req: Request) raises -> Response:
    raise Error("doc04-handler-secret")


@fieldwise_init
struct _NeedsInt(Copyable, Defaultable, Handler):
    var n: QueryInt["n"]

    def __init__(out self):
        self.n = QueryInt["n"]()

    def serve(self, req: Request) raises -> Response:
        return ok("n=" + String(self.n.value))


def _drive[H: Handler](ref h: H, req: String) raises -> String:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(
        SocketAddr.localhost(listener.local_addr().port)
    )
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    var ch = ConnHandle(server^)
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    _ = client.write(req.as_bytes())
    for _ in range(50):
        usleep(20000)
        _ = ch.on_readable(h, cfg)
        if len(ch.write_buf) > 0:
            break
    var wire = String(unsafe_from_utf8=ch.write_buf)
    client.close()
    listener.close()
    return wire^


def main() raises:
    var fds = List[c_int](length=2, fill=0)
    if external_call["pipe", c_int](fds.unsafe_ptr()) != 0:
        print("inconclusive: pipe() failed")
        raise Error("setup")
    var saved_out = external_call["dup", c_int](c_int(1))
    var saved_err = external_call["dup", c_int](c_int(2))
    _ = external_call["dup2", c_int](fds[1], c_int(1))
    _ = external_call["dup2", c_int](fds[1], c_int(2))

    var wire_a = String("")
    var wire_b = String("")
    var drive_err = String("")
    try:
        var h500 = FnHandler(_boom)
        wire_a = _drive(
            h500,
            "GET /boom HTTP/1.1\r\nHost: a\r\nX-Request-Id: doc04-rid-500\r\n\r\n",
        )
        var h400 = Extracted[_NeedsInt]()
        wire_b = _drive(
            h400,
            "GET /q?n=doc04-extract-secret HTTP/1.1\r\nHost: a\r\n"
            + "X-Request-Id: doc04-rid-400\r\n\r\n",
        )
    except e:
        drive_err = String(e)

    _ = external_call["dup2", c_int](saved_out, c_int(1))
    _ = external_call["dup2", c_int](saved_err, c_int(2))
    _ = external_call["close", c_int](saved_out)
    _ = external_call["close", c_int](saved_err)
    _ = external_call["close", c_int](fds[1])
    var logbytes = List[UInt8]()
    var tmp = List[UInt8](length=4096, fill=0)
    while True:
        var n = external_call["read", Int](fds[0], tmp.unsafe_ptr(), len(tmp))
        if n <= 0:
            break
        for i in range(n):
            logbytes.append(tmp[i])
    _ = external_call["close", c_int](fds[0])
    var log = String(unsafe_from_utf8=logbytes)

    if drive_err.byte_length() > 0:
        print("inconclusive: driving the connections raised:", drive_err)
        raise Error("setup")
    if not wire_a.startswith("HTTP/1.1 500") or "doc04-handler-secret" in wire_a:
        print("inconclusive: request A did not draw a sanitised 500:", repr(wire_a))
        raise Error("setup")
    if not wire_b.startswith("HTTP/1.1 400") or "doc04-extract-secret" in wire_b:
        print("inconclusive: request B did not draw a sanitised 400:", repr(wire_b))
        raise Error("setup")
    if "doc04-extract-secret" not in log:
        print("inconclusive: the extractor log line was not captured:", repr(log))
        raise Error("setup")

    var lines = log.split("\n")
    var a_ok = False
    var b_ok = False
    for ln in lines:
        if "doc04-handler-secret" in ln and "doc04-rid-500" in ln:
            a_ok = True
        if "doc04-extract-secret" in ln and "doc04-rid-400" in ln:
            b_ok = True
    if a_ok and b_ok:
        print("OK: both error messages are logged with their request ids")
        return
    print(
        "BUG REPRODUCED: handler 500 message logged with request id:",
        a_ok,
        "(message logged at all:",
        "doc04-handler-secret" in log,
        "); extractor 400 message logged with request id:",
        b_ok,
        "; captured log:",
        repr(log),
    )
    raise Error("DOC-04")
