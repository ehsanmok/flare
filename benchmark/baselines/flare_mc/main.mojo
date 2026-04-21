"""Flare multicore HTTP server plaintext baseline.

Same wire protocol as ``benchmark/baselines/flare/main.mojo`` but
drives the v0.4.0 ``HttpServer.serve_multicore`` path: N workers on
N pthreads, each bound to the same port with ``SO_REUSEPORT`` and
(on Linux) pinned to a specific core.

Environment:
    FLARE_BENCH_PORT   : Listen port (default 8080).
    FLARE_BENCH_WORKERS: Worker count (default 4).
    FLARE_BENCH_PIN    : "1" pins workers to cores; "0" disables (default 1).

Tuned for throughput: idle/write timeouts disabled, no cookies, no logs.
"""

from std.memory import memcpy
from std.os import getenv

from flare.http import (
    HttpServer,
    ServerConfig,
    FnHandlerCT,
    Response,
    Status,
    ok,
)
from flare.http.request import Request
from flare.net import SocketAddr


def handler(req: Request) raises -> Response:
    if req.url == "/plaintext":
        var s = "Hello, World!"
        var sb = s.as_bytes()
        var n = len(sb)
        var b = List[UInt8]()
        b.resize(n, UInt8(0))
        memcpy(dest=b.unsafe_ptr(), src=sb.unsafe_ptr(), count=n)
        var r = Response(status=200, reason="OK", body=b^)
        r.headers.set("Content-Type", "text/plain; charset=utf-8")
        return r^
    var empty = List[UInt8]()
    var nf = Response(status=404, reason="Not Found", body=empty^)
    return nf^


alias BenchHandler = FnHandlerCT[handler]
alias BENCH_CONFIG = ServerConfig(
    idle_timeout_ms=0, write_timeout_ms=0, max_keepalive_requests=100_000
)


def main() raises:
    var port_str = getenv("FLARE_BENCH_PORT", "8080")
    var port = Int(port_str)
    var workers_str = getenv("FLARE_BENCH_WORKERS", "4")
    var workers = Int(workers_str)
    if workers < 1:
        workers = 1
    var pin_str = getenv("FLARE_BENCH_PIN", "1")
    var pin = pin_str == "1"

    print(
        "flare multicore listening on 127.0.0.1:",
        port,
        " workers=",
        workers,
        " pin=",
        pin,
    )
    var srv = HttpServer.bind(
        SocketAddr.localhost(UInt16(port)), materialize[BENCH_CONFIG]()
    )
    # ``serve_multicore`` takes a runtime handler value because the
    # pthread context carries one ``H.copy()`` per worker; ``FnHandlerCT``
    # is zero-size so the copy is free and the per-worker reactor loop
    # still monomorphises against the comptime-bound function.
    var h = BenchHandler()
    srv.serve_multicore(h^, num_workers=workers, pin_cores=pin)
