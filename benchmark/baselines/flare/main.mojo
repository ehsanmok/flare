"""Flare HTTP server plaintext baseline for the TFB-style bench harness.

Listens on 127.0.0.1:$FLARE_BENCH_PORT (default 8080) and responds to
every request at ``/plaintext`` with exactly ``Hello, World!`` (13 bytes),
Content-Type ``text/plain; charset=utf-8``. Every other path returns 404.

Uses the comptime-parametric Handler path: ``FnHandlerCT[handler]`` is
a zero-size struct whose ``serve`` method is a direct call to the
comptime-bound ``handler``. Combined with ``HttpServer.serve[H]``, the
compiler monomorphises the whole reactor loop for this specific
handler so the hot-path call site is a direct, statically-known call.

Tuned for throughput: idle/write timeouts disabled, no logs.
"""

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
        return ok("Hello, World!")
    return Response(status=404, reason="Not Found")


# Comptime-bind the handler into a zero-size Handler struct. ``serve[H]``
# then monomorphises the entire reactor loop against this specific
# handler so the call site inside ``on_readable`` reduces to a direct
# statically-known call to ``handler(req^)``.
alias BenchHandler = FnHandlerCT[handler]


def main() raises:
    var port_str = getenv("FLARE_BENCH_PORT", "8080")
    var port = Int(port_str)
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    cfg.write_timeout_ms = 0
    cfg.max_keepalive_requests = 100_000
    print("flare listening on 127.0.0.1:", port)
    var srv = HttpServer.bind(SocketAddr.localhost(UInt16(port)), cfg^)
    var h = BenchHandler()
    srv.serve(h^)
