"""Flare HTTP server plaintext baseline for the TFB-style bench harness.

Listens on 127.0.0.1:$FLARE_BENCH_PORT (default 8080) and responds to
every request at ``/plaintext`` with exactly ``Hello, World!`` (13 bytes),
Content-Type ``text/plain; charset=utf-8``. Every other path returns 404.

Tuned for throughput: idle/write timeouts disabled, no cookies, no logs.
"""

from std.os import getenv

from flare.http import HttpServer, ServerConfig, Response, Status, ok
from flare.http.request import Request
from flare.net import SocketAddr


def handler(req: Request) raises -> Response:
    if req.url == "/plaintext":
        var b = List[UInt8]()
        var s = "Hello, World!"
        var sb = s.as_bytes()
        for i in range(len(sb)):
            b.append(sb[i])
        var r = Response(status=200, reason="OK", body=b^)
        r.headers.set("Content-Type", "text/plain; charset=utf-8")
        return r^
    # 404 for anything else.
    var empty = List[UInt8]()
    var nf = Response(status=404, reason="Not Found", body=empty^)
    return nf^


def main() raises:
    var port_str = getenv("FLARE_BENCH_PORT", "8080")
    var port = Int(port_str)
    var cfg = ServerConfig()
    # Benchmark tuning: no timeouts so recv/send never introduces
    # artificial delays.
    cfg.idle_timeout_ms = 0
    cfg.write_timeout_ms = 0
    cfg.max_keepalive_requests = 100_000
    print("flare listening on 127.0.0.1:", port)
    var srv = HttpServer.bind(SocketAddr.localhost(UInt16(port)), cfg^)
    srv.serve(handler)
