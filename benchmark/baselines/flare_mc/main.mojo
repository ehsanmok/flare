"""Flare multicore HTTP server plaintext baseline.

Drives ``HttpServer.serve(handler, num_workers=N)`` so N pthread
workers share a single listener fd via ``EPOLLEXCLUSIVE`` (Linux)
or fall back to plain accept (macOS). Apple-to-apple with
``hyper`` / ``axum`` / ``actix_web`` running their tokio multi-thread
runtime / four-worker actor system at the same worker count.

Environment:
    FLARE_BENCH_PORT   : Listen port (default 8080).
    FLARE_BENCH_WORKERS: Worker count (default 4).
    FLARE_BENCH_PIN    : "1" pins workers to cores; "0" disables (default 1).

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
    # ``ok`` does the bulk-memcpy body alloc and stamps
    # ``Content-Type: text/plain; charset=utf-8`` once. With the
    # move-only ``Response.__init__`` the only per-request heap
    # allocations are the 13-byte body, the two header-list slots,
    # and the two header String values — comparable to hyper /
    # axum / actix_web's ``Response::builder().body(Bytes::from(...))``
    # path.
    if req.url == "/plaintext":
        return ok("Hello, World!")
    return Response(status=404, reason="Not Found")


alias BenchHandler = FnHandlerCT[handler]
# Phase 1C: skip_header_decode_for_short_requests=True opts into
# the minimal parser that skips the per-request HeaderMap build
# entirely. The handler() above only reads req.url, so the
# headers can be left empty without affecting behaviour. Drops
# the per-request HeaderMap allocation + per-header String
# copies, which dominated the parser's CPU cost on TFB plaintext.
alias BENCH_CONFIG = ServerConfig(
    idle_timeout_ms=0,
    write_timeout_ms=0,
    max_keepalive_requests=100_000,
    skip_header_decode_for_short_requests=True,
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
    # ``serve`` with ``num_workers >= 2`` takes a runtime handler
    # value because the pthread context carries one ``H.copy()`` per
    # worker; ``FnHandlerCT`` is zero-size so the copy is free and the
    # per-worker reactor loop still monomorphises against the
    # comptime-bound function.
    var h = BenchHandler()
    srv.serve(h^, num_workers=workers, pin_cores=pin)
