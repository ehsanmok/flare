"""Flare multicore HTTP server plaintext baseline -- STATIC fast path.

Drives ``HttpServer.serve_static_multicore(resp, num_workers=N)``
so N pthread workers share a single listener fd via
``EPOLLEXCLUSIVE`` (Linux) or fall back to plain accept (macOS),
AND every request is answered with a pre-encoded
``StaticResponse`` -- ``ConnHandle.on_readable_static`` parses
far enough to locate the header terminator + Content-Length,
then ``memcpy``s the canned bytes into the write queue. No
parser builds a HeaderMap, no handler is called, no Response
struct is allocated, no headers are looked up, no body is
re-serialised per request.

This is the apples-to-apples shape against the
``benchmark/baselines/{actix_web,hyper,axum}`` setups for the
TFB-plaintext bench (``GET /plaintext`` -> 13-byte ``Hello,
World!``): every request returns the same bytes, so the
per-request work in each framework collapses to the framework's
fastest static path. flare's StaticResponse is the equivalent of
hyper's ``Bytes::from_static`` + writev / actix's
``static_response`` route.

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
    StaticResponse,
    precompute_response,
)
from flare.net import SocketAddr


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
        "flare multicore (static) listening on 127.0.0.1:",
        port,
        " workers=",
        workers,
        " pin=",
        pin,
    )
    var srv = HttpServer.bind(
        SocketAddr.localhost(UInt16(port)), materialize[BENCH_CONFIG]()
    )
    var resp = precompute_response(
        status=200,
        content_type="text/plain; charset=utf-8",
        body="Hello, World!",
    )
    srv.serve_static_multicore(resp^, num_workers=workers, pin_cores=pin)
