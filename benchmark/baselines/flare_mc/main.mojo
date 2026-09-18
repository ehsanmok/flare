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
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.request import Request
from flare.http.response import stream_response
from flare.net import SocketAddr


comptime _STREAM_CHUNKS: Int = 16
comptime _STREAM_CHUNK_BYTES: Int = 256
"""16 x 256 B = 4096 B, matching ``/4kb`` exactly, so streaming can be
measured against the buffered path at identical payload."""


def _payload(n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(97 + (i % 26)))
    return out^


@fieldwise_init
struct _FixedChunks(ChunkSource, Copyable):
    var remaining: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.remaining <= 0:
            return None
        self.remaining -= 1
        return _payload(_STREAM_CHUNK_BYTES)


def _download(n: Int) raises -> Response:
    var r = Response(Status.OK, body=_payload(n))
    r.headers.set("content-type", "application/octet-stream")
    return r^


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
    if req.url == "/stream":
        var s = stream_response(_FixedChunks(_STREAM_CHUNKS))
        s.headers.set("content-type", "application/octet-stream")
        return s^
    if req.url == "/4kb":
        return _download(4 * 1024)
    if req.url == "/64kb":
        return _download(64 * 1024)
    if req.url == "/1mb":
        return _download(1024 * 1024)
    if req.url == "/16mb":
        return _download(16 * 1024 * 1024)
    if req.url == "/upload":
        return ok(String(len(req.body)))
    return Response(status=404, reason="Not Found")


comptime BenchHandler = FnHandlerCT[handler]
# skip_header_decode_for_short_requests=True opts into the
# minimal parser that skips the per-request HeaderMap build
# entirely. The handler() above only reads req.url, so the
# headers can be left empty without affecting behaviour. Drops
# the per-request HeaderMap allocation + per-header String
# copies, which dominate the parser's CPU cost on TFB plaintext.
comptime BENCH_CONFIG = ServerConfig(
    idle_timeout_ms=0,
    write_timeout_ms=0,
    max_keepalive_requests=100_000,
    skip_header_decode_for_short_requests=True,
    # The uploads workload posts up to 16 MiB; the 10 MiB default would
    # 413 it. Body framing is unaffected by the minimal parser -- it
    # still scans Content-Length raw.
    max_body_size=32 * 1024 * 1024,
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
    # FLARE_BENCH_TLS=1 terminates TLS in-process across all workers,
    # which is what the operational gate's "TLS + multi-worker +
    # streaming" soak needs. Certs from ``pixi run bench-tls-setup``.
    if getenv("FLARE_BENCH_TLS", "0") == "1":
        var alpn = List[String]()
        alpn.append("h2")
        alpn.append("http/1.1")
        var tls_srv = HttpServer.bind_tls(
            SocketAddr.localhost(UInt16(port)),
            cert_file=getenv(
                "FLARE_BENCH_CERT", "build/tls-bench-certs/server.pem"
            ),
            key_file=getenv(
                "FLARE_BENCH_KEY", "build/tls-bench-certs/server.key"
            ),
            alpn=alpn^,
            config=materialize[BENCH_CONFIG](),
        )
        print("flare multicore listening (TLS) on 127.0.0.1:", port)
        var th = BenchHandler()
        tls_srv.serve_tls(th^, num_workers=workers)
        return

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
