"""Flare HTTP server baseline for the TFB-style bench harness.

Listens on 127.0.0.1:$FLARE_BENCH_PORT (default 8080). Routes match the
Rust and Go baselines byte-for-byte so every workload config can be run
head-to-head:

- ``/plaintext``            13-byte ``Hello, World!``
- ``/4kb`` ``/64kb`` ``/1mb`` ``/16mb``  buffered octet-stream downloads
- ``/upload``              POST, replies with the received byte count
- ``/stream``              4 KiB delivered as 16 chunked writes

``/stream`` is deliberately the same 4096 bytes as ``/4kb``: running the
two against each other isolates the cost of the streaming write path
from the cost of the payload, which is the number this release's bar
actually asks for. It has no counterpart in the Rust baselines yet, so
it is a flare-vs-flare measurement until one is added.

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
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.request import Request
from flare.http.response import stream_response
from flare.net import SocketAddr


comptime _STREAM_CHUNKS: Int = 16
comptime _STREAM_CHUNK_BYTES: Int = 256
"""16 x 256 B = 4096 B, matching ``/4kb`` exactly."""


def _payload(n: Int) -> List[UInt8]:
    """``n`` bytes of a repeating ASCII pattern."""
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(97 + (i % 26)))
    return out^


@fieldwise_init
struct _FixedChunks(ChunkSource, Copyable):
    """Emits a fixed number of equal chunks, then end-of-stream."""

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


# Comptime-bind the handler into a zero-size Handler struct. ``serve[H]``
# then monomorphises the entire reactor loop against this specific
# handler so the call site inside ``on_readable`` reduces to a direct
# statically-known call to ``handler(req^)``.
comptime BenchHandler = FnHandlerCT[handler]


def main() raises:
    var port_str = getenv("FLARE_BENCH_PORT", "8080")
    var port = Int(port_str)
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    cfg.write_timeout_ms = 0
    cfg.max_keepalive_requests = 100_000
    # The uploads workload posts up to 16 MiB; the 10 MiB default would
    # 413 it and the comparison against actix / hyper / axum (which
    # impose no such cap) would measure the wrong thing.
    cfg.max_body_size = 32 * 1024 * 1024

    # FLARE_BENCH_TLS=1 terminates TLS in-process instead of serving
    # cleartext, so the tls_* configs and the TLS soak have a server to
    # point at. Certs come from ``pixi run bench-tls-setup``; wrk does
    # not verify them, which is why self-signed is fine here.
    var h = BenchHandler()
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
            config=cfg^,
        )
        print("flare listening (TLS) on 127.0.0.1:", port)
        tls_srv.serve_tls(h^)
        return

    print("flare listening on 127.0.0.1:", port)
    var srv = HttpServer.bind(SocketAddr.localhost(UInt16(port)), cfg^)
    srv.serve(h^)
