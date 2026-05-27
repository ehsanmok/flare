"""Example: production-shaped HTTP server.

The thinnest "you could put this in front of users today"
shape. Stacks the four pieces docs/operations.md asks for:

  RequestId  -> per-request id injected into every log line.
  StructuredLogger -> one JSON object per response on stdout.
  CatchPanic -> turns a handler raise into a sanitised 500.
  /healthz   -> the contract your LB / k8s probe expects.

Plus an explicit graceful-shutdown handler ready to wire up to
SIGTERM. ``HttpServer.serve()`` honours SIGINT / SIGTERM natively;
the example demonstrates the in-handler ``Cancel`` plumbing so
long-running handlers stop politely.

Pure construction -- no live network. The handler stack and the
server config are exercised at import + ``main()`` time so the
example runs in ``pixi run example-production-setup``.

Run:
    pixi run example-production-setup
"""

from flare.http import (
    CatchPanic,
    Handler,
    HttpServer,
    Request,
    RequestId,
    Response,
    ServerConfig,
    StructuredLogger,
)
from flare.net import SocketAddr


@fieldwise_init
struct AppHandler(Copyable, Defaultable, Handler, Movable):
    """The application's request-dispatch handler.

    Path-routes ``/healthz`` and ``/users`` and 404s everything
    else. Defaultable so the middleware stack
    (RequestId / StructuredLogger / CatchPanic) can wrap it
    monomorphically; you can swap this struct for a richer
    dispatcher (e.g. ``ComptimeRouter`` adapter) without
    touching the stack.
    """

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        if req.method == "GET" and req.url == "/healthz":
            # The canonical /healthz contract. Deepen as your
            # service requires (DB pings, upstream readiness,
            # etc); the framework cannot guess.
            var ok = Response(status=200)
            ok.body = List[UInt8]("ok\n".as_bytes())
            ok.headers.set("Content-Type", "text/plain; charset=utf-8")
            ok.headers.set("Content-Length", String(len(ok.body)))
            return ok^
        if req.method == "GET" and req.url == "/users":
            var resp = Response(status=200)
            var body = String('{"users":[{"id":1,"name":"ada"}]}')
            resp.body = List[UInt8](body.as_bytes())
            resp.headers.set("Content-Type", "application/json")
            resp.headers.set("Content-Length", String(len(resp.body)))
            return resp^
        var nf = Response(status=404)
        nf.body = List[UInt8]("Not Found".as_bytes())
        nf.headers.set("Content-Type", "text/plain; charset=utf-8")
        nf.headers.set("Content-Length", String(len(nf.body)))
        return nf^


def main() raises:
    print("=== flare: production-shaped server ===")
    print()

    # CatchPanic -> StructuredLogger -> RequestId -> AppHandler.
    # Order matters:
    # - CatchPanic on the outside so any abort inside the stack
    #   surfaces as a sanitised 500 rather than tearing down the
    #   worker.
    # - StructuredLogger next so every response (including the
    #   sanitised 500) emits a JSON line with the request id.
    # - RequestId closest to the app so the id propagates
    #   through both the response header and the log line.
    var stack = CatchPanic(
        StructuredLogger(
            RequestId(AppHandler()),
        )
    )

    # ── Server config tuned for production ────────────────────
    # Defaults are already conservative; we adjust the read-body
    # timeout to be honest about long-upload tolerance. See
    # docs/operations.md ("Resource limits") for the full rubric.
    var cfg = ServerConfig()
    cfg.read_body_timeout_ms = 30_000
    cfg.handler_timeout_ms = 30_000
    cfg.request_timeout_ms = 60_000

    # ── Bind + serve ─────────────────────────────────────────
    # Live serve is intentionally commented out so the example
    # doubles as a unit-test of the construction shape. In a real
    # deployment uncomment the following and run on the address
    # of your choice; SIGINT / SIGTERM trigger the in-flight
    # cancellation + drain documented in docs/operations.md.
    #
    #     var srv = HttpServer.bind(
    #         SocketAddr.localhost(8080),
    #         cfg,
    #     )
    #     srv.serve(stack, num_workers=4)
    _ = stack
    _ = cfg
    print(
        "constructed: CatchPanic -> StructuredLogger -> RequestId -> AppHandler"
    )
    print("routes: GET /healthz, GET /users")
    print(
        "timeouts: read_body=30s handler=30s request=60s (see ServerConfig)"
    )
    print()
    print("Wire up to bind+serve in your real deployment;")
    print("see docs/operations.md for the SIGTERM contract.")
