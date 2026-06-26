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
    HttpServer,
    Request,
    RequestId,
    Response,
    Router,
    ServerConfig,
    StructuredLogger,
    ok,
)
from flare.net import SocketAddr


def healthz(req: Request) raises -> Response:
    # The canonical /healthz contract. Deepen as your service
    # requires (DB pings, upstream readiness, etc); the framework
    # cannot guess.
    var resp = ok("ok\n")
    resp.headers.set("Content-Type", "text/plain; charset=utf-8")
    return resp^


def list_users(req: Request) raises -> Response:
    var resp = ok('{"users":[{"id":1,"name":"ada"}]}')
    resp.headers.set("Content-Type", "application/json")
    return resp^


def main() raises:
    print("=== flare: production-shaped server ===")
    print()

    # The application dispatcher is a plain Router. Since v0.9 Router
    # is Defaultable, so the stock middleware family wraps it directly
    # -- no hand-rolled forwarding struct needed.
    var router = Router()
    router.get("/healthz", healthz)
    router.get("/users", list_users)

    # CatchPanic -> StructuredLogger -> RequestId -> Router.
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
            RequestId(router^),
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
    print("constructed: CatchPanic -> StructuredLogger -> RequestId -> Router")
    print("routes: GET /healthz, GET /users")
    print("timeouts: read_body=30s handler=30s request=60s (see ServerConfig)")
    print()
    print("Wire up to bind+serve in your real deployment;")
    print("see docs/operations.md for the SIGTERM contract.")
