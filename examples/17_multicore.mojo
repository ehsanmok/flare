"""Example 17 - Multicore server with `HttpServer.serve(..., num_workers=N)`.

The user-facing multicore API is the same ``serve`` method with
``num_workers >= 2``:

    srv.serve(handler, num_workers=N, pin_cores=True)

Under the hood each worker gets its own reactor and its own
``SO_REUSEPORT`` listener on the same port. The kernel load-balances
accepted connections across workers — no cross-worker coordination,
no locks on the hot path. On Linux with ``pin_cores=True`` (the
default) worker N is pinned to core ``N % num_cpus`` for cache
locality; on macOS that flag is a no-op because there is no
``sched_setaffinity``.

``serve(..., num_workers=N)`` with ``N >= 2`` blocks until another
thread calls ``srv.close()``, which is not something the test runner
can script without a threading helper. So this example:

- Builds the same ``Router`` a real multicore server would use.
- Drives that router with synthesised requests to prove the
  routing is wired, exactly the way the multicore workers would.
- Shows how to size the worker pool with ``num_cpus()`` and
  ``default_worker_count()``, without ever touching a thread
  primitive directly.
- Binds an ``HttpServer`` and closes it cleanly.
- Prints the production ``main()`` shape in full.

End-to-end multicore throughput lives in ``benchmark/`` (run
``pixi run --environment bench bench-vs-baseline-quick``).

Run:
    pixi run example-multicore
"""

from flare.http import (
    HttpServer,
    Router,
    Request,
    Response,
    Method,
    Status,
    ok,
    not_found,
)
from flare.net import SocketAddr
from flare.runtime import num_cpus, default_worker_count


# ── Handlers ────────────────────────────────────────────────────────────────


def hello(req: Request) raises -> Response:
    return ok("hello from flare")


def get_user(req: Request) raises -> Response:
    return ok("user " + req.param("id"))


def health(req: Request) raises -> Response:
    return ok("ok")


# ── Main ────────────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("flare example 17 - Multicore server (`serve(..., num_workers=N)`)")
    print("=" * 60)

    # 1. Size the worker pool with the public helpers — no thread
    #    primitives, no ``_OpaquePtr``, no ``ThreadHandle``.
    var cpus = num_cpus()
    var workers = default_worker_count()
    print("  num_cpus               :", cpus)
    print("  default_worker_count() :", workers)

    # 2. Build a Router — a real multicore server would pass a
    #    Copyable Router to ``serve(..., num_workers=N)``; each worker
    #    gets its own copy, so there is no shared state between workers.
    var router = Router()
    router.get("/", hello)
    router.get("/users/:id", get_user)
    router.get("/health", health)

    # 3. Drive the router with a synthesised request to prove the
    #    routing graph each worker would run is correctly wired.
    var r1 = router.serve(Request(method=Method.GET, url="/"))
    print("  routed GET /           →", r1.status, r1.text())
    var r2 = router.serve(Request(method=Method.GET, url="/users/42"))
    print("  routed GET /users/42   →", r2.status, r2.text())
    var r3 = router.serve(Request(method=Method.GET, url="/health"))
    print("  routed GET /health     →", r3.status, r3.text())
    var r4 = router.serve(Request(method=Method.GET, url="/missing"))
    print("  routed GET /missing    →", r4.status)

    # 4. Bind an HttpServer (port 0 = auto-assign) and close it. A
    #    production ``main()`` would now call ``srv.serve(..., num_workers=N)``
    #    (shown below); doing so here would block the test runner
    #    because graceful shutdown requires another thread to call
    #    ``srv.close()``.
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    print("  bound on port          :", srv.local_addr().port)
    srv.close()
    print("  closed cleanly")

    print()
    print("Production `main()` — what a real multicore server runs:")
    print("")
    print("    var router = Router()")
    print('    router.get("/", hello)')
    print('    router.get("/users/:id", get_user)')
    print("")
    print("    var srv = HttpServer.bind(SocketAddr.localhost(8080))")
    print("    srv.serve(router^, num_workers=default_worker_count())")
    print()
    print("OK.")
