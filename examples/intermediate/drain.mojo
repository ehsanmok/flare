"""Example 23: Graceful shutdown with ``HttpServer.drain``.

``HttpServer.close()`` is a hard stop that cuts in-flight handlers
mid-write. ``HttpServer.drain(timeout_ms)`` closes the listener (no new
connections accepted), keeps the reactor serving the connections already
open for the full ``timeout_ms`` so in-flight responses finish, then lets
the reactor flip ``CancelReason.SHUTDOWN`` on whatever is still live
before closing it -- so cancel-aware handlers and streaming bodies observe
the shutdown at their next poll instead of losing the socket mid-chunk.

**flare installs no signal handler.** Mojo has no module-level mutable
state, which is what an async-signal-safe handler needs to flip a
process-global flag, so the caller owns the ``signal(2)`` wiring:

    var srv = HttpServer.bind(...)
    # ... your platform's signal-flagging mechanism sets a flag ...
    var report = srv.drain(timeout_ms=30_000)

On the counts: the single-threaded path returns zeros, because
``serve()`` owns the serving thread, so ``drain`` has no vantage point
from which to count anything. ``Scheduler.drain`` (multi-worker) joins
its workers and reports measured per-worker numbers.

Run:
    pixi run example-drain
"""

from flare.http import HttpServer, ServerConfig, ShutdownReport
from flare.net import SocketAddr


def main() raises:
    print("=== flare Example 23: HttpServer.drain ===")
    print()

    # Config note: ``ServerConfig.shutdown_timeout_ms`` is a
    # convenience default; the actual drain timeout is the argument
    # passed to ``drain(timeout_ms)``.
    var cfg = ServerConfig(shutdown_timeout_ms=10_000)
    var srv = HttpServer.bind(SocketAddr.localhost(0), cfg^)
    print("Listening on", String(srv.local_addr()))
    print()

    print("[1] Hard stop (drain(0)):")
    var report1 = srv.drain(timeout_ms=0)
    print(" drained =", report1.drained)
    print(" timed_out =", report1.timed_out)
    print(" in_flight_at_deadline =", report1.in_flight_at_deadline)
    print()

    var srv2 = HttpServer.bind(SocketAddr.localhost(0))
    print("[2] Graceful drain (drain(100)):")
    var report2 = srv2.drain(timeout_ms=100)
    print(" drained =", report2.drained)
    print(" timed_out =", report2.timed_out)
    print(" in_flight_at_deadline =", report2.in_flight_at_deadline)
    print()

    print("Counts are zero on the single-threaded path by design --")
    print("serve() owns the serving thread, so drain cannot count.")
    print("Scheduler.drain (multi-worker) reports measured counts.")
    print()
    print("In production:")
    print(" var srv = HttpServer.bind(SocketAddr.localhost(8080))")
    print(" # ... start server in a background thread ...")
    print(" # ... main thread polls your own SIGTERM flag ...")
    print(" var report = srv.drain(timeout_ms=30_000)")
    print()
    print("=== Example 23 complete ===")
