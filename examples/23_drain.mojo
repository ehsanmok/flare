"""Example 23: Graceful shutdown with ``HttpServer.drain``.

Closes the API-surface portion of criticism §2.12: v0.4.x had
``HttpServer.close()`` (a hard stop that cuts in-flight handlers
mid-write). v0.5.0 Step 1 adds ``HttpServer.drain(timeout_ms)``
that closes the listener (no new connections accepted), waits up
to ``timeout_ms`` for in-flight reactor events to flush, and
returns a ``ShutdownReport``.

Idiomatic deployments in containers send ``SIGTERM`` with a 30s
grace period before ``SIGKILL``; the production shape is:

    var srv = HttpServer.bind(...)
    var sig = install_sigterm_handler()  # planned for v0.5.0 Step 2
    while not sig.received():
        ... do work, poll the flag at boundaries you own ...
    var report = srv.drain(timeout_ms=30_000)

Mojo doesn't yet support module-level mutable ``var``s, so the
``install_sigterm_handler`` helper that flips a process-global byte
from a libc signal handler is deferred to a later commit. This
example demonstrates the ``drain`` API directly so users can wire
it up to whatever signal-flagging mechanism their platform offers
in the meantime.

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
    print("    drained         =", report1.drained)
    print("    timed_out       =", report1.timed_out)
    print("    in_flight_at_deadline =", report1.in_flight_at_deadline)
    print()

    var srv2 = HttpServer.bind(SocketAddr.localhost(0))
    print("[2] Graceful drain (drain(100)):")
    var report2 = srv2.drain(timeout_ms=100)
    print("    drained         =", report2.drained)
    print("    timed_out       =", report2.timed_out)
    print("    in_flight_at_deadline =", report2.in_flight_at_deadline)
    print()

    print("In production:")
    print("    var srv = HttpServer.bind(SocketAddr.localhost(8080))")
    print("    # ... start server in a background thread ...")
    print("    # ... main thread polls a sigterm flag ...")
    print("    var report = srv.drain(timeout_ms=30_000)")
    print()
    print("=== Example 23 complete ===")
