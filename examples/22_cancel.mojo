"""Example 22: Cooperative cancellation with ``CancelHandler`` and ``Cancel``.

A real handler that polls ``cancel.cancelled()`` between expensive
steps so it can return early when the reactor flips the cell. The
reactor flips the cell on:

- ``CancelReason.PEER_CLOSED`` — the client TCP-disconnected before
  the response was queued.
- ``CancelReason.TIMEOUT`` — a per-request, per-handler, or
  per-body-read deadline expired (wired in commit 5 of v0.5.0
  Step 1).
- ``CancelReason.SHUTDOWN`` — ``HttpServer.drain(timeout_ms)`` was
  called (wired in commit 6 of v0.5.0 Step 1).

Cancellation is **cooperative**: the handler decides when it's safe
to bail. flare doesn't preempt synchronous code (Mojo can't, and
synchronous preemption would defeat the reactor's per-thread
invariant). The design contract is: check the flag at boundaries
the handler owns; the reactor sets the flag at the inflection
points above.

Plain ``Handler``s plug in unchanged via ``WithCancel[H]`` — the
adapter forwards ``serve(req, cancel)`` to the wrapped
``serve(req)``, ignoring cancel. Drop in via
``HttpServer.serve_cancellable(WithCancel[Router](r^))``.

This example drives ``SlowHandler.serve(req, cancel)`` directly with
a ``Cancel.never()`` (handler runs to completion) and a pre-flipped
``CancelCell`` (handler short-circuits) so the example exits cleanly
without spinning up a server.

Run:
    pixi run example-cancel
"""

from flare.http import (
    Cancel,
    CancelHandler,
    Handler,
    Request,
    Response,
    WithCancel,
    Method,
    Status,
    ok,
)


@fieldwise_init
struct SlowHandler(CancelHandler, Copyable, Movable):
    """Polls cancel between fake-DB-call steps; short-circuits on
    the first observed cancellation with a partial result.

    A real implementation might write a partial-write to a streaming
    response, log a "client hung up" line for monitoring, or roll
    back a transaction. Here we just return how many steps we got
    through.
    """

    var max_steps: Int

    def serve(self, req: Request, cancel: Cancel) raises -> Response:
        for i in range(self.max_steps):
            if cancel.cancelled():
                # Branch on the reason if you want to choose a
                # different status code per cause: 503 on shutdown,
                # 408 on timeout, etc. This example just records
                # how far we got.
                return ok("partial:" + String(i))
            # ... one expensive step ...
        return ok("done")


@fieldwise_init
struct PlainGreeter(Copyable, Defaultable, Handler, Movable):
    """A plain ``Handler`` that does not observe cancellation.

    Used below to demonstrate the ``WithCancel[H]`` adapter that
    plugs a plain handler into the cancel-aware reactor path
    unchanged.
    """

    var greeting: String

    def __init__(out self):
        self.greeting = "hello"

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting)


def main() raises:
    print("=== flare Example 22: Cancel + CancelHandler ===")
    print()

    var slow = SlowHandler(max_steps=10)

    # Path 1: handler runs to completion under Cancel.never().
    var req = Request(method=Method.GET, url="/work")
    print("[1] SlowHandler with Cancel.never():")
    var resp1 = slow.serve(req^, Cancel.never())
    print("    status =", resp1.status, "body =", resp1.text())
    print()

    # Path 2: WithCancel[PlainGreeter] forwards a plain Handler.
    print("[2] WithCancel[PlainGreeter].serve(req, Cancel.never()):")
    var req2 = Request(method=Method.GET, url="/")
    var wrapped = WithCancel[PlainGreeter](inner=PlainGreeter("hi"))
    var resp2 = wrapped.serve(req2^, Cancel.never())
    print("    status =", resp2.status, "body =", resp2.text())
    print()

    # The reactor-driven path is:
    #     HttpServer.serve_cancellable(slow^)
    # The reactor allocates a CancelCell per connection, hands a
    # Cancel handle bound to it into ``slow.serve(req, cancel)``,
    # and flips the cell on peer FIN, deadline (commit 5), or drain
    # (commit 6). The handler observes the flip on its next
    # cancel.cancelled() poll and short-circuits.
    print("In production: HttpServer.serve_cancellable(slow_handler^)")
    print("plugs SlowHandler into the cancel-aware reactor path; the")
    print("reactor flips the cell on peer FIN, deadline, or drain.")
    print()
    print("=== Example 22 complete ===")
