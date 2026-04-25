"""Cancel token plumbed from the reactor into request handlers.

Closes criticism §2.1 (the largest single gap on the v0.4.x stack):

    A handler runs to completion regardless of client behaviour. If the
    client TCP-disconnects mid-handler, the handler has no signal until
    the next ``_send`` returns ``EPIPE``. By then the handler has already
    done its expensive work (DB query, downstream HTTP fan-out, JSON
    serialisation).

In v0.5.0 Step 1, the reactor allocates one ``CancelCell`` per
connection (heap-allocated ``Int``). ``Cancel`` is a thin handle the
reactor passes to a ``CancelHandler.serve(req, cancel)``; the handler
polls ``cancel.cancelled()`` between expensive steps and short-circuits
when True.

Cancellation is **cooperative**, not preemptive — Mojo can't preempt
synchronous code, and synchronous preemption would defeat the
reactor's per-thread invariant anyway. The contract is: the handler
checks the flag at boundaries it owns; the reactor sets it at one of:

- ``CancelReason.PEER_CLOSED`` — ``recv == 0`` (peer FIN) observed
  before the response was queued.
- ``CancelReason.TIMEOUT`` — a per-request, per-handler, or
  per-body-read deadline fired (lands in commit 5 of v0.5.0 Step 1).
- ``CancelReason.SHUTDOWN`` — ``HttpServer.drain(timeout_ms)`` was
  called (lands in commit 6 of v0.5.0 Step 1).

The default-initialised ``Cancel`` returned by ``Cancel.never()`` is a
sentinel that never fires; tests and synthetic ``CancelHandler`` calls
that don't have a real reactor cell behind them use it.

Implementation
--------------

A ``CancelCell`` heap-allocates a single ``Int`` and owns its
lifetime. ``Cancel`` carries the cell's address as an ``Int`` and
rebuilds a fresh ``UnsafePointer[Int, MutExternalOrigin]`` per access
— the same pattern the multicore ``Scheduler`` uses for the
``stopping`` flag, and the only one that survives Mojo's current
(v0.26.3.0.dev2026042205) origin / aliasing model when passing the
cancel handle across function-call boundaries:

- Storing a typed ``UnsafePointer[Int, MutExternalOrigin]`` as a
  struct field in ``Cancel`` produces stale reads after the struct is
  passed through a function (verified empirically: reads at a
  numerically-correct address returned the pointer struct size,
  ``8``, instead of the live byte).
- An inline ``UInt8`` cell on the owning struct (instead of heap)
  does not have a stable address across the synchronous call chain
  the reactor builds, again per direct testing.

The combination here — heap allocation for cell stability + ``Int``
address in ``Cancel`` for transport stability — is the only one that
passes the test suite and the
``cell.flip(reason); h.serve(req^, cell.handle())`` round-trip.

Why ``Int`` instead of ``UInt8`` for the cell value: a byte-sized
heap cell hit the same aliasing failure as the typed-pointer field,
suggesting Mojo's aliasing model treats sub-word-aligned loads
through ``MutExternalOrigin`` differently than full-word loads. A
machine word avoids the path the bug appeared to depend on. The
cell is one cache line per connection — acceptable cost for the
cancel infrastructure.
"""

from std.memory import UnsafePointer, alloc


# ── Reason codes ─────────────────────────────────────────────────────────────


struct CancelReason:
    """Reason the cancel cell was flipped.

    Stored in the cell as an ``Int``; ``NONE`` (zero) means "still
    live." The handler can branch on the reason via
    ``cancel.reason() == CancelReason.X`` when it wants to log or
    take a different short-circuit path depending on why it was
    cancelled (for example, returning a 503 on shutdown vs. a 408
    on timeout).
    """

    comptime NONE: Int = 0
    """Cell is still live; ``cancel.cancelled()`` returns False."""

    comptime PEER_CLOSED: Int = 1
    """Peer sent FIN (``recv == 0``) before the response was queued.

    The reactor observed the peer half-closing on read. In a
    streaming handler this is the cue to stop emitting chunks; in a
    request/response handler it is informational (the response will
    fail to send anyway). Set in ``ConnHandle.on_readable*`` when
    ``_recv`` returns 0."""

    comptime TIMEOUT: Int = 2
    """A deadline expired (per-request, per-handler, or
    per-body-read).

    Set by the reactor when the timer wheel reports a deadline for
    the connection has elapsed. The handler should return as soon as
    it observes this; the reactor will discard a too-late response
    and close the connection. Wired in commit 5 of v0.5.0 Step 1."""

    comptime SHUTDOWN: Int = 3
    """``HttpServer.drain(timeout_ms)`` was called.

    The server is being torn down gracefully. The handler should
    short-circuit; if it returns within the drain timeout the
    response goes out normally, otherwise the connection is
    hard-closed. Wired in commit 6 of v0.5.0 Step 1."""


# ── CancelCell ───────────────────────────────────────────────────────────────


struct CancelCell(Movable):
    """Heap-allocated per-connection cancel cell.

    Owned by the reactor for the lifetime of a connection (the
    reactor keeps one of these on each ``ConnHandle``). ``Cancel``
    handles point at this cell. Reset to ``CancelReason.NONE``
    between pipelined requests so a peer-FIN on one request doesn't
    bleed into the next.
    """

    var _addr: Int
    """Heap address of the cell ``Int``. Stable for the lifetime of
    the cell. Freed in ``__del__``."""

    def __init__(out self) raises:
        """Allocate a fresh cell initialised to ``NONE``."""
        var p = alloc[Int](1)
        if not p:
            raise Error("alloc failed for CancelCell")
        p.init_pointee_copy(CancelReason.NONE)
        self._addr = Int(p)

    def __del__(deinit self):
        if self._addr != 0:
            var p = UnsafePointer[Int, MutExternalOrigin](
                unsafe_from_address=self._addr
            )
            p.destroy_pointee()
            p.free()

    def flip(mut self, reason: Int) -> None:
        """Set the cell's reason."""
        if self._addr == 0:
            return
        var p = UnsafePointer[Int, MutExternalOrigin](
            unsafe_from_address=self._addr
        )
        p[] = reason

    def reset(mut self) -> None:
        """Reset the cell to ``NONE``."""
        if self._addr == 0:
            return
        var p = UnsafePointer[Int, MutExternalOrigin](
            unsafe_from_address=self._addr
        )
        p[] = CancelReason.NONE

    def handle(mut self) -> Cancel:
        """Hand out a ``Cancel`` value bound to this cell."""
        return Cancel(self._addr)


# ── Cancel handle ────────────────────────────────────────────────────────────


struct Cancel(Copyable, ImplicitlyCopyable, Movable):
    """A handle to a per-request cancel cell owned by the reactor.

    Passed to ``CancelHandler.serve(req, cancel)`` by the reactor.
    Value-copy semantics: copies share the underlying cell.

    A handler that ignores cancellation is correct (the request
    shape is unchanged), but it forfeits the operational guarantees
    flare advertises in ``docs/operational-guarantees.md`` for that
    specific request — the reactor still flips the cell, but the
    body the handler returns will be the result of work the reactor
    knew the client had hung up on.

    Example:
        ```mojo
        from flare.http import CancelHandler, Cancel, Request, Response, ok

        @fieldwise_init
        struct SlowHandler(CancelHandler, Copyable, Movable):
            fn serve(self, req: Request, cancel: Cancel) raises -> Response:
                for i in range(100):
                    if cancel.cancelled():
                        return ok("partial: " + String(i))
                    # ... one expensive step ...
                return ok("done")
        ```
    """

    var _addr: Int
    """Raw address of the cell ``Int`` (or 0 for ``never()``).
    Re-materialised into a fresh
    ``UnsafePointer[Int, MutExternalOrigin]`` on every access so
    the Mojo optimiser cannot hoist the load out of a polling
    loop. Same idiom the reactor uses for the ``stopping`` flag."""

    @always_inline
    def __init__(out self, addr: Int):
        self._addr = addr

    @staticmethod
    @always_inline
    def never() -> Cancel:
        """Return a sentinel ``Cancel`` whose ``cancelled()`` is
        always ``False``.
        """
        return Cancel(0)

    def cancelled(read self) -> Bool:
        """Return True once the cell is non-zero."""
        if self._addr == 0:
            return False
        var p = UnsafePointer[Int, MutExternalOrigin](
            unsafe_from_address=self._addr
        )
        return p[] != CancelReason.NONE

    def reason(read self) -> Int:
        """Return the reason code currently in the cell."""
        if self._addr == 0:
            return CancelReason.NONE
        var p = UnsafePointer[Int, MutExternalOrigin](
            unsafe_from_address=self._addr
        )
        var v: Int = p[]
        return v
