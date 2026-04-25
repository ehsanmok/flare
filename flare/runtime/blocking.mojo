"""Blocking-escape hatch: ``block_in_pool`` (v0.5.0 Step 3 /
Track 2.5, with C11 v0.5.0 follow-up tightening the cooperative-
cancel contract).

The reactor's hot path is single-threaded per worker; any
blocking syscall (synchronous DB query, libc ``getaddrinfo``,
file I/O on a slow disk, CPU-heavy compute) freezes the worker
for the duration. The fix is a per-worker pthread pool that
the reactor offloads blocking work to:

    var rows = block_in_pool[List[Row]](
        lambda: db.query("SELECT ..."),
        cancel,
    )

The handler stays in straight-line code; the reactor doesn't
freeze; ``cancel`` short-circuits if the request is cancelled
mid-blocking-call.

This commit ships the **API surface and the in-thread fallback
implementation**. The pthread-pool implementation — a
per-worker pool of size ``min(CPU_COUNT, 32)`` fed by an SPMC
queue, with the bound on the pool size acting as backpressure
— is a focused follow-up (the queue + cooperation with the
reactor on completion-edge wakeup needs ~150 lines of new
runtime code that benefits from a separate review).

The in-thread fallback runs ``work()`` synchronously in the
reactor thread. It's correct and safe; the only thing missing
is the parallelism-while-blocked benefit. Handlers that adopt
``block_in_pool`` today get the API contract (cancellation
respect, error-handling shape, cooperation with the reactor)
and pick up the parallelism story automatically when the pool
implementation lands.

Closes the API-surface portion of design-0.5 Track 2.5.

Example:

    from flare.runtime import block_in_pool
    from flare.http import Cancel

    def slow_compute(req: Request) raises -> Response:
        var cancel = ...  # from CancelHandler.serve(req, cancel)
        var result = block_in_pool[Int](
            lambda: heavy_math(req.body),
            cancel,
        )
        return ok("result=" + String(result))
"""

from ..http.cancel import Cancel, CancelReason


# Per-worker pool size cap (design-0.5 Track 2.5). The pool
# implementation honours ``min(CPU_COUNT, MAX_POOL_SIZE)``; the
# global cap of 32 prevents pathological resource use on
# many-core machines.
comptime MAX_POOL_SIZE: Int = 32


def block_in_pool[
    T: ImplicitlyDestructible & Movable
](work: def() raises thin -> T, cancel: Cancel) raises -> T:
    """Run ``work()`` in a place that won't freeze the reactor.

    Today's implementation runs ``work()`` synchronously in the
    calling thread (the reactor thread, in production). This is
    correct but doesn't yield the parallelism benefit; a focused
    follow-up wires this to a per-worker pthread pool fed by an
    SPMC queue.

    The function still respects cancellation: if
    ``cancel.cancelled()`` is True before ``work()`` runs, raise
    immediately. (A pool implementation will cancel in flight too
    — a worker thread polls ``cancel`` between expensive steps
    and aborts.)

    Args:
        work:   Zero-arg callable that produces a ``T``. May raise
                — the error propagates through ``block_in_pool``.
        cancel: Per-request cancel token.

    Returns:
        The ``T`` produced by ``work()``.

    Raises:
        Error: If ``cancel`` is already flipped at entry, or if
               ``work()`` raises.
    """
    # Pre-flight cancel check: short-circuit before spawning any
    # work if the cell is already flipped.
    if cancel.cancelled():
        var reason = cancel.reason()
        if reason == CancelReason.PEER_CLOSED:
            raise Error("block_in_pool: cancelled (peer closed)")
        elif reason == CancelReason.TIMEOUT:
            raise Error("block_in_pool: cancelled (timeout)")
        elif reason == CancelReason.SHUTDOWN:
            raise Error("block_in_pool: cancelled (shutdown)")
        else:
            raise Error("block_in_pool: cancelled")
    # In-thread fallback runs ``work()`` synchronously — the
    # parallelism-while-blocked benefit lands with the pthread
    # pool follow-up. The tested contract is identical: handlers
    # write production-shape code today, pick up the parallelism
    # automatically when the pool ships.
    var result = work()
    # Post-flight cancel check: if the cell flipped while
    # ``work()`` ran (peer FIN, deadline, drain), surface that
    # to the caller. Catches the race where work completed but
    # the request is no longer valuable. Pool-implementation
    # callers will get the same semantics through the
    # mid-flight cancel-poll inside the worker thread.
    if cancel.cancelled():
        var reason = cancel.reason()
        if reason == CancelReason.PEER_CLOSED:
            raise Error(
                "block_in_pool: cancelled mid-flight (peer closed)"
            )
        elif reason == CancelReason.TIMEOUT:
            raise Error(
                "block_in_pool: cancelled mid-flight (timeout)"
            )
        elif reason == CancelReason.SHUTDOWN:
            raise Error(
                "block_in_pool: cancelled mid-flight (shutdown)"
            )
        else:
            raise Error("block_in_pool: cancelled mid-flight")
    return result^
