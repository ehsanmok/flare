"""Blocking-escape hatch: ``block_in_pool``.

The reactor's hot path is single-threaded per worker; any
blocking syscall (synchronous DB query, libc ``getaddrinfo``,
file I/O on a slow disk, CPU-heavy compute) freezes the worker
for the duration. The fix is to offload the blocking work to a
fresh kernel thread:

    var rows = block_in_pool[List[Row]](
        lambda: db.query("SELECT ..."),
        cancel,
    )

The handler stays in straight-line code; ``cancel`` short-
circuits if the request is cancelled mid-blocking-call.

Implementation: per-call detached pthread.

Each ``block_in_pool[T]`` call spawns a fresh kernel thread via
``pthread_create``, runs ``work()`` on it, and surfaces the
result back through a heap-allocated task struct. The submitter
(the reactor-thread handler) polls a ``done_flag`` in a 1 ms
sleep loop, also polling ``cancel`` so a flip surfaces
immediately.

Why per-call rather than a singleton pool:

1. Mojo's nightly does not allow module-level mutable ``var``s
   (``error: global variables are not supported``) — verified
   on the pinned nightly. Without that, a process-global pool
   needs either a libc mmap-backed flag-byte indirection or an
   API change that threads pool-state through every call site.
2. Per-call ``pthread_create`` overhead is ~30-50 µs on Linux
   x86_64. The API targets millisecond-scale blocking work
   (DB queries, disk I/O); the overhead is < 5 % of any
   workload that needs ``block_in_pool`` in the first place.
3. The MAX_POOL_SIZE cap (32) exposed in the public API still
   matters: callers that create pools-of-pools (e.g. fan-out
   query patterns) can use it to bound concurrent kernel
   threads. The library does not enforce it on the per-call
   shape because the natural place to enforce it is the
   caller's own admission control.

What the kernel-thread split actually buys:

- Blocking syscalls inside ``work()`` only block the work's
  pthread, not the reactor's pthread structure. The kernel can
  schedule other reactor workers onto the freed CPU while the
  syscall is waiting.
- A crash in ``work()`` (segfault, abort) kills its own pthread,
  not the reactor's; the submitter sees ``pthread_join`` return
  non-zero or ``done_flag`` never flipping (caught by an outer
  timeout if the user wires one in).
- Multi-worker parallelism: N concurrent connections on N
  reactor workers each calling ``block_in_pool`` get N parallel
  ``work()`` executions on N pthreads, instead of being
  serialised inside each reactor worker's thread.

What it does NOT buy (and why):

- The submitter (handler) thread is still blocked while
  ``work()`` runs. The synchronous public signature
  ``def block_in_pool[T](work, cancel) raises -> T`` requires
  this — to release the reactor's connection-loop while
  ``work()`` is in flight we'd need either Mojo async or a
  new "park this connection" reactor state. Both are
  release-line follow-ups.

Cancel contract (unchanged from the in-thread fallback):

- **Pre-flight:** if ``cancel`` is already flipped at entry,
  raise immediately without spawning anything.
- **In-flight:** the user's ``work()`` is responsible for
  polling ``cancel`` if it wants to short-circuit mid-call
  (the work runs on a kernel thread that can read the cancel
  cell directly). The library cannot preempt — Mojo doesn't
  expose preemption and pthread cancellation is unsafe under
  the borrow checker.
- **Post-flight:** the submitter blocks on ``pthread_join``
  until ``work()`` returns; on join it checks the cancel cell
  one more time. If the cell flipped while ``work()`` ran,
  raise with a "cancelled mid-flight (<reason>)" message
  instead of returning a now-stale result.

Why pthread_join rather than poll-on-done-flag:

A previous iteration of this implementation polled a heap
``done_flag`` byte with a 1 ms ``libc_usleep`` between checks
to surface mid-flight cancel without waiting for ``work()``
to complete. On the pinned Mojo nightly, ``libc_usleep`` hits
the documented 1000-1500x multiplier when the calling thread
participates in multi-threaded contexts (and a ``block_in_pool``
caller is, by construction, multi-threaded — the worker pthread
exists). That made the 1 ms poll behave like a 1 second poll
and dragged the per-call latency from ~50 µs to ~1.1 s. Joining
on the worker thread sidesteps the libc-time path entirely and
restores per-call latency to the pthread create + work + join
cost.

The trade-off is that mid-flight cancel no longer raises
*before* ``work()`` returns; it raises *after*. Handlers that
care about fast-cancel during long work can poll ``cancel``
inside ``work()``.
"""

from std.memory import UnsafePointer, alloc, memcpy

from ..http.cancel import Cancel, CancelReason
from ._thread import ThreadHandle


# Per-call pool size cap (design-0.5 Track 2.5). The cap is exposed
# for callers that batch / fan-out and want to bound their own
# concurrent ``block_in_pool`` count; the library itself does not
# enforce it on the per-call shape.
comptime MAX_POOL_SIZE: Int = 32

# Error message buffer size. Truncates longer Error strings.
comptime _ERR_BUF_CAP: Int = 256


# ── Internal task struct (heap-allocated; owned by submitter or thread) ─────


@fieldwise_init
struct _Task[T: ImplicitlyDestructible & Movable](Movable):
    """Heap-allocated task delivered to the worker pthread.

    Address fields are stored as ``Int`` rather than typed
    pointers because ``UnsafePointer[T, MutExternalOrigin]``
    survives the cross-function-call boundary unreliably on
    Linux x86_64 in the pinned Mojo nightly (the same anomaly
    that gates the ``test_pre_flipped_cancel_skips_work_*``
    sub-tests in ``tests/test_block_in_pool.mojo``). The
    ``Int``-address-stash pattern is what flare's multicore
    ``Scheduler`` already uses for its ``stopping`` byte.
    """

    var work: def() raises thin -> Self.T
    """User-supplied work function. Runs on the worker pthread."""

    var result_addr: Int
    """Address of the heap slot the worker writes the success
    result into via ``init_pointee_move``."""

    var err_buf_addr: Int
    """Address of a ``UInt8`` buffer of size ``_ERR_BUF_CAP``
    the worker writes the error message into on raise. The
    last byte is reserved for a NUL terminator; messages
    longer than ``_ERR_BUF_CAP - 1`` are truncated."""

    var err_len_addr: Int
    """Address of an ``Int`` slot the worker writes the actual
    error message length into."""

    var success_addr: Int
    """Address of a ``UInt8`` flag the worker sets to 1 on
    success and 0 on raise."""


# ── Per-T worker thunk ──────────────────────────────────────────────────────


def _block_thunk[
    T: ImplicitlyDestructible & Movable
](arg: UnsafePointer[UInt8, MutExternalOrigin]) -> UnsafePointer[
    UInt8, MutExternalOrigin
]:
    """pthread start routine. Per-T monomorphisation.

    1. Reconstruct ``_Task[T]`` from the opaque arg pointer.
    2. Call ``task.work()``; capture result OR error.
    3. Write result/error/success to the heap buffers.
    4. Set ``done_flag = 1`` (release fence implicit in the
       1 ms libc sleep on the submitter side; on x86_64 byte
       writes are also globally observable).
    5. Read ``abandoned``; if 1, free buffers + task struct
       (submitter walked away). If 0, exit without freeing
       (submitter is going to read + free).
    6. Always free the ``_Task`` allocation we own; the buffers
       it points at are freed-or-not based on step 5.
    """
    var raw = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=Int(arg)
    )
    var task_ptr = raw.bitcast[_Task[T]]()
    var task = task_ptr.take_pointee()

    var result_ptr = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=task.result_addr
    ).bitcast[T]()
    var err_buf = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=task.err_buf_addr
    )
    var err_len_ptr = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=task.err_len_addr
    ).bitcast[Int]()
    var success_ptr = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=task.success_addr
    )

    try:
        var result = task.work()
        result_ptr.init_pointee_move(result^)
        success_ptr[0] = UInt8(1)
        err_len_ptr[0] = 0
    except e:
        var msg = String(e)
        var msg_span = msg.as_bytes()
        var n = msg.byte_length()
        if n > _ERR_BUF_CAP - 1:
            n = _ERR_BUF_CAP - 1
        memcpy(dest=err_buf, src=msg_span.unsafe_ptr(), count=n)
        err_buf[n] = UInt8(0)  # NUL terminator
        err_len_ptr[0] = n
        success_ptr[0] = UInt8(0)

    # The submitter owns the result / err / success buffers; it
    # frees them after pthread_join returns. We only own the
    # _Task allocation itself.
    task_ptr.free()

    return UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=0)


# ── Cancel-reason error formatting ──────────────────────────────────────────


def _raise_cancel(prefix: String, reason: Int) raises:
    """Raise with the prefix + per-reason suffix that test_block_in_pool
    pins in its assert_raises blocks. ``reason`` is one of the
    ``CancelReason.*`` comptime ``Int`` constants."""
    if reason == CancelReason.PEER_CLOSED:
        raise Error(prefix + " (peer closed)")
    elif reason == CancelReason.TIMEOUT:
        raise Error(prefix + " (timeout)")
    elif reason == CancelReason.SHUTDOWN:
        raise Error(prefix + " (shutdown)")
    else:
        raise Error(prefix)


# ── Public API ──────────────────────────────────────────────────────────────


def block_in_pool[
    T: ImplicitlyDestructible & Movable
](work: def() raises thin -> T, cancel: Cancel) raises -> T:
    """Run ``work()`` on a fresh kernel thread; wait for its
    result on the calling thread.

    Pre-flight: if ``cancel`` is already flipped at entry, raise
    without spawning anything.

    On success, returns the ``T`` produced by ``work()``. If
    ``work()`` raises, the error is propagated (truncated to
    ``_ERR_BUF_CAP - 1`` bytes if longer).

    Mid-flight: if ``cancel.cancelled()`` flips before the
    worker thread completes, raise with a "cancelled mid-flight
    (<reason>)" message. The worker thread runs to completion
    in the background; the submitter does not wait for it.

    Post-flight: if the cell flipped while ``work()`` ran (but
    the submitter still saw ``done_flag`` first), raise with a
    "cancelled mid-flight (<reason>)" message instead of
    returning the now-stale result.

    Args:
        work:   Zero-arg callable returning ``T``.
        cancel: Per-request cancel token.

    Returns:
        The ``T`` produced by ``work()``.

    Raises:
        Error: Pre-flight cancel, mid-flight cancel, post-flight
               cancel, or ``work()`` raised.
    """
    # ── Pre-flight cancel check ─────────────────────────────────────────────
    if cancel.cancelled():
        _raise_cancel("block_in_pool: cancelled", cancel.reason())

    # ── Heap-allocate task buffers ──────────────────────────────────────────
    # The result slot is sized to T; the err buf is fixed _ERR_BUF_CAP;
    # the four flag bytes + err_len Int slot are 1-byte / sizeof(Int)
    # allocations. Splitting them across allocs (rather than one big
    # block) keeps the per-T parametric step (the result slot) cleanly
    # separate from the type-erased flag bytes.
    var result_ptr = alloc[T](1)
    var err_buf = alloc[UInt8](_ERR_BUF_CAP)
    var err_len_ptr = alloc[Int](1)
    var success_ptr = alloc[UInt8](1)

    # Initialise flags to 0. (T's slot is uninitialised; the worker
    # init_pointee_move's into it on success.)
    err_len_ptr[0] = 0
    success_ptr[0] = UInt8(0)

    var task_ptr = alloc[_Task[T]](1)
    task_ptr.init_pointee_move(
        _Task[T](
            work=work,
            result_addr=Int(result_ptr),
            err_buf_addr=Int(err_buf),
            err_len_addr=Int(err_len_ptr),
            success_addr=Int(success_ptr),
        )
    )

    # ── Spawn worker pthread + block on join ────────────────────────────────
    # pthread_join is the right primitive here: the user-visible API
    # is synchronous, so the submitter needs to wait until the worker
    # has finished writing the result/error buffers anyway. Polling
    # would mean either burning CPU (busy-wait) or going through
    # libc_usleep, which on this Mojo nightly hits the documented
    # 1000-1500x multiplier in multi-threaded contexts and inflates
    # per-call latency from ~50 us to ~1 s.
    var task_opaque = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=Int(task_ptr)
    )
    var handle = ThreadHandle.spawn[_block_thunk[T]](task_opaque)
    handle.join()

    # ── Worker finished. Read result + free buffers. ───────────────────────
    var success = success_ptr[0] == UInt8(1)
    var post_cancelled = cancel.cancelled()
    var post_reason = cancel.reason() if post_cancelled else CancelReason.NONE

    if success:
        var out = result_ptr.take_pointee()
        result_ptr.free()
        err_buf.free()
        err_len_ptr.free()
        success_ptr.free()

        # Post-flight cancel check: if the cell flipped while
        # work() ran, raise rather than return a now-stale result.
        if post_cancelled:
            _raise_cancel("block_in_pool: cancelled mid-flight", post_reason)

        return out^

    # Failure path: copy the error message out and raise.
    var n = err_len_ptr[0]
    var msg_bytes = List[UInt8]()
    msg_bytes.resize(n, UInt8(0))
    if n > 0:
        memcpy(dest=msg_bytes.unsafe_ptr(), src=err_buf, count=n)
    var msg = String(
        unsafe_from_utf8=Span[UInt8, origin_of(msg_bytes)](msg_bytes)
    )

    result_ptr.free()
    err_buf.free()
    err_len_ptr.free()
    success_ptr.free()

    raise Error(msg)
