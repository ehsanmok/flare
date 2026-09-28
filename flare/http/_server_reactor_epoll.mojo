"""epoll/kqueue server reactor loops + per-connection lifecycle glue.

The ``Reactor``-backed (epoll on Linux, kqueue on macOS) server event
loops -- dynamic-handler, static-response, cancel-aware and view-aware
variants and their dedicated/shared-listener wrappers. The shared
connection-lifecycle helpers they build on (alloc/free/lookup of a
``ConnHandle``, ``_apply_step``, ``_cleanup_conn``, the accept drainers)
live in ``flare.http._reactor.lifecycle`` and are re-exported here.
Split out of ``_server_reactor_impl.mojo`` to keep each module
within the file-size budget; ``_server_reactor_impl`` re-exports every
public name so existing ``from flare.http._server_reactor_impl import
run_reactor_loop ...`` (server.mojo, frontend.mojo, _unified_reactor_impl,
tests) call sites keep resolving unchanged. Pure code motion.
"""

from std.builtin.debug_assert import debug_assert
from std.collections import Dict, Optional
from std.ffi import c_int, c_size_t, external_call, get_errno, ErrNo
from std.os import getenv
from std.memory import Pointer, alloc, stack_allocation
from std.sys.info import CompilationTarget

from flare.crypto.hmac import base64url_decode
from flare.http.cancel import Cancel, CancelCell, CancelReason
from flare.http.handler import Handler, CancelHandler, ViewHandler
from flare.http.headers import HeaderMap
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import (
    ServerConfig,
    _find_crlfcrlf,
    _scan_content_length,
    _parse_http_request_bytes,
    _parse_http_request_bytes_minimal,
    _ascii_lower,
    _status_reason,
    _append_str,
    _append_int,
)
from flare.http.static_response import StaticResponse

# Per-connection state-machine constants, ``StepResult``, ``ConnHandle``,
# the h2c-upgrade detector, and the byte-fast-path / keep-alive helpers
# live in ``flare.http._reactor`` (split across ``conn_handle``,
# ``keepalive_scan``, and ``write_path`` modules). The sub-package's
# ``__init__`` aggregates them; we re-export every existing public
# symbol here for back-compat with imports across ``flare.http``,
# ``flare.http2``, ``flare.runtime``, ``tests/``, ``fuzz/``.
from ._reactor import (
    STATE_READING,
    STATE_WRITING,
    STATE_CLOSING,
    StepResult,
    ConnHandle,
    _detect_h2c_upgrade_inline,
    _monotonic_ms,
    _is_content_length,
    _is_date,
    _is_connection,
    _connection_is_keepalive,
    _connection_is_close,
    _compact_read_buf_drop_prefix,
    _compute_close_after,
    _wants_close,
)

from flare.net import IpAddr, SocketAddr
from flare.net._libc import _recv, _send, _close, MSG_NOSIGNAL
from flare.net.error import NetworkError
from flare.tcp import TcpStream, TcpListener, accept_fd
from flare.runtime import (
    Reactor,
    Event,
    TimerWheel,
    INTEREST_READ,
    INTEREST_WRITE,
    Pool,
    DateCache,
)
from flare.runtime.uring_reactor import (
    UringReactor,
    _pbuf_ring_add,
    _pbuf_ring_get_tail,
    _pbuf_ring_set_tail,
)
from flare.runtime.scheduler import (
    load_stop_flag,
    store_worker_stat,
    WORKER_STAT_INFLIGHT,
    WORKER_STAT_STATUS,
    WORKER_STATUS_CLEAN,
    WORKER_STATUS_CRASHED,
)


from ._reactor.lifecycle import (
    _poll_timeout_ms,
    _conn_alloc_addr,
    _conn_free_addr,
    _conn_ptr_from_int,
    _apply_step,
    _cleanup_conn,
    _accept_errno_is_retry,
    _arm_accept_timer,
    _accept_loop,
    _accept_loop_fd,
)


def _run_handler_loop_impl[
    H: Handler, is_shared: Bool
](
    listener_fd: Int,
    config: ServerConfig,
    ref handler: H,
    ref stopping: Bool,
    stats_addr: Int = 0,
) raises:
    """Shared epoll/kqueue event-loop body for the dynamic-handler path.

    Drives both the dedicated-listener (``run_reactor_loop``) and the
    multi-worker shared-listener (``run_reactor_loop_shared``) entry
    points; the public surfaces are thin wrappers that fan into this
    body with ``is_shared`` chosen at the callsite. The two paths
    differed only in (a) ``register`` vs ``register_exclusive`` for
    the listener token and (b) the byte-equivalent accept drainer
    -- folding both into one comptime-parameterised body deletes a
    full ~120 lines of duplicated event / timer / fast-path code.

    On Linux >= 4.5 ``register_exclusive`` sets ``EPOLLEXCLUSIVE`` so
    the kernel wakes only one worker per accept event; on macOS the
    flag is unavailable and the call falls back to plain ``register``
    (the wakeup pattern degrades to "wake-all, one-wins" but
    practical behaviour is similar because non-blocking ``accept``
    returns ``EAGAIN`` on the losers).

    Args:
        listener_fd: Listener fd. The dedicated path obtains it from
            its owned ``TcpListener``; the shared path borrows it
            from the multi-worker scheduler. Either way this body
            never closes the fd.
        config: Per-worker / per-server ``ServerConfig``.
        handler: Per-request callback (borrowed for the lifetime of
            the loop).
        stopping: Heap-allocated stop flag; re-read every iteration
            via a fresh externally-mutated pointer so the optimiser
            cannot LICM-hoist the load. The owning ``Scheduler`` (or
            the dedicated-path caller) flips it on shutdown.
    """
    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    comptime if is_shared:
        reactor.register_exclusive(c_int(listener_fd), UInt64(0), INTEREST_READ)
    else:
        reactor.register(c_int(listener_fd), UInt64(0), INTEREST_READ)

    var events = List[Event]()
    var exit_status = WORKER_STATUS_CLEAN
    var stopping_addr = Int(Pointer[Bool, _](to=stopping))
    while not load_stop_flag(stopping_addr):
        store_worker_stat(stats_addr, WORKER_STAT_INFLIGHT, len(conns))
        events.clear()
        try:
            _ = reactor.poll(_poll_timeout_ms(wheel), events)
        except:
            exit_status = WORKER_STATUS_CRASHED
            break

        var now_ms = UInt64(_monotonic_ms())
        var fired = List[UInt64]()
        wheel.advance(now_ms, fired)
        for i in range(len(fired)):
            var fd_tok = Int(fired[i])
            if fd_tok in conns:
                _cleanup_conn(fd_tok, conns, timers, reactor, wheel)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop_fd(
                    listener_fd,
                    reactor,
                    conns,
                    wheel,
                    timers,
                    config.idle_timeout_ms,
                    config.max_connections,
                )
                continue
            var fd = Int(evt.token)
            if fd not in conns:
                continue
            var ch_ptr = _conn_ptr_from_int(conns[fd])
            var step_done = False
            try:
                var last_step = StepResult()
                if evt.is_readable():
                    last_step = ch_ptr[].on_readable(handler, config)
                    step_done = last_step.done
                    # Fast path: while the state machine is cycling
                    # (readable -> writable on request, writable ->
                    # readable on keep-alive), drive the next step
                    # inline rather than bouncing through the
                    # reactor. The single biggest win on TFB
                    # plaintext with keep-alive. Cap at 3 cycles so
                    # malicious pipelining can't starve other fds.
                    var cycles = 0
                    while (not step_done) and cycles < 3:
                        cycles += 1
                        if (
                            last_step.want_write
                            and len(ch_ptr[].write_buf) > ch_ptr[].write_pos
                        ):
                            last_step = ch_ptr[].on_writable(config)
                            step_done = last_step.done
                        elif (
                            last_step.want_read
                            and len(ch_ptr[].read_buf) > 0
                            and ch_ptr[].state == STATE_READING
                        ):
                            last_step = ch_ptr[].on_readable(handler, config)
                            step_done = last_step.done
                        else:
                            break
                elif evt.is_writable():
                    last_step = ch_ptr[].on_writable(config)
                    step_done = last_step.done
                    # A response just finished flushing; any pipelined
                    # request behind it is already in read_buf and will
                    # raise no readable event of its own.
                    if not step_done and ch_ptr[].has_buffered_request():
                        last_step = ch_ptr[].on_readable(handler, config)
                        step_done = last_step.done
                if (
                    not step_done
                    and last_step.want_read
                    and ch_ptr[].has_buffered_request()
                ):
                    # The cycle cap stopped us with a whole request still
                    # buffered: ask for a writable edge, which a
                    # level-triggered socket raises at once, so the
                    # branch above serves it on the next poll.
                    last_step.want_write = True
                if not step_done:
                    _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
            except:
                step_done = True
            if step_done:
                _cleanup_conn(fd, conns, timers, reactor, wheel)

    store_worker_stat(stats_addr, WORKER_STAT_STATUS, exit_status)

    # Graceful shutdown: close every per-conn fd. The listener fd
    # is owned by the caller in both modes (Scheduler in the shared
    # case; the wrapper's ``mut TcpListener`` in the dedicated case)
    # and is never closed here.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn(leftover[i], conns, timers, reactor, wheel)


def run_reactor_loop[
    H: Handler
](
    mut listener: TcpListener,
    config: ServerConfig,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Run the single-threaded event loop until ``stopping`` becomes True.

    The caller (``HttpServer.serve``) owns the listener and provides
    the request handler. This function delegates the loop body to
    :func:`_run_handler_loop_impl` with ``is_shared=False`` so the
    listener registers without ``EPOLLEXCLUSIVE``.

    Args:
        listener: Bound and listening ``TcpListener`` (ownership stays
            with the caller; we only borrow for accept / fd access).
        config: Server configuration.
        handler: Per-request callback.
        stopping: Checked on every poll iteration; when True the loop
            exits and in-flight connections are closed.
    """
    listener._socket.set_nonblocking(True)
    _run_handler_loop_impl[H, is_shared=False](
        Int(listener._socket.fd), config, handler, stopping
    )


def run_reactor_loop_shared[
    H: Handler
](
    listener_fd: Int,
    config: ServerConfig,
    ref handler: H,
    ref stopping: Bool,
    stats_addr: Int = 0,
) raises:
    """Worker reactor loop sharing a single listener fd across workers.

    Multi-worker entry point. Delegates to :func:`_run_handler_loop_impl`
    with ``is_shared=True`` so the listener registers with
    ``EPOLLEXCLUSIVE`` (Linux >= 4.5; falls back to plain register on
    macOS) and the kernel wakes only one worker per accept event.

    The fairness improvement vs ``bind_reuseport`` is in the
    accept-time distribution: instead of the kernel hashing each new
    4-tuple to one of N listeners (variance: a 256-conn storm can
    land 80+ on one worker, 30 on another), every new accept is
    offered to the worker that's currently waiting in ``epoll_wait``.
    Idle workers absorb spikes; busy workers aren't burdened with
    extra conns.

    Args:
        listener_fd: Listener fd, owned by the ``Scheduler``. Must be
            in non-blocking mode before calling (the ``Scheduler``
            configures this once at bind time). This worker never
            closes ``listener_fd``.
        config: Per-worker copy of ``ServerConfig``.
        handler: Per-worker copy of ``H``.
        stopping: Heap-allocated stop flag mutated by the
            ``Scheduler`` from another thread on shutdown.
    """
    _run_handler_loop_impl[H, is_shared=True](
        listener_fd, config, handler, stopping, stats_addr
    )


def _run_static_loop_impl[
    is_shared: Bool
](
    listener_fd: Int,
    config: ServerConfig,
    resp: StaticResponse,
    ref stopping: Bool,
    stats_addr: Int = 0,
) raises:
    """Shared epoll/kqueue event-loop body for the static-response path.

    Drives both :func:`run_reactor_loop_static` (dedicated listener)
    and :func:`run_reactor_loop_static_shared` (multi-worker shared
    listener). The two paths differed only in (a) ``register`` vs
    ``register_exclusive`` for the listener token and (b) the
    byte-equivalent accept drainer; folding both into one
    comptime-parameterised body deletes ~120 lines of duplicate
    event / timer / fast-path code.

    Per-connection drive goes through
    :meth:`ConnHandle.on_readable_static`: scan to ``\\r\\n\\r\\n`` +
    ``Content-Length``, ``memcpy`` the canned bytes into ``write_buf``,
    flush. No ``Request`` allocation, no handler call, no response
    serialisation. Combined with the shared-listener variant this is
    the fastest path flare exposes for fixed-response endpoints.

    Args:
        listener_fd: Listener fd, never closed here. The dedicated
            wrapper extracts it from its owned ``TcpListener``; the
            shared wrapper borrows it from the ``StaticScheduler``.
        config: Per-worker / per-server ``ServerConfig``.
        resp: Pre-encoded static response (immutable).
        stopping: Heap-allocated stop flag re-read every iteration
            via a fresh externally-mutated pointer (LICM defeat).
    """
    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    comptime if is_shared:
        reactor.register_exclusive(c_int(listener_fd), UInt64(0), INTEREST_READ)
    else:
        reactor.register(c_int(listener_fd), UInt64(0), INTEREST_READ)

    var events = List[Event]()
    var exit_status = WORKER_STATUS_CLEAN
    var stopping_addr = Int(Pointer[Bool, _](to=stopping))
    while not load_stop_flag(stopping_addr):
        store_worker_stat(stats_addr, WORKER_STAT_INFLIGHT, len(conns))
        events.clear()
        try:
            _ = reactor.poll(_poll_timeout_ms(wheel), events)
        except:
            exit_status = WORKER_STATUS_CRASHED
            break

        var now_ms = UInt64(_monotonic_ms())
        var fired = List[UInt64]()
        wheel.advance(now_ms, fired)
        for i in range(len(fired)):
            var fd_tok = Int(fired[i])
            if fd_tok in conns:
                _cleanup_conn(fd_tok, conns, timers, reactor, wheel)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop_fd(
                    listener_fd,
                    reactor,
                    conns,
                    wheel,
                    timers,
                    config.idle_timeout_ms,
                    config.max_connections,
                )
                continue
            var fd = Int(evt.token)
            if fd not in conns:
                continue
            var ch_ptr = _conn_ptr_from_int(conns[fd])
            var step_done = False
            try:
                var last_step = StepResult()
                if evt.is_readable():
                    last_step = ch_ptr[].on_readable_static(resp, config)
                    step_done = last_step.done
                    var cycles = 0
                    while (not step_done) and cycles < 3:
                        cycles += 1
                        if (
                            last_step.want_write
                            and len(ch_ptr[].write_buf) > ch_ptr[].write_pos
                        ):
                            last_step = ch_ptr[].on_writable(config)
                            step_done = last_step.done
                        elif (
                            last_step.want_read
                            and len(ch_ptr[].read_buf) > 0
                            and ch_ptr[].state == STATE_READING
                        ):
                            last_step = ch_ptr[].on_readable_static(
                                resp, config
                            )
                            step_done = last_step.done
                        else:
                            break
                elif evt.is_writable():
                    last_step = ch_ptr[].on_writable(config)
                    step_done = last_step.done
                    # A response just finished flushing; any pipelined
                    # request behind it is already in read_buf and will
                    # raise no readable event of its own.
                    if not step_done and ch_ptr[].has_buffered_request():
                        last_step = ch_ptr[].on_readable_static(resp, config)
                        step_done = last_step.done
                if (
                    not step_done
                    and last_step.want_read
                    and ch_ptr[].has_buffered_request()
                ):
                    # The cycle cap stopped us with a whole request still
                    # buffered: ask for a writable edge, which a
                    # level-triggered socket raises at once, so the
                    # branch above serves it on the next poll.
                    last_step.want_write = True
                if not step_done:
                    _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
            except:
                step_done = True
            if step_done:
                _cleanup_conn(fd, conns, timers, reactor, wheel)

    store_worker_stat(stats_addr, WORKER_STAT_STATUS, exit_status)

    # Graceful shutdown. Dedicated path flips ``Cancel.SHUTDOWN`` on
    # every leftover ConnHandle before close (paranoia copy from the
    # cancel-aware loops; the static path's own state machine ignores
    # the cell, but cancel-aware handlers wrapped around static
    # endpoints might observe it elsewhere). Shared path skips the
    # flip to match the prior behaviour of
    # ``run_reactor_loop_static_shared``.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)

    comptime if not is_shared:
        for i in range(len(leftover)):
            var ch_ptr = _conn_ptr_from_int(conns[leftover[i]])
            ch_ptr[].cancel_cell.flip(CancelReason.SHUTDOWN)
            _cleanup_conn(leftover[i], conns, timers, reactor, wheel)
    else:
        for i in range(len(leftover)):
            _cleanup_conn(leftover[i], conns, timers, reactor, wheel)


def run_reactor_loop_static(
    mut listener: TcpListener,
    config: ServerConfig,
    resp: StaticResponse,
    ref stopping: Bool,
) raises:
    """Reactor loop specialised for a pre-encoded ``StaticResponse``.

    Mirrors ``run_reactor_loop`` but drives each connection through
    ``ConnHandle.on_readable_static(resp, config)`` instead of the
    parse-and-dispatch path. Delegates to
    :func:`_run_static_loop_impl` with ``is_shared=False`` so the
    listener registers without ``EPOLLEXCLUSIVE``.

    Args:
        listener: Bound and listening ``TcpListener`` (caller owns it;
            we borrow for accept / fd access).
        config: Server configuration.
        resp: Pre-encoded static response.
        stopping: Checked on every poll iteration; when True the loop
            exits and in-flight connections are closed.
    """
    listener._socket.set_nonblocking(True)
    _run_static_loop_impl[is_shared=False](
        Int(listener._socket.fd), config, resp, stopping
    )


def run_reactor_loop_static_shared(
    listener_fd: Int,
    config: ServerConfig,
    resp: StaticResponse,
    ref stopping: Bool,
    stats_addr: Int = 0,
) raises:
    """Multi-worker twin of :func:`run_reactor_loop_static`.

    Drives a pre-encoded ``StaticResponse`` over a SHARED listener fd
    (owned by the ``StaticScheduler``; never closed here). Delegates
    to :func:`_run_static_loop_impl` with ``is_shared=True`` so the
    listener registers with ``EPOLLEXCLUSIVE`` (Linux >= 4.5; falls
    back to plain register on macOS) and the kernel wakes only one
    worker per accept event.

    The combination of the static fast path with the multi-worker
    scheduler is the fastest path flare exposes for fixed-response
    endpoints: per-request work drops to memcpy + the syscall pair,
    which scales near-linearly across cores.

    Args:
        listener_fd: Borrowed shared listener fd. Must be in
            non-blocking mode (the ``StaticScheduler`` does this once
            at bind-time). This worker never closes it.
        config: Per-worker copy of ``ServerConfig``.
        resp: Pre-encoded static response (immutable; safely shared
            across workers via ``StaticScheduler``'s heap-stored copy).
        stopping: Heap-allocated stop flag mutated by
            ``StaticScheduler.shutdown`` from the main thread.
    """
    _run_static_loop_impl[is_shared=True](
        listener_fd, config, resp, stopping, stats_addr
    )


def run_reactor_loop_cancel[
    CH: CancelHandler
](
    mut listener: TcpListener,
    config: ServerConfig,
    ref handler: CH,
    ref stopping: Bool,
    stats_addr: Int = 0,
) raises:
    """Cancel-aware variant of ``run_reactor_loop``.

    Identical control flow to ``run_reactor_loop`` but drives each
    connection through ``ConnHandle.on_readable_cancel(handler,
    config)`` instead of ``on_readable``, so the handler receives
    a ``Cancel`` token bound to the connection's per-request
    ``CancelCell``.

    The reactor flips that cell on:
    - ``CancelReason.PEER_CLOSED`` — peer FIN observed before the
      response was queued.
    - ``CancelReason.TIMEOUT`` — wired in commit 5 of .
    - ``CancelReason.SHUTDOWN`` — wired in commit 6 of .

    Args:
        listener: Bound and listening ``TcpListener`` (caller-owned;
            borrowed for accept / fd access).
        config: Server configuration.
        handler: Per-request cancel-aware callback.
        stopping: Checked each iteration; flipping it stops the loop
            and closes in-flight connections.
    """
    listener._socket.set_nonblocking(True)
    var listener_fd = listener._socket.fd

    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    reactor.register(listener_fd, UInt64(0), INTEREST_READ)

    var events = List[Event]()
    var exit_status = WORKER_STATUS_CLEAN
    var stopping_addr = Int(Pointer[Bool, _](to=stopping))
    while not load_stop_flag(stopping_addr):
        store_worker_stat(stats_addr, WORKER_STAT_INFLIGHT, len(conns))
        events.clear()
        try:
            _ = reactor.poll(_poll_timeout_ms(wheel), events)
        except:
            exit_status = WORKER_STATUS_CRASHED
            break

        var now_ms = UInt64(_monotonic_ms())
        var fired = List[UInt64]()
        wheel.advance(now_ms, fired)
        for i in range(len(fired)):
            var fd_tok = Int(fired[i])
            if fd_tok in conns:
                _cleanup_conn(fd_tok, conns, timers, reactor, wheel)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop(
                    listener,
                    reactor,
                    conns,
                    wheel,
                    timers,
                    config.idle_timeout_ms,
                    config.max_connections,
                )
                continue
            var fd = Int(evt.token)
            if fd not in conns:
                continue
            var ch_ptr = _conn_ptr_from_int(conns[fd])
            var step_done = False
            try:
                var last_step = StepResult()
                if evt.is_readable():
                    last_step = ch_ptr[].on_readable_cancel(handler, config)
                    step_done = last_step.done
                    var cycles = 0
                    while (not step_done) and cycles < 3:
                        cycles += 1
                        if (
                            last_step.want_write
                            and len(ch_ptr[].write_buf) > ch_ptr[].write_pos
                        ):
                            last_step = ch_ptr[].on_writable(config)
                            step_done = last_step.done
                        elif (
                            last_step.want_read
                            and len(ch_ptr[].read_buf) > 0
                            and ch_ptr[].state == STATE_READING
                        ):
                            last_step = ch_ptr[].on_readable_cancel(
                                handler, config
                            )
                            step_done = last_step.done
                        else:
                            break
                elif evt.is_writable():
                    last_step = ch_ptr[].on_writable(config)
                    step_done = last_step.done
                    # A response just finished flushing; any pipelined
                    # request behind it is already in read_buf and will
                    # raise no readable event of its own.
                    if not step_done and ch_ptr[].has_buffered_request():
                        last_step = ch_ptr[].on_readable_cancel(handler, config)
                        step_done = last_step.done
                if (
                    not step_done
                    and last_step.want_read
                    and ch_ptr[].has_buffered_request()
                ):
                    # The cycle cap stopped us with a whole request still
                    # buffered: ask for a writable edge, which a
                    # level-triggered socket raises at once, so the
                    # branch above serves it on the next poll.
                    last_step.want_write = True
                if not step_done:
                    _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
            except:
                step_done = True
            if step_done:
                _cleanup_conn(fd, conns, timers, reactor, wheel)

    store_worker_stat(stats_addr, WORKER_STAT_STATUS, exit_status)

    # Graceful shutdown: walk every active conn and flip its
    # CancelCell to SHUTDOWN before closing. Cancel-aware
    # handlers (CancelHandler) observe the flip and short-circuit
    # at their next ``cancel.cancelled()`` poll. Plain Handlers
    # (which don't observe Cancel) run to completion as before.
    # The flip is in-thread (the worker walks its own conns,
    # not via cross-thread atomics) — handles the cross-thread
    # cancel-flip without exposing the per-worker registry across
    # threads.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        var ch_ptr = _conn_ptr_from_int(conns[leftover[i]])
        ch_ptr[].cancel_cell.flip(CancelReason.SHUTDOWN)
        _cleanup_conn(leftover[i], conns, timers, reactor, wheel)


def run_reactor_loop_view[
    VH: ViewHandler
](
    mut listener: TcpListener,
    config: ServerConfig,
    ref handler: VH,
    ref stopping: Bool,
    stats_addr: Int = 0,
) raises:
    """View-aware variant of ``run_reactor_loop_cancel``.

    Identical control flow but drives each connection through
    ``ConnHandle.on_readable_view(handler, config)`` instead of
    ``on_readable_cancel``, so the handler receives a borrowed
    ``RequestView[origin]`` whose body slice points directly into
    ``self.read_buf``. This satisfies the zero-copy upload
    contract for handlers that opt into the ``ViewHandler``
    shape.

    Args:
        listener: Bound and listening ``TcpListener``.
        config: Server configuration.
        handler: Per-request view-aware handler.
        stopping: Checked each iteration.
    """
    listener._socket.set_nonblocking(True)
    var listener_fd = listener._socket.fd

    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    reactor.register(listener_fd, UInt64(0), INTEREST_READ)

    var events = List[Event]()
    var exit_status = WORKER_STATUS_CLEAN
    var stopping_addr = Int(Pointer[Bool, _](to=stopping))
    while not load_stop_flag(stopping_addr):
        store_worker_stat(stats_addr, WORKER_STAT_INFLIGHT, len(conns))
        events.clear()
        try:
            _ = reactor.poll(_poll_timeout_ms(wheel), events)
        except:
            exit_status = WORKER_STATUS_CRASHED
            break

        var now_ms = UInt64(_monotonic_ms())
        var fired = List[UInt64]()
        wheel.advance(now_ms, fired)
        for i in range(len(fired)):
            var fd_tok = Int(fired[i])
            if fd_tok in conns:
                _cleanup_conn(fd_tok, conns, timers, reactor, wheel)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop(
                    listener,
                    reactor,
                    conns,
                    wheel,
                    timers,
                    config.idle_timeout_ms,
                    config.max_connections,
                )
                continue
            var fd = Int(evt.token)
            if fd not in conns:
                continue
            var ch_ptr = _conn_ptr_from_int(conns[fd])
            var step_done = False
            try:
                var last_step = StepResult()
                if evt.is_readable():
                    last_step = ch_ptr[].on_readable_view(handler, config)
                    step_done = last_step.done
                    var cycles = 0
                    while (not step_done) and cycles < 3:
                        cycles += 1
                        if (
                            last_step.want_write
                            and len(ch_ptr[].write_buf) > ch_ptr[].write_pos
                        ):
                            last_step = ch_ptr[].on_writable(config)
                            step_done = last_step.done
                        elif (
                            last_step.want_read
                            and len(ch_ptr[].read_buf) > 0
                            and ch_ptr[].state == STATE_READING
                        ):
                            last_step = ch_ptr[].on_readable_view(
                                handler, config
                            )
                            step_done = last_step.done
                        else:
                            break
                elif evt.is_writable():
                    last_step = ch_ptr[].on_writable(config)
                    step_done = last_step.done
                    # A response just finished flushing; any pipelined
                    # request behind it is already in read_buf and will
                    # raise no readable event of its own.
                    if not step_done and ch_ptr[].has_buffered_request():
                        last_step = ch_ptr[].on_readable_view(handler, config)
                        step_done = last_step.done
                if (
                    not step_done
                    and last_step.want_read
                    and ch_ptr[].has_buffered_request()
                ):
                    # The cycle cap stopped us with a whole request still
                    # buffered: ask for a writable edge, which a
                    # level-triggered socket raises at once, so the
                    # branch above serves it on the next poll.
                    last_step.want_write = True
                if not step_done:
                    _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
            except:
                step_done = True
            if step_done:
                _cleanup_conn(fd, conns, timers, reactor, wheel)

    store_worker_stat(stats_addr, WORKER_STAT_STATUS, exit_status)

    # Graceful shutdown: flip Cancel.SHUTDOWN on every in-flight
    # conn before closing — same in-thread pattern as
    # ``run_reactor_loop_cancel``. Cancel-aware
    # handlers (CancelHandler / ViewHandler) observe the flip
    # at their next ``cancel.cancelled()`` poll. Plain Handlers
    # ignore Cancel and run to completion.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        var ch_ptr = _conn_ptr_from_int(conns[leftover[i]])
        ch_ptr[].cancel_cell.flip(CancelReason.SHUTDOWN)
        _cleanup_conn(leftover[i], conns, timers, reactor, wheel)
