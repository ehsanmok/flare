"""epoll/kqueue server reactor loops + per-connection lifecycle glue.

The ``Reactor``-backed (epoll on Linux, kqueue on macOS) server event
loops -- dynamic-handler, static-response, cancel-aware and view-aware
variants and their dedicated/shared-listener wrappers -- plus the shared
connection-lifecycle helpers (alloc/free/lookup of a ``ConnHandle``,
``_apply_step`` reactor/timer translation, ``_cleanup_conn`` teardown,
and the two accept drainers) that both the epoll and io_uring loops
build on. Split out of ``_server_reactor_impl.mojo`` to keep each module
within the file-size budget; ``_server_reactor_impl`` re-exports every
public name so existing ``from flare.http._server_reactor_impl import
run_reactor_loop ...`` (server.mojo, frontend.mojo, _unified_reactor_impl,
tests) call sites keep resolving unchanged. Pure code motion.
"""

from std.builtin.debug_assert import debug_assert
from std.collections import Dict, Optional
from std.ffi import c_int, c_size_t, external_call, get_errno, ErrNo
from std.os import getenv
from std.memory import UnsafePointer, alloc, memcpy, stack_allocation
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


@always_inline
def _poll_timeout_ms(read wheel: TimerWheel, cap_ms: Int = 100) -> Int:
    """Reactor poll timeout: time until the next timer fires, capped.

    Replaces the fixed 100ms poll (D7). The ``cap_ms`` stays
    load-bearing for shutdown-flag responsiveness (the stop flag is
    re-read once per poll), so idle workers still wake at most every
    ``cap_ms``; when a timer is due sooner the reactor wakes just in
    time to fire it. Floor of 1ms avoids a busy 0ms spin on a
    just-past-due timer. Cost is one bounded ``next_fire_ms`` slot
    scan, independent of the active-timer count.
    """
    var nf = wheel.next_fire_ms()
    var now = UInt64(_monotonic_ms())
    if nf <= now:
        return 1
    var delta = Int(nf - now)
    return delta if delta < cap_ms else cap_ms


def _conn_alloc_addr(var stream: TcpStream) raises -> Int:
    """Heap-allocate a ``ConnHandle`` wrapping ``stream`` and
    return its address.

    Routes through ``Pool[ConnHandle]`` (``flare/runtime/pool.mojo``,
    ) so the unsafe-pointer plumbing is
    confined to ``flare/runtime/``. The rest of this file's hot
    path stays at the typed-Int address layer.
    """
    return Pool[ConnHandle].alloc_move(ConnHandle(stream^))


def _conn_free_addr(addr: Int):
    """Destroy and free a ``ConnHandle`` previously allocated via
    ``_conn_alloc_addr``.

    Safe to call on 0 (no-op). Routes through ``Pool[ConnHandle].free``.
    """
    Pool[ConnHandle].free(addr)


def _conn_ptr_from_int(
    addr: Int,
) -> UnsafePointer[ConnHandle, MutUntrackedOrigin]:
    """Reverse of ``_conn_alloc_addr``: reconstruct a typed pointer."""
    return UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=addr
    ).bitcast[ConnHandle]()


def _apply_step(
    fd: Int,
    step: StepResult,
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
    conn_ptr: UnsafePointer[ConnHandle, MutUntrackedOrigin],
) raises:
    """Translate a ``StepResult`` into reactor + timer-wheel operations.

    Skips ``reactor.modify`` when the new interest bits equal the
    previously-registered ones — ``reactor.modify`` is a syscall
    (epoll_ctl / kevent), so avoiding no-op transitions on keep-alive
    connections is a measurable win.
    """
    var interest: Int = 0
    if step.want_read:
        interest |= INTEREST_READ
    if step.want_write:
        interest |= INTEREST_WRITE
    if interest != 0 and interest != conn_ptr[].last_interest:
        try:
            reactor.modify(c_int(fd), interest)
            conn_ptr[].last_interest = interest
        except:
            pass
    if step.idle_timeout_ms == 0:
        if fd in timers:
            _ = wheel.cancel(timers[fd])
            _ = timers.pop(fd)
    elif step.idle_timeout_ms > 0:
        if fd in timers:
            _ = wheel.cancel(timers[fd])
        var tid = wheel.schedule(step.idle_timeout_ms, UInt64(fd))
        timers[fd] = tid


def _cleanup_conn(
    fd: Int,
    mut conns: Dict[Int, Int],
    mut timers: Dict[Int, UInt64],
    mut reactor: Reactor,
):
    """Unregister, cancel timers, and free the ConnHandle for ``fd``."""
    if fd in timers:
        try:
            _ = timers.pop(fd)
        except:
            pass
    try:
        reactor.unregister(c_int(fd))
    except:
        pass
    if fd in conns:
        try:
            var addr = conns.pop(fd)
            _conn_free_addr(addr)
        except:
            pass


# errno values consulted on the accept path. EAGAIN / EWOULDBLOCK mean
# the backlog is drained (normal stop); ECONNABORTED means one pending
# connection was aborted before we accepted it (skip it, keep draining);
# EMFILE / ENFILE mean the process / system fd table is exhausted (stop
# and let a later poll retry once fds free). Linux and macOS disagree on
# the numeric values for EAGAIN / EWOULDBLOCK / ECONNABORTED, so both
# sets are matched; a misread just degrades to the old "break on any
# error" behaviour, which is safe.
comptime _EAGAIN_LINUX: Int = 11
comptime _EAGAIN_MACOS: Int = 35
comptime _ECONNABORTED_LINUX: Int = 103
comptime _ECONNABORTED_MACOS: Int = 53


@always_inline
def _accept_errno_is_retry(ev: Int) -> Bool:
    """True when the accept errno is ECONNABORTED (skip + keep draining)."""
    return ev == _ECONNABORTED_LINUX or ev == _ECONNABORTED_MACOS


def _accept_loop(
    mut listener: TcpListener,
    mut reactor: Reactor,
    mut conns: Dict[Int, Int],
    max_connections: Int = 0,
):
    """Accept every connection available on ``listener`` (until EAGAIN).

    Each accepted socket is switched to non-blocking mode, heap-allocated
    into a ``ConnHandle``, and registered with the reactor using the
    client fd as the token.

    ``max_connections`` (0 = unlimited) caps the per-worker live table:
    at the cap the drainer stops accepting so surplus connections stay
    in the kernel backlog (backpressure) instead of growing the table
    without bound. On an accept error the errno decides the action --
    ECONNABORTED skips one and keeps draining; everything else
    (EAGAIN drained / EMFILE-ENFILE exhausted) stops this pass.
    """
    while True:
        if max_connections > 0 and len(conns) >= max_connections:
            break
        var stream: TcpStream
        try:
            stream = listener.accept()
        except:
            if _accept_errno_is_retry(Int(get_errno().value)):
                continue
            break
        try:
            stream._socket.set_nonblocking(True)
        except:
            pass
        var client_fd = Int(stream._socket.fd)
        var addr: Int
        try:
            addr = _conn_alloc_addr(stream^)
        except:
            continue
        conns[client_fd] = addr
        try:
            reactor.register(c_int(client_fd), UInt64(client_fd), INTEREST_READ)
        except:
            _conn_free_addr(addr)
            try:
                _ = conns.pop(client_fd)
            except:
                pass


def _accept_loop_fd(
    listener_fd: Int,
    mut reactor: Reactor,
    mut conns: Dict[Int, Int],
    max_connections: Int = 0,
):
    """Accept every available connection on a *borrowed* listener fd.

    Mirrors ``_accept_loop`` but takes the listener as a raw integer
    fd instead of a ``TcpListener`` so the multi-worker scheduler
    can share a single listener across workers without giving any
    one worker ownership of the underlying ``TcpListener``. The
    listener fd is owned by the ``Scheduler`` and stays open for the
    lifetime of the multi-worker run.

    Stops on ``EAGAIN`` / ``EWOULDBLOCK`` (backlog drained) or on
    ``EMFILE`` / ``ENFILE`` (fd table exhausted); skips + keeps draining
    on ``ECONNABORTED``. ``max_connections`` (0 = unlimited) caps the
    per-worker live table exactly as in ``_accept_loop``.
    """
    while True:
        if max_connections > 0 and len(conns) >= max_connections:
            break
        var stream: TcpStream
        try:
            stream = accept_fd(c_int(listener_fd))
        except:
            if _accept_errno_is_retry(Int(get_errno().value)):
                continue
            break
        try:
            stream._socket.set_nonblocking(True)
        except:
            pass
        var client_fd = Int(stream._socket.fd)
        var addr: Int
        try:
            addr = _conn_alloc_addr(stream^)
        except:
            continue
        conns[client_fd] = addr
        try:
            reactor.register(c_int(client_fd), UInt64(client_fd), INTEREST_READ)
        except:
            _conn_free_addr(addr)
            try:
                _ = conns.pop(client_fd)
            except:
                pass


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
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
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
                _cleanup_conn(fd_tok, conns, timers, reactor)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop_fd(
                    listener_fd, reactor, conns, config.max_connections
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
                if not step_done:
                    _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
            except:
                step_done = True
            if step_done:
                _cleanup_conn(fd, conns, timers, reactor)

    store_worker_stat(stats_addr, WORKER_STAT_STATUS, exit_status)

    # Graceful shutdown: close every per-conn fd. The listener fd
    # is owned by the caller in both modes (Scheduler in the shared
    # case; the wrapper's ``mut TcpListener`` in the dedicated case)
    # and is never closed here.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn(leftover[i], conns, timers, reactor)


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
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
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
                _cleanup_conn(fd_tok, conns, timers, reactor)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop_fd(
                    listener_fd, reactor, conns, config.max_connections
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
                if not step_done:
                    _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
            except:
                step_done = True
            if step_done:
                _cleanup_conn(fd, conns, timers, reactor)

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
            _cleanup_conn(leftover[i], conns, timers, reactor)
    else:
        for i in range(len(leftover)):
            _cleanup_conn(leftover[i], conns, timers, reactor)


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
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
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
                _cleanup_conn(fd_tok, conns, timers, reactor)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop(listener, reactor, conns, config.max_connections)
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
                if not step_done:
                    _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
            except:
                step_done = True
            if step_done:
                _cleanup_conn(fd, conns, timers, reactor)

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
        _cleanup_conn(leftover[i], conns, timers, reactor)


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
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
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
                _cleanup_conn(fd_tok, conns, timers, reactor)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop(listener, reactor, conns, config.max_connections)
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
                if not step_done:
                    _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
            except:
                step_done = True
            if step_done:
                _cleanup_conn(fd, conns, timers, reactor)

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
        _cleanup_conn(leftover[i], conns, timers, reactor)
