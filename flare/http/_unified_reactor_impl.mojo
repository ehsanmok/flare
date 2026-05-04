"""Unified reactor loop: HTTP/1.1 + HTTP/2 on the same listener.

Wires :class:`flare.http._server_reactor_impl.ConnHandle` (HTTP/1.1)
and :class:`flare.http._h2_conn_handle.H2ConnHandle` (HTTP/2)
behind a single accept loop that auto-detects the wire protocol per
connection by peeking the first 24 bytes for the RFC 9113 §3.4
client connection preface (``"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"``).

Per-connection lifecycle:

::

    accept -> PendingConnHandle (buffer up to 24 bytes)
                   |
       +-----------+----------+
       v                      v
     PROTO_HTTP1           PROTO_HTTP2
       |                      |
       v                      v
     ConnHandle            H2ConnHandle
   (existing HTTP/1.1)   (HTTP/2 driver in the reactor)

Both terminal handles dispatch through the same
:meth:`flare.http.Handler.serve` callback, so the user's
application code is unchanged: a :class:`flare.http.Router`, an
:class:`flare.http.App[S]`, a middleware-wrapped chain -- they
all serve identically over both wire protocols. The unified loop
exists so the user never has to choose: every accepted
connection auto-dispatches to the right per-conn state machine.

Single-listener variant (:func:`run_unified_reactor_loop`) is
the single-threaded entry point used by
:meth:`HttpServer.serve(handler, num_workers=1)`. The shared
variant (:func:`run_unified_reactor_loop_shared`) is the
multi-worker entry point used when ``num_workers >= 2``: the
:class:`Scheduler` owns the listener, every worker borrows the
fd and registers it with ``EPOLLEXCLUSIVE`` (Linux) so the
kernel wakes one worker per accept event.
"""

from std.builtin.debug_assert import debug_assert
from std.collections import Dict
from std.ffi import c_int
from std.memory import UnsafePointer

from flare.http.cancel import CancelReason
from flare.http.handler import Handler
from flare.http.server import ServerConfig
from flare.http2.server import Http2Config
from flare.net import RawSocket, SocketAddr
from flare.net._libc import AF_INET, SOCK_STREAM, _close
from flare.runtime import (
    Reactor,
    Event,
    TimerWheel,
    INTEREST_READ,
    INTEREST_WRITE,
)
from flare.tcp import TcpListener, TcpStream, accept_fd

from ._h2_conn_handle import (
    H2ConnHandle,
    PendingConnHandle,
    PROTO_HTTP1,
    PROTO_HTTP2,
    PROTO_NEED_MORE,
    _h2_conn_alloc_addr,
    _h2_conn_free_addr,
    _h2_conn_ptr_from_int,
    _pending_conn_alloc_addr,
    _pending_conn_free_addr,
    _pending_conn_ptr_from_int,
)
from ._server_reactor_impl import (
    ConnHandle,
    StepResult,
    STATE_READING,
    STATE_WRITING,
    _apply_step,
    _conn_alloc_addr,
    _conn_free_addr,
    _conn_ptr_from_int,
    _monotonic_ms,
)


# ── Per-conn dispatch helpers ──────────────────────────────────────────────


def _drive_h1[
    H: Handler
](
    fd: Int,
    addr: Int,
    ref handler: H,
    config: ServerConfig,
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
) raises -> Bool:
    """Drive one HTTP/1.1 ConnHandle through ``on_readable`` (with
    the same 3-cycle inline fast-path the standalone HTTP/1.1
    reactor uses) and apply the resulting StepResult.

    Returns ``True`` when the connection is finished (caller
    must clean it up); ``False`` to keep it live.
    """
    var ch_ptr = _conn_ptr_from_int(addr)
    var step_done = False
    try:
        var last_step = ch_ptr[].on_readable(handler, config)
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
                last_step = ch_ptr[].on_readable(handler, config)
                step_done = last_step.done
            else:
                break
        if not step_done:
            _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
    except:
        step_done = True
    return step_done


def _drive_h1_writable(
    fd: Int,
    addr: Int,
    config: ServerConfig,
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
) raises -> Bool:
    """Drive one HTTP/1.1 ConnHandle through ``on_writable`` only."""
    var ch_ptr = _conn_ptr_from_int(addr)
    var step_done = False
    try:
        var last_step = ch_ptr[].on_writable(config)
        step_done = last_step.done
        if not step_done:
            _apply_step(fd, last_step, reactor, wheel, timers, ch_ptr)
    except:
        step_done = True
    return step_done


def _apply_step_h2(
    fd: Int,
    step: StepResult,
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
    h2_ptr: UnsafePointer[H2ConnHandle, MutExternalOrigin],
) raises:
    """Translate an :class:`H2ConnHandle` step into reactor + timer ops.

    Identical to :func:`_apply_step` but typed for H2ConnHandle's
    ``last_interest`` field (the actual reactor.modify call shape
    is the same; we just need the type-correct pointer field
    update so the keep-alive interest cache works).
    """
    debug_assert[assert_mode="safe"](
        fd >= 0,
        "_apply_step_h2: fd must be non-negative; got ",
        fd,
    )
    debug_assert[assert_mode="safe"](
        Int(h2_ptr) != 0,
        "_apply_step_h2: h2_ptr must be non-NULL",
    )
    var interest: Int = 0
    if step.want_read:
        interest |= INTEREST_READ
    if step.want_write:
        interest |= INTEREST_WRITE
    if interest != 0 and interest != h2_ptr[].last_interest:
        try:
            reactor.modify(c_int(fd), interest)
            h2_ptr[].last_interest = interest
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


def _drive_h2[
    H: Handler
](
    fd: Int,
    addr: Int,
    ref handler: H,
    config: ServerConfig,
    is_readable: Bool,
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
) raises -> Bool:
    """Drive one HTTP/2 H2ConnHandle through one event."""
    var h2_ptr = _h2_conn_ptr_from_int(addr)
    var step_done = False
    try:
        var last_step: StepResult
        if is_readable:
            last_step = h2_ptr[].on_readable(handler, config)
        else:
            last_step = h2_ptr[].on_writable(config)
        step_done = last_step.done
        # Inline cycle: if the read produced bytes to send, drain
        # them in the same iteration to avoid a kernel round-trip.
        var cycles = 0
        while (not step_done) and cycles < 3:
            cycles += 1
            if (
                last_step.want_write
                and len(h2_ptr[].write_buf) > h2_ptr[].write_pos
            ):
                last_step = h2_ptr[].on_writable(config)
                step_done = last_step.done
            else:
                break
        if not step_done:
            _apply_step_h2(fd, last_step, reactor, wheel, timers, h2_ptr)
    except:
        step_done = True
    return step_done


def _cleanup_conn_unified(
    fd: Int,
    mut pending_conns: Dict[Int, Int],
    mut h1_conns: Dict[Int, Int],
    mut h2_conns: Dict[Int, Int],
    mut timers: Dict[Int, UInt64],
    mut reactor: Reactor,
):
    """Unregister, cancel timers, and free whichever per-conn handle
    owns ``fd``."""
    if fd in timers:
        try:
            _ = timers.pop(fd)
        except:
            pass
    try:
        reactor.unregister(c_int(fd))
    except:
        pass
    if fd in pending_conns:
        try:
            var addr = pending_conns.pop(fd)
            _pending_conn_free_addr(addr)
        except:
            pass
        return
    if fd in h1_conns:
        try:
            var addr = h1_conns.pop(fd)
            _conn_free_addr(addr)
        except:
            pass
        return
    if fd in h2_conns:
        try:
            var addr = h2_conns.pop(fd)
            _h2_conn_free_addr(addr)
        except:
            pass


def _migrate_pending(
    fd: Int,
    decision: Int,
    h2_config: Http2Config,
    mut pending_conns: Dict[Int, Int],
    mut h1_conns: Dict[Int, Int],
    mut h2_conns: Dict[Int, Int],
) raises -> Bool:
    """Promote a pending conn to either ConnHandle or H2ConnHandle.

    Returns ``True`` if the migration succeeded, ``False`` if it
    failed (the pending entry is freed in either case; the caller
    should treat ``False`` as "drop the connection").
    """
    if fd not in pending_conns:
        return False
    var pending_addr = pending_conns[fd]
    debug_assert[assert_mode="safe"](
        pending_addr != 0,
        "_migrate_pending: pending_conns[fd] returned null addr; fd=",
        fd,
    )
    debug_assert[assert_mode="safe"](
        decision == PROTO_HTTP1 or decision == PROTO_HTTP2,
        "_migrate_pending: invalid decision sentinel; got ",
        decision,
    )
    var pending_ptr = _pending_conn_ptr_from_int(pending_addr)
    # Snapshot what we need OUT of the pending handle before
    # destroying it. UnsafePointer dereference does not give
    # Mojo a tracked origin, so we cannot ``^`` -move the
    # ``_stream`` field directly out of ``pending_ptr[]``.
    # Instead we copy the bytes (small, max 24) and the fd /
    # peer, detach the pending's internal fd to ``-1`` so its
    # destructor doesn't double-close, then rebuild a fresh
    # TcpStream around the borrowed fd to hand to the chosen
    # per-conn handle.
    var prefaced = pending_ptr[].take_stream_and_buf()
    var inherited_fd = pending_ptr[]._stream._socket.fd
    debug_assert[assert_mode="safe"](
        Int(inherited_fd) >= 0,
        "_migrate_pending: pending handle fd was already detached; got ",
        Int(inherited_fd),
    )
    debug_assert[assert_mode="safe"](
        Int(inherited_fd) == fd,
        "_migrate_pending: pending fd does not match dispatch fd; got ",
        Int(inherited_fd),
        " vs ",
        fd,
    )
    var inherited_peer = pending_ptr[].peer
    pending_ptr[]._stream._socket.fd = c_int(-1)
    _ = pending_conns.pop(fd)
    _pending_conn_free_addr(pending_addr)

    var raw = RawSocket(inherited_fd, AF_INET, SOCK_STREAM, _wrap=True)
    var stream = TcpStream(raw^, inherited_peer)

    if decision == PROTO_HTTP2:
        try:
            var addr = _h2_conn_alloc_addr(stream^, h2_config.copy())
            h2_conns[fd] = addr
            var h2_ptr = _h2_conn_ptr_from_int(addr)
            if len(prefaced) > 0:
                h2_ptr[].push_initial_bytes(Span[UInt8, _](prefaced))
            return True
        except:
            return False
    # HTTP/1.1: allocate ConnHandle and pre-load read_buf with
    # the bytes the pending handle already drained from the
    # socket so the HTTP/1.1 parser sees a contiguous stream.
    try:
        var addr = _conn_alloc_addr(stream^)
        h1_conns[fd] = addr
        var ch_ptr = _conn_ptr_from_int(addr)
        if len(prefaced) > 0:
            for i in range(len(prefaced)):
                ch_ptr[].read_buf.append(prefaced[i])
        return True
    except:
        return False


# ── Accept loop with deferred-protocol handles ─────────────────────────────


def _accept_loop_unified(
    mut listener: TcpListener,
    mut reactor: Reactor,
    mut pending_conns: Dict[Int, Int],
):
    """Accept every available connection and register it as a
    :class:`PendingConnHandle`."""
    while True:
        var stream: TcpStream
        try:
            stream = listener.accept()
        except:
            break
        try:
            stream._socket.set_nonblocking(True)
        except:
            pass
        var client_fd = Int(stream._socket.fd)
        var addr: Int
        try:
            addr = _pending_conn_alloc_addr(stream^)
        except:
            continue
        pending_conns[client_fd] = addr
        try:
            reactor.register(c_int(client_fd), UInt64(client_fd), INTEREST_READ)
        except:
            _pending_conn_free_addr(addr)
            try:
                _ = pending_conns.pop(client_fd)
            except:
                pass


def _accept_loop_unified_fd(
    listener_fd: Int,
    mut reactor: Reactor,
    mut pending_conns: Dict[Int, Int],
):
    """Shared-listener variant of :func:`_accept_loop_unified`."""
    while True:
        var stream: TcpStream
        try:
            stream = accept_fd(c_int(listener_fd))
        except:
            break
        try:
            stream._socket.set_nonblocking(True)
        except:
            pass
        var client_fd = Int(stream._socket.fd)
        var addr: Int
        try:
            addr = _pending_conn_alloc_addr(stream^)
        except:
            continue
        pending_conns[client_fd] = addr
        try:
            reactor.register(c_int(client_fd), UInt64(client_fd), INTEREST_READ)
        except:
            _pending_conn_free_addr(addr)
            try:
                _ = pending_conns.pop(client_fd)
            except:
                pass


# ── Unified reactor loop -- single listener (single-worker) ────────────────


def run_unified_reactor_loop[
    H: Handler
](
    mut listener: TcpListener,
    config: ServerConfig,
    var h2_config: Http2Config,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Single-threaded reactor loop that auto-dispatches HTTP/1.1 vs
    HTTP/2 per connection.

    Args:
        listener: Bound + listening :class:`TcpListener`. Caller
            retains ownership; we only borrow for accept.
        config: HTTP/1.1 server configuration (used by the
            :class:`ConnHandle` state machine and timer wheel).
        h2_config: HTTP/2 server configuration (used by every
            :class:`H2ConnHandle` we instantiate when the
            preface peek decides a connection is h2).
        handler: User's request handler.
        stopping: External stop flag; checked each loop iteration
            via a fresh :class:`UnsafePointer` so the optimiser
            cannot LICM-hoist the load (the multicore Scheduler
            mutates it from another thread).
    """
    listener._socket.set_nonblocking(True)
    var listener_fd = listener._socket.fd

    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var pending_conns = Dict[Int, Int]()
    var h1_conns = Dict[Int, Int]()
    var h2_conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    reactor.register(listener_fd, UInt64(0), INTEREST_READ)

    var events = List[Event]()
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
    while not UnsafePointer[Bool, MutExternalOrigin](
        unsafe_from_address=stopping_addr
    )[]:
        events.clear()
        try:
            _ = reactor.poll(100, events)
        except:
            break

        var now_ms = UInt64(_monotonic_ms())
        var fired = List[UInt64]()
        wheel.advance(now_ms, fired)
        for i in range(len(fired)):
            var fd_tok = Int(fired[i])
            _cleanup_conn_unified(
                fd_tok, pending_conns, h1_conns, h2_conns, timers, reactor
            )

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop_unified(listener, reactor, pending_conns)
                continue
            var fd = Int(evt.token)

            # 1. Pending conn -- decide protocol.
            if fd in pending_conns:
                if not evt.is_readable():
                    continue
                var pending_ptr = _pending_conn_ptr_from_int(pending_conns[fd])
                var decision: Int
                try:
                    decision = pending_ptr[].on_readable()
                except:
                    decision = PROTO_HTTP1  # fall back so cleanup runs
                if decision == PROTO_NEED_MORE:
                    continue
                var ok = _migrate_pending(
                    fd,
                    decision,
                    h2_config,
                    pending_conns,
                    h1_conns,
                    h2_conns,
                )
                if not ok:
                    _cleanup_conn_unified(
                        fd,
                        pending_conns,
                        h1_conns,
                        h2_conns,
                        timers,
                        reactor,
                    )
                    continue
                # After migration, drive the chosen handle once
                # to consume any prefetched bytes.
                if decision == PROTO_HTTP2 and fd in h2_conns:
                    var done = _drive_h2(
                        fd,
                        h2_conns[fd],
                        handler,
                        config,
                        True,  # is_readable
                        reactor,
                        wheel,
                        timers,
                    )
                    if done:
                        _cleanup_conn_unified(
                            fd,
                            pending_conns,
                            h1_conns,
                            h2_conns,
                            timers,
                            reactor,
                        )
                elif decision == PROTO_HTTP1 and fd in h1_conns:
                    var done2 = _drive_h1(
                        fd,
                        h1_conns[fd],
                        handler,
                        config,
                        reactor,
                        wheel,
                        timers,
                    )
                    if done2:
                        _cleanup_conn_unified(
                            fd,
                            pending_conns,
                            h1_conns,
                            h2_conns,
                            timers,
                            reactor,
                        )
                continue

            # 2. HTTP/1.1 conn.
            if fd in h1_conns:
                var done3 = False
                if evt.is_readable():
                    done3 = _drive_h1(
                        fd,
                        h1_conns[fd],
                        handler,
                        config,
                        reactor,
                        wheel,
                        timers,
                    )
                elif evt.is_writable():
                    done3 = _drive_h1_writable(
                        fd, h1_conns[fd], config, reactor, wheel, timers
                    )
                if done3:
                    _cleanup_conn_unified(
                        fd,
                        pending_conns,
                        h1_conns,
                        h2_conns,
                        timers,
                        reactor,
                    )
                continue

            # 3. HTTP/2 conn.
            if fd in h2_conns:
                var done4 = _drive_h2(
                    fd,
                    h2_conns[fd],
                    handler,
                    config,
                    evt.is_readable(),
                    reactor,
                    wheel,
                    timers,
                )
                if done4:
                    _cleanup_conn_unified(
                        fd,
                        pending_conns,
                        h1_conns,
                        h2_conns,
                        timers,
                        reactor,
                    )

    # Graceful shutdown: close all live conns.
    var leftover = List[Int]()
    for kv in pending_conns.items():
        leftover.append(kv.key)
    for kv in h1_conns.items():
        leftover.append(kv.key)
    for kv in h2_conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn_unified(
            leftover[i], pending_conns, h1_conns, h2_conns, timers, reactor
        )


# ── Unified reactor loop -- shared listener (multi-worker) ──────────────────


def run_unified_reactor_loop_shared[
    H: Handler
](
    listener_fd: Int,
    config: ServerConfig,
    var h2_config: Http2Config,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Multi-worker variant of :func:`run_unified_reactor_loop`.

    The :class:`Scheduler` owns the listener; this worker borrows
    the fd and registers it with ``EPOLLEXCLUSIVE`` so the kernel
    wakes one worker per accept event (Linux >= 4.5; macOS
    degrades to plain ``register`` -- the wakeup pattern is
    "wake-all, one-wins" but practical behaviour is similar
    because ``accept(2)`` on the losers returns ``EAGAIN``).
    """
    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var pending_conns = Dict[Int, Int]()
    var h1_conns = Dict[Int, Int]()
    var h2_conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    reactor.register_exclusive(c_int(listener_fd), UInt64(0), INTEREST_READ)

    var events = List[Event]()
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
    while not UnsafePointer[Bool, MutExternalOrigin](
        unsafe_from_address=stopping_addr
    )[]:
        events.clear()
        try:
            _ = reactor.poll(100, events)
        except:
            break

        var now_ms = UInt64(_monotonic_ms())
        var fired = List[UInt64]()
        wheel.advance(now_ms, fired)
        for i in range(len(fired)):
            var fd_tok = Int(fired[i])
            _cleanup_conn_unified(
                fd_tok, pending_conns, h1_conns, h2_conns, timers, reactor
            )

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop_unified_fd(listener_fd, reactor, pending_conns)
                continue
            var fd = Int(evt.token)

            if fd in pending_conns:
                if not evt.is_readable():
                    continue
                var pending_ptr = _pending_conn_ptr_from_int(pending_conns[fd])
                var decision: Int
                try:
                    decision = pending_ptr[].on_readable()
                except:
                    decision = PROTO_HTTP1
                if decision == PROTO_NEED_MORE:
                    continue
                var ok = _migrate_pending(
                    fd,
                    decision,
                    h2_config,
                    pending_conns,
                    h1_conns,
                    h2_conns,
                )
                if not ok:
                    _cleanup_conn_unified(
                        fd,
                        pending_conns,
                        h1_conns,
                        h2_conns,
                        timers,
                        reactor,
                    )
                    continue
                if decision == PROTO_HTTP2 and fd in h2_conns:
                    var done = _drive_h2(
                        fd,
                        h2_conns[fd],
                        handler,
                        config,
                        True,
                        reactor,
                        wheel,
                        timers,
                    )
                    if done:
                        _cleanup_conn_unified(
                            fd,
                            pending_conns,
                            h1_conns,
                            h2_conns,
                            timers,
                            reactor,
                        )
                elif decision == PROTO_HTTP1 and fd in h1_conns:
                    var done2 = _drive_h1(
                        fd,
                        h1_conns[fd],
                        handler,
                        config,
                        reactor,
                        wheel,
                        timers,
                    )
                    if done2:
                        _cleanup_conn_unified(
                            fd,
                            pending_conns,
                            h1_conns,
                            h2_conns,
                            timers,
                            reactor,
                        )
                continue

            if fd in h1_conns:
                var done3 = False
                if evt.is_readable():
                    done3 = _drive_h1(
                        fd,
                        h1_conns[fd],
                        handler,
                        config,
                        reactor,
                        wheel,
                        timers,
                    )
                elif evt.is_writable():
                    done3 = _drive_h1_writable(
                        fd, h1_conns[fd], config, reactor, wheel, timers
                    )
                if done3:
                    _cleanup_conn_unified(
                        fd,
                        pending_conns,
                        h1_conns,
                        h2_conns,
                        timers,
                        reactor,
                    )
                continue

            if fd in h2_conns:
                var done4 = _drive_h2(
                    fd,
                    h2_conns[fd],
                    handler,
                    config,
                    evt.is_readable(),
                    reactor,
                    wheel,
                    timers,
                )
                if done4:
                    _cleanup_conn_unified(
                        fd,
                        pending_conns,
                        h1_conns,
                        h2_conns,
                        timers,
                        reactor,
                    )

    var leftover = List[Int]()
    for kv in pending_conns.items():
        leftover.append(kv.key)
    for kv in h1_conns.items():
        leftover.append(kv.key)
    for kv in h2_conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn_unified(
            leftover[i], pending_conns, h1_conns, h2_conns, timers, reactor
        )
