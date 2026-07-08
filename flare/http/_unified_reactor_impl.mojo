# Unified reactor loop: HTTP/1.1 + HTTP/2 on the same listener.
#
# The per-tick body and the dedicated/shared single-listener loops
# share one comptime-parametric core
# (`_run_unified_loop_for_fd[H, is_shared]`). The
# multi-listener variant retains its own outer loop because it
# discriminates accept events by ``fd in listener_fds_dict``
# instead of ``token == 0``; that fd-set discriminator is
# structurally distinct and unifying it would add complexity
# rather than remove it.

"""Unified reactor loop: HTTP/1.1 + HTTP/2 on the same listener.

Wires :class:`flare.http._server_reactor_impl.ConnHandle` (HTTP/1.1)
and :class:`flare.http._h2_conn_handle.Http2ConnHandle` (HTTP/2)
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
     ConnHandle            Http2ConnHandle
   (existing HTTP/1.1)   (HTTP/2 driver in the reactor)

Both terminal handles dispatch through the same
:meth:`flare.http.Handler.serve` callback, so the user's
application code is unchanged: a :class:`flare.http.Router`,
a middleware-wrapped chain -- they
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
    Http2ConnHandle,
    PendingConnHandle,
    PROTO_HTTP1,
    PROTO_HTTP2,
    PROTO_NEED_MORE,
    _h2_conn_alloc_addr,
    _h2_conn_alloc_addr_from_h2c_upgrade,
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


# ────────────────────────────────────────────────────────────────────────────
# Tagged-pointer dispatch encoding lives in ``_reactor/tagged_dispatch.mojo``
# (split out for file size); imported here unchanged.
# ────────────────────────────────────────────────────────────────────────────
from ._reactor.tagged_dispatch import (
    _TAG_SHIFT,
    _ADDR_MASK,
    KIND_PENDING,
    KIND_H1,
    KIND_H2,
    _pack,
    _kind,
    _addr,
)


# ── Per-conn dispatch helpers ──────────────────────────────────────────────


def _drive_h1[
    H: Handler
](
    fd: Int,
    addr: Int,
    ref handler: H,
    config: ServerConfig,
    h2_config: Http2Config,
    mut conns: Dict[Int, Int],
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
) raises -> Bool:
    """Drive one HTTP/1.1 ConnHandle through ``on_readable`` (with
    the same 3-cycle inline fast-path the standalone HTTP/1.1
    reactor uses) and apply the resulting StepResult.

    If a step returns ``h2c_upgrade=True`` (the 101 Switching
    Protocols response has flushed and the conn must migrate to
    HTTP/2), :func:`_migrate_h1_to_h2` is called to swap the
    conn-dict entry; the function then immediately drives the new
    Http2ConnHandle once so the server's initial SETTINGS frame
    flushes without a kernel round-trip.

    Returns ``True`` when the connection is finished (caller
    must clean it up); ``False`` to keep it live.
    """
    var ch_ptr = _conn_ptr_from_int(addr)
    var step_done: Bool
    try:
        var last_step = ch_ptr[].on_readable(handler, config)
        step_done = last_step.done
        var cycles = 0
        while (not step_done) and cycles < 3:
            cycles += 1
            if last_step.h2c_upgrade:
                break
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
        if last_step.h2c_upgrade and not step_done:
            # The h1 ConnHandle has flushed the 101 response. Migrate
            # to the h2 handle in place; the conn-dict entry swaps
            # KIND_H1 -> KIND_H2 + the original request becomes
            # stream id 1 on the new Http2ConnHandle.
            var migrated = _migrate_h1_to_h2(fd, h2_config, conns)
            if not migrated:
                return True  # migration failed; caller cleans up
            # Drive the new Http2ConnHandle once so its initial-SETTINGS
            # write_buf flushes immediately + reactor interest is
            # registered on the writable side.
            if fd in conns:
                var packed = conns[fd]
                if _kind(packed) == KIND_H2:
                    var done_h2 = _drive_h2(
                        fd,
                        _addr(packed),
                        handler,
                        config,
                        False,
                        reactor,
                        wheel,
                        timers,
                    )
                    return done_h2
            return False
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
    var step_done: Bool
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
    h2_ptr: UnsafePointer[Http2ConnHandle, MutUntrackedOrigin],
) raises:
    """Translate an :class:`Http2ConnHandle` step into reactor + timer ops.

    Identical to :func:`_apply_step` but typed for Http2ConnHandle's
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
    """Drive one HTTP/2 Http2ConnHandle through one event."""
    var h2_ptr = _h2_conn_ptr_from_int(addr)
    var step_done: Bool
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
    mut conns: Dict[Int, Int],
    mut timers: Dict[Int, UInt64],
    mut reactor: Reactor,
):
    """Unregister, cancel timers, and free whichever per-conn handle
    owns ``fd``. Single-dict variant -- dispatches by the kind tag
    packed into ``conns[fd]``."""
    if fd in timers:
        try:
            _ = timers.pop(fd)
        except:
            pass
    try:
        reactor.unregister(c_int(fd))
    except:
        pass
    if fd not in conns:
        return
    try:
        var packed = conns.pop(fd)
        var k = _kind(packed)
        var a = _addr(packed)
        if k == KIND_PENDING:
            _pending_conn_free_addr(a)
        elif k == KIND_H1:
            _conn_free_addr(a)
        elif k == KIND_H2:
            _h2_conn_free_addr(a)
    except:
        pass


def _migrate_h1_to_h2(
    fd: Int,
    h2_config: Http2Config,
    mut conns: Dict[Int, Int],
) raises -> Bool:
    """Migrate an h1 ``ConnHandle`` to an h2 :class:`Http2ConnHandle`.

    Triggered by ``ConnHandle.on_writable`` returning a
    :class:`StepResult` with ``h2c_upgrade=True`` after the
    ``101 Switching Protocols`` response has flushed (RFC 7540
    §3.2). Snapshots the saved ``Request`` + decoded
    ``HTTP2-Settings`` payload from the h1 handle, builds an
    Http2ConnHandle pre-seeded with those (the original request
    becomes stream id 1), and swaps the conn-dict entry from
    ``KIND_H1`` to ``KIND_H2``. The h1 handle's heap allocation is
    freed; its TCP fd is inherited by the new h2 handle.

    Returns ``True`` on success; ``False`` if the dict entry was
    missing or the migration raised mid-transition (the entry is
    already removed in that case so the caller should NOT attempt
    cleanup).
    """
    if fd not in conns:
        return False
    var packed = conns[fd]
    debug_assert[assert_mode="safe"](
        _kind(packed) == KIND_H1,
        "_migrate_h1_to_h2: entry is not KIND_H1; kind=",
        _kind(packed),
    )
    var h1_addr = _addr(packed)
    debug_assert[assert_mode="safe"](
        h1_addr != 0,
        "_migrate_h1_to_h2: conns[fd] returned null addr; fd=",
        fd,
    )
    var h1_ptr = _conn_ptr_from_int(h1_addr)
    # Pull the migration payload off the h1 handle BEFORE we
    # detach its TcpStream. ``take_h2c_upgrade_settings`` resets
    # the pending flag so a second migration attempt on the same
    # fd raises rather than silently double-using the request.
    var req = h1_ptr[].take_h2c_upgrade_request()
    var settings_payload = h1_ptr[].take_h2c_upgrade_settings()
    # Detach the TCP fd from the h1 handle: snapshot fd + peer,
    # zero the field on the h1 handle so its destructor doesn't
    # close the fd we want to inherit.
    var inherited_fd = h1_ptr[]._stream._socket.fd
    var inherited_peer = h1_ptr[].peer
    debug_assert[assert_mode="safe"](
        Int(inherited_fd) == fd,
        "_migrate_h1_to_h2: h1 fd does not match dispatch fd; got ",
        Int(inherited_fd),
        " vs ",
        fd,
    )
    h1_ptr[]._stream._socket.fd = c_int(-1)
    _conn_free_addr(h1_addr)

    var raw = RawSocket(inherited_fd, AF_INET, SOCK_STREAM, _wrap=True)
    var stream = TcpStream(raw^, inherited_peer)

    try:
        var addr = _h2_conn_alloc_addr_from_h2c_upgrade(
            stream^, h2_config.copy(), req, settings_payload^
        )
        conns[fd] = _pack(KIND_H2, addr)
        return True
    except:
        try:
            _ = conns.pop(fd)
        except:
            pass
        return False


def _migrate_pending(
    fd: Int,
    decision: Int,
    h2_config: Http2Config,
    mut conns: Dict[Int, Int],
) raises -> Bool:
    """Promote a pending conn to either ConnHandle or Http2ConnHandle.

    Mutates the dict entry **in place**: replaces the
    KIND_PENDING-tagged value with a KIND_H1- or KIND_H2-tagged
    one. Returns ``True`` on success; ``False`` means the
    migration failed AND the entry has been removed (caller
    should not attempt cleanup -- the pending was already freed).
    """
    if fd not in conns:
        return False
    var packed = conns[fd]
    debug_assert[assert_mode="safe"](
        _kind(packed) == KIND_PENDING,
        "_migrate_pending: entry is not KIND_PENDING; kind=",
        _kind(packed),
    )
    var pending_addr = _addr(packed)
    debug_assert[assert_mode="safe"](
        pending_addr != 0,
        "_migrate_pending: conns[fd] returned null addr; fd=",
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
    _pending_conn_free_addr(pending_addr)

    var raw = RawSocket(inherited_fd, AF_INET, SOCK_STREAM, _wrap=True)
    var stream = TcpStream(raw^, inherited_peer)

    if decision == PROTO_HTTP2:
        try:
            var addr = _h2_conn_alloc_addr(stream^, h2_config.copy())
            conns[fd] = _pack(KIND_H2, addr)
            var h2_ptr = _h2_conn_ptr_from_int(addr)
            if len(prefaced) > 0:
                h2_ptr[].push_initial_bytes(Span[UInt8, _](prefaced))
            return True
        except:
            try:
                _ = conns.pop(fd)
            except:
                pass
            return False
    # HTTP/1.1: allocate ConnHandle and pre-load read_buf with
    # the bytes the pending handle already drained from the
    # socket so the HTTP/1.1 parser sees a contiguous stream.
    try:
        var addr = _conn_alloc_addr(stream^)
        conns[fd] = _pack(KIND_H1, addr)
        var ch_ptr = _conn_ptr_from_int(addr)
        if len(prefaced) > 0:
            for i in range(len(prefaced)):
                ch_ptr[].read_buf.append(prefaced[i])
        return True
    except:
        try:
            _ = conns.pop(fd)
        except:
            pass
        return False


# ── Accept loop with deferred-protocol handles ─────────────────────────────


def _accept_loop_unified_fd(
    listener_fd: Int,
    mut reactor: Reactor,
    mut conns: Dict[Int, Int],
):
    """Accept every available connection on ``listener_fd`` and
    register it as a KIND_PENDING-tagged
    :class:`PendingConnHandle` in the shared ``conns`` table.

    Used by every single-listener unified loop variant (dedicated,
    shared/EPOLLEXCLUSIVE, multi-listener); the dedicated variant
    extracts the listener fd before calling.
    """
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
        conns[client_fd] = _pack(KIND_PENDING, addr)
        try:
            reactor.register(c_int(client_fd), UInt64(client_fd), INTEREST_READ)
        except:
            _pending_conn_free_addr(addr)
            try:
                _ = conns.pop(client_fd)
            except:
                pass


# ── Shared per-event dispatch + lifecycle helpers ──────────────────────────
#
# The three reactor entry points
# (run_unified_reactor_loop, _multi, _shared) used to embed three
# byte-for-byte copies of the same per-event dispatch body
# (~80 LOC each). Behaviour-preserving extraction collapses
# them into a single ``_unified_handle_conn_event`` core; the
# entry points keep their distinct accept-routing (single
# listener, multi listener, EPOLLEXCLUSIVE-shared listener) and
# each becomes a ~30-line wrapper that polls + advances timers
# + delegates per-event dispatch + drains on shutdown.


@always_inline
def _advance_timer_wheel_unified(
    now_ms: UInt64,
    mut wheel: TimerWheel,
    mut conns: Dict[Int, Int],
    mut timers: Dict[Int, UInt64],
    mut reactor: Reactor,
) raises:
    """Step the timer wheel and reap any connections whose timeout
    fired this tick.

    Centralises the three-line pattern (advance + iterate fired +
    cleanup) that was duplicated in every loop variant.
    """
    var fired = List[UInt64]()
    wheel.advance(now_ms, fired)
    for i in range(len(fired)):
        var fd_tok = Int(fired[i])
        _cleanup_conn_unified(fd_tok, conns, timers, reactor)


def _unified_handle_conn_event[
    H: Handler
](
    fd: Int,
    packed: Int,
    is_readable: Bool,
    is_writable: Bool,
    ref handler: H,
    config: ServerConfig,
    h2_config: Http2Config,
    mut conns: Dict[Int, Int],
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
) raises:
    """Dispatch one reactor event for an already-known connection fd.

    Caller has filtered out wakeup events and listener-accept
    events; ``fd`` is in ``conns``; ``packed`` is the tagged
    pointer pulled from ``conns[fd]``. The body branches on
    ``_kind(packed)`` exactly the way the three duplicate copies
    used to: HTTP/1.1 hot path first (most common in production
    keep-alive workloads), then HTTP/2, then the cold pending
    (preface-peek) path which migrates to KIND_H1 / KIND_H2 and
    drives the chosen handle once to consume any prefetched bytes.
    """
    var k = _kind(packed)

    # Hot path: HTTP/1.1 keep-alive (the most common kind in
    # production). Branch first so the optimiser can speculate
    # the success case.
    if k == KIND_H1:
        var done3 = False
        if is_readable:
            done3 = _drive_h1(
                fd,
                _addr(packed),
                handler,
                config,
                h2_config,
                conns,
                reactor,
                wheel,
                timers,
            )
        elif is_writable:
            done3 = _drive_h1_writable(
                fd,
                _addr(packed),
                config,
                reactor,
                wheel,
                timers,
            )
        if done3:
            _cleanup_conn_unified(fd, conns, timers, reactor)
        return

    if k == KIND_H2:
        var done4 = _drive_h2(
            fd,
            _addr(packed),
            handler,
            config,
            is_readable,
            reactor,
            wheel,
            timers,
        )
        if done4:
            _cleanup_conn_unified(fd, conns, timers, reactor)
        return

    # Cold path: protocol-undecided (PendingConnHandle). Runs at
    # most once per accepted conn before it promotes to KIND_H1
    # or KIND_H2 via _migrate_pending.
    if not is_readable:
        return
    var pending_ptr = _pending_conn_ptr_from_int(_addr(packed))
    var decision: Int
    try:
        decision = pending_ptr[].on_readable()
    except:
        decision = PROTO_HTTP1
    if decision == PROTO_NEED_MORE:
        return
    var ok = _migrate_pending(fd, decision, h2_config, conns)
    if not ok:
        _cleanup_conn_unified(fd, conns, timers, reactor)
        return
    # After migration, drive the chosen handle once to consume
    # any prefetched bytes (e.g. the bytes that arrived after
    # the 24-byte preface in the same TCP segment).
    if fd not in conns:
        return
    var packed2 = conns[fd]
    var k2 = _kind(packed2)
    if k2 == KIND_H2:
        var done = _drive_h2(
            fd,
            _addr(packed2),
            handler,
            config,
            True,
            reactor,
            wheel,
            timers,
        )
        if done:
            _cleanup_conn_unified(fd, conns, timers, reactor)
    elif k2 == KIND_H1:
        var done2 = _drive_h1(
            fd,
            _addr(packed2),
            handler,
            config,
            h2_config,
            conns,
            reactor,
            wheel,
            timers,
        )
        if done2:
            _cleanup_conn_unified(fd, conns, timers, reactor)


@always_inline
def _drain_remaining_conns_unified(
    mut conns: Dict[Int, Int],
    mut timers: Dict[Int, UInt64],
    mut reactor: Reactor,
) raises:
    """Close every connection still in ``conns``.

    Called from the shutdown tail of each loop variant.
    Listener fds (when applicable) are not in ``conns`` and are
    closed by the caller; the loop only borrows them.
    """
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn_unified(leftover[i], conns, timers, reactor)


# ── Unified reactor loop -- single listener (single-worker) ────────────────


def _run_unified_loop_for_fd[
    H: Handler,
    is_shared: Bool,
](
    listener_fd: Int,
    config: ServerConfig,
    var h2_config: Http2Config,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Shared body for the single-listener unified reactor loops.

    Identical poll-and-dispatch core for the dedicated
    (``is_shared=False``) and shared (``is_shared=True``) variants;
    the only listener-side difference is ``register`` vs
    ``register_exclusive``. Both register the listener under
    ``token = 0`` and route every other event by ``conns`` lookup.

    The multi-listener variant doesn't share this body because it
    routes accept events by ``fd in listener_fds_dict`` instead of
    ``token == 0`` -- that fd-set discriminator is structurally
    different enough to warrant its own outer loop.
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
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
    while not UnsafePointer[Bool, MutUntrackedOrigin](
        unsafe_from_address=stopping_addr
    )[]:
        events.clear()
        try:
            _ = reactor.poll(100, events)
        except:
            break

        var now_ms = UInt64(_monotonic_ms())
        _advance_timer_wheel_unified(now_ms, wheel, conns, timers, reactor)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop_unified_fd(listener_fd, reactor, conns)
                continue
            var fd = Int(evt.token)
            if fd not in conns:
                continue
            var packed = conns[fd]
            _unified_handle_conn_event(
                fd,
                packed,
                evt.is_readable(),
                evt.is_writable(),
                handler,
                config,
                h2_config,
                conns,
                reactor,
                wheel,
                timers,
            )

    _drain_remaining_conns_unified(conns, timers, reactor)


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
            :class:`Http2ConnHandle` we instantiate when the
            preface peek decides a connection is h2).
        handler: User's request handler.
        stopping: External stop flag; checked each loop iteration
            via a fresh :class:`UnsafePointer` so the optimiser
            cannot LICM-hoist the load (the multicore Scheduler
            mutates it from another thread).

    Delegates to :func:`_run_unified_loop_for_fd[H, False]` after
    extracting the listener fd; identical to the shared variant
    except for ``register`` vs ``register_exclusive``.
    """
    listener._socket.set_nonblocking(True)
    _run_unified_loop_for_fd[H, False](
        Int(listener._socket.fd),
        config,
        h2_config^,
        handler,
        stopping,
    )


# ── Unified reactor loop -- multi-listener (single-worker) ─────────────────


def run_unified_reactor_loop_multi[
    H: Handler
](
    mut primary: TcpListener,
    extra_fds: List[Int],
    config: ServerConfig,
    var h2_config: Http2Config,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Single-worker reactor loop demuxing accepts across N listener fds.

    Same shape and semantics as :func:`run_unified_reactor_loop`
    (HTTP/1.1 + HTTP/2 auto-dispatch via the RFC 9113 §3.4
    preface peek), with one structural difference: every listener
    fd is registered with the reactor under ``token = fd`` so the
    accept loop can route incoming events to the correct listener.
    Connection events keep the existing ``token = client_fd``
    convention; ``conns`` is the disambiguator (a token is a
    listener fd iff it's not a key in ``conns``).

    Args:
        primary: First listener (the address returned by
            :meth:`HttpServer.local_addr`). Closed by the
            ``HttpServer`` owner; the loop only borrows.
        extra_fds: Raw fds for the additional listeners attached
            via :meth:`HttpServer.bind_many`. Owned by the caller
            (typically ``HttpServer._extra_listener_fds``); closed
            by ``HttpServer.__del__``. The loop only borrows them
            for ``accept(2)``.
        config: HTTP/1.1 server configuration.
        h2_config: HTTP/2 SETTINGS for h2 peers.
        handler: User's request handler.
        stopping: External stop flag.
    """
    from flare.net.socket import RawSocket, INVALID_FD, AF_INET, SOCK_STREAM

    primary._socket.set_nonblocking(True)
    for i in range(len(extra_fds)):
        # Wrap the fd in a temp RawSocket purely so we can call
        # set_nonblocking via the existing platform-aware path
        # (macOS arm64 routes through a libflare shim; Linux uses
        # fcntl directly). Must zero the fd before drop so the
        # destructor doesn't close what HttpServer still owns.
        try:
            var tmp = RawSocket(
                c_int(extra_fds[i]), AF_INET, SOCK_STREAM, _wrap=True
            )
            tmp.set_nonblocking(True)
            tmp.fd = INVALID_FD
        except:
            pass

    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    var primary_fd = primary._socket.fd
    var listener_fds = Dict[Int, Bool]()
    listener_fds[Int(primary_fd)] = True
    reactor.register(primary_fd, UInt64(Int(primary_fd)), INTEREST_READ)
    for i in range(len(extra_fds)):
        var f = c_int(extra_fds[i])
        listener_fds[Int(f)] = True
        reactor.register(f, UInt64(Int(f)), INTEREST_READ)

    var events = List[Event]()
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
    while not UnsafePointer[Bool, MutUntrackedOrigin](
        unsafe_from_address=stopping_addr
    )[]:
        events.clear()
        try:
            _ = reactor.poll(100, events)
        except:
            break

        var now_ms = UInt64(_monotonic_ms())
        _advance_timer_wheel_unified(now_ms, wheel, conns, timers, reactor)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            var fd = Int(evt.token)
            if fd in listener_fds:
                _accept_loop_unified_fd(fd, reactor, conns)
                continue
            if fd not in conns:
                continue
            var packed = conns[fd]
            _unified_handle_conn_event(
                fd,
                packed,
                evt.is_readable(),
                evt.is_writable(),
                handler,
                config,
                h2_config,
                conns,
                reactor,
                wheel,
                timers,
            )

    # Graceful shutdown: close all live conns. Listener fds are
    # closed by ``HttpServer.__del__`` -- the loop only borrows.
    _drain_remaining_conns_unified(conns, timers, reactor)


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

    Delegates to :func:`_run_unified_loop_for_fd[H, True]`.
    """
    _run_unified_loop_for_fd[H, True](
        listener_fd,
        config,
        h2_config^,
        handler,
        stopping,
    )
