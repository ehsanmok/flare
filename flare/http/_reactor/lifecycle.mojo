"""Connection-lifecycle glue shared by the epoll/kqueue and io_uring loops.

``ConnHandle`` alloc/free/lookup, the ``StepResult`` -> reactor/timer
translation (``_apply_step``), teardown (``_cleanup_conn``), the poll
timeout, and the accept drainers with their idle-timer arming. Moved out
of ``_server_reactor_epoll`` to keep that module inside its size budget;
it re-exports every name here, so ``from
flare.http._server_reactor_epoll import _conn_alloc_addr`` and friends
keep resolving. Pure code motion.
"""

from std.builtin.debug_assert import debug_assert
from std.collections import Dict, Optional
from std.ffi import c_int, get_errno
from std.memory import Pointer

from flare.runtime import (
    Reactor,
    TimerWheel,
    INTEREST_READ,
    INTEREST_WRITE,
    Pool,
)
from flare.runtime._balance import Balancer
from flare.tcp import TcpStream, TcpListener, accept_fd

from .conn_handle import ConnHandle
from .keepalive_scan import StepResult, _monotonic_ms


@always_inline
def _poll_timeout_ms(imm wheel: TimerWheel, cap_ms: Int = 100) -> Int:
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


def _collect_fired_timers(
    now_ms: UInt64,
    mut wheel: TimerWheel,
    timers: Dict[Int, UInt64],
    mut fired_fds: List[Int],
    mut fired_ids: List[UInt64],
) raises:
    """Advance the wheel to ``now_ms`` and record which connections' timers
    fired, without closing anything yet.

    The wheel is advanced right after ``poll`` so its clock is current for
    every ``schedule`` made while the events are handled. Reaping is a
    separate step (:func:`_expired_idle_conns`) that runs *after* the
    events: a connection whose request was already waiting when its
    deadline passed (the loop was busy in another handler) gets that request
    served and its timer re-armed first, instead of being closed unanswered.

    ``fired_fds[i]`` is the connection; ``fired_ids[i]`` is the timer id
    ``timers`` held for it when it fired (0 if none), the baseline for
    "was it re-armed since".
    """
    var fired = List[UInt64]()
    wheel.advance(now_ms, fired)
    for i in range(len(fired)):
        var fd = Int(fired[i])
        fired_fds.append(fd)
        fired_ids.append(timers[fd] if fd in timers else UInt64(0))


def _expired_idle_conns(
    fired_fds: List[Int],
    fired_ids: List[UInt64],
    conns: Dict[Int, Int],
    timers: Dict[Int, UInt64],
) raises -> List[Int]:
    """The fired connections that should now be closed.

    A fired connection is spared if event handling touched it in between:
    it is gone (closed, or its fd number already belongs to a newer
    connection with its own timer), or its timer was re-armed or cleared
    (``timers[fd]`` no longer holds the id recorded when it fired). What is
    left had no activity since its deadline passed.
    """
    var out = List[Int]()
    for i in range(len(fired_fds)):
        var fd = fired_fds[i]
        if fd not in conns:
            continue
        var current = timers[fd] if fd in timers else UInt64(0)
        if current == fired_ids[i]:
            out.append(fd)
    return out^


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
) -> Pointer[ConnHandle, MutUntrackedOrigin]:
    """Reverse of ``_conn_alloc_addr``: reconstruct a typed pointer."""
    return Pointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=addr
    ).unsafe_bitcast[ConnHandle]()


def _apply_step(
    fd: Int,
    step: StepResult,
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
    conn_ptr: Pointer[ConnHandle, MutUntrackedOrigin],
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
    mut wheel: TimerWheel,
):
    """Unregister, cancel timers, and free the ConnHandle for ``fd``."""
    # Cancel, not just forget. A timer left in the wheel fires later
    # with this fd number as its payload; if the kernel has handed the
    # number to a new connection by then, the expiry closed *that*
    # connection mid-request.
    if fd in timers:
        var tid = UInt64(0)
        try:
            tid = timers.pop(fd)
        except:
            pass
        try:
            _ = wheel.cancel(tid)
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


def _arm_accept_timer(
    client_fd: Int,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
    idle_timeout_ms: Int,
):
    """Arm the idle timer for a connection that has just been accepted.

    Timers used to be armed only by the first readable event, so a
    connection that never sent a byte was never timed out: enough of
    them exhaust the fd table and the worker stops accepting. Shared by
    every accept loop, HTTP/1.1 and unified.
    """
    if idle_timeout_ms <= 0:
        return
    try:
        timers[client_fd] = wheel.schedule(idle_timeout_ms, UInt64(client_fd))
    except:
        pass


def _accept_loop(
    mut listener: TcpListener,
    mut reactor: Reactor,
    mut conns: Dict[Int, Int],
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
    idle_timeout_ms: Int,
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
            continue
        _arm_accept_timer(client_fd, wheel, timers, idle_timeout_ms)


def _accept_loop_fd(
    listener_fd: Int,
    mut reactor: Reactor,
    mut conns: Dict[Int, Int],
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
    idle_timeout_ms: Int,
    max_connections: Int = 0,
    bal: Balancer = Balancer(),
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

    When ``bal`` is enabled and this worker holds clearly more
    connections than the least-loaded peer, the new stream goes to that
    peer instead (see ``flare.runtime._balance``); otherwise it stays
    here, as before.
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
        if bal.enabled():
            var target = bal.pick(len(conns))
            if target >= 0:
                var back = _hand_off_stream(stream^, target, bal)
                if not back:
                    continue
                stream = back.take()
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
            continue
        _arm_accept_timer(client_fd, wheel, timers, idle_timeout_ms)
        bal.publish(len(conns))


def _hand_off_stream(
    var stream: TcpStream, target: Int, bal: Balancer
) -> Optional[TcpStream]:
    """Give ``stream`` to worker ``target`` through its inbox.

    Returns ``None`` once the peer owns it. When the peer refuses (it
    stopped, or its inbox is full) the stream comes back so the caller
    keeps the connection. A failed heap allocation drops it, which
    closes the connection; the allocation is one small cell.
    """
    var addr: Int
    try:
        addr = Pool[TcpStream].alloc_move(stream^)
    except:
        return None
    if bal.push(target, addr):
        return None
    var cell = Pool[TcpStream].get_ptr(addr)
    var back = cell.unsafe_take_pointee()
    cell.unsafe_free()
    return Optional[TcpStream](back^)


def _adopt_handed_off_h1(
    bal: Balancer,
    mut reactor: Reactor,
    mut conns: Dict[Int, Int],
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
    idle_timeout_ms: Int,
    max_connections: Int,
):
    """Register every stream peers left in this worker's inbox as an
    HTTP/1.1 ``ConnHandle`` (the plain and static loops)."""
    while True:
        var addr = bal.pop()
        if addr == 0:
            break
        var cell = Pool[TcpStream].get_ptr(addr)
        var stream = cell.unsafe_take_pointee()
        cell.unsafe_free()
        if max_connections > 0 and len(conns) >= max_connections:
            continue
        var client_fd = Int(stream._socket.fd)
        var conn: Int
        try:
            conn = _conn_alloc_addr(stream^)
        except:
            continue
        conns[client_fd] = conn
        try:
            reactor.register(c_int(client_fd), UInt64(client_fd), INTEREST_READ)
        except:
            _conn_free_addr(conn)
            try:
                _ = conns.pop(client_fd)
            except:
                pass
            continue
        _arm_accept_timer(client_fd, wheel, timers, idle_timeout_ms)
    bal.publish(len(conns))


struct ListenerGate(Movable):
    """Stop polling the listener(s) while a worker is at its connection cap.

    A listener with a connection waiting stays readable, so a loop that
    declines to accept at ``max_connections`` but leaves the listener
    registered wakes on every ``poll`` and spins. The gate takes the
    listener(s) out of the reactor when the live table reaches the cap and
    puts them back as soon as a slot frees; the kernel queues the waiting
    clients meanwhile, and the level-triggered listener reports them again
    on resume. ``sync`` runs once per loop turn, after the turn's
    connections have closed.

    A listener registered with ``EPOLLEXCLUSIVE`` cannot be re-armed in
    place, so pausing is a delete and resuming a fresh add.
    """

    var fds: List[Int]
    var tokens: List[UInt64]
    var armed: List[Bool]
    var exclusive: Bool
    var paused: Bool

    def __init__(out self, exclusive: Bool = False):
        self.fds = List[Int]()
        self.tokens = List[UInt64]()
        self.armed = List[Bool]()
        self.exclusive = exclusive
        self.paused = False

    def add(mut self, fd: Int, token: UInt64):
        """Track a listener that is already registered under ``token``."""
        self.fds.append(fd)
        self.tokens.append(token)
        self.armed.append(True)

    def sync(mut self, mut reactor: Reactor, live: Int, cap: Int):
        """Pause at ``live >= cap`` (``cap > 0``), resume once below it."""
        if cap <= 0:
            return
        if not self.paused:
            if live < cap:
                return
            for i in range(len(self.fds)):
                if not self.armed[i]:
                    continue
                try:
                    reactor.unregister(c_int(self.fds[i]))
                    self.armed[i] = False
                except:
                    pass
            self.paused = True
            return
        if live >= cap:
            return
        var all_armed = True
        for i in range(len(self.fds)):
            if self.armed[i]:
                continue
            try:
                if self.exclusive:
                    reactor.register_exclusive(
                        c_int(self.fds[i]), self.tokens[i], INTEREST_READ
                    )
                else:
                    reactor.register(
                        c_int(self.fds[i]), self.tokens[i], INTEREST_READ
                    )
                self.armed[i] = True
            except:
                all_armed = False
        # A listener that failed to re-arm is retried on the next turn.
        self.paused = not all_armed
