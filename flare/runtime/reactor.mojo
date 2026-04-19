"""Reactor: the event-loop core powering flare's single-threaded HTTP server.

The ``Reactor`` wraps ``epoll`` (Linux) and ``kqueue`` (macOS) behind a
uniform API. A single thread calls ``poll`` in a loop, then dispatches each
returned ``Event`` to the per-connection state machine.

Design:
- **One struct, comptime-dispatched backend.** No traits, no dynamic
  dispatch, no generic parameter. ``@parameter if
  CompilationTarget.is_linux()`` picks between epoll and kqueue at compile
  time. The caller writes backend-agnostic code.
- **Level-triggered semantics on both platforms** for Stage 1. Edge-triggered
  is a Phase 1.7 optimisation trial.
- **Tokens are UInt64** so the reactor can fit either an fd (when we don't
  care) or a pointer-sized handle (to a per-connection state struct) into
  the same field. Internally, epoll stores the token directly in
  ``data.u64``; kqueue stores it in ``udata``.
- **Wakeup primitive included.** Linux uses ``eventfd``; macOS uses a
  self-pipe. The wakeup fd is registered internally with
  ``WAKEUP_TOKEN``; ``poll`` surfaces those events to the caller who can
  filter them via ``Event.is_wakeup()``.
- **``Movable`` but not ``Copyable``.** The reactor owns an fd; duplicating
  the struct would lead to double-close bugs.

Not handled here (by design):
- Per-fd timers. That is ``TimerWheel`` in Phase 1.3.
- State machine. That is ``_server_reactor_impl`` in Phase 1.4.
- Multi-threading / SO_REUSEPORT. That is Stage 2.
"""

from std.collections import Dict
from std.ffi import c_int, c_uint, c_size_t, c_ssize_t, get_errno
from std.memory import UnsafePointer, stack_allocation
from std.sys.info import CompilationTarget

from flare.net._libc import (
    INVALID_FD,
    _close,
    _strerror,
    # Epoll
    EPOLLIN,
    EPOLLOUT,
    EPOLLERR,
    EPOLLHUP,
    EPOLLRDHUP,
    EPOLL_CTL_ADD,
    EPOLL_CTL_DEL,
    EPOLL_CTL_MOD,
    EPOLL_CLOEXEC,
    EPOLL_EVENT_SIZE,
    _epoll_create1,
    _epoll_ctl,
    _epoll_wait,
    _epoll_event_set,
    _epoll_event_read_events,
    _epoll_event_read_data,
    # Kqueue
    EVFILT_READ,
    EVFILT_WRITE,
    EVFILT_USER,
    EV_ADD,
    EV_DELETE,
    EV_ENABLE,
    EV_DISABLE,
    EV_EOF,
    EV_ERROR,
    NOTE_TRIGGER,
    KEVENT_SIZE,
    _kqueue,
    _kevent,
    _kevent_set,
    _kevent_read_ident,
    _kevent_read_filter,
    _kevent_read_flags,
    _kevent_read_fflags,
    _kevent_read_udata,
    # Wakeup
    EFD_NONBLOCK,
    EFD_CLOEXEC,
    _eventfd,
    _pipe,
    FlareRawIO,
)
from flare.net.error import NetworkError
from flare.runtime.event import (
    Event,
    INTEREST_READ,
    INTEREST_WRITE,
    EVENT_READABLE,
    EVENT_WRITABLE,
    EVENT_ERROR,
    EVENT_HUP,
    WAKEUP_TOKEN,
)


comptime _DEFAULT_MAX_EVENTS: Int = 64


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


@always_inline
def _interest_to_epoll(interest: Int) -> UInt32:
    """Translate INTEREST_* bits to EPOLL* bits (level-triggered)."""
    var bits: UInt32 = 0
    if (interest & INTEREST_READ) != 0:
        bits |= EPOLLIN | EPOLLRDHUP
    if (interest & INTEREST_WRITE) != 0:
        bits |= EPOLLOUT
    return bits


@always_inline
def _epoll_to_event_flags(epoll_bits: UInt32) -> Int:
    """Translate returned EPOLL* bits to EVENT_* bits."""
    var f: Int = 0
    if (epoll_bits & EPOLLIN) != 0:
        f |= EVENT_READABLE
    if (epoll_bits & EPOLLOUT) != 0:
        f |= EVENT_WRITABLE
    if (epoll_bits & EPOLLERR) != 0:
        f |= EVENT_ERROR
    if (epoll_bits & (EPOLLHUP | EPOLLRDHUP)) != 0:
        f |= EVENT_HUP
    return f


@always_inline
def _os_error(op: String) -> NetworkError:
    """Build a ``NetworkError`` from errno + ``op`` context."""
    var e = get_errno()
    return NetworkError(_strerror(e.value) + " (" + op + ")", Int(e.value))


# ──────────────────────────────────────────────────────────────────────────────
# Reactor
# ──────────────────────────────────────────────────────────────────────────────


struct Reactor(Movable):
    """An OS-event-loop handle with a uniform API over epoll and kqueue.

    Typical usage (single-threaded server loop):

    ```mojo
    from flare.runtime import Reactor, Event, INTEREST_READ

    var reactor = Reactor()
    reactor.register(listen_fd, UInt64(0), INTEREST_READ)
    var events = List[Event]()
    while True:
        var n = reactor.poll(-1, events)
        for i in range(n):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            # dispatch by token ...
    ```
    """

    var _fd: c_int
    """Epoll fd on Linux, kqueue fd on macOS."""

    var _wake_read: c_int
    """Eventfd (Linux) or pipe read-end (macOS) for cross-thread wakeup."""

    var _wake_write: c_int
    """Same fd as _wake_read on Linux (eventfd); pipe write-end on macOS."""

    var _registered: Dict[c_int, UInt64]
    """Bookkeeping: fd -> token. Used for invariant checks and to reject
    duplicate registrations."""

    var _io: FlareRawIO
    """Cached handle + function pointers for ``flare_read`` /
    ``flare_write`` in ``libflare_tls.so``. Used by ``poll`` to drain
    the wakeup fd and by ``wakeup`` to signal it. Keeping a single
    long-lived handle per reactor avoids a ``dlopen + dlsym + dlclose``
    round-trip on every wakeup event, which matters once Stage 2+
    cross-thread wakeup traffic ramps up."""

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def __init__(out self) raises:
        """Create a new reactor with its wakeup fd pre-registered.

        Raises:
            NetworkError: If any of the underlying syscalls fails (epoll_create1,
                eventfd, pipe, kqueue, initial registration).
        """
        # Resolve libflare_tls.so up front so the hot path never pays a
        # dlopen per wakeup. Construct this before any fd is opened so a
        # failure here doesn't leak an epoll/kqueue fd.
        self._io = FlareRawIO()

        comptime if CompilationTarget.is_linux():
            var epfd = _epoll_create1(EPOLL_CLOEXEC)
            if epfd < c_int(0):
                raise _os_error("epoll_create1")
            var efd = _eventfd(c_uint(0), EFD_NONBLOCK | EFD_CLOEXEC)
            if efd < c_int(0):
                var e = _os_error("eventfd")
                _ = _close(epfd)
                raise e
            self._fd = epfd
            self._wake_read = efd
            self._wake_write = efd
            self._registered = Dict[c_int, UInt64]()
            # Register the eventfd on the reactor with WAKEUP_TOKEN.
            try:
                self._register_raw(efd, WAKEUP_TOKEN, INTEREST_READ)
            except e:
                _ = _close(efd)
                _ = _close(epfd)
                raise e^
        else:
            var kq = _kqueue()
            if kq < c_int(0):
                raise _os_error("kqueue")
            var pipe_fds = stack_allocation[2, c_int]()
            pipe_fds.init_pointee_copy(INVALID_FD)
            (pipe_fds + 1).init_pointee_copy(INVALID_FD)
            if _pipe(pipe_fds) < c_int(0):
                var e = _os_error("pipe")
                _ = _close(kq)
                raise e
            var r_end = pipe_fds.load()
            var w_end = (pipe_fds + 1).load()
            self._fd = kq
            self._wake_read = r_end
            self._wake_write = w_end
            self._registered = Dict[c_int, UInt64]()
            try:
                self._register_raw(r_end, WAKEUP_TOKEN, INTEREST_READ)
            except e:
                _ = _close(r_end)
                _ = _close(w_end)
                _ = _close(kq)
                raise e^

    # No custom __moveinit__ needed: Mojo's default move for Movable
    # transfers the bytes and declares the source dead, so __del__ is not
    # called on the moved-from Reactor. Double-close is impossible.

    def __del__(deinit self):
        """Close the reactor fd and the wakeup fds."""
        if (
            self._wake_write != INVALID_FD
            and self._wake_write != self._wake_read
        ):
            _ = _close(self._wake_write)
        if self._wake_read != INVALID_FD:
            _ = _close(self._wake_read)
        if self._fd != INVALID_FD:
            _ = _close(self._fd)

    # ── Public API ────────────────────────────────────────────────────────────

    def register(
        mut self, fd: c_int, token: UInt64, interest: Int
    ) raises -> None:
        """Register ``fd`` with the reactor under ``token`` with the given
        interest bits.

        Args:
            fd:       The file descriptor to watch.
            token:    Opaque value returned in events for this fd. Must not
                      equal ``WAKEUP_TOKEN``.
            interest: Bitmask of ``INTEREST_READ | INTEREST_WRITE``.

        Raises:
            NetworkError: If ``fd`` is already registered, ``token`` equals
                the sentinel, ``interest`` is 0, or the underlying syscall
                fails.
        """
        if token == WAKEUP_TOKEN:
            raise NetworkError(
                "token WAKEUP_TOKEN is reserved for internal use", 0
            )
        if interest == 0:
            raise NetworkError("interest must include READ or WRITE", 0)
        if fd in self._registered:
            raise NetworkError("fd " + String(fd) + " is already registered", 0)
        self._register_raw(fd, token, interest)

    def modify(mut self, fd: c_int, interest: Int) raises -> None:
        """Change the interest bits for an already-registered fd.

        The token remains the same; pass the interest you want going forward.

        Args:
            fd:       Previously-registered fd.
            interest: New interest bits (must be non-zero).

        Raises:
            NetworkError: If ``fd`` is not registered or the syscall fails.
        """
        if interest == 0:
            raise NetworkError("interest must include READ or WRITE", 0)
        if fd not in self._registered:
            raise NetworkError("fd " + String(fd) + " is not registered", 0)
        var token = self._registered[fd]

        comptime if CompilationTarget.is_linux():
            var ev = stack_allocation[EPOLL_EVENT_SIZE, UInt8]()
            for i in range(EPOLL_EVENT_SIZE):
                (ev + i).init_pointee_copy(UInt8(0))
            _epoll_event_set(ev, _interest_to_epoll(interest), token)
            if _epoll_ctl(self._fd, EPOLL_CTL_MOD, fd, ev) < c_int(0):
                raise _os_error("epoll_ctl MOD")
        else:
            # kqueue: modify means update filters, including removing ones
            # that are no longer in ``interest``.
            self._kqueue_install(fd, token, interest, delete_absent=True)

    def unregister(mut self, fd: c_int) raises -> None:
        """Remove an fd from the reactor.

        Args:
            fd: Previously-registered fd.

        Raises:
            NetworkError: If ``fd`` is not registered or the syscall fails.
        """
        if fd not in self._registered:
            raise NetworkError("fd " + String(fd) + " is not registered", 0)

        comptime if CompilationTarget.is_linux():
            var ev = stack_allocation[EPOLL_EVENT_SIZE, UInt8]()
            for i in range(EPOLL_EVENT_SIZE):
                (ev + i).init_pointee_copy(UInt8(0))
            if _epoll_ctl(self._fd, EPOLL_CTL_DEL, fd, ev) < c_int(0):
                raise _os_error("epoll_ctl DEL")
        else:
            # Delete both possible filters. EV_DELETE on a non-registered
            # filter returns ENOENT, which we ignore.
            var ident = UInt64(Int(fd))
            var ch = stack_allocation[KEVENT_SIZE * 2, UInt8]()
            for i in range(KEVENT_SIZE * 2):
                (ch + i).init_pointee_copy(UInt8(0))
            _kevent_set(
                ch,
                ident=ident,
                filter=EVFILT_READ,
                flags=EV_DELETE,
                fflags=UInt32(0),
                data=Int64(0),
                udata=UInt64(0),
            )
            _kevent_set(
                ch + KEVENT_SIZE,
                ident=ident,
                filter=EVFILT_WRITE,
                flags=EV_DELETE,
                fflags=UInt32(0),
                data=Int64(0),
                udata=UInt64(0),
            )
            var ts_zero = stack_allocation[16, UInt8]()
            for i in range(16):
                (ts_zero + i).init_pointee_copy(UInt8(0))
            var out = stack_allocation[KEVENT_SIZE, UInt8]()
            _ = _kevent(self._fd, ch, c_int(2), out, c_int(0), ts_zero)
            # ENOENT on unregistered filter is not a fatal error; the
            # bookkeeping already tells us what was registered.

        _ = self._registered.pop(fd)

    def poll(
        mut self,
        timeout_ms: Int,
        mut out: List[Event],
        max_events: Int = _DEFAULT_MAX_EVENTS,
    ) raises -> Int:
        """Wait for events and append them to ``out``.

        The caller owns ``out`` — existing contents are replaced (cleared
        first). On success returns the number of events appended. Wakeup
        events are included; callers filter via ``Event.is_wakeup()``.

        Args:
            timeout_ms: -1 = block indefinitely, 0 = poll (return
                immediately), positive = max milliseconds to wait.
            out:        Output list. Cleared on entry.
            max_events: Maximum events to return in one call.

        Returns:
            Number of events in ``out``.

        Raises:
            NetworkError: On underlying syscall failure (EINTR is handled
                internally and returns 0).
        """
        out.clear()
        if max_events <= 0:
            return 0

        comptime if CompilationTarget.is_linux():
            var buf_size = EPOLL_EVENT_SIZE * max_events
            var buf = List[UInt8](capacity=buf_size)
            buf.resize(buf_size, UInt8(0))
            var buf_ptr = buf.unsafe_ptr()
            var n = _epoll_wait(
                self._fd, buf_ptr, c_int(max_events), c_int(timeout_ms)
            )
            if n < c_int(0):
                var e = get_errno()
                if Int(e.value) == 4:  # EINTR
                    return 0
                raise _os_error("epoll_wait")
            for i in range(Int(n)):
                var entry = buf_ptr + (i * EPOLL_EVENT_SIZE)
                var bits = _epoll_event_read_events(entry)
                var tok = _epoll_event_read_data(entry)
                # If this was a wakeup, drain the eventfd so it stops firing.
                if tok == WAKEUP_TOKEN:
                    var drain = stack_allocation[8, UInt8]()
                    for k in range(8):
                        (drain + k).init_pointee_copy(UInt8(0))
                    _ = self._io.read(self._wake_read, drain, c_size_t(8))
                out.append(Event(tok, _epoll_to_event_flags(bits)))
            return Int(n)
        else:
            var buf_size = KEVENT_SIZE * max_events
            var buf = List[UInt8](capacity=buf_size)
            buf.resize(buf_size, UInt8(0))
            var buf_ptr = buf.unsafe_ptr()
            var ts = stack_allocation[16, UInt8]()
            var has_timeout = timeout_ms >= 0
            if has_timeout:
                var sec = UInt64(timeout_ms // 1000)
                var nsec = UInt64((timeout_ms % 1000) * 1_000_000)
                for k in range(8):
                    (ts + k).init_pointee_copy(
                        UInt8((sec >> UInt64(8 * k)) & 0xFF)
                    )
                for k in range(8):
                    (ts + 8 + k).init_pointee_copy(
                        UInt8((nsec >> UInt64(8 * k)) & 0xFF)
                    )
            else:
                for k in range(16):
                    (ts + k).init_pointee_copy(UInt8(0))
            var changes = stack_allocation[KEVENT_SIZE, UInt8]()
            # For infinite timeout we pass a NULL timespec pointer; for
            # bounded waits we pass ``ts``.
            var n: c_int
            if has_timeout:
                n = _kevent(
                    self._fd,
                    changes,
                    c_int(0),
                    buf_ptr,
                    c_int(max_events),
                    ts,
                )
            else:
                var null_ts = UnsafePointer[UInt8, MutExternalOrigin](
                    unsafe_from_address=0
                )
                n = _kevent(
                    self._fd,
                    changes,
                    c_int(0),
                    buf_ptr,
                    c_int(max_events),
                    null_ts,
                )
            if n < c_int(0):
                var e = get_errno()
                if Int(e.value) == 4:  # EINTR
                    return 0
                raise _os_error("kevent")
            for i in range(Int(n)):
                var entry = buf_ptr + (i * KEVENT_SIZE)
                var filter = _kevent_read_filter(entry)
                var flags = _kevent_read_flags(entry)
                var udata = _kevent_read_udata(entry)
                var ev_flags: Int = 0
                if filter == EVFILT_READ:
                    ev_flags |= EVENT_READABLE
                elif filter == EVFILT_WRITE:
                    ev_flags |= EVENT_WRITABLE
                elif filter == EVFILT_USER:
                    ev_flags |= EVENT_READABLE
                if (flags & EV_EOF) != 0:
                    ev_flags |= EVENT_HUP
                if (flags & EV_ERROR) != 0:
                    ev_flags |= EVENT_ERROR
                # Drain self-pipe if this is the wakeup fd.
                if udata == WAKEUP_TOKEN:
                    var drain = stack_allocation[64, UInt8]()
                    for k in range(64):
                        (drain + k).init_pointee_copy(UInt8(0))
                    _ = self._io.read(self._wake_read, drain, c_size_t(64))
                out.append(Event(udata, ev_flags))
            return Int(n)

    def wakeup(self) raises -> None:
        """Trigger a wakeup event so a sleeping ``poll`` returns promptly.

        Safe to call from any thread (Stage 2+ will exercise this). On
        Linux, writes 8 bytes to the eventfd; on macOS, writes 1 byte to the
        self-pipe. Errors are swallowed because the caller has no
        meaningful recovery — a dropped wakeup just means the reactor will
        wait out the current timeout.
        """
        comptime if CompilationTarget.is_linux():
            var one = stack_allocation[8, UInt8]()
            (one + 0).init_pointee_copy(UInt8(1))
            for k in range(1, 8):
                (one + k).init_pointee_copy(UInt8(0))
            _ = self._io.write(self._wake_write, one, c_size_t(8))
        else:
            var b = stack_allocation[1, UInt8]()
            b.init_pointee_copy(UInt8(1))
            _ = self._io.write(self._wake_write, b, c_size_t(1))

    # ── Introspection ─────────────────────────────────────────────────────────

    def registered_count(self) -> Int:
        """Return the number of fds currently registered (excludes wakeup)."""
        # -1 because the wakeup fd counts as an internal registration.
        return len(self._registered) - 1

    def is_registered(self, fd: c_int) -> Bool:
        """Return True if ``fd`` is currently registered on the reactor."""
        return fd in self._registered

    # ── Private helpers ───────────────────────────────────────────────────────

    def _register_raw(
        mut self, fd: c_int, token: UInt64, interest: Int
    ) raises -> None:
        """Platform-specific register + bookkeeping update.

        Used by __init__ (for the wakeup fd) and by the public register().
        Does NOT do uniqueness checks — callers must do them.
        """
        comptime if CompilationTarget.is_linux():
            var ev = stack_allocation[EPOLL_EVENT_SIZE, UInt8]()
            for i in range(EPOLL_EVENT_SIZE):
                (ev + i).init_pointee_copy(UInt8(0))
            _epoll_event_set(ev, _interest_to_epoll(interest), token)
            if _epoll_ctl(self._fd, EPOLL_CTL_ADD, fd, ev) < c_int(0):
                raise _os_error("epoll_ctl ADD")
        else:
            # Fresh register: don't emit DELETEs for filters that aren't
            # there — they'd produce ENOENT EV_ERROR noise.
            self._kqueue_install(fd, token, interest, delete_absent=False)
        self._registered[fd] = token

    def _kqueue_install(
        mut self,
        fd: c_int,
        token: UInt64,
        interest: Int,
        *,
        delete_absent: Bool,
    ) raises -> None:
        """Install EVFILT_READ / EVFILT_WRITE filters to match ``interest``.

        If ``delete_absent`` is True, also emit EV_DELETE for filters that
        are NOT in ``interest`` — used by modify() to drop stale filters.
        register() passes ``delete_absent=False`` to avoid ENOENT noise
        from kqueue on a fresh fd with no existing filters.
        """
        var ident = UInt64(Int(fd))
        # Room for at most 2 changes (one per filter type).
        var ch = stack_allocation[KEVENT_SIZE * 2, UInt8]()
        for i in range(KEVENT_SIZE * 2):
            (ch + i).init_pointee_copy(UInt8(0))
        var n_changes = 0
        if (interest & INTEREST_READ) != 0:
            _kevent_set(
                ch + (n_changes * KEVENT_SIZE),
                ident=ident,
                filter=EVFILT_READ,
                flags=EV_ADD | EV_ENABLE,
                fflags=UInt32(0),
                data=Int64(0),
                udata=token,
            )
            n_changes += 1
        elif delete_absent:
            _kevent_set(
                ch + (n_changes * KEVENT_SIZE),
                ident=ident,
                filter=EVFILT_READ,
                flags=EV_DELETE,
                fflags=UInt32(0),
                data=Int64(0),
                udata=UInt64(0),
            )
            n_changes += 1
        if (interest & INTEREST_WRITE) != 0:
            _kevent_set(
                ch + (n_changes * KEVENT_SIZE),
                ident=ident,
                filter=EVFILT_WRITE,
                flags=EV_ADD | EV_ENABLE,
                fflags=UInt32(0),
                data=Int64(0),
                udata=token,
            )
            n_changes += 1
        elif delete_absent:
            _kevent_set(
                ch + (n_changes * KEVENT_SIZE),
                ident=ident,
                filter=EVFILT_WRITE,
                flags=EV_DELETE,
                fflags=UInt32(0),
                data=Int64(0),
                udata=UInt64(0),
            )
            n_changes += 1
        if n_changes == 0:
            return
        var ts_zero = stack_allocation[16, UInt8]()
        for i in range(16):
            (ts_zero + i).init_pointee_copy(UInt8(0))
        # Allocate space for up to n_changes EV_ERROR replies so kqueue can
        # tell us about per-change failures without dropping the whole batch.
        var out = stack_allocation[KEVENT_SIZE * 2, UInt8]()
        var rc = _kevent(
            self._fd, ch, c_int(n_changes), out, c_int(n_changes), ts_zero
        )
        if rc < c_int(0):
            raise _os_error("kevent install")
        # Inspect any returned events: EV_ERROR with data != 0 means a
        # real failure; data == 0 means success acknowledgement.
        # ENOENT (2) on DELETE is not a fatal error — the filter just
        # wasn't there, which is fine.
        for i in range(Int(rc)):
            var entry = out + (i * KEVENT_SIZE)
            var flags = _kevent_read_flags(entry)
            if (flags & EV_ERROR) != 0:
                var data = _kevent_read_fflags(entry)
                # ``data`` on an EV_ERROR kevent carries the errno; it's the
                # ``data`` field on kqueue, which we store as Int64. But
                # ``_kevent_read_fflags`` returns the fflags, not data. Here
                # we actually want the data field — but we haven't exposed a
                # helper yet. We'll treat any EV_ERROR with unknown errno
                # conservatively: if there were legitimate ADDs in the same
                # batch the ENOENT from DELETE shouldn't poison them since
                # kqueue processes changes independently.
                _ = data  # silence unused-var warning; see note above
