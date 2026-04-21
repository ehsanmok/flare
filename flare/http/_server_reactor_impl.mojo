"""Per-connection state machine for the reactor-backed HTTP server.

Owns the per-connection buffer and walks a small state machine driven by
readable / writable / timeout events from the reactor. Never blocks on I/O;
instead consumes as much as the socket's non-blocking ``recv``/``send``
makes available per event and returns control to the reactor.

State transitions:

::

    STATE_READING ─ handler returned ─> STATE_WRITING ─ flushed ─┬─> STATE_READING  (keep-alive)
                                                                └─> STATE_CLOSING  (should_close)
    STATE_READING / STATE_WRITING  ─ peer close / error / timeout ─> STATE_CLOSING

At a higher level the flow is:
  1. ``__init__`` — construct with the accepted fd and buffer sizing.
  2. Reactor event loop:
     - On readable: call ``on_readable(handler, config)``.
     - On writable: call ``on_writable()``.
     - On timeout: call ``on_timeout()``.
  3. Each call returns a ``StepResult`` telling the caller how to update
     reactor interest (read / write bits), whether to rearm the idle
     timer, and whether the connection is done.

The state machine deliberately does not own the reactor or timer wheel.
It exposes a thin step API so the reactor-backed ``HttpServer`` (Phase
1.5) owns the lifecycle while this module owns the per-conn logic.
"""

from std.collections import Dict
from std.ffi import c_int, c_size_t, external_call, get_errno, ErrNo
from std.memory import UnsafePointer, memcpy, stack_allocation
from std.sys.info import CompilationTarget, size_of

from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import (
    ServerConfig,
    _find_crlfcrlf,
    _scan_content_length,
    _parse_http_request_bytes,
    _ascii_lower,
    _status_reason,
    _append_str,
)
from flare.net._libc import _recv, _send, _close, MSG_NOSIGNAL
from flare.net.error import NetworkError
from flare.tcp import TcpStream, TcpListener
from flare.runtime import (
    Reactor,
    Event,
    TimerWheel,
    INTEREST_READ,
    INTEREST_WRITE,
)


# ── State constants ───────────────────────────────────────────────────────────

comptime STATE_READING: Int = 0
"""Reading headers and body from the socket (non-blocking)."""

comptime STATE_WRITING: Int = 1
"""Writing the response back to the socket (non-blocking)."""

comptime STATE_CLOSING: Int = 2
"""Connection is shutting down; next event should finalize close."""


# ── Step result ───────────────────────────────────────────────────────────────


struct StepResult(Copyable, ImplicitlyCopyable, Movable):
    """Outcome of one state-machine step.

    The reactor wrapper uses these fields to update its registration for
    the connection's fd (interest bits), decide whether the connection is
    finished, and arm / clear the idle timer.

    Fields:
        want_read: True if the fd should be watched for readability.
        want_write: True if the fd should be watched for writability.
        done: True if the connection is finished; caller should unregister
              the fd and close it.
        idle_timeout_ms: -1 = no change; 0 = clear any pending idle timer;
                        > 0 = arm a fresh idle timer for this many
                        milliseconds.
    """

    var want_read: Bool
    var want_write: Bool
    var done: Bool
    var idle_timeout_ms: Int

    def __init__(
        out self,
        want_read: Bool = False,
        want_write: Bool = False,
        done: Bool = False,
        idle_timeout_ms: Int = -1,
    ):
        """Construct a StepResult.

        Args:
            want_read: Whether the caller should keep read interest on the fd.
            want_write: Whether the caller should add write interest.
            done: Whether the caller should unregister and close the fd.
            idle_timeout_ms: Idle-timer rearm instruction (-1 = unchanged,
                0 = clear, >0 = arm for this many ms).
        """
        self.want_read = want_read
        self.want_write = want_write
        self.done = done
        self.idle_timeout_ms = idle_timeout_ms


# ── Connection handle ─────────────────────────────────────────────────────────


struct ConnHandle(Movable):
    """State + buffers for a single reactor-managed HTTP connection.

    **Takes ownership** of the accepted ``TcpStream`` (which owns the
    socket's fd). The stream is moved into ``_stream`` at construction
    and closed on destruction. This avoids the ASAP-destruction hazard
    that arises from passing just an ``Int32`` fd: Mojo's ownership
    model would drop the originating ``TcpStream`` as soon as its last
    explicit reference went out of scope, closing the fd out from under
    the reactor.
    """

    var _stream: TcpStream
    """Underlying connection; this struct is the sole owner. ``self.fd``
    is a fast accessor for ``self._stream._socket.fd``."""
    var state: Int
    var read_buf: List[UInt8]
    """Incoming request bytes accumulated across partial reads."""
    var headers_end: Int
    """Byte offset just past the ``\\r\\n\\r\\n`` header terminator; -1
    while headers are still being read."""
    var content_length: Int
    """Value of the Content-Length header for the current request."""
    var body_total: Int
    """Total bytes needed to have the full request: headers_end + content_length.
    """
    var write_buf: List[UInt8]
    """Serialised response bytes; drained by successive send calls."""
    var write_pos: Int
    """Number of bytes of ``write_buf`` already sent."""
    var keepalive_count: Int
    """Number of requests already served on this keep-alive connection."""
    var idle_timer_id: UInt64
    """ID of the currently-armed idle timer, 0 if none. The caller (reactor
    wrapper) manages the actual TimerWheel entry."""
    var should_close: Bool
    """True once we've decided this connection must close after writing."""
    var last_interest: Int
    """Last reactor interest bits for this conn. Used by the orchestrator
    to skip redundant ``reactor.modify`` syscalls when the wanted interest
    hasn't actually changed since the previous event."""

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def __init__(out self, var stream: TcpStream, read_buffer_size: Int = 8192):
        """Construct a ConnHandle that owns ``stream`` in STATE_READING.

        Args:
            stream: Accepted ``TcpStream`` (non-blocking mode must already
                be set by the caller). Ownership transfers into the
                ``ConnHandle``.
            read_buffer_size: Initial capacity for the read buffer.
        """
        self._stream = stream^
        self.state = STATE_READING
        self.read_buf = List[UInt8](capacity=read_buffer_size)
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1
        self.write_buf = List[UInt8]()
        self.write_pos = 0
        self.keepalive_count = 0
        self.idle_timer_id = UInt64(0)
        self.should_close = False
        # Accept registers with INTEREST_READ only.
        self.last_interest = 1  # INTEREST_READ

    @always_inline
    def fd(self) -> c_int:
        """Return the underlying fd. Fast accessor; does not check state."""
        return self._stream._socket.fd

    # ── Event handlers ────────────────────────────────────────────────────────

    def on_readable[
        H: Handler
    ](mut self, ref handler: H, config: ServerConfig,) raises -> StepResult:
        """Drive the state machine on a readable event.

        Consumes as much as the non-blocking socket makes available per
        call. Transitions to ``STATE_WRITING`` when the full request is
        parsed and the handler has returned.

        Args:
            handler: Request -> Response callback.
            config: Server configuration (limits + timeouts).

        Returns:
            A ``StepResult`` describing the new reactor-interest state.
        """
        if self.state != STATE_READING:
            # Spurious readable on a connection we've already moved past
            # reading — tell the caller to stop reading.
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        # Drain the socket until EAGAIN. Bulk-copy each chunk into
        # ``read_buf`` via resize + in-place memcpy rather than per-byte
        # append; the latter was a measurable hot-path cost at
        # 100K+ req/s.
        var chunk = stack_allocation[8192, UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                var old_len = len(self.read_buf)
                var got_int = Int(got)
                self.read_buf.resize(old_len + got_int, UInt8(0))
                var dst = self.read_buf.unsafe_ptr() + old_len
                # memcpy is substantially faster than a per-byte load/store
                # loop here because ``chunk`` is stack-allocated and
                # contiguous, and the copy is always <= 8KiB.
                memcpy(dest=dst, src=chunk, count=got_int)
                if (
                    len(self.read_buf)
                    > config.max_header_size + config.max_body_size
                ):
                    self._queue_error(413, "Content Too Large")
                    return self._transition_to_writing()
            elif got == 0:
                # Peer closed while we were still reading — half-open.
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                # Hard read error — close the connection.
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        # See if we have enough to parse.
        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
                # Still accumulating headers.
                if len(self.read_buf) > config.max_header_size:
                    self._queue_error(431, "Request Header Fields Too Large")
                    return self._transition_to_writing()
                return StepResult(
                    want_read=True,
                    want_write=False,
                    idle_timeout_ms=config.idle_timeout_ms,
                )
            self.headers_end = end
            self.content_length = _scan_content_length(
                self.read_buf, self.headers_end
            )
            if self.content_length > config.max_body_size:
                self._queue_error(413, "Content Too Large")
                return self._transition_to_writing()
            self.body_total = self.headers_end + self.content_length

        # Body not fully read yet?
        if len(self.read_buf) < self.body_total:
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=config.idle_timeout_ms,
            )

        # Parse the request.
        var req: Request
        try:
            req = _parse_http_request_bytes(
                Span[UInt8, _](self.read_buf)[: self.body_total],
                config.max_header_size,
                config.max_body_size,
                config.max_uri_length,
            )
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        # Connection disposition before handler consumes the request.
        var conn_hdr = _ascii_lower(req.headers.get("connection"))
        var is_http10 = req.version == "HTTP/1.0"
        var close_after = False
        if conn_hdr == "close":
            close_after = True
        elif is_http10 and conn_hdr != "keep-alive":
            close_after = True

        self.keepalive_count += 1
        if self.keepalive_count >= config.max_keepalive_requests:
            close_after = True
        if not config.keep_alive:
            close_after = True
        self.should_close = close_after

        # Call the handler. Exceptions are caught and converted to 500.
        var resp: Response
        try:
            resp = handler.serve(req^)
        except:
            self._queue_error(500, "Internal Server Error")
            return self._transition_to_writing()

        # Compact the read buffer: drop the processed request, keep the
        # remainder (pipelining or prefetched next request).
        if self.body_total > 0 and self.body_total <= len(self.read_buf):
            var leftover = List[UInt8](
                capacity=len(self.read_buf) - self.body_total
            )
            for i in range(self.body_total, len(self.read_buf)):
                leftover.append(self.read_buf[i])
            self.read_buf = leftover^
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1

        self._serialize_response(resp^, not close_after)
        return self._transition_to_writing()

    def on_writable(mut self, config: ServerConfig) raises -> StepResult:
        """Drive the state machine on a writable event.

        Sends as much of ``write_buf`` as the non-blocking socket accepts.
        When the buffer is fully flushed, transitions back to
        ``STATE_READING`` (keep-alive) or ``STATE_CLOSING`` based on
        ``should_close``.

        Args:
            config: Server configuration (used to compute the new idle timer
                after a successful flush).

        Returns:
            A ``StepResult`` describing the new reactor-interest state.
        """
        if self.state != STATE_WRITING:
            return StepResult(
                want_read=self.state == STATE_READING, want_write=False
            )

        while self.write_pos < len(self.write_buf):
            var remaining = len(self.write_buf) - self.write_pos
            var ptr = self.write_buf.unsafe_ptr() + self.write_pos
            var n = _send(
                self.fd(), ptr, c_size_t(remaining), c_int(MSG_NOSIGNAL)
            )
            if n > 0:
                self.write_pos += Int(n)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                # Hard write error — close.
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        if self.write_pos < len(self.write_buf):
            # Partial write — re-arm on writable.
            return StepResult(
                want_read=False,
                want_write=True,
                idle_timeout_ms=config.write_timeout_ms,
            )

        # Response fully sent.
        self.write_buf.clear()
        self.write_pos = 0

        if self.should_close:
            return StepResult(want_read=False, want_write=False, done=True)

        # Keep-alive: back to reading, possibly on already-buffered next
        # request (pipelining — data may already be in read_buf).
        self.state = STATE_READING
        return StepResult(
            want_read=True,
            want_write=False,
            idle_timeout_ms=config.idle_timeout_ms,
        )

    def on_timeout(mut self) -> StepResult:
        """Handle an idle / write timer firing.

        Returns a StepResult with ``done=True``. The caller should
        unregister and close the fd.
        """
        self.state = STATE_CLOSING
        self.should_close = True
        return StepResult(want_read=False, want_write=False, done=True)

    def close(mut self) -> None:
        """Explicitly close the underlying stream. Idempotent.

        Normally the caller does not need to call this: the stream's
        destructor closes the fd when the ``ConnHandle`` is dropped.
        """
        self._stream.close()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _transition_to_writing(mut self) -> StepResult:
        """Move into STATE_WRITING and tell the caller to watch for write."""
        self.state = STATE_WRITING
        # Reset any stale read state: the next state-machine step is
        # flushing the response, not reading more bytes.
        return StepResult(
            want_read=False,
            want_write=True,
            # Clear the idle timer; the write_timeout (if any) arms
            # separately via StepResult idle_timeout_ms on the first
            # writable step.
            idle_timeout_ms=0,
        )

    def _queue_error(mut self, status: Int, reason: String) -> None:
        """Build a minimal error response into ``write_buf`` and mark close."""
        self.should_close = True
        var body_str = String(status) + " " + reason
        var resp = Response(status=status, reason=reason)
        var body_bytes = body_str.as_bytes()
        for i in range(len(body_bytes)):
            resp.body.append(body_bytes[i])
        try:
            resp.headers.set("Content-Type", "text/plain")
        except:
            pass
        self._serialize_response(resp^, False)

    def _serialize_response(mut self, resp: Response, keep_alive: Bool) -> None:
        """Serialise ``resp`` into ``write_buf`` ready to be sent."""
        var reason = resp.reason
        if reason.byte_length() == 0:
            reason = _status_reason(resp.status)
        var body_len = len(resp.body)

        var estimated = 64 + body_len
        for i in range(resp.headers.len()):
            estimated += (
                resp.headers._keys[i].byte_length()
                + resp.headers._values[i].byte_length()
                + 4
            )
        # Reuse self.write_buf's allocated capacity across requests —
        # on_writable already clears the buffer on flush, so its backing
        # storage is idle. Avoids a per-request List allocation.
        self.write_buf.clear()
        self.write_pos = 0
        if self.write_buf.capacity < estimated:
            self.write_buf.reserve(estimated)
        var wire = self.write_buf^

        _append_str(wire, "HTTP/1.1 ")
        _append_str(wire, String(resp.status))
        _append_str(wire, " ")
        _append_str(wire, reason)
        _append_str(wire, "\r\n")

        for i in range(resp.headers.len()):
            var k = resp.headers._keys[i]
            # Case-insensitive skip of Content-Length and Connection
            # without allocating a lowercased copy each header. Compare
            # only the length-matching candidates.
            if _is_content_length(k) or _is_connection(k):
                continue
            _append_str(wire, k)
            _append_str(wire, ": ")
            _append_str(wire, resp.headers._values[i])
            _append_str(wire, "\r\n")

        _append_str(wire, "Content-Length: ")
        _append_str(wire, String(body_len))
        _append_str(wire, "\r\n")

        if keep_alive:
            _append_str(wire, "Connection: keep-alive\r\n")
        else:
            _append_str(wire, "Connection: close\r\n")

        _append_str(wire, "\r\n")

        # Bulk-copy the body. Appending byte-by-byte from ``resp.body``
        # dominated this function's cost on small-body responses.
        if body_len > 0:
            var old = len(wire)
            wire.resize(old + body_len, UInt8(0))
            memcpy(
                dest=wire.unsafe_ptr() + old,
                src=resp.body.unsafe_ptr(),
                count=body_len,
            )

        self.write_buf = wire^
        self.write_pos = 0


# ──────────────────────────────────────────────────────────────────────────────
# Reactor loop + helpers (moved here from server.mojo to avoid a circular
# import: this module already depends on server.mojo's parsing helpers).
# ──────────────────────────────────────────────────────────────────────────────


def _monotonic_ms() -> Int:
    """Return the monotonic clock in milliseconds.

    Uses ``clock_gettime(CLOCK_MONOTONIC, ...)``. The constant value 1 for
    ``CLOCK_MONOTONIC`` is portable between Linux and macOS (macOS has
    supported it since 10.12).
    """
    var buf = stack_allocation[16, UInt8]()
    for i in range(16):
        (buf + i).init_pointee_copy(UInt8(0))
    _ = external_call["clock_gettime", c_int](c_int(1), buf.bitcast[NoneType]())
    var sec: Int64 = 0
    var nsec: Int64 = 0
    for i in range(8):
        sec |= Int64(Int((buf + i).load())) << Int64(8 * i)
    for i in range(8):
        nsec |= Int64(Int((buf + 8 + i).load())) << Int64(8 * i)
    return Int(sec) * 1000 + Int(nsec) // 1_000_000


@always_inline
def _is_content_length(k: String) -> Bool:
    """Return True if ``k`` is ``Content-Length`` (ASCII case-insensitive).

    Hot path: called for every response header to decide whether
    ``_serialize_response`` should emit or skip. Avoids the lowercase
    allocation that ``_ascii_lower`` + string-compare would cost.
    """
    if k.byte_length() != 14:
        return False
    var p = k.unsafe_ptr()
    var target = "content-length"
    var t = target.unsafe_ptr()
    for i in range(14):
        var c = p[i]
        if c >= 65 and c <= 90:
            c = c + 32
        if c != t[i]:
            return False
    return True


@always_inline
def _is_connection(k: String) -> Bool:
    """Return True if ``k`` is ``Connection`` (ASCII case-insensitive)."""
    if k.byte_length() != 10:
        return False
    var p = k.unsafe_ptr()
    var target = "connection"
    var t = target.unsafe_ptr()
    for i in range(10):
        var c = p[i]
        if c >= 65 and c <= 90:
            c = c + 32
        if c != t[i]:
            return False
    return True


def _conn_alloc_addr(var stream: TcpStream) raises -> Int:
    """Heap-allocate a ``ConnHandle`` wrapping ``stream`` and return its address.

    We use libc ``malloc`` via FFI rather than ``UnsafePointer.alloc`` because
    Mojo's stdlib allocator currently doesn't expose that factory for
    Movable-only types (``ConnHandle`` owns a ``TcpStream``). ``_conn_free_addr``
    runs the destructor and frees.
    """
    var n = size_of[ConnHandle]()
    var raw = external_call["malloc", UnsafePointer[UInt8, MutExternalOrigin]](
        c_size_t(n)
    )
    if Int(raw) == 0:
        raise NetworkError("malloc failed for ConnHandle", 0)
    var ptr = raw.bitcast[ConnHandle]()
    ptr.init_pointee_move(ConnHandle(stream^))
    return Int(ptr)


def _conn_free_addr(addr: Int):
    """Destroy and free a ``ConnHandle`` allocated with ``_conn_alloc_addr``.

    Safe to call on 0 (no-op).
    """
    if addr == 0:
        return
    var raw = UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=addr)
    var ptr = raw.bitcast[ConnHandle]()
    ptr.destroy_pointee()
    _ = external_call["free", NoneType](raw.bitcast[NoneType]())


def _conn_ptr_from_int(
    addr: Int,
) -> UnsafePointer[ConnHandle, MutExternalOrigin]:
    """Reverse of ``_conn_alloc_addr``: reconstruct a typed pointer."""
    return UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=addr
    ).bitcast[ConnHandle]()


def _apply_step(
    fd: Int,
    step: StepResult,
    mut reactor: Reactor,
    mut wheel: TimerWheel,
    mut timers: Dict[Int, UInt64],
    conn_ptr: UnsafePointer[ConnHandle, MutExternalOrigin],
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


def _accept_loop(
    mut listener: TcpListener,
    mut reactor: Reactor,
    mut conns: Dict[Int, Int],
):
    """Accept every connection available on ``listener`` (until EAGAIN).

    Each accepted socket is switched to non-blocking mode, heap-allocated
    into a ``ConnHandle``, and registered with the reactor using the
    client fd as the token.
    """
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


def run_reactor_loop[
    H: Handler
](
    mut listener: TcpListener,
    config: ServerConfig,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Run the single-threaded event loop until ``stopping`` becomes True.

    The caller (``HttpServer.serve``) owns the listener and provides the
    request handler. This function owns the ``Reactor`` and ``TimerWheel``
    for the duration of the loop.

    Args:
        listener: Bound and listening ``TcpListener`` (ownership stays
            with the caller; we only borrow for accept / fd access).
        config: Server configuration.
        handler: Per-request callback.
        stopping: Checked on every poll iteration; when True the loop
            exits and in-flight connections are closed. ``stopping`` is
            re-read each iteration via a fresh external pointer so the
            compiler cannot hoist the load out of the loop — the
            multicore ``Scheduler`` mutates it from another thread.
    """
    listener._socket.set_nonblocking(True)
    var listener_fd = listener._socket.fd

    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    # Token 0 is reserved for the listener accept path.
    reactor.register(listener_fd, UInt64(0), INTEREST_READ)

    var events = List[Event]()
    # Take the address of the caller's ``stopping`` Bool once, then
    # re-materialise a fresh ``UnsafePointer`` with ``MutExternalOrigin``
    # inside the loop condition on every iteration. This defeats any
    # LICM / load-forwarding the optimiser might otherwise do: from
    # Mojo's point of view each iteration sees a brand-new pointer of
    # externally-mutated origin, which it must re-load.
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
            if fd_tok in conns:
                _cleanup_conn(fd_tok, conns, timers, reactor)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop(listener, reactor, conns)
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
                    # (readable -> writable on request, writable -> readable
                    # on keep-alive), drive the next step inline rather
                    # than bouncing through the reactor. This is the
                    # single biggest win on TFB plaintext with keep-alive.
                    # Cap at 3 cycles so malicious pipelining can't starve
                    # other fds.
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
                            # We have buffered bytes from the last recv
                            # that might be a pipelined request. Drive
                            # the state machine once more.
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

    # Graceful shutdown: close all active connections.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn(leftover[i], conns, timers, reactor)
