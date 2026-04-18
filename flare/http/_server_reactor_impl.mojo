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

from std.ffi import c_int, c_size_t, get_errno, ErrNo
from std.memory import UnsafePointer, stack_allocation
from std.sys.info import CompilationTarget

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
from flare.tcp import TcpStream


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

    @always_inline
    def fd(self) -> c_int:
        """Return the underlying fd. Fast accessor; does not check state."""
        return self._stream._socket.fd

    # ── Event handlers ────────────────────────────────────────────────────────

    def on_readable(
        mut self,
        handler: def(Request) raises -> Response,
        config: ServerConfig,
    ) raises -> StepResult:
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

        # Drain the socket until EAGAIN.
        var chunk = stack_allocation[8192, UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                for i in range(Int(got)):
                    self.read_buf.append((chunk + i).load())
                if (
                    len(self.read_buf)
                    > config.max_header_size + config.max_body_size
                ):
                    # Request is larger than any legitimate size we'll
                    # accept. Write a 413 and close.
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
            resp = handler(req^)
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
        var wire = List[UInt8](capacity=estimated)

        _append_str(wire, "HTTP/1.1 ")
        _append_str(wire, String(resp.status))
        _append_str(wire, " ")
        _append_str(wire, reason)
        _append_str(wire, "\r\n")

        for i in range(resp.headers.len()):
            var k = resp.headers._keys[i]
            var kl = _ascii_lower(k)
            if kl == "content-length" or kl == "connection":
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

        for i in range(body_len):
            wire.append(resp.body[i])

        self.write_buf = wire^
        self.write_pos = 0
