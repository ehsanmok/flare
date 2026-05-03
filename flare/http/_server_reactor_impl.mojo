"""Per-connection state machine for the reactor-backed HTTP server.

Owns the per-connection buffer and walks a small state machine driven by
readable / writable / timeout events from the reactor. Never blocks on I/O;
instead consumes as much as the socket's non-blocking ``recv``/``send``
makes available per event and returns control to the reactor.

State transitions:

::

    STATE_READING ─ handler returned ─> STATE_WRITING ─ flushed ─┬─> STATE_READING (keep-alive)
                                                                └─> STATE_CLOSING (should_close)
    STATE_READING / STATE_WRITING ─ peer close / error / timeout ─> STATE_CLOSING

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
from std.os import getenv
from std.memory import UnsafePointer, alloc, memcpy, stack_allocation
from std.sys.info import CompilationTarget

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
    _ascii_lower,
    _status_reason,
    _append_str,
    _append_int,
)
from flare.http.static_response import StaticResponse
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
)
from flare.runtime.uring_reactor import (
    UringReactor,
    _pbuf_ring_add,
    _pbuf_ring_get_tail,
    _pbuf_ring_set_tail,
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
    var peer: SocketAddr
    """Kernel-reported peer address captured from
    ``TcpStream.peer_addr()`` at construction time. Threaded into every
    parsed ``Request`` for the connection so handlers can read
    ``req.peer``. Stored here (not just on each ``Request``) because
    keep-alive connections re-parse multiple requests across a single
    ``ConnHandle`` lifetime, and the peer is identical for all of them."""
    var cancel_cell: CancelCell
    """Per-connection cancel cell. The reactor flips
    its ``Int`` to a non-zero ``CancelReason`` on peer FIN, deadline
    (commit 5), or drain (commit 6); ``on_readable_cancel`` hands a
    ``Cancel`` handle bound to this cell into
    ``CancelHandler.serve(req, cancel)``. Reset between pipelined
    requests so a cancel reason on one request doesn't leak into
    the next."""
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
    var send_in_flight: Bool
    """``True`` iff a ``IORING_OP_SEND`` SQE for this conn's
    ``write_buf`` has been submitted but the corresponding CQE
    hasn't been observed yet. Set to True by the io_uring
    buffer-ring + submit_send dispatch after each ``submit_send``,
    and back to False when the matching ``URING_OP_SEND`` CQE
    arrives. While True, recv CQEs for this conn are buffered
    into ``read_buf`` but NOT parsed -- the next request can't
    be processed until the in-flight ``write_buf`` has been
    released by the kernel. Always ``False`` on the epoll path
    (which does synchronous send + frees write_buf in
    ``on_writable``)."""

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def __init__(
        out self, var stream: TcpStream, read_buffer_size: Int = 8192
    ) raises:
        """Construct a ConnHandle that owns ``stream`` in STATE_READING.

        Args:
            stream: Accepted ``TcpStream`` (non-blocking mode must already
                be set by the caller). Ownership transfers into the
                ``ConnHandle``.
            read_buffer_size: Initial capacity for the read buffer.
        """
        # Capture the peer address before moving the stream — ``peer_addr``
        # reads from the stream's internal field, which becomes
        # inaccessible once we transfer ownership into ``self._stream``.
        self.peer = stream.peer_addr()
        self._stream = stream^
        self.cancel_cell = CancelCell()
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
        self.send_in_flight = False

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
                self.peer,
                config.expose_error_messages,
            )
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        # Connection disposition before handler consumes the request.
        var close_after = _compute_close_after(req.headers, req.version)

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

    def on_readable_from_buf[
        H: Handler
    ](
        mut self,
        bytes: Span[UInt8, _],
        ref handler: H,
        config: ServerConfig,
    ) raises -> StepResult:
        """``on_readable[H]`` variant for the io_uring recv-multishot
        path: takes pre-recv'd bytes from a kernel-delivered buffer
        instead of looping on ``_recv()`` itself.

        The caller (``run_uring_recv_reactor_loop``) gets the bytes
        from a ``URING_OP_RECV`` CQE (the kernel placed them in the
        per-conn buffer at SQE-submit time). We append them to
        ``read_buf`` and run the same header-scan / parse / handler
        / serialise / keep-alive bookkeeping as ``on_readable[H]``
        does after its drain-until-EAGAIN loop. The per-conn state
        machine is otherwise identical -- the only delta vs the
        epoll path is the source of bytes (kernel push vs userspace
        recv pull).

        The ``IORING_OP_RECV`` CQE with ``res == 0`` (peer closed)
        is handled by the caller, not here -- this method only
        runs when there are real bytes to feed.

        Args:
            bytes: New bytes to feed into the read pipeline. May be
                empty (legitimate when the kernel re-issues a
                multishot completion immediately after re-arm; we
                skip the parse step in that case).
            handler: Request -> Response callback.
            config: Server configuration.

        Returns:
            A ``StepResult`` describing the new reactor-interest
            state. ``done=True`` means the connection should be
            cleaned up.
        """
        if self.state != STATE_READING:
            # Spurious recv on a connection that already moved past
            # reading -- mirror on_readable's no-op shape.
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        if len(bytes) > 0:
            var old_len = len(self.read_buf)
            var add = len(bytes)
            self.read_buf.resize(old_len + add, UInt8(0))
            var dst = self.read_buf.unsafe_ptr() + old_len
            memcpy(dest=dst, src=bytes.unsafe_ptr(), count=add)
            if (
                len(self.read_buf)
                > config.max_header_size + config.max_body_size
            ):
                self._queue_error(413, "Content Too Large")
                return self._transition_to_writing()

        # Header completion check (mirror on_readable lines after the
        # recv loop).
        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
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

        if len(self.read_buf) < self.body_total:
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=config.idle_timeout_ms,
            )

        var req: Request
        try:
            req = _parse_http_request_bytes(
                Span[UInt8, _](self.read_buf)[: self.body_total],
                config.max_header_size,
                config.max_body_size,
                config.max_uri_length,
                self.peer,
                config.expose_error_messages,
            )
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        var close_after = _compute_close_after(req.headers, req.version)

        self.keepalive_count += 1
        if self.keepalive_count >= config.max_keepalive_requests:
            close_after = True
        if not config.keep_alive:
            close_after = True
        self.should_close = close_after

        var resp: Response
        try:
            resp = handler.serve(req^)
        except:
            self._queue_error(500, "Internal Server Error")
            return self._transition_to_writing()

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

    def on_readable_cancel[
        CH: CancelHandler
    ](mut self, ref handler: CH, config: ServerConfig,) raises -> StepResult:
        """Cancel-aware variant of ``on_readable``.

        Identical to ``on_readable`` except the per-connection
        ``CancelCell`` is reset to ``NONE`` at the top of each
        request, flipped to ``PEER_CLOSED`` on ``recv == 0``
        observed before the handler runs, and a ``Cancel`` handle
        bound to the cell is passed to ``CH.serve(req, cancel)``.

        Future commits in hook deadline (commit 5) and
        drain (commit 6) flips through the same cell.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        # Reset the cancel cell at the start of each request so a
        # cancellation observed on a previous pipelined request does
        # not leak into this one. Idempotent on the first request of
        # a connection because the cell is already ``NONE`` from
        # construction.
        self.cancel_cell.reset()

        var chunk = stack_allocation[8192, UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                var old_len = len(self.read_buf)
                var got_int = Int(got)
                self.read_buf.resize(old_len + got_int, UInt8(0))
                var dst = self.read_buf.unsafe_ptr() + old_len
                memcpy(dest=dst, src=chunk, count=got_int)
                if (
                    len(self.read_buf)
                    > config.max_header_size + config.max_body_size
                ):
                    self._queue_error(413, "Content Too Large")
                    return self._transition_to_writing()
            elif got == 0:
                # Peer closed while we were still reading — flip
                # cancel for any cancel-aware code that runs after
                # this point in the loop, then mark the connection
                # for shutdown.
                self.cancel_cell.flip(CancelReason.PEER_CLOSED)
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
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

        if len(self.read_buf) < self.body_total:
            # Body still arriving — arm the read-body deadline if
            # configured, otherwise fall back to
            # the idle timer. Closes the slow-body-upload variant
            # of criticism §2.2: a peer that keeps trickling bytes
            # below idle_timeout_ms can no longer hold a worker
            # slot indefinitely.
            var body_timeout = (
                config.read_body_timeout_ms if config.read_body_timeout_ms
                > 0 else config.idle_timeout_ms
            )
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=body_timeout,
            )

        # follow-up (Track 1.1 / C2): scan the request as a
        # ``RequestView`` borrowed into ``read_buf`` first, then
        # materialise an owned ``Request`` via ``into_owned()``
        # for the existing ``Handler.serve(req: Request)`` shape.
        # Net win: per-header String allocation eliminated during
        # parse — headers stay as offsets into the shared buffer
        # until ``into_owned`` copies them out. Body still copies
        # because today's Handler takes an owned Request; the
        # zero-copy body path waits for C3 (``ViewHandler``).
        from .request_view import parse_request_view

        var req: Request
        try:
            var view = parse_request_view(
                Span[UInt8, _](self.read_buf)[: self.body_total],
                config.max_header_size,
                config.max_body_size,
                config.max_uri_length,
                self.peer,
                config.expose_error_messages,
            )
            req = view.into_owned()
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        var close_after = _compute_close_after(req.headers, req.version)

        self.keepalive_count += 1
        if self.keepalive_count >= config.max_keepalive_requests:
            close_after = True
        if not config.keep_alive:
            close_after = True
        self.should_close = close_after

        var resp: Response
        try:
            # Hand the handler a cancel handle bound to this
            # connection's cancel cell. The cell outlives the handler
            # call (it's owned by ``self``).
            resp = handler.serve(req^, self.cancel_cell.handle())
        except:
            self._queue_error(500, "Internal Server Error")
            return self._transition_to_writing()

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

    def on_readable_view[
        VH: ViewHandler
    ](mut self, ref handler: VH, config: ServerConfig) raises -> StepResult:
        """View-aware variant of ``on_readable_cancel``.

        Same control flow as ``on_readable_cancel`` but dispatches
        the parsed ``RequestView`` directly into
        ``VH.serve_view(view, cancel)`` — the body slice borrows
        from ``self.read_buf`` and the handler reads it without
        a copy. The owned ``Request`` materialisation that the
        ``Handler.serve`` requires is skipped entirely.

        Net win on this path: handler gets ``Span[UInt8, origin]``
        body access — the headline zero-copy upload contract from
        design-0.5 §1.1.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        self.cancel_cell.reset()

        var chunk = stack_allocation[8192, UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                var old_len = len(self.read_buf)
                var got_int = Int(got)
                self.read_buf.resize(old_len + got_int, UInt8(0))
                var dst = self.read_buf.unsafe_ptr() + old_len
                memcpy(dest=dst, src=chunk, count=got_int)
                if (
                    len(self.read_buf)
                    > config.max_header_size + config.max_body_size
                ):
                    self._queue_error(413, "Content Too Large")
                    return self._transition_to_writing()
            elif got == 0:
                self.cancel_cell.flip(CancelReason.PEER_CLOSED)
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
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

        if len(self.read_buf) < self.body_total:
            var body_timeout = (
                config.read_body_timeout_ms if config.read_body_timeout_ms
                > 0 else config.idle_timeout_ms
            )
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=body_timeout,
            )

        # Parse the request as a borrowed view into ``read_buf``
        # and dispatch it directly. Body is ``Span[UInt8, origin]``
        # for the duration of the ``serve_view`` call.
        from .request_view import parse_request_view

        var resp: Response
        try:
            var view = parse_request_view(
                Span[UInt8, _](self.read_buf)[: self.body_total],
                config.max_header_size,
                config.max_body_size,
                config.max_uri_length,
                self.peer,
                config.expose_error_messages,
            )

            # Connection-disposition from the borrowed header
            # view — no allocation, just an offsets-based lookup.
            var hv = view.headers()
            var conn_hdr = _ascii_lower(String(hv.get("connection")))
            var is_http10 = view.version == "HTTP/1.0"
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

            try:
                resp = handler.serve_view(view, self.cancel_cell.handle())
            except:
                self._queue_error(500, "Internal Server Error")
                return self._transition_to_writing()
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

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

        var keepalive = not self.should_close
        self._serialize_response(resp^, keepalive)
        return self._transition_to_writing()

    def on_readable_static(
        mut self, resp: StaticResponse, config: ServerConfig
    ) raises -> StepResult:
        """Static-response variant of ``on_readable``.

        Reads as much as the non-blocking socket makes available per
        call, scans for the end-of-headers marker, discards the
        declared body bytes (if any), and queues the pre-encoded
        ``StaticResponse`` bytes into ``write_buf``. The parser never
        constructs a ``Request``; no handler is called.

        Everything else (keep-alive book-keeping, HTTP/1.0 close
        semantics, ``max_keepalive_requests`` cap, Connection header
        inspection, peer-close / EAGAIN handling, pipelined-request
        compaction of ``read_buf``) mirrors ``on_readable`` byte-for-byte
        so state machine invariants remain identical.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        var chunk = stack_allocation[8192, UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                var old_len = len(self.read_buf)
                var got_int = Int(got)
                self.read_buf.resize(old_len + got_int, UInt8(0))
                var dst = self.read_buf.unsafe_ptr() + old_len
                memcpy(dest=dst, src=chunk, count=got_int)
                if (
                    len(self.read_buf)
                    > config.max_header_size + config.max_body_size
                ):
                    self._queue_error(413, "Content Too Large")
                    return self._transition_to_writing()
            elif got == 0:
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        # Headers still incomplete?
        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
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

        # Body still incomplete?
        if len(self.read_buf) < self.body_total:
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=config.idle_timeout_ms,
            )

        # Inspect Connection header + HTTP/1.0 semantics on the raw
        # header bytes without building a Request object. Cheap scan
        # over the header region only.
        var close_after = _wants_close(self.read_buf, self.headers_end)
        self.keepalive_count += 1
        if self.keepalive_count >= config.max_keepalive_requests:
            close_after = True
        if not config.keep_alive:
            close_after = True
        self.should_close = close_after

        # Compact read buffer before writing the canned response.
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

        self._serialize_static(resp, not close_after)
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

    def _serialize_static(
        mut self, resp: StaticResponse, keep_alive: Bool
    ) -> None:
        """Queue a pre-encoded static response into ``write_buf``.

        Reuses the buffer's existing capacity across requests (same
        pattern as ``_serialize_response``) and pulls either the
        keep-alive or close variant of the pre-encoded bytes depending
        on ``keep_alive``.
        """
        self.write_buf.clear()
        self.write_pos = 0
        # Pick the keep-alive or close variant by branch rather than via
        # a conditional expression. ``List[UInt8]`` is no longer
        # ``ImplicitlyCopyable`` under Mojo 1.0.0b1+, so binding the
        # selected variant to a single ``var`` would force an implicit
        # copy that the compiler now rejects. Splitting the branch
        # keeps both arms in pure borrow + ``unsafe_ptr()`` form and
        # avoids any copy at all.
        var n: Int
        if keep_alive:
            n = len(resp.keepalive_bytes)
        else:
            n = len(resp.close_bytes)
        if self.write_buf.capacity < n:
            self.write_buf.reserve(n)
        self.write_buf.resize(n, UInt8(0))
        if keep_alive:
            memcpy(
                dest=self.write_buf.unsafe_ptr(),
                src=resp.keepalive_bytes.unsafe_ptr(),
                count=n,
            )
        else:
            memcpy(
                dest=self.write_buf.unsafe_ptr(),
                src=resp.close_bytes.unsafe_ptr(),
                count=n,
            )
        self.write_pos = 0

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
        _append_int(wire, resp.status)
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
        _append_int(wire, body_len)
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
def _connection_is_keepalive(s: String) -> Bool:
    """Hot-path byte fast-check for ``Connection: keep-alive``.

    Designed to short-circuit the per-request ``_ascii_lower`` +
    string-compare in the keep-alive policy decision. wrk2 / wrk /
    `curl --keepalive` / nearly every Rust HTTP client send the
    header value as the exact bytes ``keep-alive`` (lowercase,
    no leading whitespace). This helper matches that exact-bytes
    case in 10 byte loads + 10 compares without any allocation.

    For non-matching values (uppercase, mixed-case, ``Keep-Alive``
    with capital K, header missing, etc.) callers fall back to
    the slow path (``_ascii_lower(s) == "keep-alive"``).

    Returns False on length mismatch or any byte mismatch.
    """
    if s.byte_length() != 10:
        return False
    var p = s.unsafe_ptr()
    return (
        p[0] == ord("k")
        and p[1] == ord("e")
        and p[2] == ord("e")
        and p[3] == ord("p")
        and p[4] == ord("-")
        and p[5] == ord("a")
        and p[6] == ord("l")
        and p[7] == ord("i")
        and p[8] == ord("v")
        and p[9] == ord("e")
    )


@always_inline
def _connection_is_close(s: String) -> Bool:
    """Hot-path byte fast-check for ``Connection: close``.

    Companion to :func:`_connection_is_keepalive`. Matches the exact
    lowercase bytes ``close`` in 5 byte loads, and as a small
    extension also matches the common mixed-case ``Close`` (capital
    C only). Anything else falls through to the slow ``_ascii_lower``
    path. Returns False on length mismatch.
    """
    if s.byte_length() != 5:
        return False
    var p = s.unsafe_ptr()
    var c0 = p[0]
    if c0 != ord("c") and c0 != ord("C"):
        return False
    return (
        p[1] == ord("l")
        and p[2] == ord("o")
        and p[3] == ord("s")
        and p[4] == ord("e")
    )


@always_inline
def _compute_close_after(req_headers: HeaderMap, req_version: String) -> Bool:
    """Decide whether to close the connection after this request,
    based on RFC 9112 keep-alive policy.

    Hot path: called once per request from every on_readable_*
    state-machine entry point. The byte-fast-paths for
    ``Connection: keep-alive`` and ``Connection: close`` short-
    circuit the per-request ``_ascii_lower`` allocation when the
    header value matches the wrk2 / curl / nearly-every-Rust-
    client lowercase wire format. Mixed-case + uncommon values
    fall through to the slow allocation path.

    Caller still needs to combine this with config.max_keepalive_-
    requests + config.keep_alive (those are per-server policy, not
    per-request).
    """
    var conn_hdr = req_headers.get("connection")
    var is_http10 = req_version == "HTTP/1.0"
    if _connection_is_close(conn_hdr):
        return True
    if _connection_is_keepalive(conn_hdr):
        return False
    if conn_hdr.byte_length() == 0:
        # No Connection header. RFC 9112: HTTP/1.1 is keep-alive
        # by default; HTTP/1.0 is close by default.
        return is_http10
    # Slow path: lowercase + compare. Reachable on mixed-case
    # ``Keep-Alive`` etc.
    var lo = _ascii_lower(conn_hdr)
    if lo == "close":
        return True
    if is_http10 and lo != "keep-alive":
        return True
    return False


def _wants_close(data: List[UInt8], header_end: Int) -> Bool:
    """Scan the raw header block for HTTP/1.0 + ``Connection:`` signals
    that mean this connection should close after the response.

    Returns True when the request line declares HTTP/1.0 without a
    ``Connection: keep-alive`` override, or when any ``Connection:``
    header value equals ``close`` (case-insensitive).

    Operates directly on bytes so the static fast path doesn't need to
    construct a ``Request`` / ``HeaderMap``.
    """
    var n = header_end
    var version_is_10 = False
    # 1. Request line up to the first CRLF.
    var first_eol = -1
    for i in range(n):
        if data[i] == 10:  # LF
            first_eol = i
            break
    if first_eol < 0:
        first_eol = n
    # Look for "HTTP/1.0" on the request line.
    var http_needle = "HTTP/1.0"
    var hp = http_needle.unsafe_ptr()
    var hn = http_needle.byte_length()
    for i in range(first_eol - hn + 1):
        if i < 0:
            break
        var is_match = True
        for j in range(hn):
            if data[i + j] != hp[j]:
                is_match = False
                break
        if is_match:
            version_is_10 = True
            break
    # 2. Connection header. Case-insensitive name match, value compared
    # against "close" and "keep-alive" (lowercase).
    var needle = "connection:"
    var np = needle.unsafe_ptr()
    var nn = needle.byte_length()
    var conn_close = False
    var conn_keepalive = False
    var i = first_eol + 1
    while i < n - nn:
        var found = True
        for j in range(nn):
            var c = data[i + j]
            if c >= 65 and c <= 90:
                c = c + 32
            if c != np[j]:
                found = False
                break
        if found:
            var pos = i + nn
            while pos < n and (data[pos] == 32 or data[pos] == 9):
                pos += 1
            # Compare value until CR, LF, or end-of-header-block.
            var v_end = pos
            while v_end < n and data[v_end] != 13 and data[v_end] != 10:
                v_end += 1
            # Lowercase slice compare against "close" and "keep-alive".
            var val_len = v_end - pos
            if val_len == 5:
                var ck = True
                for j in range(5):
                    var c = data[pos + j]
                    if c >= 65 and c <= 90:
                        c = c + 32
                    if c != UInt8(ord("close"[j])):
                        ck = False
                        break
                if ck:
                    conn_close = True
            if val_len == 10:
                var ck2 = True
                for j in range(10):
                    var c = data[pos + j]
                    if c >= 65 and c <= 90:
                        c = c + 32
                    if c != UInt8(ord("keep-alive"[j])):
                        ck2 = False
                        break
                if ck2:
                    conn_keepalive = True
            break
        i += 1
    if conn_close:
        return True
    if version_is_10 and not conn_keepalive:
        return True
    return False


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


def _accept_loop_fd(
    listener_fd: Int,
    mut reactor: Reactor,
    mut conns: Dict[Int, Int],
):
    """Accept every available connection on a *borrowed* listener fd.

    Mirrors ``_accept_loop`` but takes the listener as a raw integer
    fd instead of a ``TcpListener`` so the multi-worker scheduler
    can share a single listener across workers without giving any
    one worker ownership of the underlying ``TcpListener``. The
    listener fd is owned by the ``Scheduler`` and stays open for the
    lifetime of the multi-worker run.

    Stops on the first ``accept(2)`` error (typically ``EAGAIN`` /
    ``EWOULDBLOCK`` once the kernel's accept queue is drained for
    this worker) — same shape as ``_accept_loop`` so the caller
    sees identical "drain until empty" semantics.
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


def run_reactor_loop_shared[
    H: Handler
](
    listener_fd: Int,
    config: ServerConfig,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Worker reactor loop sharing a single listener fd across workers.

    multi-worker entry point. Functionally identical to
    ``run_reactor_loop`` but:

    1. ``listener_fd`` is borrowed from the ``Scheduler`` (the
       ``Scheduler`` owns the underlying ``TcpListener`` and closes
       it on shutdown). This worker never closes ``listener_fd``.
    2. The listener is registered with ``Reactor.register_exclusive``
       so the kernel sets ``EPOLLEXCLUSIVE`` on Linux (>= 4.5),
       waking only one worker per accept event. On macOS the flag
       is unavailable and registration falls back to plain
       ``register`` — the wakeup pattern degrades to "wake-all,
       one-wins" but practical behaviour is similar because
       non-blocking ``accept`` returns ``EAGAIN`` on the losers.

    The fairness improvement vs ``bind_reuseport`` is in the
    accept-time distribution: instead of the kernel hashing each
    new 4-tuple to one of N listeners (variance: a 256-conn storm
    can land 80+ on one worker, 30 on another), every new accept
    is offered to the worker that's currently waiting in
    ``epoll_wait``. Idle workers absorb spikes; busy workers
    aren't burdened with extra conns. The
    ``benchmark/configs/throughput_mc.yaml`` p99 collapses from
    seconds to milliseconds with this entry point (see
    ``the design notes``).

    Args:
        listener_fd: Listener fd, owned by the ``Scheduler``. Must
            be in non-blocking mode before calling (the
            ``Scheduler`` configures this once at bind time).
        config: Per-worker copy of ``ServerConfig``.
        handler: Per-worker copy of ``H``.
        stopping: Heap-allocated stop flag; ``Scheduler``
            mutates it from another thread on shutdown. Re-read
            each iteration via a fresh external pointer so the
            compiler cannot LICM-hoist the load.
    """
    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    # EPOLLEXCLUSIVE on Linux; plain register on macOS. Token 0 is
    # reserved for the listener accept path (same convention as
    # ``run_reactor_loop``).
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
            if fd_tok in conns:
                _cleanup_conn(fd_tok, conns, timers, reactor)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop_fd(listener_fd, reactor, conns)
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

    # Graceful shutdown: close all active per-conn fds. The shared
    # listener fd is owned by ``Scheduler`` and stays open until
    # ``Scheduler.shutdown`` closes it.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
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
    parse-and-dispatch path. The canned bytes are ``memcpy``d into
    ``write_buf`` per request — no ``Request`` construction, no
    handler call, no response serialisation.

    Args:
        listener: Bound and listening ``TcpListener`` (caller owns it;
            we borrow for accept / fd access).
        config: Server configuration.
        resp: Pre-encoded static response.
        stopping: Checked on every poll iteration; when True the loop
            exits and in-flight connections are closed.
    """
    listener._socket.set_nonblocking(True)
    var listener_fd = listener._socket.fd

    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var conns = Dict[Int, Int]()
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

    # Graceful shutdown: flip Cancel.SHUTDOWN on every in-flight
    # conn before closing — same in-thread pattern as
    # ``run_reactor_loop_cancel`` (C12 / Track 3.2). Cancel-aware
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


def run_reactor_loop_static_shared(
    listener_fd: Int,
    config: ServerConfig,
    resp: StaticResponse,
    ref stopping: Bool,
) raises:
    """Multi-worker twin of :func:`run_reactor_loop_static`.

    Drives a pre-encoded ``StaticResponse`` over a SHARED listener fd
    (owned by the ``Scheduler`` / ``StaticScheduler``; never closed
    here). Same per-conn state machine as ``run_reactor_loop_static``
    -- ``ConnHandle.on_readable_static`` parses far enough to find
    ``\\r\\n\\r\\n`` + ``Content-Length`` and then ``memcpy``s the
    canned bytes -- but registers via ``register_exclusive`` so the
    kernel wakes only one worker per accept event (``EPOLLEXCLUSIVE``
    on Linux >= 4.5; degrades to wake-all on macOS).

    The combination of the static fast path (no parser, no handler,
    no allocation per request, no response serialisation) with the
    multi-worker scheduler closes the v0.7 throughput gap on TFB
    plaintext: the per-request work drops to memcpy + the syscall
    pair, which scales near-linearly across cores.

    Args:
        listener_fd: Borrowed shared listener fd. Must be in
            non-blocking mode (the Scheduler does this once at
            bind-time). This worker never closes it.
        config: Per-worker copy of ``ServerConfig``.
        resp: Pre-encoded static response (immutable; safely shared
            across workers via ``StaticScheduler``'s heap-stored
            copy).
        stopping: Heap-allocated stop flag mutated by
            ``StaticScheduler.shutdown`` from the main thread.
    """
    var reactor = Reactor()
    var wheel = TimerWheel(now_ms=UInt64(_monotonic_ms()))
    var conns = Dict[Int, Int]()
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
            if fd_tok in conns:
                _cleanup_conn(fd_tok, conns, timers, reactor)

        for i in range(len(events)):
            var evt = events[i]
            if evt.is_wakeup():
                continue
            if evt.token == UInt64(0):
                _accept_loop_fd(listener_fd, reactor, conns)
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

    # Worker shutdown: close per-conn fds. Shared listener fd
    # stays open -- StaticScheduler.shutdown closes it after
    # joining all workers.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn(leftover[i], conns, timers, reactor)


def run_reactor_loop_cancel[
    CH: CancelHandler
](
    mut listener: TcpListener,
    config: ServerConfig,
    ref handler: CH,
    ref stopping: Bool,
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

    # Graceful shutdown: walk every active conn and flip its
    # CancelCell to SHUTDOWN before closing. Cancel-aware
    # handlers (CancelHandler) observe the flip and short-circuit
    # at their next ``cancel.cancelled()`` poll. Plain Handlers
    # (which don't observe Cancel) run to completion as before.
    # The flip is in-thread (the worker walks its own conns,
    # not via cross-thread atomics) — closes the design-0.5
    # Track 3.2 cross-thread cancel-flip without exposing the
    # per-worker registry across threads.
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
) raises:
    """View-aware variant of ``run_reactor_loop_cancel``.

    Identical control flow but drives each connection through
    ``ConnHandle.on_readable_view(handler, config)`` instead of
    ``on_readable_cancel``, so the handler receives a borrowed
    ``RequestView[origin]`` whose body slice points directly into
    ``self.read_buf``. Closes the design-0.5 §1.1 zero-copy
    upload contract for handlers that opt into the
    ``ViewHandler`` shape.

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

    # Graceful shutdown: flip Cancel.SHUTDOWN on every in-flight
    # conn before closing — same in-thread pattern as
    # ``run_reactor_loop_cancel`` (C12 / Track 3.2). Cancel-aware
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


# ── io_uring server-loop dispatch (Track B0 wire-in) ────────────────────────
#
# When ``use_uring_backend()`` is true (Linux kernel exposes io_uring
# AND ``FLARE_DISABLE_IO_URING`` is unset), ``HttpServer.serve_static``
# routes through ``run_uring_reactor_loop_static`` below instead of
# the epoll/kqueue ``run_reactor_loop_static`` above.
#
# How it differs from the epoll path
# -----------------------------------
#
# * Backend: ``UringReactor`` (multishot accept on the listener,
#   multishot poll per connection fd) instead of ``Reactor``
#   (epoll_wait on Linux, kqueue on macOS). One ``io_uring_enter``
#   per loop iteration replaces ``epoll_wait`` + ``epoll_ctl(MOD)``
#   per modify; the multishot accept replaces the
#   ``while True: accept(); EAGAIN`` drain loop with one CQE per
#   accepted connection.
# * Per-conn state machine: **unchanged**. ``ConnHandle.on_readable_static``
#   and ``on_writable`` still do their own non-blocking ``recv`` /
#   ``send`` on the socket fd. The uring path only replaces the
#   *readiness notifier*: the kernel posts a ``URING_OP_POLL`` CQE
#   when the fd becomes readable / writable, and the dispatch loop
#   calls the same on_readable_static / on_writable code that the
#   epoll path runs. This keeps the wire-in surgical: zero changes
#   to the parser / response framer / keep-alive logic.
# * Cleanup: closing the connection fd implicitly cancels the
#   kernel's multishot poll on it. Any final-no-more-events CQE
#   that arrives after cleanup looks like a "conn_id not in dict"
#   miss in the dispatch switch and is silently ignored.
# * Modify (read <-> write): ``cancel_poll(fd) +
#   arm_poll_readable_multishot(fd, mask)`` is the io_uring
#   equivalent of ``epoll_ctl(EPOLL_CTL_MOD, fd, mask)``. We
#   trigger it from ``_apply_step_uring`` only when the new
#   interest mask actually differs from the currently-armed one,
#   matching the epoll path's no-op-skip optimisation.


def _alloc_conn_from_accepted_fd(fd: Int) raises -> Int:
    """Wrap an already-accepted client fd in a ConnHandle and
    return its address.

    Mirrors ``_conn_alloc_addr`` but takes a raw integer fd
    (the kernel returns the accepted fd directly in the
    ``IORING_OP_ACCEPT`` CQE's ``res`` field; we don't get to
    call ``accept(2)`` ourselves on the io_uring multishot
    accept path).

    Sets ``TCP_NODELAY`` + non-blocking on the fd to match the
    contract of :func:`flare.tcp.listener.accept_fd`. The peer
    address is left empty (loopback placeholder) -- the
    multishot-accept path discards it for performance, and the
    static-response path (the only consumer of this helper today)
    doesn't use ``Request.peer``.
    """
    from std.ffi import c_int
    from flare.net.socket import RawSocket
    from flare.net._libc import AF_INET, SOCK_STREAM

    var raw = RawSocket(c_int(fd), AF_INET, SOCK_STREAM, True)
    raw.set_tcp_nodelay(True)
    raw.set_nonblocking(True)
    var stream = TcpStream(raw^, SocketAddr.localhost(0))
    return Pool[ConnHandle].alloc_move(ConnHandle(stream^))


def _cleanup_conn_uring(
    fd: Int,
    mut conns: Dict[Int, Int],
):
    """``_cleanup_conn`` analog for the io_uring backend.

    Closing the fd implicitly cancels every multishot poll the
    kernel holds against it, so we don't bother issuing
    ``cancel_poll`` here -- the kernel auto-posts a final
    no-more-events CQE shortly after close, which the dispatch
    loop drops as a "conn_id not in dict" miss.

    The ConnHandle's destructor (run via ``Pool[ConnHandle].free``)
    closes the underlying ``TcpStream`` socket, which is the
    actual ``close(fd)`` syscall.
    """
    if fd in conns:
        try:
            var addr = conns.pop(fd)
            _conn_free_addr(addr)
        except:
            pass


def run_uring_reactor_loop_static(
    mut listener: TcpListener,
    config: ServerConfig,
    resp: StaticResponse,
    ref stopping: Bool,
) raises:
    """io_uring-backed reactor loop for the static-response path.

    Functional twin of :func:`run_reactor_loop_static` but uses
    :class:`flare.runtime.uring_reactor.UringReactor` for both the
    accept path (multishot accept; one SQE arms it, the kernel
    posts an accept CQE per incoming connection) and the per-conn
    readiness path (multishot poll for ``POLLIN | POLLRDHUP`` on
    accepted fds; ``POLLOUT`` after ``on_readable_static``
    transitions the connection to write-mode).

    Per-connection ``ConnHandle.on_readable_static`` /
    ``on_writable`` are unchanged -- the uring path replaces
    *readiness notification*, not the per-conn syscall pattern.
    A future v0.7.x commit will swap the in-handle ``recv`` for
    ``IORING_OP_RECV`` + ``IORING_RECV_MULTISHOT`` against the
    per-worker BufferPool to drop the recv syscall entirely.

    Linux-only. Caller is expected to gate this on
    :func:`flare.runtime.uring_reactor.use_uring_backend`.

    Args:
        listener: Bound and listening ``TcpListener`` (caller
            owns it; we borrow for accept / fd access).
        config: Server configuration.
        resp: Pre-encoded static response from
            ``precompute_response(...)``.
        stopping: Checked on every loop iteration; when True the
            loop exits and in-flight connections are closed.
    """
    comptime if not CompilationTarget.is_linux():
        raise Error(
            "run_uring_reactor_loop_static: io_uring path is Linux-only"
        )
    from flare.runtime.uring_reactor import (
        URING_OP_ACCEPT,
        URING_OP_POLL,
        UringCompletion,
        UringReactor,
    )
    from flare.runtime.io_uring_sqe import POLLIN, POLLOUT, POLLRDHUP

    listener._socket.set_nonblocking(True)
    var listener_fd = Int(listener._socket.fd)

    var ureactor = UringReactor(256)
    var conns = Dict[Int, Int]()

    # Multishot accept: one SQE arms it; the kernel posts a CQE per
    # accepted connection with the new fd in ``comp.res``.
    ureactor.arm_listener_multishot(listener_fd, UInt64(0))

    var completions = List[UringCompletion]()
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
    while not UnsafePointer[Bool, MutExternalOrigin](
        unsafe_from_address=stopping_addr
    )[]:
        completions.clear()
        try:
            # min_complete=1 -> block until at least one CQE arrives.
            # Closing the listener (HttpServer.close()) terminates the
            # multishot accept which posts a final CQE and wakes us up,
            # so the loop exits promptly on graceful-shutdown.
            _ = ureactor.poll(1, completions, 64)
        except:
            break

        for i in range(len(completions)):
            var comp = completions[i]
            if comp.op == URING_OP_ACCEPT:
                # Multishot accept completion. ``comp.res`` is the new
                # client fd on success, or a negative errno on error
                # (typically -EBADF when the listener is closed during
                # graceful shutdown -- we let the outer ``stopping``
                # check handle that).
                if comp.is_error():
                    continue
                var client_fd = Int(comp.res)
                var addr: Int
                try:
                    addr = _alloc_conn_from_accepted_fd(client_fd)
                except:
                    # Fd-allocator failure (rare; OOM); close the
                    # accepted fd to avoid leaking it.
                    var c = c_int(client_fd)
                    _ = _close(c)
                    continue
                conns[client_fd] = addr
                var ch_ptr = _conn_ptr_from_int(addr)
                # Track the initial interest so the no-op-skip in
                # the dispatch path works on the first read->read cycle.
                ch_ptr[].last_interest = Int(POLLIN | POLLRDHUP)
                try:
                    ureactor.arm_poll_readable_multishot(
                        client_fd, UInt64(client_fd), POLLIN | POLLRDHUP
                    )
                except:
                    _cleanup_conn_uring(client_fd, conns)
                continue

            if comp.op != URING_OP_POLL:
                # Wakeup CQEs are filtered inside UringReactor.poll;
                # remove-acks (URING_OP_POLL_REMOVE) + the
                # final-no-more-events poll CQE land here when a
                # re-arm cancelled an existing poll. Both are safe
                # to ignore -- the new poll SQE is already in flight
                # by the time we see them.
                continue

            # URING_OP_POLL completion. ``conn_id`` is the connection
            # fd; ``comp.res`` carries the OR of poll bits that fired.
            var fd = Int(comp.conn_id)
            if fd not in conns:
                # Stale CQE from a connection that was just cleaned up.
                continue

            var ch_ptr = _conn_ptr_from_int(conns[fd])
            var step_done = False
            try:
                var poll_bits = UInt32(comp.res)
                var last_step = StepResult()
                var did_anything = False

                if (poll_bits & POLLIN) != 0:
                    last_step = ch_ptr[].on_readable_static(resp, config)
                    step_done = last_step.done
                    did_anything = True
                    # Inline-cycle keep-alive optimisation, mirroring
                    # the epoll path: while the state machine is still
                    # cycling, drive the next step rather than bouncing
                    # back through the reactor. Cap at 3 cycles.
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

                if (not did_anything) and (poll_bits & POLLOUT) != 0:
                    last_step = ch_ptr[].on_writable(config)
                    step_done = last_step.done

                if not step_done:
                    # Compute the new interest mask + re-arm if it
                    # changed. This is the io_uring equivalent of
                    # _apply_step's ``reactor.modify(fd, interest)``.
                    var new_mask: UInt32 = 0
                    if last_step.want_read:
                        new_mask |= POLLIN | POLLRDHUP
                    if last_step.want_write:
                        new_mask |= POLLOUT
                    if new_mask != 0:
                        var key = Int(new_mask)
                        if key != ch_ptr[].last_interest:
                            if ch_ptr[].last_interest != 0:
                                try:
                                    ureactor.cancel_poll(UInt64(fd))
                                except:
                                    pass
                            try:
                                ureactor.arm_poll_readable_multishot(
                                    fd, UInt64(fd), new_mask
                                )
                                ch_ptr[].last_interest = key
                            except:
                                step_done = True
            except:
                step_done = True
            if step_done:
                _cleanup_conn_uring(fd, conns)

    # Graceful shutdown: drop every in-flight conn. Closing each fd
    # implicitly tears down its kernel-side multishot poll.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn_uring(leftover[i], conns)


# ── io_uring buffer-ring dispatch (Track B0 wire-in v3, handler path) ───────
#
# The production handler-path io_uring loop. Supersedes the two reverted
# attempts (poll-multishot in c8cd770, recv-multishot in 981eb8e) by using
# the kernel-managed buffer ring substrate (PROVIDE_BUFFERS +
# IOSQE_BUFFER_SELECT + true IORING_RECV_MULTISHOT) shipped in bf6ca75.
#
# Why this finally works
# ----------------------
#
# The c8cd770 poll-multishot attempt failed because IORING_OP_POLL_ADD's
# multishot mode defaults to edge-triggered semantics -- the dispatch
# drained via recv-EAGAIN, blocked on the next io_uring_enter, and lost
# the readiness edge for back-to-back keep-alive requests.
#
# The 981eb8e recv-multishot attempt failed because IORING_OP_RECV with
# IORING_RECV_MULTISHOT REQUIRES IOSQE_BUFFER_SELECT -- without a
# kernel-managed buffer source, multishot recv either errors, fires
# once and stops, or unsafely reuses the user's single buffer across
# overlapping CQEs. The workaround (single-shot recv + per-CQE re-arm
# against a per-conn 8 KiB pinned buffer) hit a deterministic
# ConnHandle lifecycle bug at exactly request #62.
#
# This third attempt does it the way every Rust io_uring HTTP server
# (tokio-uring, monoio, glommio) does it:
#
#   1. At reactor startup, allocate a per-worker buffer pool of
#      N × 8 KiB and seed it via arm_provide_buffers(bgid). The
#      kernel takes ownership of the buffer ring; we keep the
#      backing allocation alive (free at reactor shutdown).
#   2. On each accept CQE, arm one IORING_OP_RECV +
#      IORING_RECV_MULTISHOT + IOSQE_BUFFER_SELECT SQE with
#      buf_group=bgid. The kernel auto-rotates buffers from the
#      pool for every recv on this fd; one SQE per connection
#      drives an unbounded stream of recv CQEs.
#   3. On each recv CQE, the buffer id is in the CQE's flags
#      high 16 bits (IORING_CQE_F_BUFFER set). We compute the
#      buffer's address as ``pool + bid * BUF_SIZE``, feed the
#      bytes into ConnHandle.on_readable_from_buf[H] (the
#      additive scaffolding from 0116178), and re-provide the
#      same buffer back to the pool via a one-shot
#      arm_provide_buffers(bgid, nbufs=1, bid=bid) re-fill SQE.
#   4. On step_done, just free the conn (close fd; kernel
#      cancels any pending recv multishot SQE). No per-conn
#      buffer to free -- the buffer was already returned to the
#      pool in step 3 (or will be returned by the kernel on the
#      next CQE).
#
# This eliminates the per-conn buffer pinning that triggered the
# c6ccc79 lifecycle bug AND drops the recv syscall per request
# (the kernel hands us bytes via the buffer ring), which is the
# performance unlock the +30 % gap to hyper is budgeted for.
#
# Send path is unchanged from the recv-multishot attempt: synchronous
# on_writable using non-blocking _send. v0.7.x will swap to
# UringReactor.submit_send for the additional syscall savings on the
# response path.


comptime _URING_BR_BUF_SIZE: Int = 8192
comptime _URING_BR_NBUFS: Int = 256
comptime _URING_BR_BGID: UInt16 = 1

# Generation-stamped conn_id encoding -- the fix for the
# 9cf97d0 SIGSEGV under concurrent connections.
#
# When connection A on fd=8 closes, the kernel may have a
# trailing recv CQE in flight (the final-no-more-events CQE
# from the cancelled multishot recv) tagged with conn_id=8.
# If a new connection B is accepted on the *same* fd=8 before
# we see that stale CQE, our naive ``conn_id = fd`` scheme
# routes the stale CQE to B's freshly-armed recv state -- which
# either double-arms recv (kernel SIGSEGV territory) or feeds
# stale buffer-id data into B's parser. Generation-stamped
# conn_ids fix this: each accept bumps a per-worker monotonic
# generation counter, packs ``(gen << 24) | fd`` into the
# 56-bit conn_id space, and stores the conn under that full
# packed id. Stale CQEs from connection A carry the OLD gen
# bits and miss the ``if conn_id not in conns`` lookup --
# they're dropped cleanly, never touching connection B's
# state.
#
# 24-bit fd / 32-bit gen split: fd values fit in 24 bits even
# at the kernel's per-process limit (typically 2^20 on a
# default ulimit); 32-bit generation gives 4 billion connections
# per worker before wrap-around (effectively infinite for any
# bench window).

comptime _URING_BR_FD_BITS: Int = 24
comptime _URING_BR_FD_MASK: UInt64 = (
    UInt64(1) << UInt64(_URING_BR_FD_BITS)
) - UInt64(1)


@always_inline
def _br_pack_conn_id(fd: Int, gen: UInt64) -> UInt64:
    """Pack ``(gen, fd)`` into the 56-bit conn_id slot used by
    the buffer-ring dispatch."""
    return (gen << UInt64(_URING_BR_FD_BITS)) | (UInt64(fd) & _URING_BR_FD_MASK)


@always_inline
def _br_unpack_fd(conn_id: UInt64) -> Int:
    """Extract the fd portion of a packed buffer-ring conn_id."""
    return Int(conn_id & _URING_BR_FD_MASK)


def _alloc_recv_buffer_pool() raises -> Int:
    """Allocate the worker-local recv buffer pool: ``_URING_BR_NBUFS``
    contiguous buffers of ``_URING_BR_BUF_SIZE`` bytes.

    Caller owns the lifetime; the kernel retains pointers via the
    PROVIDE_BUFFERS SQE but the userspace allocation must outlive
    the reactor (released on graceful shutdown via
    ``_free_recv_buffer_pool``).
    """
    var size = _URING_BR_NBUFS * _URING_BR_BUF_SIZE
    var raw = alloc[UInt8](size)
    # Zero-init defensively; kernel will overwrite the prefix of
    # each buffer on every recv, but a stale read of an unused
    # slot (e.g. dump-on-error) shouldn't trip on uninitialised
    # memory.
    for i in range(size):
        (raw + i).init_pointee_copy(UInt8(0))
    return Int(raw)


def _free_recv_buffer_pool(addr: Int):
    """Release the pool previously returned by ``_alloc_recv_buffer_pool``."""
    if addr == 0:
        return
    var p = UnsafePointer[UInt8, MutExternalOrigin](unsafe_from_address=addr)
    p.free()


def _cleanup_conn_uring_br(
    conn_id: UInt64,
    mut conns: Dict[UInt64, Int],
    mut ureactor: UringReactor,
):
    """``_cleanup_conn`` for the buffer-ring path.

    Cleanup ordering matters because there's a kernel-level race
    between conn-close and reaccept-on-the-same-fd: if we close
    the fd while the kernel still has an armed multishot recv on
    it, the kernel's implicit cancel of that recv races against
    a potential new accept on the reused fd. Empirically this
    SIGSEGV's our process under sustained conn-churn (sequential
    8 short-lived conns reproduces; sleep(50ms) between conns
    masks it; ASAN's slowdown also masks it).

    The fix: explicitly cancel the multishot recv BEFORE freeing
    the ConnHandle, so the kernel processes the cancel cleanly
    while the fd is still open and the io_uring ring resources
    for that recv are still valid. The cancel CQE arrives a few
    iterations later and is silently dropped (no op tag handler
    for URING_OP_CANCEL); the recv's terminal CQE is dropped via
    the ``conn_id not in conns`` gen-stamp miss.
    """
    if conn_id in conns:
        # Issue the cancel BEFORE freeing the ConnHandle (which
        # closes the fd). cancel_conn uses URING_OP_ASYNC_CANCEL
        # targeting the recv SQE tagged with this conn_id.
        try:
            ureactor.cancel_conn(conn_id)
        except:
            # SQ pressure -- fall back to implicit cancel via fd
            # close. Higher race risk but the only alternative is
            # to drop the cleanup which would leak the conn.
            pass
        try:
            var addr = conns.pop(conn_id)
            _conn_free_addr(addr)
        except:
            pass


def _drive_handler_with_submit_send[
    H: Handler,
](
    fd: Int,
    conn_id: UInt64,
    bytes: Span[UInt8, _],
    config: ServerConfig,
    ref handler: H,
    ch_ptr: UnsafePointer[ConnHandle, MutExternalOrigin],
    mut ureactor: UringReactor,
) raises -> Bool:
    """Drive one request via parse → handler → submit_send.

    After ``on_readable_from_buf`` parses the request and queues
    the response in ``write_buf``, this helper submits an
    ``IORING_OP_SEND`` SQE pointing at the write_buf bytes
    (instead of the synchronous ``_send`` syscall used in
    ``_drive_handler_after_buf_recv``). The conn is marked
    ``send_in_flight=True``; subsequent recv CQEs for this conn
    just buffer bytes into read_buf without parsing (the next
    request can't be processed until the kernel releases the
    write_buf via the matching send CQE).

    Returns True iff the conn should be cleaned up (handler
    raised, response framing failed, etc.).
    """
    var step_done = False
    try:
        var last_step = ch_ptr[].on_readable_from_buf(bytes, handler, config)
        step_done = last_step.done
        # Pipelined-request inline cycle: drain everything in
        # read_buf BEFORE submitting the send (so we batch
        # multiple responses if the client pipelined). Each
        # cycle iter writes to write_buf; the LAST one's bytes
        # are what we submit_send.
        while not step_done:
            if (
                last_step.want_read
                and len(ch_ptr[].read_buf) > 0
                and ch_ptr[].state == STATE_READING
            ):
                # NOTE: we DON'T call on_writable here -- we let
                # write_buf accumulate, then submit_send the
                # whole thing once.
                var empty_buf = stack_allocation[1, UInt8]()
                last_step = ch_ptr[].on_readable_from_buf(
                    Span[UInt8, _](ptr=empty_buf, length=0),
                    handler,
                    config,
                )
                step_done = last_step.done
            else:
                break
        # If we're now in STATE_WRITING with bytes to send, fire
        # off the submit_send + mark in-flight. The send CQE will
        # land later; the dispatch handler will reset state +
        # process any deferred read_buf bytes then.
        if (
            (not step_done)
            and ch_ptr[].state == STATE_WRITING
            and len(ch_ptr[].write_buf) > ch_ptr[].write_pos
        ):
            var write_ptr = ch_ptr[].write_buf.unsafe_ptr() + ch_ptr[].write_pos
            var write_len = len(ch_ptr[].write_buf) - ch_ptr[].write_pos
            try:
                ureactor.submit_send(fd, write_ptr, write_len, conn_id)
                ch_ptr[].send_in_flight = True
            except:
                # SQ full -- can't kick off the send. Drop the
                # conn rather than leaving the response stranded.
                step_done = True
    except:
        step_done = True
    return step_done


def _on_send_cqe_complete[
    H: Handler,
](
    fd: Int,
    conn_id: UInt64,
    config: ServerConfig,
    ref handler: H,
    ch_ptr: UnsafePointer[ConnHandle, MutExternalOrigin],
    mut ureactor: UringReactor,
) raises -> Bool:
    """Handle a ``URING_OP_SEND`` CQE: clear the send-in-flight
    state, drain any read_buf bytes that were buffered while the
    send was in flight, and start a new request cycle if there
    are buffered bytes.

    Returns True iff the conn should be cleaned up (e.g.,
    ``should_close`` was set on the just-sent response and there
    are no more requests to serve).
    """
    ch_ptr[].send_in_flight = False
    # Reset the write buffer so the next request's response
    # serializes from a clean state.
    ch_ptr[].write_buf.clear()
    ch_ptr[].write_pos = 0
    # Was this the close-after-send response? If so, the conn is
    # done.
    if ch_ptr[].should_close:
        return True
    # Transition back to reading; drain any pipelined bytes that
    # arrived while send was in flight.
    ch_ptr[].state = STATE_READING
    if len(ch_ptr[].read_buf) > 0:
        var empty_buf = stack_allocation[1, UInt8]()
        return _drive_handler_with_submit_send[H](
            fd,
            conn_id,
            Span[UInt8, _](ptr=empty_buf, length=0),
            config,
            handler,
            ch_ptr,
            ureactor,
        )
    return False


def _drive_handler_after_buf_recv[
    H: Handler,
](
    bytes: Span[UInt8, _],
    config: ServerConfig,
    ref handler: H,
    ch_ptr: UnsafePointer[ConnHandle, MutExternalOrigin],
) raises -> Bool:
    """Sync-send variant kept as a fallback / reference -- see
    ``_drive_handler_with_submit_send`` for the production io_uring
    path that uses ``submit_send`` instead of synchronous
    ``on_writable``.
    """
    var step_done = False
    try:
        var last_step = ch_ptr[].on_readable_from_buf(bytes, handler, config)
        step_done = last_step.done
        while not step_done:
            if (
                last_step.want_write
                and len(ch_ptr[].write_buf) > ch_ptr[].write_pos
            ):
                last_step = ch_ptr[].on_writable(config)
                step_done = last_step.done
                if (not step_done) and last_step.want_write:
                    step_done = True
            elif (
                last_step.want_read
                and len(ch_ptr[].read_buf) > 0
                and ch_ptr[].state == STATE_READING
            ):
                # Pipelined request already in read_buf -- drive the
                # parser without appending more bytes. Use stack-
                # allocated empty span (Span over a temp List would
                # be a use-after-free).
                var empty_buf = stack_allocation[1, UInt8]()
                last_step = ch_ptr[].on_readable_from_buf(
                    Span[UInt8, _](ptr=empty_buf, length=0),
                    handler,
                    config,
                )
                step_done = last_step.done
            else:
                break
    except:
        step_done = True
    return step_done


def run_uring_bufring_reactor_loop[
    H: Handler,
](
    mut listener: TcpListener,
    config: ServerConfig,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Single-worker io_uring buffer-ring reactor loop.

    Production handler-path io_uring loop. See the module-level
    "io_uring buffer-ring dispatch" comment block above for the
    design rationale and the *Why this finally works* note.
    Linux-only.
    """
    comptime if not CompilationTarget.is_linux():
        raise Error(
            "run_uring_bufring_reactor_loop: io_uring path is Linux-only"
        )
    from flare.runtime.uring_reactor import (
        URING_OP_ACCEPT,
        URING_OP_PROVIDE_BUFFERS,
        URING_OP_RECV,
        URING_OP_SEND,
        UringCompletion,
        UringReactor,
    )
    from flare.runtime.io_uring_sqe import IORING_CQE_F_BUFFER

    listener._socket.set_nonblocking(True)
    var listener_fd = Int(listener._socket.fd)

    # SQ depth 4096: under multishot recv + submit_send + 64-conn
    # bursts, SQ pressure can spike (initial accept burst arms 64
    # multishot recvs simultaneously; each subsequent recv CQE
    # may submit_send + cancel + close-on-disarm). 512 SQEs was
    # not enough -- the dispatch hit silent next_sqe failures
    # under sustained 64-conn load and crashed.
    var ureactor = UringReactor(4096)
    var conns = Dict[UInt64, Int]()
    var next_gen: UInt64 = 1

    # ``FLARE_SUBMIT_SEND=1`` opts in to the kernel-async
    # IORING_OP_SEND wire-in (substrate ships always; default is
    # synchronous send). Empirically synchronous send WINS on
    # tiny-response workloads like TFB plaintext: each request
    # cycles recv → handler → sync send → next recv = 1
    # io_uring_enter; submit_send splits this into two cycles
    # (recv+submit_send → send-CQE → next recv) and the extra
    # io_uring_enter overhead exceeds the saved send syscall for
    # responses small enough to never block. submit_send wins on
    # workloads with larger responses where the kernel's send
    # buffer fills up + back-pressures, but for the gate-defining
    # TFB plaintext bench the sync path is faster. Substrate is
    # exposed so kernels with io_uring_send_batched (kernel 6.5+)
    # or larger payloads can be A/B'd.
    var submit_send = getenv("FLARE_SUBMIT_SEND") == "1"

    # Allocate the worker's recv buffer pool + register a kernel-
    # mapped buffer ring (PBUF_RING). 2.7x faster than the legacy
    # IORING_OP_PROVIDE_BUFFERS path per Linux kernel benchmarks
    # (commit c7fb194: 27M vs 10M ops/sec replenish-1) AND uses
    # SQE-free shared-memory tail bumps for refills, removing the
    # per-CQE PROVIDE_BUFFERS SQE that was hammering the SQ on the
    # legacy path.
    var pool_addr = _alloc_recv_buffer_pool()
    var ring_addr = ureactor.register_pbuf_ring(_URING_BR_BGID, _URING_BR_NBUFS)
    # Seed all N buffers into the ring. tail starts at 0; each
    # entry points into the per-worker buffer pool at offset
    # bid * _URING_BR_BUF_SIZE.
    for i in range(_URING_BR_NBUFS):
        _pbuf_ring_add(
            ring_addr,
            _URING_BR_NBUFS,
            UInt64(pool_addr + i * _URING_BR_BUF_SIZE),
            UInt32(_URING_BR_BUF_SIZE),
            UInt16(i),
            i,
            UInt16(0),
        )
    _pbuf_ring_set_tail(ring_addr, UInt16(_URING_BR_NBUFS))

    ureactor.arm_listener_multishot(listener_fd, UInt64(0))

    var completions = List[UringCompletion]()
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
    while not UnsafePointer[Bool, MutExternalOrigin](
        unsafe_from_address=stopping_addr
    )[]:
        completions.clear()
        try:
            _ = ureactor.poll(1, completions, 64)
        except:
            break

        for i in range(len(completions)):
            var comp = completions[i]
            if comp.op == URING_OP_ACCEPT:
                if comp.is_error():
                    continue
                var client_fd = Int(comp.res)
                var conn_addr: Int
                try:
                    conn_addr = _alloc_conn_from_accepted_fd(client_fd)
                except:
                    var c = c_int(client_fd)
                    _ = _close(c)
                    continue
                # Mint a fresh conn_id stamped with the next
                # generation. Even if the kernel reuses the same
                # fd value as a recently-closed conn, the new
                # conn_id is unique and any trailing stale CQEs
                # from the closed conn miss our conns dict.
                var conn_id = _br_pack_conn_id(client_fd, next_gen)
                next_gen += 1
                conns[conn_id] = conn_addr
                try:
                    ureactor.arm_recv_buffer_select(
                        client_fd,
                        _URING_BR_BGID,
                        conn_id,
                        True,
                    )
                except:
                    _cleanup_conn_uring_br(conn_id, conns, ureactor)
                continue

            if comp.op == URING_OP_PROVIDE_BUFFERS:
                continue

            if comp.op == URING_OP_SEND:
                # submit_send completion. Reset send-in-flight,
                # drain any deferred read_buf bytes, kick a new
                # request cycle if there's pipelined data.
                var send_conn_id = comp.conn_id
                if send_conn_id not in conns:
                    continue
                var send_fd = _br_unpack_fd(send_conn_id)
                var send_ch_ptr = _conn_ptr_from_int(conns[send_conn_id])
                var send_done = _on_send_cqe_complete[H](
                    send_fd,
                    send_conn_id,
                    config,
                    handler,
                    send_ch_ptr,
                    ureactor,
                )
                if send_done:
                    _cleanup_conn_uring_br(send_conn_id, conns, ureactor)
                continue

            if comp.op != URING_OP_RECV:
                continue

            var conn_id = comp.conn_id
            if conn_id not in conns:
                continue
            if comp.res <= 0:
                _cleanup_conn_uring_br(conn_id, conns, ureactor)
                continue
            if (comp.flags & IORING_CQE_F_BUFFER) == UInt32(0):
                _cleanup_conn_uring_br(conn_id, conns, ureactor)
                continue

            var fd = _br_unpack_fd(conn_id)
            var bid = Int(comp.flags >> UInt32(16))
            var n = Int(comp.res)
            var pool_ptr = UnsafePointer[UInt8, MutExternalOrigin](
                unsafe_from_address=pool_addr
            )
            var buf = pool_ptr + (bid * _URING_BR_BUF_SIZE)
            var ch_ptr = _conn_ptr_from_int(conns[conn_id])
            var bytes = Span[UInt8, _](ptr=buf, length=n)
            var step_done = False
            if submit_send:
                if ch_ptr[].send_in_flight:
                    for i in range(n):
                        ch_ptr[].read_buf.append((buf + i).load())
                else:
                    step_done = _drive_handler_with_submit_send[H](
                        fd,
                        conn_id,
                        bytes,
                        config,
                        handler,
                        ch_ptr,
                        ureactor,
                    )
            else:
                step_done = _drive_handler_after_buf_recv[H](
                    bytes, config, handler, ch_ptr
                )

            # Recycle the buffer back into the ring (SQE-free).
            var cur_tail = _pbuf_ring_get_tail(ring_addr)
            _pbuf_ring_add(
                ring_addr,
                _URING_BR_NBUFS,
                UInt64(Int(buf)),
                UInt32(_URING_BR_BUF_SIZE),
                UInt16(bid),
                0,
                cur_tail,
            )
            _pbuf_ring_set_tail(ring_addr, cur_tail + UInt16(1))

            # Re-arm if the kernel disarmed the multishot.
            if (not step_done) and (not comp.has_more):
                try:
                    ureactor.arm_recv_buffer_select(
                        fd,
                        _URING_BR_BGID,
                        conn_id,
                        True,
                    )
                except:
                    step_done = True

            if step_done:
                _cleanup_conn_uring_br(conn_id, conns, ureactor)

    # Graceful shutdown.
    var leftover = List[UInt64]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn_uring_br(leftover[i], conns, ureactor)
    try:
        ureactor.unregister_pbuf_ring(
            _URING_BR_BGID, ring_addr, _URING_BR_NBUFS
        )
    except:
        pass
    _free_recv_buffer_pool(pool_addr)


def run_uring_bufring_reactor_loop_shared[
    H: Handler,
](
    listener_fd: Int,
    config: ServerConfig,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Multi-worker io_uring buffer-ring reactor loop.

    Sharing-listener twin of :func:`run_uring_bufring_reactor_loop`.
    Each pthread worker owns its own UringReactor + per-worker
    buffer pool (no cross-worker sharing -- the buffer ring is
    per-ring, and rings are per-worker). Multishot accept on the
    shared listener fd from each worker; kernel hands each new
    connection to exactly one worker. Linux-only.
    """
    comptime if not CompilationTarget.is_linux():
        raise Error(
            "run_uring_bufring_reactor_loop_shared: io_uring path is Linux-only"
        )
    from flare.runtime.uring_reactor import (
        URING_OP_ACCEPT,
        URING_OP_PROVIDE_BUFFERS,
        URING_OP_RECV,
        URING_OP_SEND,
        UringCompletion,
        UringReactor,
    )
    from flare.runtime.io_uring_sqe import IORING_CQE_F_BUFFER

    var ureactor = UringReactor(4096)
    var conns = Dict[UInt64, Int]()
    var next_gen: UInt64 = 1
    var submit_send = getenv("FLARE_SUBMIT_SEND") == "1"

    var pool_addr = _alloc_recv_buffer_pool()
    var ring_addr = ureactor.register_pbuf_ring(_URING_BR_BGID, _URING_BR_NBUFS)
    for i in range(_URING_BR_NBUFS):
        _pbuf_ring_add(
            ring_addr,
            _URING_BR_NBUFS,
            UInt64(pool_addr + i * _URING_BR_BUF_SIZE),
            UInt32(_URING_BR_BUF_SIZE),
            UInt16(i),
            i,
            UInt16(0),
        )
    _pbuf_ring_set_tail(ring_addr, UInt16(_URING_BR_NBUFS))

    ureactor.arm_listener_multishot(listener_fd, UInt64(0))

    var completions = List[UringCompletion]()
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
    while not UnsafePointer[Bool, MutExternalOrigin](
        unsafe_from_address=stopping_addr
    )[]:
        completions.clear()
        try:
            _ = ureactor.poll(1, completions, 64)
        except:
            break

        for i in range(len(completions)):
            var comp = completions[i]
            if comp.op == URING_OP_ACCEPT:
                if comp.is_error():
                    continue
                var client_fd = Int(comp.res)
                var conn_addr: Int
                try:
                    conn_addr = _alloc_conn_from_accepted_fd(client_fd)
                except:
                    var c = c_int(client_fd)
                    _ = _close(c)
                    continue
                var conn_id = _br_pack_conn_id(client_fd, next_gen)
                next_gen += 1
                conns[conn_id] = conn_addr
                try:
                    ureactor.arm_recv_buffer_select(
                        client_fd,
                        _URING_BR_BGID,
                        conn_id,
                        True,
                    )
                except:
                    _cleanup_conn_uring_br(conn_id, conns, ureactor)
                continue

            if comp.op == URING_OP_PROVIDE_BUFFERS:
                continue

            if comp.op == URING_OP_SEND:
                var send_conn_id = comp.conn_id
                if send_conn_id not in conns:
                    continue
                var send_fd = _br_unpack_fd(send_conn_id)
                var send_ch_ptr = _conn_ptr_from_int(conns[send_conn_id])
                var send_done = _on_send_cqe_complete[H](
                    send_fd,
                    send_conn_id,
                    config,
                    handler,
                    send_ch_ptr,
                    ureactor,
                )
                if send_done:
                    _cleanup_conn_uring_br(send_conn_id, conns, ureactor)
                continue

            if comp.op != URING_OP_RECV:
                continue

            var conn_id = comp.conn_id
            if conn_id not in conns:
                continue
            if comp.res <= 0:
                _cleanup_conn_uring_br(conn_id, conns, ureactor)
                continue
            if (comp.flags & IORING_CQE_F_BUFFER) == UInt32(0):
                _cleanup_conn_uring_br(conn_id, conns, ureactor)
                continue

            var fd = _br_unpack_fd(conn_id)
            var bid = Int(comp.flags >> UInt32(16))
            var n = Int(comp.res)
            var pool_ptr = UnsafePointer[UInt8, MutExternalOrigin](
                unsafe_from_address=pool_addr
            )
            var buf = pool_ptr + (bid * _URING_BR_BUF_SIZE)
            var ch_ptr = _conn_ptr_from_int(conns[conn_id])
            var bytes = Span[UInt8, _](ptr=buf, length=n)
            var step_done = False
            if submit_send:
                if ch_ptr[].send_in_flight:
                    for i in range(n):
                        ch_ptr[].read_buf.append((buf + i).load())
                else:
                    step_done = _drive_handler_with_submit_send[H](
                        fd,
                        conn_id,
                        bytes,
                        config,
                        handler,
                        ch_ptr,
                        ureactor,
                    )
            else:
                step_done = _drive_handler_after_buf_recv[H](
                    bytes, config, handler, ch_ptr
                )

            # Re-fill via shared-memory tail bump (PBUF_RING).
            var cur_tail = _pbuf_ring_get_tail(ring_addr)
            _pbuf_ring_add(
                ring_addr,
                _URING_BR_NBUFS,
                UInt64(Int(buf)),
                UInt32(_URING_BR_BUF_SIZE),
                UInt16(bid),
                0,
                cur_tail,
            )
            _pbuf_ring_set_tail(ring_addr, cur_tail + UInt16(1))

            if (not step_done) and (not comp.has_more):
                try:
                    ureactor.arm_recv_buffer_select(
                        fd,
                        _URING_BR_BGID,
                        conn_id,
                        True,
                    )
                except:
                    step_done = True

            if step_done:
                _cleanup_conn_uring_br(conn_id, conns, ureactor)

    # Worker shutdown: close all per-conn fds + free pool +
    # unregister the kernel ring. Shared listener fd stays open
    # -- Scheduler.shutdown closes it.
    var leftover = List[UInt64]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn_uring_br(leftover[i], conns, ureactor)
    try:
        ureactor.unregister_pbuf_ring(
            _URING_BR_BGID, ring_addr, _URING_BR_NBUFS
        )
    except:
        pass
    _free_recv_buffer_pool(pool_addr)
