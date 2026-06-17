"""Per-connection state machine for the reactor-backed HTTP server.

This module owns ``ConnHandle`` -- the per-connection state machine
that walks each H1 connection through ``STATE_READING`` ->
``STATE_WRITING`` -> ``STATE_CLOSING`` driven by readable / writable
/ timeout events from the reactor.

Byte-fast-path / keep-alive helpers (the ``STATE_*`` constants, the
``StepResult`` return shape, the byte-level ``Connection``-header
matchers, the HTTP/1.0 ``_wants_close`` raw-bytes scanner, the
read-buffer compaction helper, and the h2c upgrade detection
wrapper) live in :mod:`flare.http._reactor.keepalive_scan` and are
re-exported here so existing import sites in ``flare.http``,
``flare.http2``, ``flare.runtime``, the tests, and the fuzz corpus
keep working unchanged.

The five reader entry points (default, bufring, cancel-aware,
view-based, static) dispatch through a shared set of helpers
parameterised on a comptime :class:`DispatchConfig` so the H1 hot
path stays straight-line and the byte-source-step duplication that
the previous shape carried collapses into a single helper.

State transitions::

    STATE_READING ─ handler returned ─> STATE_WRITING ─ flushed ─┬─> STATE_READING (keep-alive)
                                                                └─> STATE_CLOSING (should_close)
    STATE_READING / STATE_WRITING ─ peer close / error / timeout ─> STATE_CLOSING

The sister module ``flare/http/_server_reactor_impl.mojo`` owns the
I/O-bearing pieces -- reactor entry-point loops, ``Pool[ConnHandle]``
allocation glue, io_uring buffer-ring glue -- and re-exports
every public symbol below for back-compat with existing imports
across ``flare/http/``, ``flare/http2/``, ``flare/runtime/``, tests,
and the fuzz corpus.

# TODO(2026-08-31, track-h1-dispatch): this module still exceeds the
# 600-line reactor cap (``tools/check_reactor_size.sh`` allowlists it
# for that reason). The natural seam left to extract is
# :mod:`flare.http._reactor.h1_dispatch`: the parse-and-dispatch step
# of each ``on_readable_*`` reader (minimal / view / cancel-aware /
# static), called from the thin per-handler entry point that retains
# only its trait binding. Until that lands, every entry added to the
# allowlist (this module or otherwise) MUST carry a dated TODO and a
# deadline; the lint hygiene rule in
# ``tools/check_reactor_size.sh`` enforces the policy.
"""

from std.collections import List, Optional
from std.ffi import c_int, c_size_t, ErrNo, get_errno
from std.memory import memcpy, stack_allocation

from flare.crypto.hmac import base64url_decode
from flare.http.cancel import CancelCell, CancelReason
from flare.http.handler import Handler, CancelHandler, ViewHandler
from flare.http.headers import HeaderMap
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import (
    ServerConfig,
    _find_crlfcrlf,
    _parse_http_request_bytes,
    _parse_http_request_bytes_minimal,
    _scan_content_length,
)
from flare.http.static_response import StaticResponse
from flare.net import SocketAddr
from flare.net._libc import _recv, _send, MSG_NOSIGNAL
from flare.tcp import TcpStream
from flare.runtime import DateCache

from .keepalive_scan import (
    STATE_CLOSING,
    STATE_READING,
    STATE_WRITING,
    StepResult,
    _compact_read_buf_drop_prefix,
    _compute_close_after,
    _connection_is_close,
    _connection_is_keepalive,
    _detect_h2c_upgrade_inline,
    _is_connection,
    _is_content_length,
    _is_date,
    _monotonic_ms,
    _wants_close,
)
from .write_path import (
    build_error_response,
    queue_h2c_upgrade_101,
    serialize_response_into,
    serialize_static_into,
)


# ── Dispatch-config comptime tags ─────────────────────────────────────────────

comptime BYTE_SOURCE_RECV: Int = 0
"""Drain the non-blocking socket via ``_recv`` until EAGAIN."""
comptime BYTE_SOURCE_BUFRING: Int = 1
"""Use kernel-provided bytes (io_uring buffer-ring path); skip
``_recv``."""


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
    """Per-connection cancel cell. The reactor flips its ``Int`` to a
    non-zero ``CancelReason`` on peer FIN, deadline expiry, or drain
    signal; the cancel-aware reader hands a ``Cancel`` handle bound to
    this cell into ``CancelHandler.serve(req, cancel)``. Reset between
    pipelined requests so a cancel reason on one request doesn't leak
    into the next."""
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
    hasn't been observed yet. While True, recv CQEs for this conn
    are buffered into ``read_buf`` but NOT parsed -- the next
    request can't be processed until the in-flight ``write_buf``
    has been released by the kernel. Always ``False`` on the
    epoll path (which does synchronous send + frees write_buf in
    ``on_writable``)."""

    var _h2c_upgrade_pending: Bool
    """``True`` iff this h1 connection has received a valid
    ``Upgrade: h2c`` request (RFC 7540 §3.2), queued the
    ``101 Switching Protocols`` response into ``write_buf``, and
    is now waiting for that response to flush before the unified
    reactor migrates the conn-dict entry from ``KIND_H1`` to
    ``KIND_H2``."""
    var _h2c_upgrade_request: Optional[Request]
    """The original h1 request that triggered the h2c upgrade.
    The unified reactor's migration helper consumes this to seed
    stream id 1 on the new :class:`H2ConnHandle`."""
    var _h2c_upgrade_settings: List[UInt8]
    """Base64url-decoded raw bytes of the inbound ``HTTP2-Settings``
    header (a SETTINGS frame body per RFC 7540 §3.2.1). Applied
    to the new HTTP/2 connection state during migration."""

    var _date_cache: DateCache
    """Per-connection cached ``Date:`` header (RFC 9110 §6.6.1).
    The ``clock_gettime`` call on Linux x86_64 is vDSO-fast (no
    syscall) and the 29-byte formatter only runs when the
    wall-clock second has rolled over since the previous response
    on this connection."""

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
        self._h2c_upgrade_pending = False
        self._h2c_upgrade_request = Optional[Request]()
        self._h2c_upgrade_settings = List[UInt8]()
        self._date_cache = DateCache()

    @always_inline
    def fd(self) -> c_int:
        """Return the underlying fd. Fast accessor; does not check state."""
        return self._stream._socket.fd

    # ── Shared step helpers ───────────────────────────────────────────────────

    @always_inline
    def _drain_recv[
        flips_cancel_on_close: Bool
    ](mut self, config: ServerConfig) raises -> Optional[StepResult]:
        """Drain the non-blocking socket via ``_recv`` into
        ``self.read_buf`` until EAGAIN. Returns ``Some(StepResult)``
        when the state machine should bail (peer-close, oversize,
        hard error); ``None`` when the buffer is up-to-date and the
        caller should fall through to the parse step.

        The ``flips_cancel_on_close`` comptime flag selects whether
        a peer-close (``recv == 0``) flips this connection's
        ``CancelCell`` to ``PEER_CLOSED`` before returning the
        done-result; only the cancel- and view-aware reader paths
        request the flip.
        """
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
                    return Optional[StepResult](self._transition_to_writing())
            elif got == 0:
                comptime if flips_cancel_on_close:
                    self.cancel_cell.flip(CancelReason.PEER_CLOSED)
                self.should_close = True
                return Optional[StepResult](
                    StepResult(want_read=False, want_write=False, done=True)
                )
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                self.should_close = True
                return Optional[StepResult](
                    StepResult(want_read=False, want_write=False, done=True)
                )
        return Optional[StepResult]()

    @always_inline
    def _append_pre_recv_bytes(
        mut self, bytes: Span[UInt8, _], config: ServerConfig
    ) raises -> Optional[StepResult]:
        """Append kernel-pre-delivered ``bytes`` (io_uring buffer-ring
        path) into ``self.read_buf``. Mirror of :meth:`_drain_recv`
        for the BUFRING byte source; identical body-size cap check.
        """
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
                return Optional[StepResult](self._transition_to_writing())
        return Optional[StepResult]()

    @always_inline
    def _check_request_complete(
        mut self, config: ServerConfig, body_timeout_ms: Int = -1
    ) raises -> Optional[StepResult]:
        """Return ``Some(StepResult)`` while the buffered bytes do not
        yet form a complete request; ``None`` when the request is
        fully buffered and ready to dispatch.

        Sets ``self.headers_end``, ``self.content_length``, and
        ``self.body_total`` as a side effect on the first scan of the
        header block; subsequent calls re-use those values.

        ``body_timeout_ms`` is honoured only while the body is still
        arriving; a negative value falls back to
        ``config.idle_timeout_ms``.
        """
        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
                if len(self.read_buf) > config.max_header_size:
                    self._queue_error(431, "Request Header Fields Too Large")
                    return Optional[StepResult](self._transition_to_writing())
                return Optional[StepResult](
                    StepResult(
                        want_read=True,
                        want_write=False,
                        idle_timeout_ms=config.idle_timeout_ms,
                    )
                )
            self.headers_end = end
            self.content_length = _scan_content_length(
                self.read_buf, self.headers_end
            )
            if self.content_length > config.max_body_size:
                self._queue_error(413, "Content Too Large")
                return Optional[StepResult](self._transition_to_writing())
            self.body_total = self.headers_end + self.content_length
        if len(self.read_buf) < self.body_total:
            var timeout = (
                body_timeout_ms if body_timeout_ms
                > 0 else config.idle_timeout_ms
            )
            return Optional[StepResult](
                StepResult(
                    want_read=True,
                    want_write=False,
                    idle_timeout_ms=timeout,
                )
            )
        return Optional[StepResult]()

    @always_inline
    def _apply_keepalive_policy(
        mut self, config: ServerConfig, close_after: Bool
    ) -> Bool:
        """Roll the per-request keep-alive book-keeping (request count
        cap, server-policy override) into the final close decision
        and store it on ``self.should_close``. Returns the same value
        so the caller can use it for the ``Connection:`` response
        header.
        """
        self.keepalive_count += 1
        var final = close_after
        if self.keepalive_count >= config.max_keepalive_requests:
            final = True
        if not config.keep_alive:
            final = True
        self.should_close = final
        return final

    @always_inline
    def _finalise_response(
        mut self, var resp: Response, close_after: Bool
    ) -> StepResult:
        """Compact the read buffer, reset the per-request offsets,
        serialise ``resp`` into ``self.write_buf``, and transition
        into ``STATE_WRITING``.
        """
        if self.body_total > 0 and self.body_total <= len(self.read_buf):
            _compact_read_buf_drop_prefix(self.read_buf, self.body_total)
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1
        self._serialize_response(resp^, not close_after)
        return self._transition_to_writing()

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
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        var drained = self._drain_recv[flips_cancel_on_close=False](config)
        if drained:
            return drained.value()
        var pending = self._check_request_complete(config)
        if pending:
            return pending.value()

        # Parse the request. ``skip_header_decode_for_short_requests``
        # picks the minimal parser that skips HeaderMap construction.
        var req: Request
        var close_after: Bool
        try:
            if config.skip_header_decode_for_short_requests:
                req = _parse_http_request_bytes_minimal(
                    Span[UInt8, _](self.read_buf)[: self.body_total],
                    self.headers_end,
                    self.content_length,
                    config.max_body_size,
                    config.max_uri_length,
                    self.peer,
                    config.expose_error_messages,
                )
                close_after = _wants_close(self.read_buf, self.headers_end)
            else:
                req = _parse_http_request_bytes(
                    Span[UInt8, _](self.read_buf)[: self.body_total],
                    config.max_header_size,
                    config.max_body_size,
                    config.max_uri_length,
                    self.peer,
                    config.expose_error_messages,
                )
                close_after = _compute_close_after(req.headers, req.version)
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        # h2c upgrade detection (RFC 7540 §3.2). Hot-path-aware: 99.99 %
        # of inbound requests don't carry ``Upgrade: h2c`` so we
        # short-circuit on the first cheap header lookup -- a single
        # ``HeaderMap.get("upgrade")`` returning the empty string skips
        # the entire upgrade-handling branch.
        if req.headers.get("upgrade").byte_length() != 0:
            var settings_payload: Optional[List[UInt8]]
            try:
                settings_payload = self._h2c_upgrade_decode_settings(
                    req.headers
                )
            except:
                settings_payload = Optional[List[UInt8]]()
            if settings_payload:
                self._start_h2c_upgrade(req^, settings_payload.value().copy())
                if self.body_total > 0 and self.body_total <= len(
                    self.read_buf
                ):
                    _compact_read_buf_drop_prefix(
                        self.read_buf, self.body_total
                    )
                self.headers_end = -1
                self.content_length = 0
                self.body_total = -1
                self.state = STATE_WRITING
                return StepResult(
                    want_read=False,
                    want_write=True,
                    idle_timeout_ms=0,
                )

        var final_close = self._apply_keepalive_policy(config, close_after)
        var resp: Response
        try:
            resp = handler.serve(req^)
        except:
            self._queue_error(500, "Internal Server Error")
            return self._transition_to_writing()
        return self._finalise_response(resp^, final_close)

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
            state.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        var appended = self._append_pre_recv_bytes(bytes, config)
        if appended:
            return appended.value()
        var pending = self._check_request_complete(config)
        if pending:
            return pending.value()

        var req: Request
        var close_after: Bool
        try:
            if config.skip_header_decode_for_short_requests:
                req = _parse_http_request_bytes_minimal(
                    Span[UInt8, _](self.read_buf)[: self.body_total],
                    self.headers_end,
                    self.content_length,
                    config.max_body_size,
                    config.max_uri_length,
                    self.peer,
                    config.expose_error_messages,
                )
                close_after = _wants_close(self.read_buf, self.headers_end)
            else:
                req = _parse_http_request_bytes(
                    Span[UInt8, _](self.read_buf)[: self.body_total],
                    config.max_header_size,
                    config.max_body_size,
                    config.max_uri_length,
                    self.peer,
                    config.expose_error_messages,
                )
                close_after = _compute_close_after(req.headers, req.version)
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        var final_close = self._apply_keepalive_policy(config, close_after)
        var resp: Response
        try:
            resp = handler.serve(req^)
        except:
            self._queue_error(500, "Internal Server Error")
            return self._transition_to_writing()
        return self._finalise_response(resp^, final_close)

    def on_readable_cancel[
        CH: CancelHandler
    ](mut self, ref handler: CH, config: ServerConfig,) raises -> StepResult:
        """Cancel-aware variant of ``on_readable``.

        Identical to ``on_readable`` except the per-connection
        ``CancelCell`` is reset to ``NONE`` at the top of each
        request, flipped to ``PEER_CLOSED`` on ``recv == 0``
        observed before the handler runs, and a ``Cancel`` handle
        bound to the cell is passed to ``CH.serve(req, cancel)``.
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

        var drained = self._drain_recv[flips_cancel_on_close=True](config)
        if drained:
            return drained.value()
        var pending = self._check_request_complete(
            config, body_timeout_ms=config.read_body_timeout_ms
        )
        if pending:
            return pending.value()

        # Use the view-based parser then materialise an owned
        # ``Request`` so the existing ``Handler.serve(req: Request)``
        # shape still applies. Per-header String allocation is
        # eliminated during parse -- headers stay as offsets into
        # the shared buffer until ``into_owned`` copies them out.
        from flare.http.request_view import parse_request_view

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
        var final_close = self._apply_keepalive_policy(config, close_after)
        var resp: Response
        try:
            # Hand the handler a cancel handle bound to this
            # connection's cancel cell. The cell outlives the handler
            # call (it's owned by ``self``).
            resp = handler.serve(req^, self.cancel_cell.handle())
        except:
            self._queue_error(500, "Internal Server Error")
            return self._transition_to_writing()
        return self._finalise_response(resp^, final_close)

    def on_readable_view[
        VH: ViewHandler
    ](mut self, ref handler: VH, config: ServerConfig) raises -> StepResult:
        """View-aware variant of ``on_readable_cancel``.

        Same control flow as ``on_readable_cancel`` but dispatches
        the parsed ``RequestView`` directly into
        ``VH.serve_view(view, cancel)`` -- the body slice borrows
        from ``self.read_buf`` and the handler reads it without
        a copy. The owned ``Request`` materialisation that the
        ``Handler.serve`` requires is skipped entirely.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        self.cancel_cell.reset()

        var drained = self._drain_recv[flips_cancel_on_close=True](config)
        if drained:
            return drained.value()
        var pending = self._check_request_complete(
            config, body_timeout_ms=config.read_body_timeout_ms
        )
        if pending:
            return pending.value()

        from flare.http.request_view import parse_request_view
        from flare.http.server import _ascii_lower

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

            # Connection-disposition from the borrowed header view --
            # no allocation, just an offsets-based lookup.
            var hv = view.headers()
            var conn_hdr = _ascii_lower(String(hv.get("connection")))
            var is_http10 = view.version == "HTTP/1.0"
            var close_after = False
            if conn_hdr == "close":
                close_after = True
            elif is_http10 and conn_hdr != "keep-alive":
                close_after = True

            var _final_close = self._apply_keepalive_policy(config, close_after)

            try:
                resp = handler.serve_view(view, self.cancel_cell.handle())
            except:
                self._queue_error(500, "Internal Server Error")
                return self._transition_to_writing()
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        var keepalive = not self.should_close
        return self._finalise_response(resp^, not keepalive)

    def on_readable_static(
        mut self, resp: StaticResponse, config: ServerConfig
    ) raises -> StepResult:
        """Static-response variant of ``on_readable``.

        Reads as much as the non-blocking socket makes available per
        call, scans for the end-of-headers marker, discards the
        declared body bytes (if any), and queues the pre-encoded
        ``StaticResponse`` bytes into ``write_buf``. The parser never
        constructs a ``Request``; no handler is called.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        var drained = self._drain_recv[flips_cancel_on_close=False](config)
        if drained:
            return drained.value()
        var pending = self._check_request_complete(config)
        if pending:
            return pending.value()

        # Inspect Connection header + HTTP/1.0 semantics on the raw
        # header bytes without building a Request object. Cheap scan
        # over the header region only.
        var close_after = _wants_close(self.read_buf, self.headers_end)
        var final_close = self._apply_keepalive_policy(config, close_after)

        if self.body_total > 0 and self.body_total <= len(self.read_buf):
            _compact_read_buf_drop_prefix(self.read_buf, self.body_total)
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1

        self._serialize_static(resp, not final_close)
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

        # h2c upgrade migration cue: the 101 Switching Protocols response
        # has just flushed. Tell the unified reactor to swap the conn-dict
        # entry from KIND_H1 to KIND_H2.
        if self._h2c_upgrade_pending:
            return StepResult(
                want_read=False,
                want_write=False,
                done=False,
                idle_timeout_ms=0,
                h2c_upgrade=True,
            )

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

    def take_h2c_upgrade_request(mut self) raises -> Request:
        """Move the saved h2c upgrade ``Request`` out of this handle.

        Companion to :meth:`take_h2c_upgrade_settings`; callers
        invoke both to extract the migration payload before freeing
        the h1 handle. Setting the in-flight flag to ``False`` here
        is deferred to :meth:`take_h2c_upgrade_settings` so a partial
        take doesn't silently leave the settings buffer behind.
        """
        if not self._h2c_upgrade_pending:
            raise Error("take_h2c_upgrade_request: not pending")
        if not self._h2c_upgrade_request:
            raise Error("take_h2c_upgrade_request: payload missing")
        return self._h2c_upgrade_request.take()

    def take_h2c_upgrade_settings(mut self) -> List[UInt8]:
        """Move the saved decoded ``HTTP2-Settings`` payload out
        of this handle. Resets the in-flight flag so a subsequent
        migration attempt raises rather than silently re-using the
        same buffer.
        """
        var settings = self._h2c_upgrade_settings^
        self._h2c_upgrade_settings = List[UInt8]()
        self._h2c_upgrade_pending = False
        return settings^

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

    def _h2c_upgrade_decode_settings(
        self, headers: HeaderMap
    ) raises -> Optional[List[UInt8]]:
        """Inspect a parsed h1 request's headers and return the decoded
        ``HTTP2-Settings`` payload iff this is a valid h2c upgrade.

        Returns ``None`` when:

        * The request lacks ``Upgrade: h2c`` + ``HTTP2-Settings``.
        * The ``HTTP2-Settings`` value isn't valid base64url.
        * The decoded payload's length isn't a multiple of 6 (an
          ill-formed SETTINGS body per RFC 7540 §3.2.1).
        """
        if not _detect_h2c_upgrade_inline(headers):
            return Optional[List[UInt8]]()
        var s = headers.get("http2-settings")
        if s.byte_length() == 0:
            return Optional[List[UInt8]]()
        var decoded: List[UInt8]
        try:
            decoded = base64url_decode(s)
        except:
            return Optional[List[UInt8]]()
        if (len(decoded) % 6) != 0:
            return Optional[List[UInt8]]()
        return Optional[List[UInt8]](decoded^)

    def _start_h2c_upgrade(
        mut self, var req: Request, var settings_payload: List[UInt8]
    ) -> None:
        """Save the migration payload + queue the ``101 Switching Protocols``
        response. Caller must have already verified the upgrade is valid via
        :meth:`_h2c_upgrade_decode_settings`."""
        self._h2c_upgrade_settings = settings_payload^
        self._h2c_upgrade_request = Optional[Request](req^)
        self._h2c_upgrade_pending = True
        queue_h2c_upgrade_101(self.write_buf)
        self.write_pos = 0

    def _queue_error(mut self, status: Int, reason: String) -> None:
        """Build a minimal error response into ``write_buf`` and mark close."""
        self.should_close = True
        var resp = build_error_response(status, reason)
        self._serialize_response(resp^, False)

    def _serialize_static(
        mut self, resp: StaticResponse, keep_alive: Bool
    ) -> None:
        """Queue a pre-encoded static response into ``write_buf``."""
        serialize_static_into(self.write_buf, self.write_pos, resp, keep_alive)
        self.write_pos = 0

    def _serialize_response(mut self, resp: Response, keep_alive: Bool) -> None:
        """Serialise ``resp`` into ``write_buf`` ready to be sent."""
        serialize_response_into(
            self.write_buf, self._date_cache, resp, keep_alive
        )
        self.write_pos = 0
