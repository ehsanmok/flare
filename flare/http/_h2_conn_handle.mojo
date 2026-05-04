"""Per-connection state machine for HTTP/2 inside the reactor.

Symmetric counterpart to :class:`flare.http._server_reactor_impl.ConnHandle`
for HTTP/2: owns one accepted ``TcpStream``, drives a
:class:`flare.http2.server.H2Connection` over non-blocking
``recv`` / ``send`` syscalls, dispatches every completed stream's
request through the user's :class:`flare.http.Handler`, and queues
the response frames back through the same socket. The state-machine
shape (``on_readable`` / ``on_writable`` returning a
:class:`StepResult`) is byte-for-byte identical to the HTTP/1.1
``ConnHandle`` so the unified
:class:`flare.http.server.HttpServer` reactor loop dispatches both
connection types via a single ``StepResult`` translator
(``_apply_step``).

State transitions (mirror ConnHandle):

::

    STATE_READING  -- response queued -->  STATE_WRITING
    STATE_WRITING  -- write_buf flushed --> STATE_READING (h2 multiplexes)
    STATE_READING  / STATE_WRITING -- peer FIN / error --> STATE_CLOSING

Unlike HTTP/1.1, h2 connections are persistent and multiplex many
streams concurrently: ``on_readable`` may dispatch multiple
``handler.serve(req)`` calls per event (one per ``stream id``
that finished within the inbound bytes) and the connection stays
open after the response flushes. Only an explicit ``GOAWAY`` or a
peer FIN moves to ``STATE_CLOSING``.

The constructor pre-loads the H2 server's initial SETTINGS frame
into ``write_buf`` so the very first ``on_writable`` after the
client preface arrives flushes both the SETTINGS and the
SETTINGS-ACK in one syscall.
"""

from std.builtin.debug_assert import debug_assert
from std.collections import Dict
from std.ffi import c_int, c_size_t, ErrNo, get_errno
from std.memory import UnsafePointer, stack_allocation

from flare.http.cancel import Cancel, CancelCell, CancelReason
from flare.http.handler import Handler
from flare.http.headers import HeaderMap
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ServerConfig
from flare.http2.server import H2Connection, Http2Config
from flare.net import IpAddr, SocketAddr
from flare.net._libc import _recv, _send, MSG_NOSIGNAL
from flare.runtime import Pool
from flare.tcp import TcpStream

from ._server_reactor_impl import (
    StepResult,
    STATE_READING,
    STATE_WRITING,
    STATE_CLOSING,
)


# ── H2ConnHandle ────────────────────────────────────────────────────────────


struct H2ConnHandle(Movable):
    """State + buffers for a single reactor-managed HTTP/2 connection.

    Owns an accepted ``TcpStream`` (closes the fd on destruction)
    and an :class:`H2Connection` driver (the same byte-level
    feed/drain machine the standalone server uses, just driven
    from the reactor instead of a blocking socket loop).
    """

    var _stream: TcpStream
    """Underlying TCP stream; this struct is the sole owner."""

    var peer: SocketAddr
    """Kernel-reported peer address captured at accept time. Threaded
    into every parsed :class:`flare.http.Request` so handlers can
    read ``req.peer`` regardless of the wire protocol."""

    var cancel_cell: CancelCell
    """Per-connection cancel cell, present for parity with
    :class:`flare.http._server_reactor_impl.ConnHandle`. Wired into
    each per-stream ``handler.serve`` call once the unified
    server's :class:`flare.http.cancel.CancelHandler` plumbing for
    h2 streams lands; for now it stays zero-initialised so the
    presence of the field doesn't break the reactor loop's
    cleanup paths."""

    var state: Int
    """One of :data:`STATE_READING` / :data:`STATE_WRITING` /
    :data:`STATE_CLOSING`. Same constants the HTTP/1.1
    ``ConnHandle`` uses."""

    var h2: H2Connection
    """The byte-level HTTP/2 driver. The connection preface +
    initial SETTINGS the *client* sent get pushed into this via
    :meth:`feed`; queued outbound bytes get pulled via
    :meth:`drain` and shovelled into ``write_buf`` for the
    reactor's ``send`` syscall."""

    var write_buf: List[UInt8]
    """Outbound bytes ready to be sent (response HEADERS/DATA
    frames + auto-acks like SETTINGS_ACK / PING_ACK /
    WINDOW_UPDATE). Populated by ``on_readable`` after each
    feed/dispatch round."""

    var write_pos: Int
    """Number of bytes of :attr:`write_buf` already sent."""

    var should_close: Bool
    """True once we've decided this connection must close after the
    last queued bytes flush (peer GOAWAY received, or graceful
    shutdown)."""

    var idle_timer_id: UInt64
    """ID of the currently-armed idle timer, 0 if none. The
    reactor loop manages the actual TimerWheel entry."""

    var last_interest: Int
    """Last reactor interest bits for this conn. Used to skip
    redundant ``reactor.modify`` syscalls when the wanted
    interest hasn't actually changed since the previous event."""

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def __init__(
        out self, var stream: TcpStream, var config: Http2Config
    ) raises:
        """Construct an H2ConnHandle that owns ``stream``.

        Args:
            stream: Accepted ``TcpStream`` (non-blocking mode must
                already be set by the caller). Ownership transfers
                into the handle.
            config: HTTP/2 SETTINGS the server advertises to the
                peer. Validated by ``H2Connection.with_config``.
        """
        # Snapshot the peer address before moving the stream.
        self.peer = stream.peer_addr()
        self._stream = stream^
        self.cancel_cell = CancelCell()
        self.state = STATE_READING
        self.h2 = H2Connection.with_config(config^)
        self.write_buf = List[UInt8]()
        self.write_pos = 0
        self.should_close = False
        self.idle_timer_id = UInt64(0)
        self.last_interest = 1  # INTEREST_READ

    @always_inline
    def fd(self) -> c_int:
        """Return the underlying fd (fast accessor)."""
        return self._stream._socket.fd

    # ── Pre-buffered preface bytes (for the unified server's peek path)

    def push_initial_bytes(mut self, bytes: Span[UInt8, _]) raises:
        """Replay bytes already read from the socket into the H2 driver.

        The unified :class:`flare.http.server.HttpServer` peeks the
        first 24 bytes on a fresh connection to detect the H2
        preface (``"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"``).
        Once we decide it's HTTP/2 those bytes have already been
        consumed from the socket; this helper feeds them into the
        H2 driver before the reactor's first ``on_readable`` call
        so the connection preface is recognised and the server's
        initial SETTINGS frame is pre-queued in ``write_buf``.
        """
        self.h2.feed(bytes)
        var ack = self.h2.drain()
        if len(ack) > 0:
            for i in range(len(ack)):
                self.write_buf.append(ack[i])

    # ── Event handlers ────────────────────────────────────────────────────────

    def on_readable[
        H: Handler
    ](mut self, ref handler: H, config: ServerConfig) raises -> StepResult:
        """Drive the state machine on a readable event.

        Drains the socket non-blockingly, feeds bytes into the H2
        driver, dispatches every newly-completed stream's request
        through ``handler.serve`` and queues the encoded response
        frames into ``write_buf``. Returns a :class:`StepResult`
        that flips the reactor to ``INTEREST_WRITE`` if there's
        outbound data ready, or stays on ``INTEREST_READ`` to wait
        for more frames.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )
        # FFI precondition: the recv loop assumes a real fd. If it
        # underflows we'd silently swallow EBADF on every iteration
        # and burn a CPU; the assert documents the contract.
        debug_assert[assert_mode="safe"](
            Int(self.fd()) >= 0,
            "H2ConnHandle.on_readable: fd must be non-negative; got ",
            Int(self.fd()),
        )
        var chunk = stack_allocation[8192, UInt8]()
        var inbound = List[UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                var got_int = Int(got)
                debug_assert[assert_mode="safe"](
                    got_int <= 8192,
                    "H2ConnHandle._recv: returned > buf size; got ",
                    got_int,
                )
                for i in range(got_int):
                    inbound.append(chunk[i])
            elif got == 0:
                # Peer FIN observed mid-connection. Mark closed
                # so the reactor unregisters the fd after any
                # remaining write_buf flushes.
                self.should_close = True
                return StepResult(
                    want_read=False,
                    want_write=len(self.write_buf) > self.write_pos,
                    done=len(self.write_buf) == self.write_pos,
                )
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                # Hard read error -- close.
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
        # Push everything we just read into the h2 driver. ``feed``
        # auto-handles the connection preface (24 bytes) the first
        # time it's called and queues a SETTINGS_ACK / PING_ACK /
        # WINDOW_UPDATE / SETTINGS reply via the same outbox we
        # drain below.
        if len(inbound) > 0:
            self.h2.feed(Span[UInt8, _](inbound))
        # Dispatch any newly-completed streams.
        var ids = self.h2.take_completed_streams()
        for i in range(len(ids)):
            var sid = ids[i]
            var req = self.h2.take_request(sid)
            req.peer = self.peer
            var resp: Response
            try:
                resp = handler.serve(req^)
            except:
                resp = Response(status=500, reason="Internal Server Error")
            try:
                self.h2.emit_response(sid, resp^)
            except:
                # If response framing fails (shouldn't happen),
                # tear the connection down rather than silently
                # losing the stream.
                self.should_close = True
        # Drain everything the driver wants to send.
        var out = self.h2.drain()
        if len(out) > 0:
            for i in range(len(out)):
                self.write_buf.append(out[i])
        if self.h2.conn.goaway_received:
            self.should_close = True
        # Decide reactor interest: write if there are bytes to
        # flush, otherwise stay on read for the next frame.
        var has_outbound = len(self.write_buf) > self.write_pos
        if has_outbound:
            self.state = STATE_WRITING
            return StepResult(
                want_read=False,
                want_write=True,
                idle_timeout_ms=config.write_timeout_ms,
            )
        return StepResult(
            want_read=True,
            want_write=False,
            idle_timeout_ms=config.idle_timeout_ms,
        )

    def on_writable(mut self, config: ServerConfig) raises -> StepResult:
        """Drive the state machine on a writable event.

        Pumps as much of :attr:`write_buf` as the kernel accepts.
        When the buffer is fully flushed, transitions back to
        ``STATE_READING`` (HTTP/2 multiplexes -- the connection
        stays open across many request/response pairs) unless
        :attr:`should_close` is set, in which case the connection
        is finished.
        """
        if self.state != STATE_WRITING:
            return StepResult(
                want_read=self.state == STATE_READING, want_write=False
            )
        debug_assert[assert_mode="safe"](
            Int(self.fd()) >= 0,
            "H2ConnHandle.on_writable: fd must be non-negative; got ",
            Int(self.fd()),
        )
        debug_assert[assert_mode="safe"](
            self.write_pos >= 0 and self.write_pos <= len(self.write_buf),
            "H2ConnHandle.on_writable: write_pos out of range; got ",
            self.write_pos,
        )
        while self.write_pos < len(self.write_buf):
            var remaining = len(self.write_buf) - self.write_pos
            var ptr = self.write_buf.unsafe_ptr() + self.write_pos
            debug_assert[assert_mode="safe"](
                remaining > 0 and Int(ptr) != 0,
                "H2ConnHandle._send: buf must be non-NULL when remaining > 0",
            )
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
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
        if self.write_pos < len(self.write_buf):
            # Partial write -- come back when the kernel has more
            # space. Re-arm the write idle timer so a slow client
            # doesn't keep us pinned indefinitely.
            return StepResult(
                want_read=False,
                want_write=True,
                idle_timeout_ms=config.write_timeout_ms,
            )
        # write_buf fully drained; reset for the next response.
        self.write_buf.clear()
        self.write_pos = 0
        if self.should_close:
            return StepResult(want_read=False, want_write=False, done=True)
        # h2 stays open across many requests; back to reading.
        self.state = STATE_READING
        return StepResult(
            want_read=True,
            want_write=False,
            idle_timeout_ms=config.idle_timeout_ms,
        )


# ── Pool helpers (mirror _server_reactor_impl.mojo's ConnHandle pool) ────


def _h2_conn_alloc_addr(
    var stream: TcpStream, var config: Http2Config
) raises -> Int:
    """Heap-allocate an :class:`H2ConnHandle` and return its address.

    Routes through ``Pool[H2ConnHandle]`` so all unsafe-pointer
    plumbing stays in :mod:`flare.runtime.pool`. Symmetric with
    :func:`flare.http._server_reactor_impl._conn_alloc_addr`.
    """
    var addr = Pool[H2ConnHandle].alloc_move(H2ConnHandle(stream^, config^))
    debug_assert[assert_mode="safe"](
        addr != 0,
        "_h2_conn_alloc_addr: Pool returned 0",
    )
    return addr


def _h2_conn_free_addr(addr: Int):
    """Destroy + free an :class:`H2ConnHandle` previously allocated
    via :func:`_h2_conn_alloc_addr`."""
    debug_assert[assert_mode="safe"](
        addr != 0,
        "_h2_conn_free_addr: addr must be non-zero (double-free?)",
    )
    Pool[H2ConnHandle].free(addr)


def _h2_conn_ptr_from_int(
    addr: Int,
) -> UnsafePointer[H2ConnHandle, MutExternalOrigin]:
    """Reverse of :func:`_h2_conn_alloc_addr`: typed pointer from an Int."""
    debug_assert[assert_mode="safe"](
        addr != 0,
        "_h2_conn_ptr_from_int: cannot reconstruct from null addr",
    )
    return UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=addr
    ).bitcast[H2ConnHandle]()


# ── Protocol-detection (preface peek) ──────────────────────────────────────


comptime _H2_PREFACE_BYTES_LEN: Int = 24
"""Length in bytes of the RFC 9113 §3.4 ``PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n``
client connection preface."""


comptime PROTO_NEED_MORE: Int = 0
"""Decision sentinel: PendingConnHandle hasn't seen enough bytes yet."""

comptime PROTO_HTTP1: Int = 1
"""Decision sentinel: the first bytes don't match the H2 preface
prefix; this connection is HTTP/1.1 (or h2c via Upgrade, which the
HTTP/1.1 ConnHandle handles via the existing
``detect_h2c_upgrade`` helper)."""

comptime PROTO_HTTP2: Int = 2
"""Decision sentinel: the first 24 bytes match the H2 preface
exactly; this connection is HTTP/2 via prior knowledge."""


def _h2_preface_byte(i: Int) -> UInt8:
    """Return the i-th byte of the H2 client connection preface
    (``"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"``)."""
    var s = String("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    return s.unsafe_ptr()[i]


struct PendingConnHandle(Movable):
    """Per-connection state for an accepted socket whose protocol has
    not yet been determined.

    Buffers up to 24 bytes from the socket non-blockingly until it
    can decide whether the peer is speaking HTTP/1.1 (any byte
    sequence that doesn't prefix-match the H2 preface) or HTTP/2
    via prior knowledge (full 24-byte preface match per RFC 9113
    §3.4). The buffered bytes are NEVER discarded -- they're
    handed to the chosen :class:`flare.http._server_reactor_impl.ConnHandle`
    or :class:`H2ConnHandle` via the move-out helper so the
    chosen state machine sees a contiguous byte stream.

    The ``on_readable`` step returns one of :data:`PROTO_NEED_MORE`,
    :data:`PROTO_HTTP1`, or :data:`PROTO_HTTP2`. The unified
    reactor loop swaps the dict entry for the chosen handle on
    decision and continues driving the new handle on the next
    event.
    """

    var _stream: TcpStream
    """Underlying TCP stream; this struct owns the fd until the
    decision is taken via :meth:`take_stream_and_buf`."""

    var peer: SocketAddr
    """Peer address snapshotted at accept time, threaded onto the
    chosen :class:`ConnHandle` / :class:`H2ConnHandle` so handlers
    keep their existing ``req.peer`` semantics."""

    var preface_buf: List[UInt8]
    """Bytes read so far while waiting for a protocol decision.
    Maximum :data:`_H2_PREFACE_BYTES_LEN` long."""

    var idle_timer_id: UInt64
    """ID of the currently-armed idle timer, 0 if none."""

    var last_interest: Int
    """Last reactor interest bits for this conn."""

    def __init__(out self, var stream: TcpStream) raises:
        self.peer = stream.peer_addr()
        self._stream = stream^
        self.preface_buf = List[UInt8](capacity=_H2_PREFACE_BYTES_LEN)
        self.idle_timer_id = UInt64(0)
        self.last_interest = 1  # INTEREST_READ

    @always_inline
    def fd(self) -> c_int:
        """Return the underlying fd (fast accessor)."""
        return self._stream._socket.fd

    def on_readable(mut self) raises -> Int:
        """Pull more bytes off the socket and return one of
        :data:`PROTO_NEED_MORE` / :data:`PROTO_HTTP1` / :data:`PROTO_HTTP2`.

        Reads non-blockingly. The buffer keeps EVERY byte read
        (not just the preface-prefix ones) so :meth:`take_stream_and_buf`
        hands the whole prefix to the chosen per-conn handle --
        otherwise an HTTP/1.1 request whose first byte fails the
        preface check would have its remaining bytes (already
        delivered by ``recv`` in the same syscall) dropped on the
        floor and the parser would see a truncated request line.
        """
        # FFI precondition: the preface peek requires a real fd.
        debug_assert[assert_mode="safe"](
            Int(self.fd()) >= 0,
            "PendingConnHandle.on_readable: fd must be non-negative; got ",
            Int(self.fd()),
        )
        # Invariant: preface_buf never exceeds _H2_PREFACE_BYTES_LEN
        # because we cap ``want`` and the loop exits at equality.
        debug_assert[assert_mode="safe"](
            len(self.preface_buf) <= _H2_PREFACE_BYTES_LEN,
            "PendingConnHandle: preface_buf overflow; got ",
            len(self.preface_buf),
        )
        # Read up to 24 bytes total. We always store ALL bytes
        # ``recv`` returns; the preface-prefix check only decides
        # WHETHER to keep reading (preface match) or stop early
        # (mismatch -> HTTP/1.1). The chosen per-conn handle
        # consumes the same bytes via :meth:`take_stream_and_buf`.
        var chunk = stack_allocation[_H2_PREFACE_BYTES_LEN, UInt8]()
        var decision_known: Bool = False
        var decision: Int = PROTO_HTTP1
        while len(self.preface_buf) < _H2_PREFACE_BYTES_LEN:
            var want = _H2_PREFACE_BYTES_LEN - len(self.preface_buf)
            debug_assert[assert_mode="safe"](
                want > 0 and want <= _H2_PREFACE_BYTES_LEN,
                "PendingConnHandle: want out of range; got ",
                want,
            )
            var got = _recv(self.fd(), chunk, c_size_t(want), c_int(0))
            if got > 0:
                var got_int = Int(got)
                debug_assert[assert_mode="safe"](
                    got_int <= want,
                    "PendingConnHandle._recv: returned > want; got ",
                    got_int,
                )
                for i in range(got_int):
                    var b = chunk[i]
                    var pos = len(self.preface_buf)
                    debug_assert[assert_mode="safe"](
                        pos >= 0 and pos < _H2_PREFACE_BYTES_LEN,
                        "PendingConnHandle: preface_byte index OOR; got ",
                        pos,
                    )
                    self.preface_buf.append(b)
                    if (not decision_known) and b != _h2_preface_byte(pos):
                        decision_known = True
                        decision = PROTO_HTTP1
                if decision_known:
                    return decision
            elif got == 0:
                # Peer FIN before we could decide; treat as h1
                # so the existing graceful-close path tears it
                # down.
                return PROTO_HTTP1
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    if decision_known:
                        return decision
                    return PROTO_NEED_MORE
                # Hard error -> treat as h1 so cleanup runs.
                return PROTO_HTTP1
        # All 24 bytes accumulated and none triggered an early
        # mismatch -> the prefix matches the preface exactly ->
        # this is HTTP/2.
        return PROTO_HTTP2

    def take_stream_and_buf(
        mut self,
    ) -> List[UInt8]:
        """Move the buffered preface bytes out of the handle.

        The :attr:`_stream` is moved separately by the caller via a
        regular field move (`var s = handle._stream^`) since Mojo
        tuple returns are clunky for non-Movable mixes. The caller
        is responsible for freeing the empty handle via
        :func:`_pending_conn_free_addr` after taking ownership of
        both fields.
        """
        var out = self.preface_buf^
        self.preface_buf = List[UInt8]()
        return out^


def _pending_conn_alloc_addr(var stream: TcpStream) raises -> Int:
    """Heap-allocate a :class:`PendingConnHandle` and return its address."""
    var addr = Pool[PendingConnHandle].alloc_move(PendingConnHandle(stream^))
    debug_assert[assert_mode="safe"](
        addr != 0,
        "_pending_conn_alloc_addr: Pool returned 0",
    )
    return addr


def _pending_conn_free_addr(addr: Int):
    """Destroy + free a :class:`PendingConnHandle`."""
    debug_assert[assert_mode="safe"](
        addr != 0,
        "_pending_conn_free_addr: addr must be non-zero (double-free?)",
    )
    Pool[PendingConnHandle].free(addr)


def _pending_conn_ptr_from_int(
    addr: Int,
) -> UnsafePointer[PendingConnHandle, MutExternalOrigin]:
    """Reverse of :func:`_pending_conn_alloc_addr`."""
    debug_assert[assert_mode="safe"](
        addr != 0,
        "_pending_conn_ptr_from_int: cannot reconstruct from null addr",
    )
    return UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=addr
    ).bitcast[PendingConnHandle]()
