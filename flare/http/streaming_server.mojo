"""Typed streaming-handler surface.

A custom multiplexing / streaming front -- the shape a streaming
proxy needs -- used to drop to the raw reactor and smuggle every live
object (the reactor, the streams, the buffers) as an ``Int`` address,
rebuilding it with ``UnsafePointer(unsafe_from_address=...)``, plus
hand-rolled ``alloc`` per-slot tables and a free list. This module
removes that: the framework owns the connection lifecycle and the
reactor; the handler is a typed struct whose fields are its shared
state and which receives a framework-owned ``StreamConn`` per event.

Pieces:

- ``StreamHandler`` -- the lifecycle trait (``on_open`` / ``on_upstream``
  / ``on_writable`` / ``on_close``). Every method takes ``mut self``
  (the typed shared state, one instance shared across all connections)
  and a ``mut`` ref to the framework-owned ``StreamConn``. No raw
  token, no address-as-``Int``.
- ``StreamConn`` -- the framework-owned per-connection handle. Owns the
  client ``TcpStream``, a per-connection ``Cancel`` cell, a stable
  per-connection id, the close flag, and a single owned outbound write
  buffer (``send`` queues; ``flush_blocking`` / ``drain_nonblocking``
  empty it). No per-slot ``alloc`` table, no free list.
- ``run_stream_connection`` -- a blocking single-connection driver that
  walks one connection through the lifecycle. The reactor-integrated
  multi-connection entry point (``HttpServer.serve_streaming``, in
  ``_stream_reactor_impl``) builds on the same trait and the same
  ``StreamConn``; this driver is the testable single-connection core
  and is itself useful for one-connection UDS sidecars.

Typed-state model
-----------------

Mojo (1.0.0b2) has neither parameterized traits nor associated types,
so a single ``StreamHandler`` cannot carry a per-handler "state type
S" or "per-connection type U" in its method signatures and still let
the method *body* read those typed fields. The model that is both
typed and usable:

- **Shared state** is the handler struct's own fields. The framework
  holds one handler instance and calls it (via ``mut self``) for every
  connection and every event, so the fields are shared, mutable, and
  fully typed -- this is the shared ``ServeState`` (e.g. a persistent
  ``FrameMux``) reached as a typed ref rather than an ``Int`` address.
- **Per-connection state** for the common single-upstream relay is
  framework-owned: ``conn.attach_upstream(source)`` moves an
  ``UpstreamChunkSource`` into the ``StreamConn``, the framework pumps
  it (``relay_upstream``), and teardown closes it. The relay front then
  has *no* per-connection container at all and touches no file
  descriptor or byte ``Span``.
- **Richer per-connection state** (fan-in, several upstreams, custom
  bookkeeping) is still keyed by ``conn.id()`` in a typed container the
  handler declares once (e.g. ``Dict[Int, MyConnState]``). The
  framework assigns the id and signals ``on_open`` / ``on_close`` so
  the handler inserts / removes its entry -- no ``alloc``, no manual
  free list, lifecycle framework-owned.

Together this removes the need for a hand-rolled context of ``Int``
addresses and the ``alloc[...](max_slots)`` slot tables + free stack a
raw-reactor front would otherwise carry.
"""

from std.collections import Optional
from std.ffi import c_int, c_size_t, get_errno, ErrNo
from std.memory import memcpy

from .async_body import ChunkPoll, UpstreamChunkSource
from .cancel import Cancel, CancelCell, CancelReason
from flare.net import NetworkError
from flare.net._libc import _recv, _send, _strerror, MSG_NOSIGNAL
from flare.tcp import TcpStream


comptime DEFAULT_HI_WATERMARK: Int = 256 * 1024
"""Default high watermark for the per-connection relay buffer. When
unwritten outbound bytes reach this, the reactor drops read interest on
the attached upstream fd so a slow client cannot force unbounded token
buffering. ponytail: a fixed 256 KiB ceiling -- one in-flight relay
window; tune per-connection with ``set_watermarks`` if a front needs a
deeper or shallower pipe."""

comptime DEFAULT_LO_WATERMARK: Int = 64 * 1024
"""Default low watermark. Once the relay buffer drains back to this, the
reactor re-arms upstream read interest. The hi/lo gap is the hysteresis
band that stops interest from thrashing on every chunk."""


# ── StreamConn ─────────────────────────────────────────────────────────────


struct StreamConn(Movable):
    """Framework-owned per-connection handle.

    Owns the accepted client stream and a per-connection cancel cell,
    carries a stable per-connection id (for the handler to key its own
    typed per-connection state), and the close flag the handler trips
    when it is done with the connection. The ``client`` stream is owned
    here (sole owner) and closed when the handle is dropped -- the same
    ownership rule the reactor's ``ConnHandle`` follows.

    For the common streaming-proxy shape it also owns one optional
    ``UpstreamChunkSource``: ``attach_upstream(source)`` moves the source
    in, ``relay_upstream`` drains it, and teardown closes it -- so a
    relay front carries no per-connection table and never names a file
    descriptor or a byte ``Span``.
    """

    var client: TcpStream
    """The accepted client connection. Sole owner; closed on drop."""
    var _id: Int
    """Stable per-connection id assigned by the framework. The handler
    keys its typed per-connection state on this value."""
    var _cancel_cell: CancelCell
    """Per-connection cancel cell. ``cancel()`` hands out a ``Cancel``
    bound to it; the driver / reactor flips it on peer FIN / deadline /
    drain."""
    var _close_requested: Bool
    """Set by the front via ``request_close()`` once it has finished
    with the connection; the driver / reactor tears the connection down
    after the current step returns."""
    var out_buf: List[UInt8]
    """Pending outbound bytes. ``send`` appends here; the blocking
    driver flushes with ``flush_blocking`` and the reactor drains
    incrementally with ``drain_nonblocking`` on writable edges. This is
    the single owned write buffer (no per-slot ``alloc`` table)."""
    var out_pos: Int
    """Bytes of ``out_buf`` already written to the socket. The unwritten
    tail is ``out_buf[out_pos:]``; ``out_pos == len(out_buf)`` means
    fully drained."""
    var _upstream_fd: Int
    """Upstream fd the front wants the reactor to watch, or ``-1`` for
    none. Set by ``attach_upstream`` / cleared by ``detach_upstream``;
    the reactor reconciles it into the epoll set and fires
    ``on_upstream`` when the fd is readable. The front owns the
    upstream's lifetime (open/close); the framework only watches it."""
    var _reg_upstream_fd: Int
    """Reactor bookkeeping: the upstream fd currently registered (or
    ``-1``). Lets the reactor diff desired vs registered without a
    reverse lookup. Framework-internal; fronts never touch it."""
    var _hi_watermark: Int
    """Relay-buffer high watermark: at this occupancy upstream read
    interest is dropped. Defaults to ``DEFAULT_HI_WATERMARK``."""
    var _lo_watermark: Int
    """Relay-buffer low watermark: below this, upstream read interest
    is re-armed. Defaults to ``DEFAULT_LO_WATERMARK``."""
    var _upstream_paused: Bool
    """Backpressure state: True while upstream reads are gated off because the
    client write buffer is above the high watermark. Hysteresis: cleared
    only when occupancy falls to the low watermark."""
    var _reg_upstream_interest: Int
    """Reactor bookkeeping: interest bits currently registered for the
    upstream fd (``-1`` unknown). Lets the reactor skip redundant
    ``modify`` calls when the watermark state is unchanged."""
    var _pause_count: Int
    """Number of high-watermark crossings (upstream paused). Observable
    for backpressure tests; cheap counter otherwise."""
    var _resume_count: Int
    """Number of low-watermark crossings (upstream resumed)."""
    var _inbound_enabled: Bool
    """Inbound opt-in: when True the front consumes the inbound request body
    itself via ``read_body`` and the reactor stops draining-and-discarding
    client bytes for FIN detection (which would otherwise steal the
    body). Default False -- existing fronts are unchanged."""
    var _write_syscalls: Int
    """Count of ``send(2)`` calls issued by ``drain_nonblocking`` /
    ``flush_blocking``. A burst of K chunks queued via ``send`` (each a
    memcpy into the single ``out_buf``) flushes in one syscall when the
    socket accepts it -- so this stays ~1 per drain regardless of K,
    removing the per-token syscall tax. Observable for the microbench."""
    var _upstream: Optional[UpstreamChunkSource]
    """Framework-owned upstream source, set by the source-taking
    ``attach_upstream`` overload. When present the framework owns its
    lifetime (closes it on teardown) and ``relay_upstream`` drains it --
    the front never touches a file descriptor or a per-connection table.
    Empty when the front manages its own upstream via the raw-fd overload."""

    def __init__(out self, var client: TcpStream, id: Int = 0) raises:
        """Adopt ``client`` into a fresh per-connection handle."""
        self.client = client^
        self._id = id
        self._cancel_cell = CancelCell()
        self._close_requested = False
        self.out_buf = List[UInt8]()
        self.out_pos = 0
        self._upstream_fd = -1
        self._reg_upstream_fd = -1
        self._hi_watermark = DEFAULT_HI_WATERMARK
        self._lo_watermark = DEFAULT_LO_WATERMARK
        self._upstream_paused = False
        self._reg_upstream_interest = -1
        self._pause_count = 0
        self._resume_count = 0
        self._inbound_enabled = False
        self._write_syscalls = 0
        self._upstream = None

    @always_inline
    def id(self) -> Int:
        """Stable per-connection id (key for handler-owned per-conn
        state)."""
        return self._id

    @always_inline
    def fd(self) -> c_int:
        """Underlying client fd. Fast accessor; does not check state."""
        return self.client._socket.fd

    @always_inline
    def cancel(mut self) -> Cancel:
        """Return a ``Cancel`` handle bound to this connection's cell."""
        return self._cancel_cell.handle()

    @always_inline
    def flip_cancel(mut self, reason: Int):
        """Flip the connection's cancel cell (framework-internal)."""
        self._cancel_cell.flip(reason)

    @always_inline
    def request_close(mut self):
        """Ask the framework to close this connection after the current
        lifecycle step returns."""
        self._close_requested = True

    @always_inline
    def is_closing(self) -> Bool:
        """True once ``request_close`` has been called."""
        return self._close_requested

    # ── Upstream attachment ────────────────────────────────────────

    def attach_upstream(mut self, var src: UpstreamChunkSource):
        """Attach an upstream source and let the framework run it.

        This is the recommended, low-ceremony path: hand the connection
        the source and the framework takes over -- it reads the fd to
        watch internally (no descriptors in front code), owns the
        source for the connection's lifetime (closing it on teardown),
        and ``relay_upstream`` drains it. The front never keeps a
        per-connection table, never names a file descriptor, and never
        remembers to close anything.

        ```mojo
        def on_open(mut self, mut conn: StreamConn) raises:
            conn.attach_upstream(UpstreamChunkSource.connect(self.backend))
        ```
        """
        self._upstream_fd = Int(src.fd())
        self._upstream = src^

    @always_inline
    def attach_upstream(mut self, fd: Int):
        """Low-level: ask the reactor to watch a raw ``fd`` (a
        front-owned upstream socket / pipe / eventfd) for readability.

        Prefer the ``attach_upstream(UpstreamChunkSource)`` overload --
        it hides the descriptor and the lifetime. Use this only for an
        upstream that is not an ``UpstreamChunkSource`` (a bare pipe, an
        eventfd). The front then owns ``fd``'s lifetime: it opened the
        upstream and must close it (typically by holding the stream in
        its own per-connection state and dropping it in ``on_close``).
        The framework only adds/removes ``fd`` from the event loop.
        """
        self._upstream_fd = fd

    @always_inline
    def detach_upstream(mut self):
        """Stop watching the attached upstream and drop any
        framework-owned source. The reactor unregisters the fd on the
        next reconcile."""
        self._upstream_fd = -1
        self._upstream = None

    @always_inline
    def has_upstream(self) -> Bool:
        """True if an upstream fd is currently attached."""
        return self._upstream_fd != -1

    @always_inline
    def has_attached_source(self) -> Bool:
        """True if a framework-owned ``UpstreamChunkSource`` is attached
        (via the source-taking ``attach_upstream``)."""
        return Bool(self._upstream)

    def upstream(mut self) -> ref[self._upstream] UpstreamChunkSource:
        """The framework-owned upstream source, for fronts that want to
        poll it directly instead of using ``relay_upstream``.

        Only valid when ``has_attached_source()``; call after attaching
        via ``attach_upstream(UpstreamChunkSource)``.
        """
        return self._upstream.value()

    @always_inline
    def _poll_upstream(mut self, cancel: Cancel) raises -> ChunkPoll:
        """Poll the framework-owned source once, isolating its mutable
        borrow so the caller can ``send`` in the same step without an
        aliasing conflict."""
        return self._upstream.value().poll(cancel)

    def relay_upstream(mut self) raises:
        """Drain the attached source into the client with backpressure.

        The standard ``on_upstream`` body, shipped once so every relay
        front does not re-derive it: pull ready chunks and ``send`` them
        until the client write buffer hits the high watermark (so a
        single readable edge cannot overshoot the bound -- the reactor
        re-arms upstream interest when the client drains), request close
        on EOF, and stop on pending (the reactor parks on the fd, no
        spin). No-op if no source is attached.

        ```mojo
        def on_upstream(mut self, mut conn: StreamConn) raises:
            conn.relay_upstream()
        ```
        """
        if not self._upstream:
            return
        var cancel = self.cancel()
        while not self.write_buffer_full():
            var p = self._poll_upstream(cancel)
            if p.is_ready():
                self.send(p.take_chunk())
            elif p.is_eof():
                self.request_close()
                break
            else:
                break

    def _maybe_cancel_upstream(mut self):
        """Framework-internal: on teardown, if the connection was
        cancelled (client FIN / deadline / drain) and owns a source,
        emit one CANCEL frame upstream so the backend stops producing
        tokens nobody will read. Idempotent and best-effort -- normal
        EOF completion has already latched the source, so this only
        fires on a genuine abandon."""
        if not self._upstream:
            return
        if not self.cancel().cancelled():
            return
        try:
            self._upstream.value().send_cancel()
        except:
            pass

    @always_inline
    def upstream_fd(self) -> Int:
        """The attached upstream fd, or ``-1`` if none."""
        return self._upstream_fd

    @always_inline
    def reg_upstream_fd(self) -> Int:
        """Framework-internal: the upstream fd currently registered with
        the reactor, or ``-1``."""
        return self._reg_upstream_fd

    @always_inline
    def _set_reg_upstream_fd(mut self, fd: Int):
        """Framework-internal: record the reactor's registered upstream
        fd after a reconcile."""
        self._reg_upstream_fd = fd

    # ── Backpressure watermarks ────────────────────────────────────

    def set_watermarks(mut self, hi: Int, lo: Int):
        """Tune the relay-buffer hi/lo watermarks for this connection.

        ``hi`` is the occupancy at which the reactor stops reading the
        attached upstream; ``lo`` (< ``hi``) is where it resumes. Values
        are clamped to a sane order (``lo`` forced below ``hi``) so a
        front cannot wedge the gate shut. Call in ``on_open`` to size the
        relay pipe before any bytes flow.
        """
        var h = hi if hi > 0 else 1
        var l = lo if lo >= 0 else 0
        if l >= h:
            l = h - 1
        self._hi_watermark = h
        self._lo_watermark = l

    @always_inline
    def hi_watermark(self) -> Int:
        """The high watermark in bytes."""
        return self._hi_watermark

    @always_inline
    def lo_watermark(self) -> Int:
        """The low watermark in bytes."""
        return self._lo_watermark

    @always_inline
    def write_buffer_full(self) -> Bool:
        """True once unwritten outbound bytes reach the high watermark.

        A relay front should check this in its ``on_upstream`` drain loop
        and stop pulling from the upstream when it returns True, so a
        single readable edge cannot overshoot the bound before the
        reactor's interest gate takes effect on the next reconcile.
        """
        return self.pending_out() >= self._hi_watermark

    @always_inline
    def upstream_paused(self) -> Bool:
        """True while upstream reads are gated off by backpressure."""
        return self._upstream_paused

    @always_inline
    def pause_count(self) -> Int:
        """How many times upstream reads were paused (hi crossings)."""
        return self._pause_count

    @always_inline
    def resume_count(self) -> Int:
        """How many times upstream reads were resumed (lo crossings)."""
        return self._resume_count

    def apply_backpressure(mut self) -> Bool:
        """Recompute the upstream read gate from buffer occupancy with
        hi/lo hysteresis; update the paused flag and crossing counters.

        Returns whether the attached upstream fd should currently be read
        (``True`` = arm ``INTEREST_READ``; ``False`` = pause). Pauses on
        crossing the high watermark, resumes on falling to the low one;
        between the two it holds the prior state -- the band that stops
        interest thrash. Framework-internal: the reactor calls this on
        each reconcile.
        """
        var occ = self.pending_out()
        if not self._upstream_paused:
            if occ >= self._hi_watermark:
                self._upstream_paused = True
                self._pause_count += 1
        else:
            if occ <= self._lo_watermark:
                self._upstream_paused = False
                self._resume_count += 1
        return not self._upstream_paused

    @always_inline
    def reg_upstream_interest(self) -> Int:
        """Framework-internal: upstream interest bits currently
        registered (``-1`` unknown)."""
        return self._reg_upstream_interest

    @always_inline
    def _set_reg_upstream_interest(mut self, interest: Int):
        """Framework-internal: record registered upstream interest after a
        reconcile."""
        self._reg_upstream_interest = interest

    @always_inline
    def set_nonblocking(mut self, enabled: Bool) raises:
        """Toggle non-blocking mode on the client socket (reactor
        path sets this once at accept)."""
        self.client._socket.set_nonblocking(enabled)

    def send(mut self, data: Span[UInt8, _]):
        """Queue ``data`` for delivery to the client.

        Buffered, not written immediately: the blocking driver flushes
        with ``flush_blocking`` after each lifecycle step; the reactor
        drains with ``drain_nonblocking`` on writable edges. Same call
        site in both modes, so a front never blocks the event loop.

        Token-burst coalescing: each ``send`` is an O(n) memcpy into
        the single contiguous ``out_buf`` -- it issues no syscall. When a
        front emits K ready chunks in one reactor tick (call ``send`` K
        times), the subsequent drain flushes all K in ONE ``send(2)``,
        removing the per-token syscall round-trip that dominates long-
        output nTPOT. ponytail: the gather is a memcpy into ``out_buf``,
        not a zero-copy ``writev`` over the K chunk buffers; swap in
        ``writev_buf`` over a chunk vector only if that memcpy shows up in
        a profile -- the syscall count (the nTPOT win) is already 1."""
        var n = len(data)
        if n == 0:
            return
        var old = len(self.out_buf)
        self.out_buf.resize(old + n, UInt8(0))
        memcpy(
            dest=self.out_buf.unsafe_ptr() + old,
            src=data.unsafe_ptr(),
            count=n,
        )

    @always_inline
    def send(mut self, data: List[UInt8]):
        """Queue an owned byte list for the client (no ``Span`` wrap).

        Convenience over ``send(Span[UInt8, _])`` for the common case
        where a front holds a ``List[UInt8]`` -- e.g. a chunk just taken
        from a ``ChunkPoll``. Same coalescing semantics."""
        self.send(Span[UInt8, _](data))

    @always_inline
    def send(mut self, text: StringSlice):
        """Queue a UTF-8 string for the client (no byte juggling).

        Convenience for text protocols (SSE, NDJSON, a status line):
        ``conn.send("data: " + line + \"\\n\")``. Appends the string's
        UTF-8 bytes with the same coalescing as ``send(Span[UInt8, _])``."""
        self.send(text.as_bytes())

    @always_inline
    def pending_out(self) -> Int:
        """Unwritten outbound bytes (``len(out_buf) - out_pos``)."""
        return len(self.out_buf) - self.out_pos

    @always_inline
    def has_pending_out(self) -> Bool:
        """True if there are unwritten outbound bytes."""
        return self.out_pos < len(self.out_buf)

    @always_inline
    def write_syscalls(self) -> Int:
        """Number of ``send(2)`` calls issued so far by the drain path.
        A burst of K chunks queued via ``send`` flushes in one syscall, so
        this advances by ~1 per drain regardless of K."""
        return self._write_syscalls

    @always_inline
    def reset_write_syscalls(mut self):
        """Reset the write-syscall counter (for microbenches)."""
        self._write_syscalls = 0

    @always_inline
    def _reset_out(mut self):
        """Drop the outbound buffer (fully flushed)."""
        self.out_buf.clear()
        self.out_pos = 0

    def _compact(mut self):
        """Reclaim the already-written prefix of ``out_buf`` so a slow
        client cannot make the buffer grow without bound."""
        if self.out_pos == 0:
            return
        var rem = len(self.out_buf) - self.out_pos
        if rem == 0:
            self._reset_out()
            return
        var nb = List[UInt8](capacity=rem)
        nb.resize(rem, UInt8(0))
        memcpy(
            dest=nb.unsafe_ptr(),
            src=self.out_buf.unsafe_ptr() + self.out_pos,
            count=rem,
        )
        self.out_buf = nb^
        self.out_pos = 0

    def flush_blocking(mut self) raises:
        """Write all pending outbound bytes, blocking. Used by the
        single-connection driver."""
        if self.out_pos < len(self.out_buf):
            var rem = Span[UInt8, _](
                ptr=self.out_buf.unsafe_ptr() + self.out_pos,
                length=len(self.out_buf) - self.out_pos,
            )
            self.client.write_all(rem)
        self._reset_out()

    def drain_nonblocking(mut self) raises -> Bool:
        """Write as much of the pending buffer as the socket accepts
        without blocking.

        Returns ``True`` once the buffer is fully flushed, ``False`` if
        the socket would block (EAGAIN) with bytes still pending -- the
        caller then keeps ``INTEREST_WRITE`` armed and retries on the
        next writable edge. Raises on a real socket error (EPIPE /
        ECONNRESET) so the reactor closes the connection.
        """
        while self.out_pos < len(self.out_buf):
            var ptr = self.out_buf.unsafe_ptr() + self.out_pos
            var n_to = len(self.out_buf) - self.out_pos
            self._write_syscalls += 1
            var sent = _send(
                self.client._socket.fd, ptr, c_size_t(n_to), MSG_NOSIGNAL
            )
            if sent > 0:
                self.out_pos += Int(sent)
                continue
            if sent == 0:
                break
            var e = get_errno()
            if e == ErrNo.EINTR:
                continue
            if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                self._compact()
                return False
            raise NetworkError(
                _strerror(e.value) + " (stream send)", Int(e.value)
            )
        self._reset_out()
        return True

    def recv(mut self, mut buf: List[UInt8], max_bytes: Int) raises -> Int:
        """Append up to ``max_bytes`` bytes read from the client onto
        ``buf``. Returns the count read (0 on peer EOF)."""
        var old = len(buf)
        buf.resize(old + max_bytes, UInt8(0))
        var n = self.client.read(buf.unsafe_ptr() + old, max_bytes)
        buf.resize(old + n, UInt8(0))
        return n

    # ── Incremental inbound body ───────────────────────────────────

    @always_inline
    def enable_inbound(mut self, enabled: Bool = True):
        """Opt into front-owned inbound body consumption.

        Call in ``on_open`` for a front that reads a (possibly large)
        request body itself via ``read_body``. While enabled the reactor
        no longer drains-and-discards client bytes for FIN detection, so
        the body bytes reach the front intact; the front pulls them in
        bounded chunks (peak memory independent of body size) and detects
        end-of-body when ``read_body`` returns ``eof``.
        """
        self._inbound_enabled = enabled

    @always_inline
    def inbound_enabled(self) -> Bool:
        """True if the front owns inbound body consumption."""
        return self._inbound_enabled

    def read_body(mut self, max_bytes: Int = 65536) raises -> ChunkPoll:
        """Read up to ``max_bytes`` of the inbound request body, without
        blocking, as a ``ChunkPoll`` (so inbound and outbound share
        one tri-state shape):

        - ``ready(bytes)`` -- a body chunk is available now;
        - ``eof()`` -- the client finished the body (clean FIN);
        - ``pending(fd)`` -- nothing buffered yet; the reactor will fire
          again on the next readable edge (no busy-poll).

        A front loops on this in ``on_writable`` (the streaming reactor
        keeps the connection live), processing each chunk and dropping it,
        so peak memory is one chunk regardless of total body size up to
        whatever ceiling the front enforces.
        """
        while True:
            var buf = List[UInt8](capacity=max_bytes)
            buf.resize(max_bytes, UInt8(0))
            var n = _recv(
                self.client._socket.fd,
                buf.unsafe_ptr(),
                c_size_t(max_bytes),
                c_int(0),
            )
            if n > 0:
                buf.resize(Int(n), UInt8(0))
                return ChunkPoll.ready(buf^)
            if n == 0:
                return ChunkPoll.eof()
            var e = get_errno()
            if e == ErrNo.EINTR:
                continue
            if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                return ChunkPoll.pending(self.client._socket.fd)
            raise NetworkError(
                _strerror(e.value) + " (inbound body recv)", Int(e.value)
            )


# ── StreamHandler ──────────────────────────────────────────────────────────


trait StreamHandler(ImplicitlyDestructible, Movable):
    """Lifecycle callbacks for one logical stream.

    The framework owns the reactor and the connection; the handler is a
    typed struct whose fields are its shared state. Every callback takes
    ``mut self`` (that typed shared state) and a ``mut`` ref to the
    framework-owned ``StreamConn``. There is no raw token and no
    address-as-``Int`` anywhere in the front.
    """

    def on_open(mut self, mut conn: StreamConn) raises:
        """Called once when the connection is accepted. Parse the
        request, attach an upstream, begin the response."""
        ...

    def on_upstream(mut self, mut conn: StreamConn) raises:
        """Called when the attached upstream is readable. For a source
        attached via ``conn.attach_upstream(UpstreamChunkSource)`` the
        whole body is ``conn.relay_upstream()`` (drain ready chunks to
        the client with backpressure, close on EOF). A front that
        attached a raw fd reads it itself and calls ``conn.send``."""
        ...

    def on_writable(mut self, mut conn: StreamConn) raises:
        """Called on a writable edge. Emit the next chunk of the
        response; call ``conn.request_close()`` when the stream is
        complete."""
        ...

    def on_close(mut self, mut conn: StreamConn) raises:
        """Called once as the connection is torn down (front FIN,
        deadline, or ``request_close``). Release per-connection
        resources."""
        ...


# ── Single-connection blocking driver ──────────────────────────────────────


def run_stream_connection[
    H: StreamHandler
](mut handler: H, var client: TcpStream, id: Int = 0) raises:
    """Drive one accepted ``client`` connection through the handler
    lifecycle, blocking.

    Calls ``on_open`` once, then ``on_writable`` repeatedly until the
    front requests close (so a streaming front emits chunk-by-chunk),
    then ``on_close`` exactly once. ``on_upstream`` is only driven by the
    reactor path (``serve_streaming``); this blocking driver is the
    single-connection core used by tests and one-shot sidecars.

    The connection is closed when ``conn`` drops at function exit.
    """
    var conn = StreamConn(client^, id)
    handler.on_open(conn)
    conn.flush_blocking()
    while not conn.is_closing():
        handler.on_writable(conn)
        conn.flush_blocking()
    handler.on_close(conn)
