"""Non-blocking server-side TLS connection state machine.

``TlsConnHandle`` is the ciphertext-side companion to
:class:`flare.http._reactor.conn_handle.ConnHandle`. Where ``ConnHandle``
drives a plaintext H1 connection across readable/writable edges,
``TlsConnHandle`` wraps the *same* edge-driven ``StepResult`` contract
around OpenSSL's non-blocking ``SSL_accept`` / ``SSL_read`` / ``SSL_write``
so a TLS-terminated connection can live in the reactor without a blocking
handshake thread.

Design (additive; the plaintext hot path is untouched):

- The handle **owns** the accepted ``TcpStream`` (hence the fd) exactly
  like ``ConnHandle``, avoiding the ASAP-destruction hazard of passing a
  bare fd.
- It creates the ``SSL*`` from a shared per-server :class:`ServerCtx`
  (``SSL_new`` + ``SSL_set_fd`` + ``SSL_set_accept_state`` via
  ``server_ssl_new_accept``) and keeps its **own** pinned
  ``OwnedDLHandle`` to ``libflare_tls.so`` so post-accept I/O and the
  ``__deinit__`` free path never depend on the ``ServerCtx`` outliving the
  connection or on being threaded back in by the caller. (dlopen of an
  already-mapped .so only bumps a refcount.)
- :meth:`drive_handshake` maps OpenSSL's ``WANT_READ`` / ``WANT_WRITE`` /
  complete / fatal into a ``StepResult`` (``want_read`` / ``want_write`` /
  ``done``). On completion it reads the negotiated ALPN protocol + SNI
  host so the caller can dispatch h1 vs h2 (reusing
  :mod:`flare.http.alpn_dispatch`).
- :meth:`recv` / :meth:`send` are the ciphertext seams: they return the
  plaintext byte count (>0) or a ``SSL_IO_*`` sentinel, which the caller
  maps to the same re-arm logic ``ConnHandle`` uses for ``EAGAIN``.

Streaming composes for free: once the handshake completes, the h1 chunked
pump and the h2 DATA pump already emit on writable edges -- they simply
write their bytes through :meth:`send` (ciphertext) instead of ``_send``.
"""

from std.builtin.debug_assert import debug_assert
from std.ffi import c_int
from std.collections import List
from std.memory import Pointer

from flare.net import SocketAddr
from flare.runtime import Pool
from flare.tcp import TcpStream
from flare.tls._server_ffi import ServerCtx

from .keepalive_scan import StepResult
from .tls_transport import (
    TlsTransport,
    TLS_HANDSHAKE,
    TLS_ESTABLISHED,
    TLS_CLOSED,
    HS_DONE,
    HS_WANT_READ,
    HS_WANT_WRITE,
)


struct TlsConnHandle(Movable):
    """Per-connection non-blocking TLS state for a reactor-managed
    connection.

    Owns the accepted ``TcpStream`` and the ``SSL*`` handle. Drop frees
    the ``SSL`` (via the pinned library handle) and closes the fd through
    the stream's own destructor.
    """

    var _stream: TcpStream
    """Underlying connection; sole owner of the fd."""
    var peer: SocketAddr
    """Kernel-reported peer address, captured before the stream moves in."""
    var transport: TlsTransport
    """The ``SSL*`` half. Moved out alongside ``_stream`` when the
    connection is promoted to an h1 / h2 handle after ALPN."""
    var alpn: String
    """Negotiated ALPN protocol (``""`` until handshake completes / none)."""
    var sni: String
    """Client-supplied SNI host (``""`` if absent)."""
    var last_interest: Int
    """Last reactor interest bits armed for this fd, so a handshake that
    keeps asking for the same direction does not re-issue ``epoll_ctl``
    on every edge."""

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def __init__(out self, var stream: TcpStream, ctx: ServerCtx) raises:
        """Construct a handle owning ``stream``, with a fresh
        accept-state ``SSL`` bound to ``stream``'s fd.

        Args:
            stream: Accepted ``TcpStream`` (already in non-blocking mode).
                Ownership transfers into the handle.
            ctx: Shared server ``SSL_CTX`` the ``SSL`` is spawned from.

        Raises:
            If ``SSL_new`` / ``SSL_set_fd`` fails (returns null).
        """
        self.peer = stream.peer_addr()
        # A reactor-driven TLS connection must be non-blocking so
        # SSL_accept / SSL_read / SSL_write surface WANT_READ/WANT_WRITE
        # instead of blocking the event loop. accept(2) yields a socket
        # that inherits the listener's blocking mode, so force it here.
        stream._socket.set_nonblocking(True)
        var fd = Int(stream._socket.fd)
        self._stream = stream^
        self.transport = TlsTransport(ctx, fd)
        self.alpn = ""
        self.sni = ""
        self.last_interest = 1  # INTEREST_READ, matching accept-time arm

    @always_inline
    def fd(self) -> c_int:
        """Underlying fd. Fast accessor; does not check phase."""
        return self._stream._socket.fd

    @always_inline
    def phase(self) -> Int:
        """Current TLS phase; see the ``TLS_*`` tags."""
        return self.transport.phase

    def handshake_done(self) -> Bool:
        """True once the handshake has completed successfully."""
        return self.transport.established()

    # Promotion note: once ALPN has selected h1 or h2 the reactor moves
    # ``_stream`` and ``transport`` out of this handle with regular field
    # moves (``var s = h._stream^; var t = h.transport^``) and hands both
    # to the protocol handle, mirroring how ``PendingConnHandle`` releases
    # its stream. Mojo suppresses the moved-from fields' destructors, so
    # the fd is closed once (by the new owner) and the ``SSL*`` freed once
    # (by the moved transport).

    # ── State machine ──────────────────────────────────────────────────────

    def drive_handshake(mut self) raises -> StepResult:
        """Advance ``SSL_accept`` one step and return the reactor interest.

        Returns a ``StepResult``:

        - handshake complete → ``want_read=True`` (ready to read the first
          application record); ALPN + SNI are now populated.
        - ``WANT_READ`` → ``want_read=True`` (re-arm readable, call again).
        - ``WANT_WRITE`` → ``want_write=True`` (re-arm writable, call
          again).
        - fatal → ``done=True`` (tear the connection down).

        Idempotent once established: returns the ready-to-read result
        without re-driving the handshake.
        """
        if self.transport.established():
            return StepResult(want_read=True, want_write=False)
        if self.transport.closed():
            return StepResult(want_read=False, want_write=False, done=True)

        var rc = self.transport.do_handshake()
        if rc == HS_DONE:
            self.alpn = self.transport.read_alpn()
            self.sni = self.transport.read_sni()
            return StepResult(want_read=True, want_write=False)
        elif rc == HS_WANT_READ:
            return StepResult(want_read=True, want_write=False)
        elif rc == HS_WANT_WRITE:
            return StepResult(want_read=False, want_write=True)
        else:
            return StepResult(want_read=False, want_write=False, done=True)

    def recv(mut self, mut buf: List[UInt8], max_bytes: Int) raises -> Int:
        """Non-blocking ``SSL_read`` of up to ``max_bytes`` into ``buf``.

        Appends the plaintext bytes to ``buf`` and returns the count
        (>0), or a ``SSL_IO_*`` sentinel: ``SSL_IO_WANT_READ`` /
        ``SSL_IO_WANT_WRITE`` (re-arm the matching interest and call
        again), ``SSL_IO_CLOSED`` (peer close_notify — clean EOF), or
        ``SSL_IO_FATAL``. On CLOSED/FATAL the phase moves to
        ``TLS_CLOSED``. ``max_bytes`` bounds one read.
        """
        return self.transport.recv(buf, max_bytes)

    def send(mut self, bytes: Span[UInt8, _], off: Int = 0) raises -> Int:
        """Non-blocking ``SSL_write`` of ``bytes[off:]``.

        Returns the number of plaintext bytes consumed (>0) or a
        ``SSL_IO_*`` sentinel. Partial writes are the caller's to resume
        (advance ``off`` by the return value). On CLOSED/FATAL the phase
        moves to ``TLS_CLOSED``.
        """
        return self.transport.send(bytes, off)

    def close(mut self) -> None:
        """Explicitly close the underlying stream. Idempotent."""
        self._stream.close()


# ── Heap boxing for the reactor's tagged-pointer conn table ───────────────


def _tls_conn_alloc_addr(var stream: TcpStream, ctx: ServerCtx) raises -> Int:
    """Heap-allocate a :class:`TlsConnHandle` and return its address."""
    var addr = Pool[TlsConnHandle].alloc_move(TlsConnHandle(stream^, ctx))
    debug_assert[assert_mode="safe"](
        addr != 0,
        "_tls_conn_alloc_addr: Pool returned 0",
    )
    return addr


def _tls_conn_free_addr(addr: Int):
    """Destroy + free a :class:`TlsConnHandle`."""
    debug_assert[assert_mode="safe"](
        addr != 0,
        "_tls_conn_free_addr: addr must be non-zero (double-free?)",
    )
    Pool[TlsConnHandle].free(addr)


def _tls_conn_ptr_from_int(
    addr: Int,
) -> Pointer[TlsConnHandle, MutUntrackedOrigin]:
    """Reverse of :func:`_tls_conn_alloc_addr`: rebuild a typed pointer."""
    return Pointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=addr
    ).unsafe_bitcast[TlsConnHandle]()
