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
  ``__del__`` free path never depend on the ``ServerCtx`` outliving the
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

from std.ffi import c_int, OwnedDLHandle
from std.collections import List

from flare.net import SocketAddr, _find_flare_lib
from flare.tcp import TcpStream
from flare.tls._server_ffi import (
    ServerCtx,
    server_ssl_new_accept,
    SSL_IO_WANT_READ,
    SSL_IO_WANT_WRITE,
    SSL_IO_CLOSED,
    SSL_IO_FATAL,
    _do_ssl_do_handshake,
    _do_ssl_read_ex,
    _do_ssl_write_ex,
    _do_ssl_get_alpn_selected,
    _do_ssl_get_sni_host,
    _do_ssl_free,
)

from .keepalive_scan import StepResult


# ── TLS phase tags ─────────────────────────────────────────────────────────

comptime TLS_HANDSHAKE: Int = 0
"""``SSL_accept`` is still negotiating; drive it on each edge."""
comptime TLS_ESTABLISHED: Int = 1
"""Handshake complete; ``recv`` / ``send`` carry application bytes."""
comptime TLS_CLOSED: Int = 2
"""Fatal error or clean shutdown observed; the fd should be torn down."""


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
    var _lib: OwnedDLHandle
    """Pinned ``libflare_tls.so`` handle used for every post-accept FFI
    call and the ``SSL_free`` in ``__del__``. Independent of the
    ``ServerCtx`` lifetime."""
    var ssl_addr: Int
    """Raw ``SSL*`` as an Int. Zero once freed."""
    var phase: Int
    """One of ``TLS_HANDSHAKE`` / ``TLS_ESTABLISHED`` / ``TLS_CLOSED``."""
    var alpn: String
    """Negotiated ALPN protocol (``""`` until handshake completes / none)."""
    var sni: String
    """Client-supplied SNI host (``""`` if absent)."""

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
        self.ssl_addr = server_ssl_new_accept(ctx, fd)
        if self.ssl_addr == 0:
            raise Error("TlsConnHandle: server_ssl_new_accept returned null")
        self._lib = OwnedDLHandle(_find_flare_lib())
        self.phase = TLS_HANDSHAKE
        self.alpn = ""
        self.sni = ""

    def __del__(deinit self):
        """Free the ``SSL`` (fd close is the moved-in stream's job)."""
        if self.ssl_addr != 0:
            _do_ssl_free(self._lib, self.ssl_addr)

    @always_inline
    def fd(self) -> c_int:
        """Underlying fd. Fast accessor; does not check phase."""
        return self._stream._socket.fd

    def handshake_done(self) -> Bool:
        """True once the handshake has completed successfully."""
        return self.phase == TLS_ESTABLISHED

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
        if self.phase == TLS_ESTABLISHED:
            return StepResult(want_read=True, want_write=False)
        if self.phase == TLS_CLOSED:
            return StepResult(want_read=False, want_write=False, done=True)

        var rc = _do_ssl_do_handshake(self._lib, self.ssl_addr)
        if rc == 0:
            self.phase = TLS_ESTABLISHED
            self.alpn = _do_ssl_get_alpn_selected(self._lib, self.ssl_addr)
            self.sni = _do_ssl_get_sni_host(self._lib, self.ssl_addr)
            return StepResult(want_read=True, want_write=False)
        elif rc == 1:
            return StepResult(want_read=True, want_write=False)
        elif rc == 2:
            return StepResult(want_read=False, want_write=True)
        else:
            self.phase = TLS_CLOSED
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
        if max_bytes <= 0:
            return 0
        var old_len = len(buf)
        buf.resize(old_len + max_bytes, UInt8(0))
        var dst = Int(buf.unsafe_ptr()) + old_len
        var n = _do_ssl_read_ex(self._lib, self.ssl_addr, dst, max_bytes)
        if n > 0:
            buf.resize(old_len + n, UInt8(0))
            return n
        buf.resize(old_len, UInt8(0))
        if n == SSL_IO_CLOSED or n == SSL_IO_FATAL:
            self.phase = TLS_CLOSED
        return n

    def send(mut self, bytes: Span[UInt8, _], off: Int = 0) raises -> Int:
        """Non-blocking ``SSL_write`` of ``bytes[off:]``.

        Returns the number of plaintext bytes consumed (>0) or a
        ``SSL_IO_*`` sentinel. Partial writes are the caller's to resume
        (advance ``off`` by the return value). On CLOSED/FATAL the phase
        moves to ``TLS_CLOSED``.
        """
        var n = len(bytes) - off
        if n <= 0:
            return 0
        var ptr = Int(bytes.unsafe_ptr()) + off
        var rc = _do_ssl_write_ex(self._lib, self.ssl_addr, ptr, n)
        if rc <= 0 and (rc == SSL_IO_CLOSED or rc == SSL_IO_FATAL):
            self.phase = TLS_CLOSED
        return rc

    def close(mut self) -> None:
        """Explicitly close the underlying stream. Idempotent."""
        self._stream.close()
