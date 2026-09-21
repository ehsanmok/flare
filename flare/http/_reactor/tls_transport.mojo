"""Stream-agnostic OpenSSL I/O for a reactor-managed TLS connection.

``TlsTransport`` owns the ``SSL*`` and the pinned ``libflare_tls.so``
handle for one connection, and nothing else -- in particular it does
**not** own the fd. That split is what lets a TLS connection change
protocol handles mid-life: :class:`TlsConnHandle` drives the handshake
holding the ``TcpStream`` plus a transport, and once ALPN is known both
are moved into the h1 :class:`ConnHandle` or the
:class:`Http2ConnHandle` that will serve the connection. The fd keeps
exactly one owner throughout (the ``TcpStream``), and the ``SSL*`` keeps
exactly one owner (this struct).

The handle keeps its own ``OwnedDLHandle`` rather than borrowing the
``ServerCtx``'s so post-handshake I/O and the ``SSL_free`` in
``__deinit__`` never depend on the ``ServerCtx`` outliving the connection.
``dlopen`` of an already-mapped ``.so`` only bumps a refcount.

Return contract for :meth:`recv` / :meth:`send`: a positive value is a
plaintext byte count; a negative value is one of the ``SSL_IO_*``
sentinels. ``WANT_READ`` / ``WANT_WRITE`` are the TLS analogue of
``EAGAIN`` and can appear on *either* call -- a renegotiation makes
``SSL_read`` ask for writability and ``SSL_write`` ask for readability,
which is why callers must feed the sentinel back into their reactor
interest rather than assuming direction from the method name.
"""

from std.ffi import OwnedDLHandle
from std.collections import List

from flare.net import _find_flare_lib
from flare.tls._server_ffi import (
    ServerCtx,
    server_ssl_new_accept,
    SSL_IO_CLOSED,
    SSL_IO_FATAL,
    _do_ssl_do_handshake,
    _do_ssl_read_ex,
    _do_ssl_write_ex,
    _do_ssl_get_alpn_selected,
    _do_ssl_get_sni_host,
    _do_ssl_free,
)


# ── TLS phase tags ─────────────────────────────────────────────────────────

comptime TLS_HANDSHAKE: Int = 0
"""``SSL_accept`` is still negotiating; drive it on each edge."""
comptime TLS_ESTABLISHED: Int = 1
"""Handshake complete; ``recv`` / ``send`` carry application bytes."""
comptime TLS_CLOSED: Int = 2
"""Fatal error or clean shutdown observed; the fd should be torn down."""


# ── Handshake step codes (mirror of the wrapper's rc) ──────────────────────

comptime HS_DONE: Int = 0
"""Handshake completed; ALPN + SNI are readable."""
comptime HS_WANT_READ: Int = 1
"""Needs more ciphertext; re-arm readable and call again."""
comptime HS_WANT_WRITE: Int = 2
"""Needs socket writability; re-arm writable and call again."""


struct TlsTransport(Movable):
    """The ``SSL*`` half of a TLS connection, with no fd ownership."""

    var _lib: OwnedDLHandle
    """Pinned ``libflare_tls.so`` handle used for every FFI call and the
    ``SSL_free`` in ``__deinit__``."""
    var ssl_addr: Int
    """Raw ``SSL*`` as an Int. Zero once freed."""
    var phase: Int
    """One of ``TLS_HANDSHAKE`` / ``TLS_ESTABLISHED`` / ``TLS_CLOSED``."""

    def __init__(out self, ctx: ServerCtx, fd: Int) raises:
        """Spawn an accept-state ``SSL`` from ``ctx`` bound to ``fd``.

        Args:
            ctx: Shared server ``SSL_CTX``. Not retained.
            fd: Already-non-blocking socket the ``SSL`` reads and writes.

        Raises:
            If ``SSL_new`` / ``SSL_set_fd`` fails (returns null).
        """
        self.ssl_addr = server_ssl_new_accept(ctx, fd)
        if self.ssl_addr == 0:
            raise Error("TlsTransport: server_ssl_new_accept returned null")
        self._lib = OwnedDLHandle(_find_flare_lib())
        self.phase = TLS_HANDSHAKE

    @staticmethod
    def adopt(ssl_addr: Int, phase: Int = TLS_ESTABLISHED) raises -> Self:
        """Take ownership of an ``SSL*`` released by another transport.

        The reactor cannot ``^``-move a transport out of an
        ``Pointer`` deref (no tracked origin), so promotion from
        the handshake handle to the protocol handle goes through
        :meth:`release` + ``adopt``, mirroring how the fd is detached
        and rewrapped as a ``RawSocket``. The fresh ``OwnedDLHandle``
        is a refcount bump on an already-mapped library.
        """
        var out = Self(ssl_addr, phase, OwnedDLHandle(_find_flare_lib()))
        return out^

    def __init__(out self, ssl_addr: Int, phase: Int, var lib: OwnedDLHandle):
        """Raw field-wise init used by :meth:`adopt`."""
        self.ssl_addr = ssl_addr
        self.phase = phase
        self._lib = lib^

    def release(mut self) -> Int:
        """Surrender the ``SSL*`` without freeing it.

        Zeroes the field so this transport's ``__deinit__`` becomes a
        no-op; the caller must hand the address to :meth:`adopt`.
        """
        var out = self.ssl_addr
        self.ssl_addr = 0
        return out

    def __deinit__(deinit self):
        """Free the ``SSL``. The fd belongs to whoever owns the stream."""
        if self.ssl_addr != 0:
            try:
                _do_ssl_free(self._lib, self.ssl_addr)
            except:
                pass

    @always_inline
    def established(self) -> Bool:
        """True once the handshake has completed successfully."""
        return self.phase == TLS_ESTABLISHED

    @always_inline
    def closed(self) -> Bool:
        """True once a fatal error or clean shutdown was observed."""
        return self.phase == TLS_CLOSED

    def do_handshake(mut self) raises -> Int:
        """Advance ``SSL_accept`` one step.

        Returns ``HS_DONE`` / ``HS_WANT_READ`` / ``HS_WANT_WRITE``, or a
        negative value on a fatal error (phase moves to ``TLS_CLOSED``).
        """
        var rc = _do_ssl_do_handshake(self._lib, self.ssl_addr)
        if rc == HS_DONE:
            self.phase = TLS_ESTABLISHED
        elif rc != HS_WANT_READ and rc != HS_WANT_WRITE:
            self.phase = TLS_CLOSED
            return -1
        return rc

    def read_alpn(self) raises -> String:
        """Negotiated ALPN protocol; ``""`` when none was selected."""
        return _do_ssl_get_alpn_selected(self._lib, self.ssl_addr)

    def read_sni(self) raises -> String:
        """Client-supplied SNI host; ``""`` when absent."""
        return _do_ssl_get_sni_host(self._lib, self.ssl_addr)

    def recv(mut self, mut buf: List[UInt8], max_bytes: Int) raises -> Int:
        """Non-blocking ``SSL_read`` of up to ``max_bytes``, appended to
        ``buf``. Returns the plaintext count (>0) or an ``SSL_IO_*``
        sentinel; ``CLOSED`` / ``FATAL`` also move the phase.
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

        Returns the plaintext bytes consumed (>0) or an ``SSL_IO_*``
        sentinel. Partial writes are the caller's to resume.
        """
        var n = len(bytes) - off
        if n <= 0:
            return 0
        var ptr = Int(bytes.unsafe_ptr()) + off
        var rc = _do_ssl_write_ex(self._lib, self.ssl_addr, ptr, n)
        if rc <= 0 and (rc == SSL_IO_CLOSED or rc == SSL_IO_FATAL):
            self.phase = TLS_CLOSED
        return rc
