"""TLS stream: encrypts a TcpStream via OpenSSL FFI.

The shared library ``libflare_tls.so`` is built automatically on pixi
activation via ``flare/tls/ffi/build.sh`` and installed to
``$CONDA_PREFIX/lib/`` when using the packaged distribution.

Opaque C pointers (SSL_CTX*, SSL*) are held as ``Int`` values since Mojo
nightly requires all ``UnsafePointer`` type parameters to have an explicit
``mut`` parameter which is not inferable for ``NoneType``. Using ``Int``
(64-bit on all supported platforms) stores pointer values safely.

Security defaults enforced unconditionally:
- TLS 1.2 minimum (TLS 1.0 / 1.1 disabled at the protocol level)
- Forward-secret AEAD cipher suites only (ECDHE + AES-GCM / ChaCha20)
- Certificate verification REQUIRED (opt-out via ``TlsConfig.insecure()``)
- SNI always sent for hostname targets

Example:
    ```mojo
    from flare.tls import TlsStream, TlsConfig

    var stream = TlsStream.connect("example.com", 443, TlsConfig())
    stream.write_all("GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n".as_bytes())
    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    var n = stream.read(buf.unsafe_ptr(), len(buf))
    ```

## OwnedDLHandle / ASAP-destruction discipline

Mojo's ASAP destruction policy reclaims an ``OwnedDLHandle`` right
after its last Mojo-visible use. In a naive ``var lib =
OwnedDLHandle(...); var fn = lib.get_function(...); fn(...)``
sequence the runtime considers ``lib`` dead immediately after
``get_function`` returns and runs the destructor (``dlclose``)
before ``fn`` is invoked, leaving the cached function pointer
dangling into freed memory.

Discipline this file follows: every FFI call goes through a
``_do_ssl_*(read lib: OwnedDLHandle, ...)`` borrow helper that
does both ``get_function`` and the invocation inside the borrow.
Public methods open ``lib`` once and pass it through to a chain
of helpers; the borrow keeps the dylib mapped across the whole
sequence. Same idiom as
``flare.http.encoding._do_compress`` /
``flare.http.middleware._flare_fs_access`` /
``flare.tls._server_ffi._do_ssl_ctx_new_server``.
"""

from std.sys import stderr
from std.ffi import OwnedDLHandle, c_int
from std.memory import UnsafePointer, stack_allocation
from ..dns import resolve
from ..net import SocketAddr, NetworkError, _find_flare_lib
from ..tcp import TcpStream
from ..tcp.stream import _connect_with_fallback
from ..io import Readable
from .config import TlsConfig, TlsVerify
from .error import (
    TlsHandshakeError,
    CertificateExpired,
    CertificateHostnameMismatch,
    CertificateUntrusted,
)

# Subject DN buffer size (matches X509_NAME_oneline output limit)
comptime _CERT_SUBJ_LEN: Int = 512


@always_inline
def _c_str(s: String) -> Int:
    """Return a C ``char*`` (as ``Int``) pointing to ``s``'s data.

    Safety: The returned pointer is valid only as long as ``s`` is alive.
    Never store the returned ``Int`` beyond the lifetime of ``s``.

    Args:
        s: Mojo ``String`` whose null-terminated bytes are to be passed to C.

    Returns:
        Integer representation of the ``const char*`` pointer.
    """
    return Int(s.unsafe_ptr())


# ── Borrow helpers (one per FFI export) ──────────────────────────────────────


def _c_err(read lib: OwnedDLHandle) -> String:
    """Return the last OpenSSL error string from ``flare_ssl_last_error()``.

    Args:
        lib: Borrowed handle to ``libflare_tls`` (kept mapped across
            the call).

    Returns:
        Human-readable error string (empty if no error).
    """
    var fn_err = lib.get_function[
        def() thin abi("C") -> UnsafePointer[UInt8, MutExternalOrigin]
    ]("flare_ssl_last_error")
    var p = fn_err()
    return String(StringSlice(unsafe_from_utf8_ptr=p))


def _do_ssl_ctx_new(read lib: OwnedDLHandle) -> Int:
    var f = lib.get_function[def() thin abi("C") -> Int]("flare_ssl_ctx_new")
    return f()


def _do_ssl_ctx_free(read lib: OwnedDLHandle, ctx: Int):
    if ctx == 0:
        return
    var f = lib.get_function[def(Int) thin abi("C") -> None](
        "flare_ssl_ctx_free"
    )
    f(ctx)


def _do_ssl_ctx_set_security_policy(read lib: OwnedDLHandle, ctx: Int) -> Int:
    var f = lib.get_function[def(Int) thin abi("C") -> c_int](
        "flare_ssl_ctx_set_security_policy"
    )
    return Int(f(ctx))


def _do_ssl_ctx_set_verify_peer(
    read lib: OwnedDLHandle, ctx: Int, verify: c_int
) -> Int:
    var f = lib.get_function[def(Int, c_int) thin abi("C") -> c_int](
        "flare_ssl_ctx_set_verify_peer"
    )
    return Int(f(ctx, verify))


def _do_ssl_ctx_load_ca_bundle(
    read lib: OwnedDLHandle, ctx: Int, ca_path: String
) -> Int:
    var f = lib.get_function[def(Int, Int) thin abi("C") -> c_int](
        "flare_ssl_ctx_load_ca_bundle"
    )
    return Int(f(ctx, _c_str(ca_path)))


def _do_ssl_ctx_load_cert_key(
    read lib: OwnedDLHandle, ctx: Int, cert_path: String, key_path: String
) -> Int:
    var f = lib.get_function[def(Int, Int, Int) thin abi("C") -> c_int](
        "flare_ssl_ctx_load_cert_key"
    )
    return Int(f(ctx, _c_str(cert_path), _c_str(key_path)))


def _do_ssl_ctx_set_alpn_protos(
    read lib: OwnedDLHandle, ctx: Int, blob: List[UInt8]
) -> Int:
    var f = lib.get_function[def(Int, Int, c_int) thin abi("C") -> c_int](
        "flare_ssl_ctx_set_alpn_protos"
    )
    return Int(f(ctx, Int(blob.unsafe_ptr()), c_int(len(blob))))


def _do_ssl_new(read lib: OwnedDLHandle, ctx: Int, fd: c_int) -> Int:
    var f = lib.get_function[def(Int, c_int) thin abi("C") -> Int](
        "flare_ssl_new"
    )
    return f(ctx, fd)


def _do_ssl_free(read lib: OwnedDLHandle, ssl: Int):
    if ssl == 0:
        return
    var f = lib.get_function[def(Int) thin abi("C") -> None]("flare_ssl_free")
    f(ssl)


def _do_ssl_connect(read lib: OwnedDLHandle, ssl: Int, sni: String) -> Int:
    var f = lib.get_function[def(Int, Int) thin abi("C") -> c_int](
        "flare_ssl_connect"
    )
    return Int(f(ssl, _c_str(sni)))


def _do_ssl_read(
    read lib: OwnedDLHandle,
    ssl: Int,
    buf: UnsafePointer[UInt8, _],
    size: Int,
) -> Int:
    var f = lib.get_function[def(Int, Int, c_int) thin abi("C") -> c_int](
        "flare_ssl_read"
    )
    return Int(f(ssl, Int(buf), c_int(size)))


def _do_ssl_write(
    read lib: OwnedDLHandle, ssl: Int, data: Span[UInt8, _]
) -> Int:
    var f = lib.get_function[def(Int, Int, c_int) thin abi("C") -> c_int](
        "flare_ssl_write"
    )
    return Int(f(ssl, Int(data.unsafe_ptr()), c_int(len(data))))


def _do_ssl_shutdown(read lib: OwnedDLHandle, ssl: Int) -> Int:
    var f = lib.get_function[def(Int) thin abi("C") -> c_int](
        "flare_ssl_shutdown"
    )
    return Int(f(ssl))


def _do_ssl_get_version(read lib: OwnedDLHandle, ssl: Int) -> String:
    var f = lib.get_function[
        def(Int) thin abi("C") -> UnsafePointer[UInt8, MutExternalOrigin]
    ]("flare_ssl_get_version")
    var p = f(ssl)
    return String(StringSlice(unsafe_from_utf8_ptr=p))


def _do_ssl_get_cipher(read lib: OwnedDLHandle, ssl: Int) -> String:
    var f = lib.get_function[
        def(Int) thin abi("C") -> UnsafePointer[UInt8, MutExternalOrigin]
    ]("flare_ssl_get_cipher")
    var p = f(ssl)
    return String(StringSlice(unsafe_from_utf8_ptr=p))


def _do_ssl_get_peer_cert_subject(
    read lib: OwnedDLHandle, ssl: Int, buf: UnsafePointer[UInt8, _], size: Int
) -> Int:
    var f = lib.get_function[def(Int, Int, c_int) thin abi("C") -> c_int](
        "flare_ssl_get_peer_cert_subject"
    )
    return Int(f(ssl, Int(buf), c_int(size)))


def _do_ssl_get_alpn_selected(
    read lib: OwnedDLHandle, ssl: Int, buf: UnsafePointer[UInt8, _], size: Int
) -> Int:
    var f = lib.get_function[def(Int, Int, c_int) thin abi("C") -> c_int](
        "flare_ssl_get_alpn_selected"
    )
    return Int(f(ssl, Int(buf), c_int(size)))


# ── Error classification ──────────────────────────────────────────────────


def _classify_tls_error(err: String, host: String) raises:
    """Map an OpenSSL error string to a typed TLS error and raise it.

    The C wrapper prefixes certificate verification failures with ``"verify:"``
    to distinguish them from generic I/O errors.

    Args:
        err: Error string from ``flare_ssl_last_error()``.
        host: Hostname the client tried to connect to (for context).

    Raises:
        CertificateExpired: If the cert has passed its ``notAfter``.
        CertificateHostnameMismatch: If hostname does not match the cert.
        CertificateUntrusted: For other certificate verification failures.
        TlsHandshakeError: For all other handshake errors.
    """
    if err.startswith("verify:"):
        var reason = String(unsafe_from_utf8=err.as_bytes()[7:])
        if (
            "certificate has expired" in reason
            or "certificate is not yet valid" in reason
        ):
            raise CertificateExpired(reason)
        if "hostname mismatch" in reason or "IP address mismatch" in reason:
            raise CertificateHostnameMismatch(host, reason)
        raise CertificateUntrusted(reason)
    raise TlsHandshakeError(err)


# ── Shared TLS-context setup helper ──────────────────────────────────────────
#
# Both ``connect`` and ``connect_timeout`` share the same SSL_CTX setup
# sequence (new + security policy + verify mode + CA bundle). Factor it
# into a single borrow-aware helper so the dylib stays mapped across all
# steps. Returns the freshly-allocated ``SSL_CTX*`` (as ``Int``) and the
# caller is responsible for freeing it via ``_do_ssl_ctx_free``.


def _build_ssl_ctx(read lib: OwnedDLHandle, config: TlsConfig) raises -> Int:
    var ctx = _do_ssl_ctx_new(lib)
    if ctx == 0:
        raise TlsHandshakeError(_c_err(lib))

    if _do_ssl_ctx_set_security_policy(lib, ctx) != 0:
        var err = _c_err(lib)
        _do_ssl_ctx_free(lib, ctx)
        raise TlsHandshakeError("Security policy error: " + err)

    _ = _do_ssl_ctx_set_verify_peer(lib, ctx, c_int(config.verify))

    # Skip CA bundle load in insecure mode — see the matching comment in
    # flare/tls/config.mojo's module docstring for the Mojo 0.26
    # String-concat aliasing quirk that motivates the gate.
    if config.verify != TlsVerify.NONE:
        if _do_ssl_ctx_load_ca_bundle(lib, ctx, config.ca_bundle) != 0:
            var err = _c_err(lib)
            _do_ssl_ctx_free(lib, ctx)
            raise TlsHandshakeError("CA bundle load failed: " + err)

    return ctx


struct TlsStream(Movable, Readable):
    """An encrypted TCP stream using TLS (via OpenSSL FFI).

    Wraps a ``TcpStream`` with OpenSSL's SSL session. The TLS handshake is
    performed in ``connect``; all subsequent I/O is routed through OpenSSL.

    Opaque C pointers (``SSL_CTX*``, ``SSL*``) are stored as ``Int`` values —
    the canonical approach in Mojo nightly for FFI-managed handles.

    The connection is shut down with a ``close_notify`` alert when destroyed
    or when ``close()`` is called explicitly.

    This type is ``Movable`` but not ``Copyable`` — an SSL session cannot
    be duplicated.

    Security defaults:
        - TLS 1.2 minimum (TLS 1.0 / 1.1 disabled via protocol version + options)
        - Forward-secret AEAD ciphers only (ECDHE + AES-GCM / ChaCha20)
        - Certificate verification on by default
        - SNI always sent for hostname targets

    Thread safety:
        Not thread-safe.

    Example:
        ```mojo
        var stream = TlsStream.connect("httpbin.org", 443, TlsConfig())
        stream.write_all("GET /get HTTP/1.1\\r\\nHost: httpbin.org\\r\\n\\r\\n".as_bytes())
        ```
    """

    # Safety: _ctx and _ssl are pointer values managed by the OpenSSL lifecycle
    # functions in libflare_tls.so. They are valid (non-zero) until close() is
    # called. _tcp keeps the OS fd alive for as long as _ssl needs it.
    # Ownership: this struct owns both _ctx and _ssl; they are freed in close().
    var _ctx: Int  # SSL_CTX* as Int (0 = null / closed)
    var _ssl: Int  # SSL* as Int (0 = null / closed)
    var _tcp: TcpStream  # owns the TCP fd

    def __init__(out self, var tcp: TcpStream, ctx: Int, ssl: Int):
        """Internal constructor — use ``TlsStream.connect`` instead.

        Args:
            tcp: Connected TCP stream (fd used by ssl after handshake).
            ctx: SSL_CTX* stored as Int.
            ssl: SSL* stored as Int (handshake already complete).
        """
        self._tcp = tcp^
        self._ctx = ctx
        self._ssl = ssl

    def __del__(deinit self):
        """Send ``close_notify`` and free OpenSSL objects (best-effort)."""
        if self._ssl != 0:
            try:
                var lib = OwnedDLHandle(_find_flare_lib())
                _ = _do_ssl_shutdown(lib, self._ssl)
                _do_ssl_free(lib, self._ssl)
                _do_ssl_ctx_free(lib, self._ctx)
            except:
                pass  # best-effort; tcp fd closed by _tcp.__del__

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(var self) -> TlsStream:
        """Transfer ownership of ``self`` into the ``with`` block.

        Returns:
            This ``TlsStream`` (moved).
        """
        return self^

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    def connect(
        host: String, port: UInt16, config: TlsConfig
    ) raises -> TlsStream:
        """Open a TLS connection to ``host:port``.

        Resolves the hostname (IPv4), opens a ``TcpStream``, configures
        OpenSSL, and performs the TLS handshake.

        When ``config.verify == TlsVerify.NONE``, a security warning is
        printed to stderr on every call (intentional).

        Args:
            host: Hostname or IP string. SNI is derived from this value.
            port: Destination TCP port (typically 443 for HTTPS).
            config: TLS configuration (verification mode, CA bundle, mTLS).

        Returns:
            A ``TlsStream`` with the TLS handshake complete.

        Raises:
            NetworkError: DNS resolution or TCP connect failure.
            TlsHandshakeError: Generic TLS handshake failure.
            CertificateExpired: Server cert has passed its notAfter.
            CertificateHostnameMismatch: Hostname does not match the cert.
            CertificateUntrusted: Cert not trusted by any CA in bundle.
        """
        if config.verify == TlsVerify.NONE:
            print(
                (
                    "[flare TLS SECURITY WARNING] Certificate verification is"
                    " disabled. This connection is vulnerable to"
                    " man-in-the-middle attacks. Never use TlsConfig.insecure()"
                    " in production."
                ),
                file=stderr,
            )

        # ── 1. DNS resolution and TCP connect with fallback ───────────────────
        var tcp = _connect_with_fallback(host, port, 5000)

        # ── 2. Load OpenSSL wrapper library ───────────────────────────────────
        var lib = OwnedDLHandle(_find_flare_lib())

        # ── 3. SSL_CTX + security policy + verify + CA bundle ────────────────
        var ctx = _build_ssl_ctx(lib, config)

        # ── 4. mTLS: load client cert + key if provided ──────────────────────
        if config.cert_file != "" and config.key_file != "":
            if (
                _do_ssl_ctx_load_cert_key(
                    lib, ctx, config.cert_file, config.key_file
                )
                != 0
            ):
                var err = _c_err(lib)
                _do_ssl_ctx_free(lib, ctx)
                raise TlsHandshakeError("mTLS cert/key load failed: " + err)

        # ── 5. Client-side ALPN (RFC 7301) ──────────────────────────────────
        if len(config.alpn) > 0:
            var blob = List[UInt8]()
            for i in range(len(config.alpn)):
                var p = config.alpn[i]
                var n = p.byte_length()
                if n == 0 or n > 255:
                    _do_ssl_ctx_free(lib, ctx)
                    raise TlsHandshakeError(
                        "TlsConfig.alpn: each protocol id must be 1..255"
                        " bytes (RFC 7301)"
                    )
                blob.append(UInt8(n))
                var pp = p.unsafe_ptr()
                for j in range(n):
                    blob.append(pp[j])
            if len(blob) > 255:
                _do_ssl_ctx_free(lib, ctx)
                raise TlsHandshakeError(
                    "TlsConfig.alpn: wire-format protos blob must be"
                    " <= 255 bytes total"
                )
            if _do_ssl_ctx_set_alpn_protos(lib, ctx, blob) != 0:
                var err = _c_err(lib)
                _do_ssl_ctx_free(lib, ctx)
                raise TlsHandshakeError("ALPN setup failed: " + err)

        # ── 6. Create SSL session bound to the TCP fd ─────────────────────────
        var ssl = _do_ssl_new(lib, ctx, tcp._socket.fd)
        if ssl == 0:
            var err = _c_err(lib)
            _do_ssl_ctx_free(lib, ctx)
            raise TlsHandshakeError(err)

        # ── 7. TLS handshake (flare_ssl_connect sends SNI) ────────────────────
        var sni = config.server_name if config.server_name != "" else host
        if _do_ssl_connect(lib, ssl, sni) != 0:
            var err = _c_err(lib)
            _do_ssl_free(lib, ssl)
            _do_ssl_ctx_free(lib, ctx)
            _classify_tls_error(err, host)
            # _classify_tls_error always raises; unreachable:
            raise TlsHandshakeError(err)

        return TlsStream(tcp^, ctx, ssl)

    @staticmethod
    def connect_timeout(
        host: String, port: UInt16, config: TlsConfig, timeout_ms: Int
    ) raises -> TlsStream:
        """Connect with TLS, failing after ``timeout_ms`` milliseconds.

        Uses ``TcpStream.connect_timeout`` for the TCP phase; the TLS
        handshake shares the same timeout budget.

        Args:
            host: Hostname or IP string.
            port: Destination TCP port.
            config: TLS configuration.
            timeout_ms: Maximum milliseconds for TCP + TLS handshake combined.

        Returns:
            A ``TlsStream`` with the handshake complete.

        Raises:
            ConnectionTimeout: If the deadline expires during TCP.
            NetworkError: DNS resolution failure.
            TlsHandshakeError: Generic TLS handshake failure.
            CertificateExpired: Server cert expired.
            CertificateHostnameMismatch: Hostname does not match the cert.
            CertificateUntrusted: Cert not trusted by any CA.
        """
        if config.verify == TlsVerify.NONE:
            print(
                (
                    "[flare TLS SECURITY WARNING] Certificate verification is"
                    " disabled. This connection is vulnerable to"
                    " man-in-the-middle attacks. Never use TlsConfig.insecure()"
                    " in production."
                ),
                file=stderr,
            )

        var tcp = _connect_with_fallback(host, port, timeout_ms)
        var lib = OwnedDLHandle(_find_flare_lib())

        var ctx = _build_ssl_ctx(lib, config)

        var ssl = _do_ssl_new(lib, ctx, tcp._socket.fd)
        if ssl == 0:
            var err = _c_err(lib)
            _do_ssl_ctx_free(lib, ctx)
            raise TlsHandshakeError(err)

        var sni = config.server_name if config.server_name != "" else host
        if _do_ssl_connect(lib, ssl, sni) != 0:
            var err = _c_err(lib)
            _do_ssl_free(lib, ssl)
            _do_ssl_ctx_free(lib, ctx)
            _classify_tls_error(err, host)
            raise TlsHandshakeError(err)

        return TlsStream(tcp^, ctx, ssl)

    # ── I/O ───────────────────────────────────────────────────────────────────

    def read(mut self, buf: UnsafePointer[UInt8, _], size: Int) raises -> Int:
        """Decrypt and read up to ``size`` bytes into ``buf``.

        Returns 0 on clean TLS closure (``close_notify`` received).

        Args:
            buf: Destination buffer; the caller must provide at least
                  ``size`` bytes of valid storage.
            size: Maximum number of bytes to read.

        Returns:
            Bytes placed in ``buf``, or 0 on clean EOF.

        Raises:
            NetworkError: On I/O or decryption error.
        """
        var lib = OwnedDLHandle(_find_flare_lib())
        var n = _do_ssl_read(lib, self._ssl, buf, size)
        if n < 0:
            raise NetworkError("TLS read error: " + _c_err(lib))
        return n

    def read_exact(mut self, buf: UnsafePointer[UInt8, _], size: Int) raises:
        """Read exactly ``size`` bytes into ``buf``.

        Args:
            buf: Destination buffer; must have at least ``size`` bytes.
            size: Number of bytes to read.

        Raises:
            NetworkError: If EOF arrives before the buffer is full, or on error.
        """
        var received = 0
        while received < size:
            var n = self.read(buf + received, size - received)
            if n == 0:
                raise NetworkError("TLS EOF before buffer full")
            received += n

    def write(self, data: Span[UInt8, _]) raises -> Int:
        """Encrypt and send bytes.

        Args:
            data: Bytes to encrypt and transmit.

        Returns:
            Number of bytes written (may be less than ``len(data)``).

        Raises:
            NetworkError: On I/O or encryption error.
        """
        var lib = OwnedDLHandle(_find_flare_lib())
        var n = _do_ssl_write(lib, self._ssl, data)
        if n < 0:
            raise NetworkError("TLS write error: " + _c_err(lib))
        return n

    def write_all(self, data: Span[UInt8, _]) raises:
        """Encrypt and send all of ``data``.

        Loops until all bytes are transmitted or an error occurs.

        Args:
            data: Bytes to transmit completely.

        Raises:
            NetworkError: On I/O or encryption error.
        """
        var total = len(data)
        var sent = 0
        var ptr = data.unsafe_ptr()
        while sent < total:
            var chunk = Span[UInt8, _](ptr=ptr + sent, length=total - sent)
            sent += self.write(chunk)

    # ── Introspection ─────────────────────────────────────────────────────────

    def tls_version(self) -> String:
        """Return the negotiated TLS version string.

        Returns:
            E.g. ``"TLSv1.3"`` or ``"TLSv1.2"``. Returns ``"unknown"`` if
            called before the handshake or if the library cannot be loaded.
        """
        try:
            var lib = OwnedDLHandle(_find_flare_lib())
            return _do_ssl_get_version(lib, self._ssl)
        except:
            return "unknown"

    def cipher_suite(self) -> String:
        """Return the negotiated cipher suite name.

        Returns:
            E.g. ``"TLS_AES_256_GCM_SHA384"`` or ``"unknown"``.
        """
        try:
            var lib = OwnedDLHandle(_find_flare_lib())
            return _do_ssl_get_cipher(lib, self._ssl)
        except:
            return "unknown"

    def peer_cert_subject(self) raises -> String:
        """Return the subject DN of the server's certificate.

        Args are described above. Do NOT use for security decisions —
        use ``config.verify`` for that.

        Returns:
            E.g. ``"/CN=example.com/O=Example Inc/C=US"``.

        Raises:
            NetworkError: If no peer certificate is available.
        """
        var lib = OwnedDLHandle(_find_flare_lib())
        var buf = stack_allocation[_CERT_SUBJ_LEN, UInt8]()
        var rc = _do_ssl_get_peer_cert_subject(
            lib, self._ssl, buf, _CERT_SUBJ_LEN
        )
        if rc != 0:
            raise NetworkError("peer_cert_subject: " + _c_err(lib))
        return String(StringSlice(unsafe_from_utf8_ptr=buf))

    # ── ALPN introspection ───────────────────────────────────────────────────

    def alpn_selected(self) raises -> String:
        """Return the ALPN protocol the server selected, or ``""`` if
        ALPN was not negotiated.

        Calls ``flare_ssl_get_alpn_selected`` (RFC 7301) on the
        live SSL session. Useful for clients that advertise
        multiple protocols via :attr:`flare.tls.TlsConfig.alpn`
        (e.g. ``["h2", "http/1.1"]``) and need to know which one
        the server picked before kicking off the higher-level
        protocol driver.

        Raises:
            NetworkError: When the underlying call fails (almost
                always means the SSL session is closed).
        """
        if self._ssl == 0:
            return String("")
        var lib = OwnedDLHandle(_find_flare_lib())
        var buf = stack_allocation[64, UInt8]()
        var rc = _do_ssl_get_alpn_selected(lib, self._ssl, buf, 64)
        if rc < 0:
            raise NetworkError("alpn_selected: " + _c_err(lib))
        if rc == 0:
            return String("")
        return String(StringSlice(unsafe_from_utf8_ptr=buf))

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(mut self):
        """Send ``close_notify`` and close the underlying TCP stream.

        Idempotent — safe to call multiple times. The destructor also calls
        this, so explicit ``close()`` is not required.
        """
        if self._ssl != 0:
            try:
                var lib = OwnedDLHandle(_find_flare_lib())
                _ = _do_ssl_shutdown(lib, self._ssl)
                _do_ssl_free(lib, self._ssl)
                _do_ssl_ctx_free(lib, self._ctx)
            except:
                pass
            self._ssl = 0
            self._ctx = 0
        self._tcp.close()
