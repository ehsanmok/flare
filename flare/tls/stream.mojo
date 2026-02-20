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
"""

from sys import stderr
from ffi import OwnedDLHandle, c_int
from memory import UnsafePointer, stack_allocation
from ..dns import resolve_v4
from ..net import SocketAddr, NetworkError, _find_flare_lib
from ..tcp import TcpStream
from ..io import Readable
from .config import TlsConfig, TlsVerify
from .error import (
    TlsHandshakeError,
    CertificateExpired,
    CertificateHostnameMismatch,
    CertificateUntrusted,
)

# Subject DN buffer size (matches X509_NAME_oneline output limit)

# Subject DN buffer size (matches X509_NAME_oneline output limit)
comptime _CERT_SUBJ_LEN: Int = 512


@always_inline
fn _c_str(s: String) -> Int:
    """Return a C ``char*`` (as ``Int``) pointing to ``s``'s data.

    Safety: The returned pointer is valid only as long as ``s`` is alive.
    Never store the returned ``Int`` beyond the lifetime of ``s``.

    Args:
        s: Mojo ``String`` whose null-terminated bytes are to be passed to C.

    Returns:
        Integer representation of the ``const char*`` pointer.
    """
    # unsafe_ptr() returns a pointer to the null-terminated internal buffer.
    return Int(s.unsafe_ptr())


@always_inline
fn _c_err(lib: OwnedDLHandle) -> String:
    """Return the last OpenSSL error string from ``flare_ssl_last_error()``.

    Args:
        lib: Loaded ``libflare_tls.so`` handle.

    Returns:
        Human-readable error string (empty if no error).
    """
    var fn_err = lib.get_function[
        fn() -> UnsafePointer[UInt8, MutExternalOrigin]
    ]("flare_ssl_last_error")
    var p = fn_err()
    return String(StringSlice(unsafe_from_utf8_ptr=p))


fn _classify_tls_error(err: String, host: String) raises:
    """Map an OpenSSL error string to a typed TLS error and raise it.

    The C wrapper prefixes certificate verification failures with ``"verify:"``
    to distinguish them from generic I/O errors.

    Args:
        err:  Error string from ``flare_ssl_last_error()``.
        host: Hostname the client tried to connect to (for context).

    Raises:
        CertificateExpired:          If the cert has passed its ``notAfter``.
        CertificateHostnameMismatch: If hostname does not match the cert.
        CertificateUntrusted:        For other certificate verification failures.
        TlsHandshakeError:           For all other handshake errors.
    """
    if err.startswith("verify:"):
        var reason = String(err[7:])  # strip "verify:" prefix
        if (
            "certificate has expired" in reason
            or "certificate is not yet valid" in reason
        ):
            raise CertificateExpired(reason)
        if "hostname mismatch" in reason or "IP address mismatch" in reason:
            raise CertificateHostnameMismatch(host, reason)
        raise CertificateUntrusted(reason)
    raise TlsHandshakeError(err)


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
        Not thread-safe in v0.1.0.

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
    var _ssl: Int  # SSL*     as Int (0 = null / closed)
    var _tcp: TcpStream  # owns the TCP fd

    fn __init__(out self, var tcp: TcpStream, ctx: Int, ssl: Int):
        """Internal constructor — use ``TlsStream.connect`` instead.

        Args:
            tcp: Connected TCP stream (fd used by ssl after handshake).
            ctx: SSL_CTX* stored as Int.
            ssl: SSL* stored as Int (handshake already complete).
        """
        self._tcp = tcp^
        self._ctx = ctx
        self._ssl = ssl

    fn __moveinit__(out self, deinit take: TlsStream):
        self._tcp = take._tcp^
        self._ctx = take._ctx
        self._ssl = take._ssl

    fn __del__(deinit self):
        """Send ``close_notify`` and free OpenSSL objects (best-effort)."""
        if self._ssl != 0:
            try:
                var lib = OwnedDLHandle(_find_flare_lib())
                var fn_shutdown = lib.get_function[fn(Int) -> c_int](
                    "flare_ssl_shutdown"
                )
                _ = fn_shutdown(self._ssl)
                var fn_ssl_free = lib.get_function[fn(Int) -> None](
                    "flare_ssl_free"
                )
                fn_ssl_free(self._ssl)
                var fn_ctx_free = lib.get_function[fn(Int) -> None](
                    "flare_ssl_ctx_free"
                )
                fn_ctx_free(self._ctx)
            except:
                pass  # best-effort; tcp fd closed by _tcp.__del__

    # ── Context manager ───────────────────────────────────────────────────────

    fn __enter__(var self) -> TlsStream:
        """Transfer ownership of ``self`` into the ``with`` block.

        Returns:
            This ``TlsStream`` (moved).
        """
        return self^

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    fn connect(
        host: String, port: UInt16, config: TlsConfig
    ) raises -> TlsStream:
        """Open a TLS connection to ``host:port``.

        Resolves the hostname (IPv4), opens a ``TcpStream``, configures
        OpenSSL, and performs the TLS handshake.

        When ``config.verify == TlsVerify.NONE``, a security warning is
        printed to stderr on every call (intentional).

        Args:
            host:   Hostname or IP string. SNI is derived from this value.
            port:   Destination TCP port (typically 443 for HTTPS).
            config: TLS configuration (verification mode, CA bundle, mTLS).

        Returns:
            A ``TlsStream`` with the TLS handshake complete.

        Raises:
            NetworkError:                DNS resolution or TCP connect failure.
            TlsHandshakeError:           Generic TLS handshake failure.
            CertificateExpired:          Server cert has passed its notAfter.
            CertificateHostnameMismatch: Hostname does not match the cert.
            CertificateUntrusted:        Cert not trusted by any CA in bundle.
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

        # ── 1. DNS resolution and TCP connect ─────────────────────────────────
        var addrs = resolve_v4(host)
        if len(addrs) == 0:
            raise NetworkError(
                "DNS resolution returned no addresses for: " + host
            )
        var tcp = TcpStream.connect(SocketAddr(addrs[0], port))

        # ── 2. Load OpenSSL wrapper library ───────────────────────────────────
        var lib = OwnedDLHandle(_find_flare_lib())

        # Load function pointers (type annotations use Int for void* handles)
        var fn_ctx_new = lib.get_function[fn() -> Int]("flare_ssl_ctx_new")
        var fn_ctx_free = lib.get_function[fn(Int) -> None](
            "flare_ssl_ctx_free"
        )
        var fn_set_security = lib.get_function[fn(Int) -> c_int](
            "flare_ssl_ctx_set_security_policy"
        )
        var fn_set_verify = lib.get_function[fn(Int, c_int) -> c_int](
            "flare_ssl_ctx_set_verify_peer"
        )
        var fn_load_ca = lib.get_function[fn(Int, Int) -> c_int](
            "flare_ssl_ctx_load_ca_bundle"
        )
        var fn_load_cert_key = lib.get_function[fn(Int, Int, Int) -> c_int](
            "flare_ssl_ctx_load_cert_key"
        )
        var fn_ssl_new = lib.get_function[fn(Int, c_int) -> Int](
            "flare_ssl_new"
        )
        var fn_ssl_free = lib.get_function[fn(Int) -> None]("flare_ssl_free")
        var fn_ssl_connect = lib.get_function[fn(Int, Int) -> c_int](
            "flare_ssl_connect"
        )

        # ── 3. Create SSL_CTX and enforce security policy ─────────────────────
        var ctx = fn_ctx_new()
        if ctx == 0:
            raise TlsHandshakeError(_c_err(lib))

        if fn_set_security(ctx) != 0:
            fn_ctx_free(ctx)
            raise TlsHandshakeError("Security policy error: " + _c_err(lib))

        # ── 4. Certificate verification mode ─────────────────────────────────
        _ = fn_set_verify(ctx, c_int(config.verify))

        if fn_load_ca(ctx, _c_str(config.ca_bundle)) != 0:
            fn_ctx_free(ctx)
            raise TlsHandshakeError("CA bundle load failed: " + _c_err(lib))

        # ── 5. mTLS: load client cert + key if provided ───────────────────────
        if config.cert_file != "" and config.key_file != "":
            if (
                fn_load_cert_key(
                    ctx, _c_str(config.cert_file), _c_str(config.key_file)
                )
                != 0
            ):
                fn_ctx_free(ctx)
                raise TlsHandshakeError(
                    "mTLS cert/key load failed: " + _c_err(lib)
                )

        # ── 6. Create SSL session bound to the TCP fd ─────────────────────────
        var ssl = fn_ssl_new(ctx, c_int(tcp._socket.fd))
        if ssl == 0:
            fn_ctx_free(ctx)
            raise TlsHandshakeError(_c_err(lib))

        # ── 7. TLS handshake (flare_ssl_connect sends SNI) ────────────────────
        var sni = config.server_name if config.server_name != "" else host
        if fn_ssl_connect(ssl, _c_str(sni)) != 0:
            var err = _c_err(lib)
            fn_ssl_free(ssl)
            fn_ctx_free(ctx)
            _classify_tls_error(err, host)
            # _classify_tls_error always raises; unreachable:
            raise TlsHandshakeError(err)

        return TlsStream(tcp^, ctx, ssl)

    @staticmethod
    fn connect_timeout(
        host: String, port: UInt16, config: TlsConfig, timeout_ms: Int
    ) raises -> TlsStream:
        """Connect with TLS, failing after ``timeout_ms`` milliseconds.

        Uses ``TcpStream.connect_timeout`` for the TCP phase; the TLS
        handshake shares the same timeout budget in v0.1.0.

        Args:
            host:       Hostname or IP string.
            port:       Destination TCP port.
            config:     TLS configuration.
            timeout_ms: Maximum milliseconds for TCP + TLS handshake combined.

        Returns:
            A ``TlsStream`` with the handshake complete.

        Raises:
            ConnectionTimeout:           If the deadline expires during TCP.
            NetworkError:                DNS resolution failure.
            TlsHandshakeError:           Generic TLS handshake failure.
            CertificateExpired:          Server cert expired.
            CertificateHostnameMismatch: Hostname does not match the cert.
            CertificateUntrusted:        Cert not trusted by any CA.
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

        var addrs = resolve_v4(host)
        if len(addrs) == 0:
            raise NetworkError(
                "DNS resolution returned no addresses for: " + host
            )
        var tcp = TcpStream.connect_timeout(
            SocketAddr(addrs[0], port), timeout_ms
        )

        var lib = OwnedDLHandle(_find_flare_lib())
        var fn_ctx_new = lib.get_function[fn() -> Int]("flare_ssl_ctx_new")
        var fn_ctx_free = lib.get_function[fn(Int) -> None](
            "flare_ssl_ctx_free"
        )
        var fn_set_security = lib.get_function[fn(Int) -> c_int](
            "flare_ssl_ctx_set_security_policy"
        )
        var fn_set_verify = lib.get_function[fn(Int, c_int) -> c_int](
            "flare_ssl_ctx_set_verify_peer"
        )
        var fn_load_ca = lib.get_function[fn(Int, Int) -> c_int](
            "flare_ssl_ctx_load_ca_bundle"
        )
        var fn_ssl_new = lib.get_function[fn(Int, c_int) -> Int](
            "flare_ssl_new"
        )
        var fn_ssl_free = lib.get_function[fn(Int) -> None]("flare_ssl_free")
        var fn_ssl_connect = lib.get_function[fn(Int, Int) -> c_int](
            "flare_ssl_connect"
        )

        var ctx = fn_ctx_new()
        if ctx == 0:
            raise TlsHandshakeError(_c_err(lib))

        if fn_set_security(ctx) != 0:
            fn_ctx_free(ctx)
            raise TlsHandshakeError("Security policy error: " + _c_err(lib))

        _ = fn_set_verify(ctx, c_int(config.verify))

        if fn_load_ca(ctx, _c_str(config.ca_bundle)) != 0:
            fn_ctx_free(ctx)
            raise TlsHandshakeError("CA bundle load failed: " + _c_err(lib))

        var ssl = fn_ssl_new(ctx, c_int(tcp._socket.fd))
        if ssl == 0:
            fn_ctx_free(ctx)
            raise TlsHandshakeError(_c_err(lib))

        var sni = config.server_name if config.server_name != "" else host
        if fn_ssl_connect(ssl, _c_str(sni)) != 0:
            var err = _c_err(lib)
            fn_ssl_free(ssl)
            fn_ctx_free(ctx)
            _classify_tls_error(err, host)
            raise TlsHandshakeError(err)

        return TlsStream(tcp^, ctx, ssl)

    # ── I/O ───────────────────────────────────────────────────────────────────

    fn read(mut self, buf: UnsafePointer[UInt8], size: Int) raises -> Int:
        """Decrypt and read up to ``size`` bytes into ``buf``.

        Returns 0 on clean TLS closure (``close_notify`` received).

        Args:
            buf:  Destination buffer; the caller must provide at least
                  ``size`` bytes of valid storage.
            size: Maximum number of bytes to read.

        Returns:
            Bytes placed in ``buf``, or 0 on clean EOF.

        Raises:
            NetworkError: On I/O or decryption error.
        """
        var lib = OwnedDLHandle(_find_flare_lib())
        var fn_read = lib.get_function[fn(Int, Int, c_int) -> c_int](
            "flare_ssl_read"
        )
        var n = fn_read(self._ssl, Int(buf), c_int(size))
        if n < 0:
            raise NetworkError("TLS read error: " + _c_err(lib))
        return Int(n)

    fn read_exact(mut self, buf: UnsafePointer[UInt8], size: Int) raises:
        """Read exactly ``size`` bytes into ``buf``.

        Args:
            buf:  Destination buffer; must have at least ``size`` bytes.
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

    fn write(self, data: Span[UInt8]) raises -> Int:
        """Encrypt and send bytes.

        Args:
            data: Bytes to encrypt and transmit.

        Returns:
            Number of bytes written (may be less than ``len(data)``).

        Raises:
            NetworkError: On I/O or encryption error.
        """
        var lib = OwnedDLHandle(_find_flare_lib())
        var fn_write = lib.get_function[fn(Int, Int, c_int) -> c_int](
            "flare_ssl_write"
        )
        var n = fn_write(self._ssl, Int(data.unsafe_ptr()), c_int(len(data)))
        if n < 0:
            raise NetworkError("TLS write error: " + _c_err(lib))
        return Int(n)

    fn write_all(self, data: Span[UInt8]) raises:
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
            var chunk = Span[UInt8](ptr=ptr + sent, length=total - sent)
            sent += self.write(chunk)

    # ── Introspection ─────────────────────────────────────────────────────────

    fn tls_version(self) -> String:
        """Return the negotiated TLS version string.

        Returns:
            E.g. ``"TLSv1.3"`` or ``"TLSv1.2"``. Returns ``"unknown"`` if
            called before the handshake or if the library cannot be loaded.
        """
        try:
            var lib = OwnedDLHandle(_find_flare_lib())
            var fn_ver = lib.get_function[
                fn(Int) -> UnsafePointer[UInt8, MutExternalOrigin]
            ]("flare_ssl_get_version")
            var p = fn_ver(self._ssl)
            return String(StringSlice(unsafe_from_utf8_ptr=p))
        except:
            return "unknown"

    fn cipher_suite(self) -> String:
        """Return the negotiated cipher suite name.

        Returns:
            E.g. ``"TLS_AES_256_GCM_SHA384"`` or ``"unknown"``.
        """
        try:
            var lib = OwnedDLHandle(_find_flare_lib())
            var fn_cipher = lib.get_function[
                fn(Int) -> UnsafePointer[UInt8, MutExternalOrigin]
            ]("flare_ssl_get_cipher")
            var p = fn_cipher(self._ssl)
            return String(StringSlice(unsafe_from_utf8_ptr=p))
        except:
            return "unknown"

    fn peer_cert_subject(self) raises -> String:
        """Return the subject DN of the server's certificate.

        Args are described above. Do NOT use for security decisions —
        use ``config.verify`` for that.

        Returns:
            E.g. ``"/CN=example.com/O=Example Inc/C=US"``.

        Raises:
            NetworkError: If no peer certificate is available.
        """
        var lib = OwnedDLHandle(_find_flare_lib())
        var fn_subj = lib.get_function[fn(Int, Int, c_int) -> c_int](
            "flare_ssl_get_peer_cert_subject"
        )
        # Safety: buf is stack-allocated; fn_subj writes at most _CERT_SUBJ_LEN
        # bytes; String() copies before buf goes out of scope.
        var buf = stack_allocation[_CERT_SUBJ_LEN, UInt8]()
        var rc = fn_subj(self._ssl, Int(buf), c_int(_CERT_SUBJ_LEN))
        if rc != 0:
            raise NetworkError("peer_cert_subject: " + _c_err(lib))
        # Convert null-terminated C string to Mojo String
        return String(StringSlice(unsafe_from_utf8_ptr=buf))

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    fn close(mut self):
        """Send ``close_notify`` and close the underlying TCP stream.

        Idempotent — safe to call multiple times. The destructor also calls
        this, so explicit ``close()`` is not required.
        """
        if self._ssl != 0:
            try:
                var lib = OwnedDLHandle(_find_flare_lib())
                var fn_shutdown = lib.get_function[fn(Int) -> c_int](
                    "flare_ssl_shutdown"
                )
                _ = fn_shutdown(self._ssl)
                var fn_ssl_free = lib.get_function[fn(Int) -> None](
                    "flare_ssl_free"
                )
                fn_ssl_free(self._ssl)
                var fn_ctx_free = lib.get_function[fn(Int) -> None](
                    "flare_ssl_ctx_free"
                )
                fn_ctx_free(self._ctx)
            except:
                pass
            self._ssl = 0
            self._ctx = 0
        self._tcp.close()
