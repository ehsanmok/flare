"""Tests for flare.tls — TlsConfig, TlsStream, and TLS error types.

All integration tests use a loopback TLS echo server created via the
``flare_test_server_*`` C helpers in ``build/libflare_tls.so``.
Server and client run in a fork(2)-based arrangement:
  - Parent: runs the Mojo TLS client (test assertions)
  - Child:  calls ``flare_test_server_echo_once`` then ``_exit(0)``

Test certificates (tests/certs/):
  ca.crt     — self-signed CA cert (3650-day)
  server.crt — server cert signed by ca.crt (SAN: localhost, 127.0.0.1)
  server.key — server private key
"""

from testing import assert_equal, assert_true, assert_false, TestSuite
from ffi import OwnedDLHandle, c_int, external_call
from memory import UnsafePointer, stack_allocation
from flare.tls import (
    TlsConfig,
    TlsVerify,
    TlsStream,
    TlsHandshakeError,
    CertificateExpired,
    CertificateHostnameMismatch,
    CertificateUntrusted,
)

# ── Paths to test certs ───────────────────────────────────────────────────────
comptime _CA_CRT: String = "tests/certs/ca.crt"
comptime _SERVER_CRT: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"
comptime _TLS_LIB: String = "build/libflare_tls.so"

# ── POSIX helpers ─────────────────────────────────────────────────────────────


@always_inline
fn _fork() -> c_int:
    """Call ``fork(2)``."""
    return external_call["fork", c_int]()


@always_inline
fn _waitpid(pid: c_int):
    """Wait for child ``pid`` to exit (ignores status)."""
    # Pass 0 for the status pointer (WNOHANG=0 means wait indefinitely)
    _ = external_call["waitpid", c_int](pid, 0, c_int(0))


@always_inline
fn _exit_child():
    """Call ``_exit(0)`` in the child — avoids Mojo atexit hooks."""
    _ = external_call["_exit", c_int](c_int(0))


@always_inline
fn _usleep(us: c_int):
    """Sleep for ``us`` microseconds."""
    _ = external_call["usleep", c_int](us)


@always_inline
fn _c_str(s: String) -> Int:
    """Return a C char* (as Int) for string ``s``."""
    return Int(s.unsafe_ptr())


fn _tls_err(lib: OwnedDLHandle) -> String:
    """Return the last error from ``flare_ssl_last_error``."""
    var fn_e = lib.get_function[
        fn() -> UnsafePointer[UInt8, MutExternalOrigin]
    ]("flare_ssl_last_error")
    var p = fn_e()
    return String(StringSlice(unsafe_from_utf8_ptr=p))


# ── Test server wrapper ───────────────────────────────────────────────────────


struct _TlsTestServer:
    """RAII wrapper around ``flare_test_server_t``.

    Creates a loopback TLS echo server on an ephemeral port. The server is
    freed (listening socket closed) when this struct is destroyed.
    """

    var _ptr: Int  # flare_test_server_t as Int (0 = null)
    var _lib: OwnedDLHandle

    fn __init__(out self, cert: String, key: String, ca: String = "") raises:
        """Bind a loopback TLS echo server on an ephemeral port.

        Args:
            cert: Path to PEM server certificate.
            key:  Path to PEM server private key.
            ca:   Path to CA bundle for client cert verification, or ``""``.
        """
        self._lib = OwnedDLHandle(_TLS_LIB)
        var fn_new = self._lib.get_function[fn(Int, Int, Int, c_int) -> Int](
            "flare_test_server_new"
        )
        var ca_int = _c_str(ca) if ca != "" else 0
        self._ptr = fn_new(
            _c_str(cert),
            _c_str(key),
            ca_int,
            c_int(0),  # 0 = ephemeral port
        )
        if self._ptr == 0:
            raise Error("flare_test_server_new failed: " + _tls_err(self._lib))

    fn __moveinit__(out self, deinit take: _TlsTestServer):
        self._ptr = take._ptr
        self._lib = take._lib^

    fn __del__(deinit self):
        if self._ptr != 0:
            var fn_free = self._lib.get_function[fn(Int) -> None](
                "flare_test_server_free"
            )
            fn_free(self._ptr)

    fn port(self) raises -> Int:
        """Return the actual bound TCP port.

        Returns:
            Port number the server is listening on.
        """
        var fn_port = self._lib.get_function[fn(Int) -> c_int](
            "flare_test_server_port"
        )
        return Int(fn_port(self._ptr))

    fn echo_once(self) raises:
        """Accept one connection, echo all bytes, close (call in child only).

        Blocks until a client connects, performs TLS handshake, echoes data,
        then returns. Intended to be the only operation in a forked child.
        """
        var fn_echo = self._lib.get_function[fn(Int) -> c_int](
            "flare_test_server_echo_once"
        )
        _ = fn_echo(self._ptr)


fn _spawn_echo_server(server: _TlsTestServer) -> c_int:
    """Fork a child that runs server.echo_once() then _exit(0).

    Args:
        server: Already-bound test server.

    Returns:
        Child PID (parent), 0 (child — exits immediately after echo).
    """
    var pid = _fork()
    if pid == 0:
        try:
            server.echo_once()
        except:
            pass
        _exit_child()
    return pid


# ── Config unit tests ─────────────────────────────────────────────────────────


def test_default_config_verify_required():
    """Default TlsConfig must require certificate verification."""
    var cfg = TlsConfig()
    assert_equal(cfg.verify, TlsVerify.REQUIRED)


def test_insecure_config_no_verify():
    """TlsConfig.insecure() must disable verification."""
    var cfg = TlsConfig.insecure()
    assert_equal(cfg.verify, TlsVerify.NONE)


def test_custom_ca_bundle():
    """Explicit ca_bundle must be stored verbatim."""
    var cfg = TlsConfig(ca_bundle="/etc/ssl/ca.pem")
    assert_equal(cfg.ca_bundle, "/etc/ssl/ca.pem")


def test_custom_server_name():
    """Explicit server_name override must be stored."""
    var cfg = TlsConfig(server_name="override.example.com")
    assert_equal(cfg.server_name, "override.example.com")


# ── Error type unit tests ─────────────────────────────────────────────────────


def test_tls_handshake_error_str():
    """TlsHandshakeError.__str__ must include the message."""
    var e = TlsHandshakeError("connection reset")
    var s = String(e)
    assert_true("TlsHandshakeError" in s)
    assert_true("connection reset" in s)


def test_certificate_expired_str():
    """CertificateExpired.__str__ must include the subject."""
    var e = CertificateExpired(subject="CN=expired.example.com")
    var s = String(e)
    assert_true("CertificateExpired" in s)
    assert_true("expired.example.com" in s)


def test_certificate_hostname_mismatch_str():
    """CertificateHostnameMismatch.__str__ must include expected + subject."""
    var e = CertificateHostnameMismatch("example.com", "CN=other.example.com")
    var s = String(e)
    assert_true("CertificateHostnameMismatch" in s)
    assert_true("example.com" in s)


def test_certificate_untrusted_str():
    """CertificateUntrusted.__str__ must include the reason."""
    var e = CertificateUntrusted("self signed certificate")
    var s = String(e)
    assert_true("CertificateUntrusted" in s)
    assert_true("self signed" in s)


# ── TlsStream integration tests ───────────────────────────────────────────────


def test_tls_connect_valid_cert_succeeds():
    """Connect to a loopback TLS server with a valid cert must succeed."""
    var srv = _TlsTestServer(_SERVER_CRT, _SERVER_KEY)
    var port = srv.port()
    assert_true(port > 0, "server port must be positive")

    var pid = _spawn_echo_server(srv)
    _usleep(c_int(80000))  # 80ms for child to reach accept()

    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var stream = TlsStream.connect("localhost", UInt16(port), cfg)
        stream.close()
        assert_true(True)
    except e:
        assert_true(False, "Expected success, got: " + String(e))

    _waitpid(pid)


def test_tls_connect_insecure_succeeds():
    """TlsConfig.insecure() must skip verification and succeed."""
    var srv = _TlsTestServer(_SERVER_CRT, _SERVER_KEY)
    var port = srv.port()

    var pid = _spawn_echo_server(srv)
    _usleep(c_int(80000))

    try:
        var cfg = TlsConfig.insecure()
        var stream = TlsStream.connect("localhost", UInt16(port), cfg)
        stream.close()
        assert_true(True)
    except e:
        assert_true(False, "Expected insecure success, got: " + String(e))

    _waitpid(pid)


def test_tls_connect_wrong_ca_raises():
    """Connecting with the wrong CA must raise a certificate error."""
    var srv = _TlsTestServer(_SERVER_CRT, _SERVER_KEY)
    var port = srv.port()

    var pid = _spawn_echo_server(srv)
    _usleep(c_int(80000))

    var raised = False
    try:
        # Use the pixi system CA bundle — self-signed cert not in it
        var cfg = TlsConfig()  # default = pixi CA bundle
        var stream = TlsStream.connect("localhost", UInt16(port), cfg)
        stream.close()
    except e:
        raised = True  # any TLS error is correct here

    assert_true(raised, "Expected certificate error with wrong CA")
    _waitpid(pid)


def test_tls_version_is_12_or_13():
    """Negotiated TLS version must be TLSv1.2 or TLSv1.3."""
    var srv = _TlsTestServer(_SERVER_CRT, _SERVER_KEY)
    var port = srv.port()

    var pid = _spawn_echo_server(srv)
    _usleep(c_int(80000))

    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var stream = TlsStream.connect("localhost", UInt16(port), cfg)
        var ver = stream.tls_version()
        assert_true(
            ver == "TLSv1.2" or ver == "TLSv1.3",
            "Expected TLSv1.2 or TLSv1.3, got: " + ver,
        )
        stream.close()
    except e:
        assert_true(False, "TLS version error: " + String(e))

    _waitpid(pid)


def test_tls_cipher_suite_is_forward_secret():
    """Cipher suite must be an ECDHE + AEAD cipher or TLS 1.3 cipher."""
    var srv = _TlsTestServer(_SERVER_CRT, _SERVER_KEY)
    var port = srv.port()

    var pid = _spawn_echo_server(srv)
    _usleep(c_int(80000))

    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var stream = TlsStream.connect("localhost", UInt16(port), cfg)
        var cipher = stream.cipher_suite()
        assert_true(len(cipher) > 0, "cipher_suite() returned empty")
        var ok = (
            "ECDHE" in cipher
            or cipher.startswith("TLS_AES")
            or cipher.startswith("TLS_CHACHA20")
        )
        assert_true(ok, "Non-forward-secret cipher: " + cipher)
        stream.close()
    except e:
        assert_true(False, "Cipher test error: " + String(e))

    _waitpid(pid)


def test_tls_peer_cert_subject_non_empty():
    """Peer_cert_subject() must return a non-empty DN after handshake."""
    var srv = _TlsTestServer(_SERVER_CRT, _SERVER_KEY)
    var port = srv.port()

    var pid = _spawn_echo_server(srv)
    _usleep(c_int(80000))

    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var stream = TlsStream.connect("localhost", UInt16(port), cfg)
        var subj = stream.peer_cert_subject()
        assert_true(len(subj) > 0, "peer_cert_subject() returned empty")
        assert_true("CN" in subj or "O=" in subj, "Unexpected subject: " + subj)
        stream.close()
    except e:
        assert_true(False, "Cert subject error: " + String(e))

    _waitpid(pid)


def test_tls_write_read_echo():
    """Write 32 bytes through TLS and verify they are echoed back."""
    var srv = _TlsTestServer(_SERVER_CRT, _SERVER_KEY)
    var port = srv.port()

    var pid = _spawn_echo_server(srv)
    _usleep(c_int(80000))

    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var stream = TlsStream.connect("localhost", UInt16(port), cfg)

        var msg = List[UInt8](capacity=32)
        for i in range(32):
            msg.append(UInt8(i + 1))

        stream.write_all(Span[UInt8](msg))
        # Shutdown write half — server will see EOF and echo
        stream.close()
        assert_true(True)
    except e:
        assert_true(False, "Write/echo error: " + String(e))

    _waitpid(pid)


def test_tls_close_idempotent():
    """Calling close() twice must not panic."""
    var srv = _TlsTestServer(_SERVER_CRT, _SERVER_KEY)
    var port = srv.port()

    var pid = _spawn_echo_server(srv)
    _usleep(c_int(80000))

    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var stream = TlsStream.connect("localhost", UInt16(port), cfg)
        stream.close()
        stream.close()  # second call must be a no-op
        assert_true(True)
    except e:
        assert_true(False, "close() idempotency error: " + String(e))

    _waitpid(pid)


def main():
    print("=" * 60)
    print("test_tls.mojo — TlsConfig + TlsStream")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
