"""Mojo bindings for the server-side TLS FFI helpers.

Exposes the C-side functions added to
``flare/tls/ffi/openssl_wrapper.cpp`` for the server-side SSL_CTX
+ SSL lifecycle. Mirrors the ``flare/tls/stream.mojo`` binding
pattern: ``OwnedDLHandle`` to ``libflare_tls.so``, individually
typed ``get_function`` calls per FFI export.

Minimum-friction surface for the C7 reactor state machine:

- ``ServerCtx``: holds an ``SSL_CTX*`` (as ``Int``) plus the
  loaded ``OwnedDLHandle``.
- ``ServerCtx.new(cert_path, key_path)``: combine new + load.
- ``ServerCtx.set_alpn(protos)``: ALPN preference (servers
  bound here advertise + select via the C-side callback).
- ``ServerCtx.set_verify_client_cert(ca_path)``: mTLS opt-in.
- ``ServerCtx.reload(cert_path, key_path)``: cert rotation.
- ``ServerCtx.new_accept(fd)``: returns an ``Int`` SSL handle.
- ``ServerSsl``: holds the SSL handle + a borrow on the loaded
  library; ``do_handshake`` returns 0 / 1 / 2 / -1 per the C
  contract; ``alpn_selected``, ``protocol``, ``cipher``, and
  ``sni_host`` read introspection state.

Wiring into ``TlsAcceptor`` (which today is API-surface
scaffolding from S3.1) lands in C7 alongside the reactor
``STATE_TLS_HANDSHAKE`` state machine; this file is the FFI
layer those wires plug into.

## OwnedDLHandle / ASAP-destruction discipline

Mojo's ASAP destruction policy reclaims an ``OwnedDLHandle`` right
after its last Mojo-visible use. In a naive ``var lib =
OwnedDLHandle(...); var fn = lib.get_function(...); fn(...)``
sequence the runtime considers ``lib`` dead immediately after
``get_function`` returns and runs the destructor (``dlclose``)
before ``fn`` is invoked, leaving the cached function pointer
dangling into freed memory. The same applies in subtler ways to
struct-field handles when the JIT can prove no further field reads
follow within a method.

The discipline this file follows: every FFI call goes through a
``_do_*(read lib: OwnedDLHandle, ...)`` borrow helper that does
both ``get_function`` and the invocation inside the borrow. Public
methods open the handle (or read it from ``self._lib``) and
delegate. Same idiom as ``flare.http.encoding._do_compress`` and
``flare.http.middleware._flare_fs_access``.
"""

from std.ffi import c_int, OwnedDLHandle
from std.memory import UnsafePointer

from ..net import _find_flare_lib


# ── FFI handle wrappers ────────────────────────────────────────────────────


def _c_str(s: String) -> Int:
    """Return ``s``'s UTF-8 byte pointer as an ``Int`` for FFI
    pass-through. ``s`` must outlive the call."""
    return Int(s.unsafe_ptr())


# ── Borrow helpers (one per FFI export) ───────────────────────────────────
#
# Every helper takes ``read lib: OwnedDLHandle`` and does both
# ``get_function`` and the call inside the borrow, so the dylib
# stays mapped across the entire FFI surface.


def _do_ssl_ctx_new_server(
    read lib: OwnedDLHandle, cert_path: String, key_path: String
) raises -> Int:
    var f = lib.get_function[def(Int, Int) thin abi("C") -> Int](
        "flare_ssl_ctx_new_server"
    )
    var addr = f(_c_str(cert_path), _c_str(key_path))
    if addr == 0:
        raise Error("flare_ssl_ctx_new_server failed (see TLS error log)")
    return addr


def _do_ssl_ctx_free(read lib: OwnedDLHandle, addr: Int):
    var f = lib.get_function[def(Int) thin abi("C") -> None](
        "flare_ssl_ctx_free"
    )
    f(addr)


def _do_ssl_ctx_reload(
    read lib: OwnedDLHandle, addr: Int, cert_path: String, key_path: String
) raises:
    var f = lib.get_function[def(Int, Int, Int) thin abi("C") -> c_int](
        "flare_ssl_ctx_reload"
    )
    if Int(f(addr, _c_str(cert_path), _c_str(key_path))) != 0:
        raise Error("flare_ssl_ctx_reload failed")


def _do_ssl_ctx_set_alpn(
    read lib: OwnedDLHandle, addr: Int, protos: List[UInt8]
) raises:
    var f = lib.get_function[def(Int, Int, c_int) thin abi("C") -> c_int](
        "flare_ssl_ctx_set_alpn_server"
    )
    if Int(f(addr, Int(protos.unsafe_ptr()), c_int(len(protos)))) != 0:
        raise Error("flare_ssl_ctx_set_alpn_server failed")


def _do_ssl_ctx_set_verify_client_cert(
    read lib: OwnedDLHandle, addr: Int, ca_path: String
) raises:
    var f = lib.get_function[def(Int, Int) thin abi("C") -> c_int](
        "flare_ssl_ctx_set_verify_client_cert"
    )
    if Int(f(addr, _c_str(ca_path))) != 0:
        raise Error("flare_ssl_ctx_set_verify_client_cert failed")


def _do_ssl_new_accept(read lib: OwnedDLHandle, ctx_addr: Int, fd: Int) -> Int:
    var f = lib.get_function[def(Int, c_int) thin abi("C") -> Int](
        "flare_ssl_new_accept"
    )
    return f(ctx_addr, c_int(fd))


def _do_ssl_do_handshake(read lib: OwnedDLHandle, ssl_addr: Int) -> Int:
    var f = lib.get_function[def(Int) thin abi("C") -> c_int](
        "flare_ssl_do_handshake"
    )
    return Int(f(ssl_addr))


def _do_ssl_get_alpn_selected(read lib: OwnedDLHandle, ssl_addr: Int) -> String:
    var f = lib.get_function[def(Int, Int, c_int) thin abi("C") -> c_int](
        "flare_ssl_get_alpn_selected"
    )
    var buf = List[UInt8](capacity=64)
    buf.resize(64, UInt8(0))
    var n = Int(f(ssl_addr, Int(buf.unsafe_ptr()), c_int(64)))
    if n <= 0:
        return ""
    return String(unsafe_from_utf8=Span[UInt8, _](buf[:n]))


def _do_ssl_get_sni_host(read lib: OwnedDLHandle, ssl_addr: Int) -> String:
    var f = lib.get_function[def(Int, Int, c_int) thin abi("C") -> c_int](
        "flare_ssl_get_sni_host"
    )
    var buf = List[UInt8](capacity=256)
    buf.resize(256, UInt8(0))
    var n = Int(f(ssl_addr, Int(buf.unsafe_ptr()), c_int(256)))
    if n <= 0:
        return ""
    return String(unsafe_from_utf8=Span[UInt8, _](buf[:n]))


def _do_ssl_free(read lib: OwnedDLHandle, ssl_addr: Int):
    var f = lib.get_function[def(Int) thin abi("C") -> None]("flare_ssl_free")
    f(ssl_addr)


# ── ServerCtx wrapper ─────────────────────────────────────────────────────


struct ServerCtx(Movable):
    """Server-side ``SSL_CTX`` wrapper.

    Owns the underlying ``SSL_CTX*`` and the loaded
    ``libflare_tls.so`` handle. Drop runs ``flare_ssl_ctx_free``
    so the OpenSSL reference is released.
    """

    var _addr: Int
    """Raw ``SSL_CTX*`` as an ``Int``. Zero means uninitialised
    or already freed."""

    var _lib: OwnedDLHandle
    """Pinned library handle so dlclose doesn't tear the .so out
    from under any in-flight ``SSL`` we created."""

    def __init__(out self, var lib: OwnedDLHandle, addr: Int):
        self._lib = lib^
        self._addr = addr

    def __del__(deinit self):
        if self._addr != 0:
            _do_ssl_ctx_free(self._lib, self._addr)

    @staticmethod
    def new(cert_path: String, key_path: String) raises -> ServerCtx:
        """Construct a server ``SSL_CTX`` configured with TLS 1.2+
        / forward-secret AEAD ciphers and the supplied cert /
        key. Raises on cert load / key mismatch / null alloc.
        """
        var lib = OwnedDLHandle(_find_flare_lib())
        var addr = _do_ssl_ctx_new_server(lib, cert_path, key_path)
        return ServerCtx(lib^, addr)

    def reload(self, cert_path: String, key_path: String) raises:
        """Reload cert + key without restarting. Raises on file
        load error / key mismatch."""
        _do_ssl_ctx_reload(self._lib, self._addr, cert_path, key_path)

    def set_alpn(self, protos: List[UInt8]) raises:
        """Set the wire-format ALPN protocols list.

        ``protos`` is the OpenSSL wire format:
        ``len_byte || proto_bytes || len_byte || proto_bytes || ...``
        For example, advertising ``["h2", "http/1.1"]`` is:
        ``[2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1']``.
        """
        _do_ssl_ctx_set_alpn(self._lib, self._addr, protos)

    def set_verify_client_cert(self, ca_path: String) raises:
        """Enable mTLS — clients must present a cert signed by a
        CA in ``ca_path``."""
        _do_ssl_ctx_set_verify_client_cert(self._lib, self._addr, ca_path)

    def addr(self) -> Int:
        """Underlying ``SSL_CTX*`` as an Int."""
        return self._addr


def server_ssl_new_accept(ctx: ServerCtx, fd: Int) raises -> Int:
    """Wrap ``SSL_new + SSL_set_fd + SSL_set_accept_state`` into
    a single FFI call. Returns the ``SSL*`` as an ``Int`` (or 0
    on failure). The reactor caller is responsible for calling
    ``flare_ssl_free`` to release."""
    return _do_ssl_new_accept(ctx._lib, ctx._addr, fd)


def server_ssl_do_handshake(ctx: ServerCtx, ssl_addr: Int) raises -> Int:
    """Drive ``SSL_accept`` one step. Returns:

    - 0 → handshake complete.
    - 1 → WANT_READ; reactor should re-arm readable interest.
    - 2 → WANT_WRITE; reactor should re-arm writable interest.
    - -1 → fatal; close the connection.
    """
    return _do_ssl_do_handshake(ctx._lib, ssl_addr)


def server_ssl_get_alpn_selected(
    ctx: ServerCtx, ssl_addr: Int
) raises -> String:
    """Return the negotiated ALPN protocol, or empty string if
    none was negotiated."""
    return _do_ssl_get_alpn_selected(ctx._lib, ssl_addr)


def server_ssl_get_sni_host(ctx: ServerCtx, ssl_addr: Int) raises -> String:
    """Return the SNI hostname the client sent, or empty string
    if no SNI extension was present."""
    return _do_ssl_get_sni_host(ctx._lib, ssl_addr)


def server_ssl_free(ctx: ServerCtx, ssl_addr: Int) raises:
    """Release an ``SSL*`` allocated via ``server_ssl_new_accept``."""
    if ssl_addr == 0:
        return
    _do_ssl_free(ctx._lib, ssl_addr)
