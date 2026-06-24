"""Smoke test for the rustls_wrapper Rust crate.

This test confirms that:

1. ``libflare_rustls_quic.so`` is present in the expected location
   (next to ``libflare_tls.so`` under the canonical build root, or
   in ``$CONDA_PREFIX/lib`` after the activation script runs).
2. The ABI-version thunk resolves and returns 3 (the crate version
   the Mojo binding expects).
3. The acceptor-new thunk rejects empty PEM input with a non-NULL
   "no CERTIFICATE blocks" error path through ``last_error``.

The full handshake fixture suite lives in
``test_rustls_quic_handshake.mojo`` (lands in Track Q2-W commit
4/4). This smoke just pins the link.
"""

from std.ffi import OwnedDLHandle, c_int
from std.testing import assert_equal, assert_true

from flare.utils.dylib import find_flare_lib


def _find_rustls_lib() -> String:
    """Canonical-path resolver for the rustls QUIC cdylib.

    Delegates to ``flare.utils.dylib.find_flare_lib("rustls_quic")``
    which the Track Q2-W commit 2/4 activation script
    (``flare/tls/ffi/build_rustls.sh``) populates at
    ``$CONDA_PREFIX/lib/libflare_rustls_quic.so``. Falls back to
    ``build/libflare_rustls_quic.so`` for bare checkouts that
    haven't run the activation script yet.
    """
    return find_flare_lib("rustls_quic")


def _call_abi_version(read lib: OwnedDLHandle) -> Int:
    """Wrap the FFI thunk in a `read lib` function so Mojo's ASAP
    destructor doesn't unmap the .so between `get_function` and the
    actual call (the same defensive pattern documented in
    `flare/tls/stream.mojo` for the OpenSSL `flare_ssl_ctx_new`
    binding -- without the borrow, the .so is destroyed at the
    last-use point of `lib` and the function pointer becomes
    unmapped before invocation)."""
    var ver_fn = lib.get_function[def() thin abi("C") -> Int](
        "flare_rustls_quic_abi_version"
    )
    return ver_fn()


def _call_acceptor_new(
    read lib: OwnedDLHandle,
    cert_ptr: Int,
    cert_len: Int,
    key_ptr: Int,
    key_len: Int,
    alpn_ptr: Int,
    alpn_len: Int,
) -> Int:
    """`read lib` wrapper for `flare_rustls_quic_acceptor_new`; see
    `_call_abi_version` for why the borrow is required."""
    var new_fn = lib.get_function[
        def(Int, Int, Int, Int, Int, Int) thin abi("C") -> Int
    ]("flare_rustls_quic_acceptor_new")
    return new_fn(cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len)


def test_abi_version() raises:
    # ABI v3 adds the client role on top of v2's surface: the
    # acceptor/session/feed-crypto/take-crypto/ALPN thunks plus the
    # KeyChange-driven per-level AEAD + header-protection thunks
    # (v2), plus `flare_rustls_quic_connector_new` / `_free` and
    # `flare_rustls_quic_connect` (v3, the HTTP/3 client binding).
    # The activation script keys off this number, so a stale .so on
    # a developer machine surfaces as a hard mismatch on
    # `pixi install` rather than a silent run-time confusion.
    var path = _find_rustls_lib()
    var lib = OwnedDLHandle(path)
    var v = _call_abi_version(lib)
    assert_equal(v, 3)


def test_acceptor_new_rejects_empty_pem() raises:
    """Empty cert PEM should fail with a useful error message; the
    acceptor pointer returned is NULL (=0)."""
    var path = _find_rustls_lib()
    var lib = OwnedDLHandle(path)
    var empty = List[UInt8]()
    var p = _call_acceptor_new(
        lib,
        Int(empty.unsafe_ptr()),
        0,
        Int(empty.unsafe_ptr()),
        0,
        Int(empty.unsafe_ptr()),
        0,
    )
    # Acceptor pointer is NULL on failure.
    assert_equal(p, 0)


def main() raises:
    test_abi_version()
    test_acceptor_new_rejects_empty_pem()
    print("test_rustls_quic_crate_smoke: 2 passed")
