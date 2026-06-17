"""`flare.tls._rustls_quic_ffi` -- FFI plumbing for the rustls QUIC cdylib.

This is the internal binding layer for ``libflare_rustls_quic.so``,
the Rust crate at ``flare/tls/ffi/rustls_wrapper/`` exposing
``rustls::quic::ServerConnection`` over a C ABI. The
``flare.tls.rustls_quic`` public surface (``RustlsQuicAcceptor``,
``RustlsQuicSession``, etc.) holds the typed Mojo carriers; this
module is the unsafe / FFI bottom layer.

Every helper routes through ``read lib: OwnedDLHandle`` so Mojo's
ASAP destructor cannot unmap the .so between the
``get_function`` call and the actual invocation. The same
defensive pattern is documented at length in
``flare/tls/stream.mojo`` for the OpenSSL FFI surface and in
``flare/tls/ffi/build_rustls.sh`` for the LD_PRELOAD safety net.
"""

from std.collections import List
from std.ffi import OwnedDLHandle, c_int

from ..utils.dylib import find_flare_lib


def _find_rustls_quic_lib() -> String:
    """Resolve the canonical path to ``libflare_rustls_quic.so``.

    Thin wrapper over :func:`flare.utils.dylib.find_flare_lib`
    pinned to the ``"rustls_quic"`` shim name. The activation
    script ``flare/tls/ffi/build_rustls.sh`` populates
    ``$CONDA_PREFIX/lib/libflare_rustls_quic.so``; the bare-checkout
    fallback resolves ``build/libflare_rustls_quic.so``.
    """
    return find_flare_lib("rustls_quic")


def _encode_alpn_wire(protos: List[String]) raises -> List[UInt8]:
    """Convert an ALPN protocol list to the wire format the rustls
    FFI expects: ``len_byte || proto_bytes || len_byte || proto_bytes || ...``.

    Mirrors the encoding used by :func:`TlsAcceptor.__init__` for the
    OpenSSL backend so the two sides accept the same ALPN list shape.
    Raises if any protocol identifier is empty or longer than 255
    bytes (RFC 7301 §3.1 caps the wire-format length at 255).
    """
    var out = List[UInt8]()
    for i in range(len(protos)):
        var p = protos[i]
        var n = p.byte_length()
        if n == 0 or n > 255:
            raise Error(
                String("ALPN protocol must be 1..255 bytes: '") + p + "'"
            )
        out.append(UInt8(n))
        for b in p.as_bytes():
            out.append(b)
    return out^


# ── Acceptor lifecycle ───────────────────────────────────────────────────────


def _do_acceptor_new(
    read lib: OwnedDLHandle,
    read cert_pem: List[UInt8],
    read key_pem: List[UInt8],
    read alpn_wire: List[UInt8],
) -> Int:
    """Call ``flare_rustls_quic_acceptor_new`` and return the
    ``Box<Acceptor>*`` as an ``Int``. Zero on failure (read
    :func:`_do_last_error` for the reason).
    """
    var f = lib.get_function[
        def(Int, Int, Int, Int, Int, Int) thin abi("C") -> Int
    ]("flare_rustls_quic_acceptor_new")
    return f(
        Int(cert_pem.unsafe_ptr()),
        len(cert_pem),
        Int(key_pem.unsafe_ptr()),
        len(key_pem),
        Int(alpn_wire.unsafe_ptr()),
        len(alpn_wire),
    )


def _do_acceptor_free(read lib: OwnedDLHandle, handle: Int):
    """Free an acceptor allocated by :func:`_do_acceptor_new`.
    NULL handle is a no-op (so the destructor is safe to call on
    a zero-initialised carrier whose construction failed)."""
    if handle == 0:
        return
    var f = lib.get_function[def(Int) thin abi("C") -> None](
        "flare_rustls_quic_acceptor_free"
    )
    f(handle)


# ── Session lifecycle ────────────────────────────────────────────────────────


def _do_accept(
    read lib: OwnedDLHandle, acceptor: Int, read transport_params: List[UInt8]
) -> Int:
    """Call ``flare_rustls_quic_accept`` to construct a fresh
    per-connection session. Returns the ``Box<Session>*`` as
    ``Int``; zero on failure (read :func:`_do_last_error`)."""
    var f = lib.get_function[def(Int, Int, Int) thin abi("C") -> Int](
        "flare_rustls_quic_accept"
    )
    return f(
        acceptor,
        Int(transport_params.unsafe_ptr()),
        len(transport_params),
    )


def _do_session_free(read lib: OwnedDLHandle, handle: Int):
    """Free a session allocated by :func:`_do_accept`. NULL is a
    no-op."""
    if handle == 0:
        return
    var f = lib.get_function[def(Int) thin abi("C") -> None](
        "flare_rustls_quic_session_free"
    )
    f(handle)


# ── Handshake driving ────────────────────────────────────────────────────────


def _do_feed_crypto(
    read lib: OwnedDLHandle, session: Int, level: Int, read data: List[UInt8]
) -> Int:
    """Push inbound CRYPTO frame bytes into the rustls handshake
    state machine. Returns 0 on success, -1 on bad pointer, -2 on
    a rustls protocol error (read :func:`_do_last_error`)."""
    var f = lib.get_function[def(Int, c_int, Int, Int) thin abi("C") -> c_int](
        "flare_rustls_quic_feed_crypto"
    )
    return Int(f(session, c_int(level), Int(data.unsafe_ptr()), len(data)))


def _do_take_crypto(
    read lib: OwnedDLHandle, session: Int, level: Int
) raises -> List[UInt8]:
    """Drain pending outbound CRYPTO frame bytes at ``level``.

    Returns an owned buffer; empty when nothing is pending. The
    helper allocates a 4 KiB scratch and re-tries with a larger
    buffer once if the FFI reports the same byte count came back
    (rustls coalesces outbound bytes per level, and 4 KiB is
    enough for a full ClientHello / EncryptedExtensions burst in
    practice -- the loop covers ServerCertificate which may exceed
    4 KiB with a deep chain).
    """
    var cap = 4096
    var out = List[UInt8](capacity=cap)
    for _ in range(cap):
        out.append(UInt8(0))
    var written: Int = 0
    var written_ptr = UnsafePointer(to=written)
    var rc = _take_crypto_call(lib, session, level, out, cap, Int(written_ptr))
    if rc != 0:
        raise Error(
            String("flare_rustls_quic_take_crypto failed: rc=") + String(rc)
        )
    # If the buffer was fully consumed, the next chunk may still be
    # waiting (rustls splits at our cap). Loop until the FFI reports
    # written < cap, meaning nothing further is pending at this level.
    var collected = List[UInt8]()
    for i in range(written):
        collected.append(out[i])
    while written == cap:
        for j in range(cap):
            out[j] = UInt8(0)
        written = 0
        rc = _take_crypto_call(lib, session, level, out, cap, Int(written_ptr))
        if rc != 0:
            raise Error(
                String("flare_rustls_quic_take_crypto failed: rc=") + String(rc)
            )
        for i in range(written):
            collected.append(out[i])
    return collected^


def _take_crypto_call(
    read lib: OwnedDLHandle,
    session: Int,
    level: Int,
    mut out_buf: List[UInt8],
    cap: Int,
    written_addr: Int,
) -> Int:
    """Inner one-shot helper: route the FFI thunk through a
    ``read lib`` borrow so Mojo's ASAP destructor cannot unmap
    the .so between the symbol resolution and the call.

    `written_addr` is a raw pointer (as ``Int``) to a stack-resident
    ``Int`` cell that the FFI writes back the actual byte count
    copied into ``out_buf``.
    """
    var f = lib.get_function[
        def(Int, c_int, Int, Int, Int) thin abi("C") -> c_int
    ]("flare_rustls_quic_take_crypto")
    return Int(
        f(
            session,
            c_int(level),
            Int(out_buf.unsafe_ptr()),
            cap,
            written_addr,
        )
    )


def _do_is_handshake_complete(read lib: OwnedDLHandle, session: Int) -> Bool:
    """``flare_rustls_quic_is_handshake_complete`` returns 1 once
    the 1-RTT keys are derived, 0 while still handshaking, -1 on
    NULL session (treated as "not complete" by callers)."""
    if session == 0:
        return False
    var f = lib.get_function[def(Int) thin abi("C") -> c_int](
        "flare_rustls_quic_is_handshake_complete"
    )
    return Int(f(session)) == 1


def _do_alpn(read lib: OwnedDLHandle, session: Int) raises -> String:
    """Return the negotiated ALPN identifier (empty if none).
    Raises on the FFI's bad-pointer / out-cap-too-small codes."""
    if session == 0:
        raise Error(
            "flare_rustls_quic_alpn: NULL session (the rustls"
            " session handle is zero -- typically because the"
            " acceptor failed to construct with the supplied PEM)"
        )
    var f = lib.get_function[def(Int, Int, Int, Int) thin abi("C") -> c_int](
        "flare_rustls_quic_alpn"
    )
    var buf = List[UInt8](capacity=256)
    for _ in range(256):
        buf.append(UInt8(0))
    var written: Int = 0
    var written_addr = Int(UnsafePointer(to=written))
    var rc = Int(f(session, Int(buf.unsafe_ptr()), 256, written_addr))
    if rc < 0:
        raise Error(String("flare_rustls_quic_alpn returned ") + String(rc))
    if written == 0:
        return String("")
    # Build the ALPN identifier as a String from the bytes the
    # FFI just wrote. The identifiers we care about are ASCII
    # (RFC 7301 §3.1 -- "Protocols are named by IANA-registered
    # byte strings, with no embedded NUL bytes"); the
    # ``unsafe_from_utf8 = Span(buf[:n])`` shape is the
    # canonical path used by ``flare.tls._server_ffi`` for the
    # OpenSSL alpn-selected helper.
    return String(unsafe_from_utf8=Span[UInt8, _](buf[:written]))


# ── Per-level AEAD + header protection ─────────────────────────────────────


def _do_have_keys(read lib: OwnedDLHandle, session: Int, level: Int) -> Int:
    """``flare_rustls_quic_have_keys``: 1 if rustls has installed
    keys at ``level``, 0 otherwise, -1 on bad pointer / level out
    of range.

    The QuicListener reactor calls this after every take_crypto
    pump to learn whether the Handshake (2) or 1-RTT (3) `Keys`
    slot has flipped from None to Some(_). Once
    installed, the matching packet/header thunks below dispatch
    AEAD + HP through rustls's already-derived `Keys` instead of
    re-deriving them from a traffic secret on the flare side
    (rustls's `quic::Secrets` is `pub(crate)`-sealed).
    """
    if session == 0:
        return -1
    var f = lib.get_function[def(Int, c_int) thin abi("C") -> c_int](
        "flare_rustls_quic_have_keys"
    )
    return Int(f(session, c_int(level)))


def _do_packet_encrypt(
    read lib: OwnedDLHandle,
    session: Int,
    level: Int,
    packet_number: UInt64,
    read header: List[UInt8],
    mut payload: List[UInt8],
) raises -> List[UInt8]:
    """``flare_rustls_quic_packet_encrypt``: encrypt ``payload``
    in place at the given encryption level and return the
    16-byte authentication tag.

    ``header`` is the QUIC packet header (used as AEAD AAD per
    RFC 9001 §5.3). ``payload`` is mutated in place; the caller
    appends the returned tag to the on-wire packet.

    Raises if the FFI returns a non-zero code: rustls error
    text is in :func:`_do_last_error`.
    """
    var f = lib.get_function[
        def(
            Int, c_int, UInt64, Int, Int, Int, Int, Int, Int, Int
        ) thin abi("C") -> c_int
    ]("flare_rustls_quic_packet_encrypt")
    var tag = List[UInt8](capacity=16)
    for _ in range(16):
        tag.append(UInt8(0))
    # The FFI also reports the tag length via ``tag_written``, but
    # that out-parameter read-back is unreliable across the opaque
    # FFI call (the optimizer folds it to the initial 0, which would
    # truncate the tag to an empty slice and ship unauthenticated
    # packets). The QUIC AEAD suites (AES-GCM / ChaCha20-Poly1305)
    # always emit a 16-byte tag (RFC 9001 sec 5.3), and rustls has
    # already copied those 16 bytes into ``tag``, so we keep the
    # full buffer rather than depend on the readback.
    var written: Int = 0
    var rc = Int(
        f(
            session,
            c_int(level),
            packet_number,
            Int(header.unsafe_ptr()),
            len(header),
            Int(payload.unsafe_ptr()),
            len(payload),
            Int(tag.unsafe_ptr()),
            len(tag),
            Int(UnsafePointer(to=written)),
        )
    )
    if rc != 0:
        raise Error(
            String("flare_rustls_quic_packet_encrypt returned ") + String(rc)
        )
    return tag^


def _do_packet_decrypt(
    read lib: OwnedDLHandle,
    session: Int,
    level: Int,
    packet_number: UInt64,
    read header: List[UInt8],
    mut payload: List[UInt8],
) raises -> Int:
    """``flare_rustls_quic_packet_decrypt``: verify + strip the
    AEAD tag from ``payload`` in place at the given encryption
    level. Returns the plaintext length (always
    ``len(payload) - 16`` for AEAD-GCM / ChaCha20-Poly1305).

    Raises if rustls rejects the tag (the typical "wrong keys at
    this level" symptom).
    """
    var f = lib.get_function[
        def(Int, c_int, UInt64, Int, Int, Int, Int, Int) thin abi("C") -> c_int
    ]("flare_rustls_quic_packet_decrypt")
    var plaintext_len: Int = 0
    # Keep the pointer in a named variable across the FFI call:
    # a throwaway ``Int(UnsafePointer(to=...))`` temporary lets the
    # optimizer treat ``plaintext_len`` as non-escaping and fold the
    # write-back to the initial 0. Dereferencing the live pointer
    # forces a reload of the value rustls actually wrote.
    var len_ptr = UnsafePointer(to=plaintext_len)
    var rc = Int(
        f(
            session,
            c_int(level),
            packet_number,
            Int(header.unsafe_ptr()),
            len(header),
            Int(payload.unsafe_ptr()),
            len(payload),
            Int(len_ptr),
        )
    )
    if rc != 0:
        raise Error(
            String("flare_rustls_quic_packet_decrypt returned ") + String(rc)
        )
    return len_ptr[]


def _do_header_encrypt(
    read lib: OwnedDLHandle,
    session: Int,
    level: Int,
    read sample: List[UInt8],
    first_byte_addr: Int,
    pn_addr: Int,
    pn_len: Int,
) raises:
    """``flare_rustls_quic_header_encrypt``: apply QUIC header
    protection (RFC 9001 §5.4) to the packet's first byte +
    packet-number bytes using rustls's
    ``Keys.local.header.encrypt_in_place``.

    ``sample`` MUST be 16 bytes from the encrypted payload (the
    region starting 4 bytes after the start of the packet-number
    field, regardless of declared pn length -- rustls samples
    exactly 16 bytes for the cipher suites we speak).
    ``first_byte_addr`` / ``pn_addr`` are raw pointer values (as
    Int) so the caller can keep the byte cells on the stack and
    let rustls write through.
    """
    var f = lib.get_function[
        def(Int, c_int, Int, Int, Int, Int, Int) thin abi("C") -> c_int
    ]("flare_rustls_quic_header_encrypt")
    var rc = Int(
        f(
            session,
            c_int(level),
            Int(sample.unsafe_ptr()),
            len(sample),
            first_byte_addr,
            pn_addr,
            pn_len,
        )
    )
    if rc != 0:
        raise Error(
            String("flare_rustls_quic_header_encrypt returned ") + String(rc)
        )


def _do_header_decrypt(
    read lib: OwnedDLHandle,
    session: Int,
    level: Int,
    read sample: List[UInt8],
    first_byte_addr: Int,
    pn_addr: Int,
    pn_len: Int,
) raises:
    """``flare_rustls_quic_header_decrypt``: remove QUIC header
    protection from the packet's first byte + packet-number
    bytes using rustls's ``Keys.remote.header.decrypt_in_place``.
    Same sample contract as :func:`_do_header_encrypt`.
    """
    var f = lib.get_function[
        def(Int, c_int, Int, Int, Int, Int, Int) thin abi("C") -> c_int
    ]("flare_rustls_quic_header_decrypt")
    var rc = Int(
        f(
            session,
            c_int(level),
            Int(sample.unsafe_ptr()),
            len(sample),
            first_byte_addr,
            pn_addr,
            pn_len,
        )
    )
    if rc != 0:
        raise Error(
            String("flare_rustls_quic_header_decrypt returned ") + String(rc)
        )


def _do_last_error(read lib: OwnedDLHandle) -> String:
    """Read the thread-local last-error message set by the
    rustls FFI. Returns an empty string when no message is
    recorded.
    """
    var f = lib.get_function[
        def() thin abi("C") -> UnsafePointer[UInt8, MutExternalOrigin]
    ]("flare_rustls_quic_last_error")
    var p = f()
    return String(StringSlice(unsafe_from_utf8_ptr=p))
