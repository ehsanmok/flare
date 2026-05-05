"""HMAC-SHA256 + URL-safe base64 over the OpenSSL FFI.

The C-side wrapper (``flare/tls/ffi/openssl_wrapper.cpp``) exports
``flare_hmac_sha256`` and ``flare_hmac_sha256_verify``; the latter
uses ``CRYPTO_memcmp`` so the verify path is constant-time. Both
are reached through an ``OwnedDLHandle`` against
``libflare_tls.so`` (resolved by the same helper TLS uses).

This module is the only path through which flare touches HMAC; the
``flare.http.session`` layer composes ``hmac_sha256`` +
``base64url_*`` into ``SignedCookie`` / ``Session`` /
``SessionStore``.

## Base64 URL-safe (RFC 4648 paragraph 5)

``base64url_encode`` produces no padding; ``base64url_decode``
accepts both padded and unpadded inputs. The alphabet is
``A-Z a-z 0-9 - _``. Cookie bodies must avoid ``;`` / ``,`` / ``=``;
the no-padding URL-safe variant is the canonical choice (matches
JSON Web Signature compact serialisation).
"""

from std.ffi import c_int, OwnedDLHandle
from std.memory import UnsafePointer

from ..net.socket import _find_flare_lib


# ─────────────────────────────────────────────────────────────────────────────
# Mojo's ASAP destruction policy reclaims a function-local ``OwnedDLHandle``
# right after its last Mojo-visible use, which in a naive
# ``var lib = OwnedDLHandle(...); var fn = lib.get_function(...); fn(...)``
# pattern is the ``get_function`` call — *not* the ``fn(...)`` invocation,
# because once the cached function pointer has been read out the runtime
# considers ``lib`` dead. The destructor calls ``dlclose``, the dylib gets
# unmapped, and the cached pointer dangles into freed memory by the time we
# call it.  See the long discussion in ``flare/http/encoding.mojo`` and the
# brotli / ``_flare_fs_access`` ports for the same idiom.
#
# The fix is to anchor ``lib``'s lifetime to a scope that the runtime can
# see is still live during the FFI call: open the handle in the public
# function and pass it through to a ``read lib`` (borrowed) helper that
# does the ``get_function`` + invocation. The borrow keeps the outer
# ``OwnedDLHandle`` alive across the call.
# ─────────────────────────────────────────────────────────────────────────────


def _do_hmac_sha256(
    read lib: OwnedDLHandle,
    key: List[UInt8],
    msg: List[UInt8],
    mut out: List[UInt8],
) raises:
    var fn_hmac = lib.get_function[
        def(Int, Int, Int, Int, Int) thin abi("C") -> c_int
    ]("flare_hmac_sha256")
    var rc = fn_hmac(
        Int(key.unsafe_ptr()),
        len(key),
        Int(msg.unsafe_ptr()),
        len(msg),
        Int(out.unsafe_ptr()),
    )
    if Int(rc) != 0:
        raise Error("flare_hmac_sha256: FFI call failed")


def hmac_sha256(key: List[UInt8], msg: List[UInt8]) raises -> List[UInt8]:
    """Compute HMAC-SHA256(key, msg). Returns a 32-byte digest.

    Args:
        key: Secret key bytes (any length, including empty per
             RFC 4231 vector 1).
        msg: Message bytes.

    Returns:
        A ``List[UInt8]`` of length 32 holding the digest.

    Raises:
        Error: If the underlying FFI call fails (e.g. OpenSSL
               misconfiguration).
    """
    var out = List[UInt8](length=32, fill=UInt8(0))
    var lib = OwnedDLHandle(_find_flare_lib())
    _do_hmac_sha256(lib, key, msg, out)
    return out^


def _do_hmac_sha256_verify(
    read lib: OwnedDLHandle,
    key: List[UInt8],
    msg: List[UInt8],
    mac: List[UInt8],
) raises -> Bool:
    var fn_v = lib.get_function[
        def(Int, Int, Int, Int, Int) thin abi("C") -> c_int
    ]("flare_hmac_sha256_verify")
    var rc = fn_v(
        Int(key.unsafe_ptr()),
        len(key),
        Int(msg.unsafe_ptr()),
        len(msg),
        Int(mac.unsafe_ptr()),
    )
    var rc_int = Int(rc)
    if rc_int < 0:
        raise Error("flare_hmac_sha256_verify: FFI call failed")
    return rc_int == 1


def hmac_sha256_verify(
    key: List[UInt8], msg: List[UInt8], mac: List[UInt8]
) raises -> Bool:
    """Verify an HMAC-SHA256 tag in constant time.

    Args:
        key: Secret key bytes.
        msg: Message bytes.
        mac: Candidate 32-byte MAC tag.

    Returns:
        ``True`` if ``mac`` is a valid HMAC-SHA256 tag for
        ``(key, msg)``. ``False`` for length mismatch or any byte
        difference (the comparison is constant-time over the full
        32-byte width).

    Raises:
        Error: If the underlying FFI call fails.
    """
    if len(mac) != 32:
        return False
    var lib = OwnedDLHandle(_find_flare_lib())
    return _do_hmac_sha256_verify(lib, key, msg, mac)


# ── URL-safe base64 (RFC 4648 paragraph 5, no padding) ─────────────────────


def _b64_alphabet() -> StaticString:
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def base64url_encode(data: List[UInt8]) -> String:
    """Encode bytes as URL-safe base64 (no padding).

    Alphabet: ``A-Za-z0-9-_``. ``+`` / ``/`` from RFC 4648 paragraph 4
    are replaced by ``-`` / ``_``; trailing ``=`` padding is stripped
    so the output is cookie-safe.
    """
    var alpha = _b64_alphabet().unsafe_ptr()
    var n = len(data)
    if n == 0:
        return ""
    var out = List[UInt8]()
    out.reserve((n * 4 + 2) // 3)
    var src = data.unsafe_ptr()
    var i = 0
    while i + 3 <= n:
        var b0 = Int(src[i])
        var b1 = Int(src[i + 1])
        var b2 = Int(src[i + 2])
        out.append(alpha[(b0 >> 2) & 63])
        out.append(alpha[((b0 << 4) | (b1 >> 4)) & 63])
        out.append(alpha[((b1 << 2) | (b2 >> 6)) & 63])
        out.append(alpha[b2 & 63])
        i += 3
    var rem = n - i
    if rem == 1:
        var b0 = Int(src[i])
        out.append(alpha[(b0 >> 2) & 63])
        out.append(alpha[(b0 << 4) & 63])
    elif rem == 2:
        var b0 = Int(src[i])
        var b1 = Int(src[i + 1])
        out.append(alpha[(b0 >> 2) & 63])
        out.append(alpha[((b0 << 4) | (b1 >> 4)) & 63])
        out.append(alpha[(b1 << 2) & 63])
    return String(unsafe_from_utf8=Span[UInt8, _](out))


@always_inline
def _b64_decode_byte(c: UInt8) raises -> Int:
    """Return the alphabet index of ``c``, or raise on invalid input.

    Accepts both URL-safe (``-`` / ``_``) and standard (``+`` / ``/``)
    alphabets so callers can be lenient. Padding ``=`` is rejected
    here; the decoder strips it before calling.
    """
    if c >= 65 and c <= 90:
        return Int(c) - 65
    if c >= 97 and c <= 122:
        return Int(c) - 97 + 26
    if c >= 48 and c <= 57:
        return Int(c) - 48 + 52
    if c == 45 or c == 43:
        return 62
    if c == 95 or c == 47:
        return 63
    raise Error("base64url_decode: invalid character")


def base64url_decode(s: String) raises -> List[UInt8]:
    """Decode URL-safe base64 (with or without trailing ``=``).

    Args:
        s: Encoded string. Trailing ``=`` characters are tolerated.

    Returns:
        Decoded byte list.

    Raises:
        Error: When ``s`` contains a character outside the base64
               alphabet, or its length is invalid.
    """
    var n = s.byte_length()
    var src = s.unsafe_ptr()
    while n > 0 and src[n - 1] == 61:  # strip '='
        n -= 1
    if n == 0:
        return List[UInt8]()
    if n % 4 == 1:
        raise Error("base64url_decode: invalid length")

    var out = List[UInt8]()
    out.reserve((n * 3) // 4)
    var i = 0
    while i + 4 <= n:
        var b0 = _b64_decode_byte(src[i])
        var b1 = _b64_decode_byte(src[i + 1])
        var b2 = _b64_decode_byte(src[i + 2])
        var b3 = _b64_decode_byte(src[i + 3])
        out.append(UInt8(((b0 << 2) | (b1 >> 4)) & 255))
        out.append(UInt8(((b1 << 4) | (b2 >> 2)) & 255))
        out.append(UInt8(((b2 << 6) | b3) & 255))
        i += 4
    var rem = n - i
    if rem == 2:
        var b0 = _b64_decode_byte(src[i])
        var b1 = _b64_decode_byte(src[i + 1])
        out.append(UInt8(((b0 << 2) | (b1 >> 4)) & 255))
    elif rem == 3:
        var b0 = _b64_decode_byte(src[i])
        var b1 = _b64_decode_byte(src[i + 1])
        var b2 = _b64_decode_byte(src[i + 2])
        out.append(UInt8(((b0 << 2) | (b1 >> 4)) & 255))
        out.append(UInt8(((b1 << 4) | (b2 >> 2)) & 255))
    return out^
