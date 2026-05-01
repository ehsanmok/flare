"""Server-side authentication extractors + CSRF helper.

The v0.6 :mod:`flare.http.auth` module ships ``BasicAuth`` and
``BearerAuth`` for the **client** side — they apply credentials
to an outbound request's ``Authorization`` header.

This module provides the symmetric **server-side** primitives:

- ``BearerExtract`` — pulls the Bearer token out of the inbound
  request's ``Authorization`` header and exposes it to handlers
  via the ``Extractor`` trait (drop-in for ``Extracted[H]``).
- ``BasicExtract`` — decodes the inbound Basic credentials
  (``Authorization: Basic <base64-username:password>``) into
  ``username`` / ``password`` strings.
- ``parse_bearer_token`` / ``parse_basic_credentials`` — the
  underlying parsers, exposed for callers who want to assemble
  their own auth flow without going through ``Extracted``.
- ``CsrfToken`` — encode / verify constant-time comparison
  for double-submit-cookie CSRF protection (OWASP Cheat Sheet
  §3.1.1, "Double Submit Cookie pattern").

Why server-side parsers, separate from the v0.6 client-side
applicators:

- An ``HttpServer`` handler that needs to authenticate the
  caller has to *parse* an ``Authorization`` header, not write
  one. The ``BasicAuth.apply`` shape doesn't fit (writes vs
  reads are different operations on the same header name).
- Symmetry with v0.6 ``Header[T, name]`` extractor pattern:
  callers who put ``var token: BearerExtract`` on their
  ``Extracted[H]`` struct get the same auto-injection
  semantics they get for path / query / header extractors.
- CSRF lives here because every server-side auth pattern
  needs it (or needs to deliberately opt out of it). Bundling
  it with the auth extractors keeps the surface tight and
  the imports obvious.

Spec compliance:

- ``BearerExtract`` follows RFC 6750 §2.1: token = ``b64token``
  per the Augmented BNF, which permits ``A-Z a-z 0-9 - . _ ~ +
  /`` and trailing ``=`` padding. We pass the token through
  verbatim — the resource server is responsible for token
  introspection / signature verification.
- ``BasicExtract`` follows RFC 7617 §2: ``user-pass = userid ":"
  password`` after base64 decode, where ``userid`` may not
  contain ``:`` but ``password`` may. We split on the first
  ``:`` only.
- ``CsrfToken`` follows OWASP guidance: 32-byte random token,
  base64url-encoded, constant-time compare. Token generation
  uses ``urandom``-fed bytes (caller responsibility — we
  accept the bytes; we don't seed a PRNG ourselves so the
  randomness contract stays explicit).
"""

from .extract import Extractor
from .request import Request


# ── Base64 decoder (RFC 4648) ───────────────────────────────────────────────


def _b64_decode(s: String) raises -> List[UInt8]:
    """Decode RFC 4648 standard base64 ``s`` (with or without
    ``=`` padding) into raw bytes.

    Raises on:
    - characters outside the base64 alphabet
    - ``s`` length mod 4 != 0 after padding restoration
    - misplaced ``=`` padding (only at the tail; at most 2)

    URL-safe base64 (``-_`` substituted for ``+/``) is **not**
    accepted here — that's :func:`_b64url_decode` below. RFC 7617
    Basic credentials use the standard alphabet.
    """
    var n = s.byte_length()
    if n == 0:
        return List[UInt8]()
    if n % 4 != 0:
        raise Error("base64 decode: input length not a multiple of 4")
    var out = List[UInt8]()
    out.reserve(n // 4 * 3)
    var p = s.unsafe_ptr()
    var pad = 0
    if n >= 1 and Int(p[n - 1]) == ord("="):
        pad = 1
    if n >= 2 and Int(p[n - 2]) == ord("="):
        pad = 2
    if pad > 2:
        raise Error("base64 decode: too much padding")
    var blocks = n // 4
    for blk in range(blocks):
        var v0 = _b64_value(Int(p[blk * 4 + 0]))
        var v1 = _b64_value(Int(p[blk * 4 + 1]))
        var v2_byte = Int(p[blk * 4 + 2])
        var v3_byte = Int(p[blk * 4 + 3])
        var v2 = -1 if v2_byte == ord("=") else _b64_value(v2_byte)
        var v3 = -1 if v3_byte == ord("=") else _b64_value(v3_byte)
        # First two sextets are always required.
        if v0 < 0 or v1 < 0:
            raise Error("base64 decode: invalid character")
        if blk < blocks - 1:
            # Padding only allowed in the last block.
            if v2 < 0 or v3 < 0:
                raise Error("base64 decode: padding before tail")
        out.append(UInt8(((v0 << 2) | (v1 >> 4)) & 0xFF))
        if v2 >= 0:
            out.append(UInt8((((v1 & 0xF) << 4) | (v2 >> 2)) & 0xFF))
        if v3 >= 0:
            out.append(UInt8((((v2 & 0x3) << 6) | v3) & 0xFF))
    return out^


def _b64_value(b: Int) -> Int:
    """Map a base64 alphabet byte to its 6-bit value, or -1 if
    not in the alphabet. Branch-free table would be nicer but
    Mojo's ``StaticTuple[256]`` story is in flux; use a switch
    so the code stays portable across nightlies."""
    if b >= ord("A") and b <= ord("Z"):
        return b - ord("A")
    if b >= ord("a") and b <= ord("z"):
        return b - ord("a") + 26
    if b >= ord("0") and b <= ord("9"):
        return b - ord("0") + 52
    if b == ord("+"):
        return 62
    if b == ord("/"):
        return 63
    return -1


def _b64url_value(b: Int) -> Int:
    """Same as :func:`_b64_value` but for URL-safe base64
    (RFC 4648 §5: ``-_`` replace ``+/``)."""
    if b >= ord("A") and b <= ord("Z"):
        return b - ord("A")
    if b >= ord("a") and b <= ord("z"):
        return b - ord("a") + 26
    if b >= ord("0") and b <= ord("9"):
        return b - ord("0") + 52
    if b == ord("-"):
        return 62
    if b == ord("_"):
        return 63
    return -1


# ── Header parsers ─────────────────────────────────────────────────────────


def parse_bearer_token(authz: String) raises -> String:
    """Return the token portion of an ``Authorization: Bearer X``
    header value, raising on malformed input.

    Tolerates leading whitespace and a single space between the
    scheme and the token (per RFC 6750 §2.1 "credentials =
    auth-scheme 1*SP token"). The scheme match is
    case-insensitive per RFC 7235 §2.1.
    """
    if authz.byte_length() == 0:
        raise Error("authorization: empty value")
    var p = authz.unsafe_ptr()
    var n = authz.byte_length()
    var i = 0
    while i < n and Int(p[i]) == ord(" "):
        i += 1
    if i + 7 > n:
        raise Error("authorization: too short for Bearer scheme")
    var scheme_match = (
        (Int(p[i]) == ord("B") or Int(p[i]) == ord("b"))
        and (Int(p[i + 1]) == ord("E") or Int(p[i + 1]) == ord("e"))
        and (Int(p[i + 2]) == ord("A") or Int(p[i + 2]) == ord("a"))
        and (Int(p[i + 3]) == ord("R") or Int(p[i + 3]) == ord("r"))
        and (Int(p[i + 4]) == ord("E") or Int(p[i + 4]) == ord("e"))
        and (Int(p[i + 5]) == ord("R") or Int(p[i + 5]) == ord("r"))
        and Int(p[i + 6]) == ord(" ")
    )
    if not scheme_match:
        raise Error("authorization: scheme is not Bearer")
    i += 7
    while i < n and Int(p[i]) == ord(" "):
        i += 1
    if i >= n:
        raise Error("authorization: empty Bearer token")
    var out = String(capacity=n - i)
    for j in range(i, n):
        out += chr(Int(p[j]))
    return out^


@fieldwise_init
struct BasicCredentials(Copyable, Movable):
    """Decoded RFC 7617 Basic credentials."""

    var username: String
    var password: String


def parse_basic_credentials(authz: String) raises -> BasicCredentials:
    """Decode an ``Authorization: Basic <base64>`` header value
    into a :class:`BasicCredentials` pair.

    Splits the post-decode bytes on the first ``:`` per RFC 7617
    §2: ``user-pass = userid ":" password``, where ``userid``
    may not contain ``:`` but ``password`` may.
    """
    if authz.byte_length() == 0:
        raise Error("authorization: empty value")
    var p = authz.unsafe_ptr()
    var n = authz.byte_length()
    var i = 0
    while i < n and Int(p[i]) == ord(" "):
        i += 1
    if i + 6 > n:
        raise Error("authorization: too short for Basic scheme")
    var scheme_match = (
        (Int(p[i]) == ord("B") or Int(p[i]) == ord("b"))
        and (Int(p[i + 1]) == ord("A") or Int(p[i + 1]) == ord("a"))
        and (Int(p[i + 2]) == ord("S") or Int(p[i + 2]) == ord("s"))
        and (Int(p[i + 3]) == ord("I") or Int(p[i + 3]) == ord("i"))
        and (Int(p[i + 4]) == ord("C") or Int(p[i + 4]) == ord("c"))
        and Int(p[i + 5]) == ord(" ")
    )
    if not scheme_match:
        raise Error("authorization: scheme is not Basic")
    i += 6
    while i < n and Int(p[i]) == ord(" "):
        i += 1
    if i >= n:
        raise Error("authorization: empty Basic credentials")
    var b64 = String(capacity=n - i)
    for j in range(i, n):
        b64 += chr(Int(p[j]))
    var raw = _b64_decode(b64)
    var raw_n = len(raw)
    var split = -1
    for k in range(raw_n):
        if Int(raw[k]) == ord(":"):
            split = k
            break
    if split < 0:
        raise Error("authorization: missing ':' in Basic credentials")
    var user = String(capacity=split)
    for k in range(split):
        user += chr(Int(raw[k]))
    var pw = String(capacity=raw_n - split - 1)
    for k in range(split + 1, raw_n):
        pw += chr(Int(raw[k]))
    return BasicCredentials(user^, pw^)


# ── Extractors ─────────────────────────────────────────────────────────────


@fieldwise_init
struct BearerExtract(Copyable, Defaultable, Extractor, Movable):
    """Extracts the Bearer token from the inbound
    ``Authorization`` header.

    Raises on missing header, missing scheme, or non-Bearer
    scheme. Empty token also raises so handlers that opt in to
    this extractor never have to second-guess the value.
    """

    var token: String

    def __init__(out self):
        self.token = ""

    def apply(mut self, req: Request) raises:
        if not req.headers.contains("authorization"):
            raise Error("authorization: missing header")
        self.token = parse_bearer_token(req.headers.get("authorization"))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct BasicExtract(Copyable, Defaultable, Extractor, Movable):
    """Extracts RFC 7617 Basic credentials from the inbound
    ``Authorization`` header.

    Raises on missing header, missing scheme, non-Basic scheme,
    base64 decode failure, or missing ``:`` separator after
    decode.
    """

    var username: String
    var password: String

    def __init__(out self):
        self.username = ""
        self.password = ""

    def apply(mut self, req: Request) raises:
        if not req.headers.contains("authorization"):
            raise Error("authorization: missing header")
        var creds = parse_basic_credentials(req.headers.get("authorization"))
        self.username = creds.username
        self.password = creds.password

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


# ── CSRF ──────────────────────────────────────────────────────────────────


def csrf_token_b64url(token_bytes: List[UInt8]) -> String:
    """Render a raw CSRF token (typically 32 random bytes from
    ``urandom``) as a URL-safe base64 string suitable for
    embedding in an HTML form / cookie.

    The output is unpadded (RFC 4648 §5 with the recommendation
    "implementations MUST include appropriate padding" treated
    as MAY for cookie values, matching the Django / Express
    CSRF cookie shape).
    """
    var n = len(token_bytes)
    var out = String(capacity=((n + 2) // 3) * 4)
    var alphabet = String(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    var ap = alphabet.unsafe_ptr()
    var i = 0
    while i + 3 <= n:
        var a = Int(token_bytes[i])
        var b = Int(token_bytes[i + 1])
        var c = Int(token_bytes[i + 2])
        out += chr(Int(ap[a >> 2]))
        out += chr(Int(ap[((a & 3) << 4) | (b >> 4)]))
        out += chr(Int(ap[((b & 0xF) << 2) | (c >> 6)]))
        out += chr(Int(ap[c & 0x3F]))
        i += 3
    if n - i == 1:
        var a = Int(token_bytes[i])
        out += chr(Int(ap[a >> 2]))
        out += chr(Int(ap[(a & 3) << 4]))
    elif n - i == 2:
        var a = Int(token_bytes[i])
        var b = Int(token_bytes[i + 1])
        out += chr(Int(ap[a >> 2]))
        out += chr(Int(ap[((a & 3) << 4) | (b >> 4)]))
        out += chr(Int(ap[(b & 0xF) << 2]))
    return out^


def csrf_token_compare(a: String, b: String) -> Bool:
    """Constant-time string comparison for CSRF token check.

    Returns ``False`` immediately on length mismatch (the length
    itself is not a secret per OWASP). Otherwise XORs every byte
    pair and folds into an accumulator so the runtime is
    independent of the position of the first differing byte —
    blocking BREACH-style timing oracles against the token
    cookie.
    """
    if a.byte_length() != b.byte_length():
        return False
    var n = a.byte_length()
    var ap = a.unsafe_ptr()
    var bp = b.unsafe_ptr()
    var diff = UInt8(0)
    for i in range(n):
        diff |= ap[i] ^ bp[i]
    return diff == UInt8(0)


@fieldwise_init
struct CsrfToken(Copyable, Movable):
    """A CSRF token pair (cookie value + form value) ready for
    constant-time comparison.

    Caller fills the ``cookie`` and ``submitted`` fields from the
    request (typically: ``cookie`` from the
    ``Cookie: csrf=<value>`` header, ``submitted`` from the form
    field or ``X-CSRF-Token`` header). The :func:`verify` method
    folds them through :func:`csrf_token_compare` for the final
    check.

    Token generation is intentionally outside this surface — the
    caller picks the entropy source (``urandom`` / ``rdrand`` /
    HSM-backed) and feeds the bytes to :func:`csrf_token_b64url`.
    """

    var cookie: String
    var submitted: String

    def verify(self) -> Bool:
        """Return True iff the cookie and submitted token match
        in constant time."""
        return csrf_token_compare(self.cookie, self.submitted)
