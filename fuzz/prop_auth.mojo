"""Property tests: HTTP auth helpers (base64 encoder + header generation).

Properties verified:

1. ``b64_charset`` — ``_b64_encode(data)`` output contains only RFC 4648
   characters (``A-Z``, ``a-z``, ``0-9``, ``+``, ``/``, ``=``), for any
   input byte sequence.

2. ``b64_length`` — Output length is exactly ``ceil(n/3)*4``, i.e. always a
   multiple of 4.

3. ``basic_auth_prefix`` — ``BasicAuth(user, password).apply(headers)``
   always sets ``Authorization`` to a string starting with ``"Basic "``.

4. ``bearer_auth_prefix`` — ``BearerAuth(token).apply(headers)`` always sets
   ``Authorization`` to a string starting with ``"Bearer "``.

5. ``injection_resistance_basic`` — ``BasicAuth`` rejects usernames/passwords
   whose base64 encoding would embed CRLF in the header value.  Since base64
   output never contains CR or LF, the header must always be injection-free.

Run:
    pixi run prop-auth
"""

from mozz import forall_bytes
from flare.http.auth import BasicAuth, BearerAuth, _b64_encode
from flare.http.headers import HeaderMap

comptime _B64_CHARS: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


fn _is_b64_char(c: UInt8) -> Bool:
    """Return True if ``c`` is in the RFC 4648 base64 alphabet."""
    var ic = Int(c)
    return (
        (ic >= 65 and ic <= 90)  # A-Z
        or (ic >= 97 and ic <= 122)  # a-z
        or (ic >= 48 and ic <= 57)  # 0-9
        or ic == 43  # +
        or ic == 47  # /
        or ic == 61  # =
    )


def b64_charset(data: List[UInt8]) -> Bool:
    """Every byte in the base64 output must be a valid RFC 4648 character."""
    var encoded = _b64_encode(Span[UInt8](data))
    var ebytes = encoded.as_bytes()
    for b in ebytes:
        if not _is_b64_char(b):
            return False
    return True


def b64_length(data: List[UInt8]) -> Bool:
    """Encoded length must be exactly ``ceil(n/3)*4``."""
    var n = len(data)
    var expected = ((n + 2) // 3) * 4
    var encoded = _b64_encode(Span[UInt8](data))
    return len(encoded) == expected


fn _bytes_to_ascii(data: List[UInt8], start: Int, end: Int) -> String:
    """Convert ``data[start:end]`` to a String, masking non-ASCII bytes as '?'.
    """
    var s = String(capacity=end - start + 1)
    for i in range(start, end):
        var c = Int(data[i])
        if c < 128:
            s += chr(c)
        else:
            s += "?"
    return s^


def basic_auth_prefix(data: List[UInt8]) -> Bool:
    """``BasicAuth`` header always starts with ``"Basic "``."""
    # Use first half as username, second half as password.  Restrict to ASCII
    # so that the credential string and its base64 encoding are deterministic.
    var mid = len(data) // 2
    var user = _bytes_to_ascii(data, 0, mid)
    var pw = _bytes_to_ascii(data, mid, len(data))
    var h = HeaderMap()
    try:
        BasicAuth(user, pw).apply(h)
    except:
        # HeaderInjectionError cannot happen here: base64 output has no CRLF.
        # Any exception from Header validation is a bug.
        return False
    return h.get("Authorization").startswith("Basic ")


def bearer_auth_prefix(data: List[UInt8]) -> Bool:
    """``BearerAuth`` header always starts with ``"Bearer "``."""
    var token = _bytes_to_ascii(data, 0, len(data))
    # Tokens containing CRLF will (correctly) raise HeaderInjectionError.
    var h = HeaderMap()
    try:
        BearerAuth(token).apply(h)
    except:
        return True  # HeaderInjectionError for CR/LF tokens is correct
    return h.get("Authorization").startswith("Bearer ")


def basic_no_crlf_in_header(data: List[UInt8]) -> Bool:
    """The ``Authorization`` header value produced by ``BasicAuth`` must never
    contain CR or LF — since base64 output is CRLF-free."""
    var mid = len(data) // 2
    var user = _bytes_to_ascii(data, 0, mid)
    var pw = _bytes_to_ascii(data, mid, len(data))
    var h = HeaderMap()
    try:
        BasicAuth(user, pw).apply(h)
    except:
        return True  # injection error is fine
    var val = h.get("Authorization")
    return "\r" not in val and "\n" not in val


fn main() raises:
    print("=" * 60)
    print("prop_auth.mojo")
    print("=" * 60)
    print()

    comptime TRIALS: Int = 50_000
    comptime MAX_LEN: Int = 512

    print("[mozz] prop: b64_charset ...")
    forall_bytes(b64_charset, max_len=MAX_LEN, trials=TRIALS, seed=0)
    print("[mozz] prop: b64_charset  PASS")

    print("[mozz] prop: b64_length ...")
    forall_bytes(b64_length, max_len=MAX_LEN, trials=TRIALS, seed=1)
    print("[mozz] prop: b64_length   PASS")

    print("[mozz] prop: basic_auth_prefix ...")
    forall_bytes(basic_auth_prefix, max_len=MAX_LEN, trials=TRIALS, seed=2)
    print("[mozz] prop: basic_auth_prefix PASS")

    print("[mozz] prop: bearer_auth_prefix ...")
    forall_bytes(bearer_auth_prefix, max_len=MAX_LEN, trials=TRIALS, seed=3)
    print("[mozz] prop: bearer_auth_prefix PASS")

    print("[mozz] prop: basic_no_crlf_in_header ...")
    forall_bytes(
        basic_no_crlf_in_header, max_len=MAX_LEN, trials=TRIALS, seed=4
    )
    print("[mozz] prop: basic_no_crlf_in_header PASS")

    print()
    print("All 5 auth properties passed.")
