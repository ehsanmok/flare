"""``flare.crypto.base64`` -- RFC 4648 §4 standard base64 encode/decode.

Consolidates three identical near-duplicate encoders: the
standard-alphabet base64 implementation lived in three places
before -- ``_b64_encode`` in ``flare.http.auth``,
``_base64_encode`` in ``flare.ws.client``, ``_b64_encode_srv`` in
``flare.ws.server`` -- each with the same RFC 4648 §4 table and
the same chunk-of-3 / pad-tail loop. This module is the single
canonical home; the three call sites now import from here.

The URL-safe (RFC 4648 §5, no padding) variant for cookies and
JWT lives at :mod:`flare.crypto.hmac`
(:func:`base64url_encode` / :func:`base64url_decode`); the two
alphabets diverge on ``+`` / ``/`` vs ``-`` / ``_`` and on
padding behaviour. The HTTP-side ``Basic`` auth header
(RFC 7617) and the WebSocket ``Sec-WebSocket-Accept`` derivation
(RFC 6455 §4.2.2) require the standard alphabet *with* ``=``
padding, which is what this module provides.

## Public API

```mojo
from flare.crypto.base64 import base64_encode, base64_decode
```

* :func:`base64_encode(data: Span[UInt8, _]) -> String` --
  alphabet ``A-Za-z0-9+/`` with ``=`` padding to a multiple of 4.
* :func:`base64_decode(s: String) raises -> List[UInt8]` --
  inverse; tolerates missing padding, raises on invalid bytes.
"""


# Standard alphabet from RFC 4648 §4 (Table 1). Differs from the
# URL-safe alphabet only on the last two characters (``+`` / ``/``
# vs ``-`` / ``_``).
comptime _BASE64_TABLE: String = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


def base64_encode(data: Span[UInt8, _]) -> String:
    """Encode bytes as standard RFC 4648 §4 base64 with ``=`` padding.

    Alphabet ``A-Za-z0-9+/``. Output length is always a multiple
    of 4; ``=`` is appended so the ``2/3 -> 4`` round-up is
    preserved.

    Args:
        data: Input bytes.

    Returns:
        Base64-encoded string (with ``=`` padding).
    """
    var n = len(data)
    var out = String(capacity=((n + 2) // 3) * 4 + 1)
    var tbl = _BASE64_TABLE.unsafe_ptr()
    var i = 0
    while i + 3 <= n:
        var a = Int(data[i])
        var b = Int(data[i + 1])
        var c = Int(data[i + 2])
        out += chr(Int(tbl[a >> 2]))
        out += chr(Int(tbl[((a & 3) << 4) | (b >> 4)]))
        out += chr(Int(tbl[((b & 0xF) << 2) | (c >> 6)]))
        out += chr(Int(tbl[c & 0x3F]))
        i += 3
    if n - i == 1:
        var a = Int(data[i])
        out += chr(Int(tbl[a >> 2]))
        out += chr(Int(tbl[(a & 3) << 4]))
        out += "=="
    elif n - i == 2:
        var a = Int(data[i])
        var b = Int(data[i + 1])
        out += chr(Int(tbl[a >> 2]))
        out += chr(Int(tbl[((a & 3) << 4) | (b >> 4)]))
        out += chr(Int(tbl[(b & 0xF) << 2]))
        out += "="
    return out^


@always_inline
def _decode_byte(c: UInt8) raises -> Int:
    """Return the alphabet index of ``c``, or raise on invalid input.

    Accepts both standard (``+`` / ``/``) and URL-safe (``-`` / ``_``)
    alphabet bytes so callers can be lenient on the wire while
    still emitting the standard form. Padding ``=`` is rejected
    here; the decoder strips it before calling.
    """
    if c >= 65 and c <= 90:
        return Int(c) - 65  # A-Z
    if c >= 97 and c <= 122:
        return Int(c) - 97 + 26  # a-z
    if c >= 48 and c <= 57:
        return Int(c) - 48 + 52  # 0-9
    if c == 43 or c == 45:
        return 62  # '+' or '-'
    if c == 47 or c == 95:
        return 63  # '/' or '_'
    raise Error("base64_decode: invalid character")


def base64_decode(s: String) raises -> List[UInt8]:
    """Decode standard RFC 4648 §4 base64 (with or without ``=``).

    Args:
        s: Encoded string; trailing ``=`` characters are tolerated
           but not required.

    Returns:
        Decoded byte list.

    Raises:
        Error: When ``s`` contains a character outside the base64
               alphabet, or its length is otherwise invalid.
    """
    var n = s.byte_length()
    var src = s.unsafe_ptr()
    while n > 0 and src[n - 1] == 61:  # strip trailing '='
        n -= 1
    if n == 0:
        return List[UInt8]()
    if n % 4 == 1:
        raise Error("base64_decode: invalid length")

    var out = List[UInt8]()
    out.reserve((n * 3) // 4)
    var i = 0
    while i + 4 <= n:
        var b0 = _decode_byte(src[i])
        var b1 = _decode_byte(src[i + 1])
        var b2 = _decode_byte(src[i + 2])
        var b3 = _decode_byte(src[i + 3])
        out.append(UInt8(((b0 << 2) | (b1 >> 4)) & 0xFF))
        out.append(UInt8(((b1 << 4) | (b2 >> 2)) & 0xFF))
        out.append(UInt8(((b2 << 6) | b3) & 0xFF))
        i += 4
    var rem = n - i
    if rem == 2:
        var b0 = _decode_byte(src[i])
        var b1 = _decode_byte(src[i + 1])
        out.append(UInt8(((b0 << 2) | (b1 >> 4)) & 0xFF))
    elif rem == 3:
        var b0 = _decode_byte(src[i])
        var b1 = _decode_byte(src[i + 1])
        var b2 = _decode_byte(src[i + 2])
        out.append(UInt8(((b0 << 2) | (b1 >> 4)) & 0xFF))
        out.append(UInt8(((b1 << 4) | (b2 >> 2)) & 0xFF))
    return out^
