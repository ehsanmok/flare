"""``application/x-www-form-urlencoded`` parsing (WHATWG URL Living Standard, §5.1).

The format predates RFC 3986 by a decade and lives separately as the
HTML form serialisation algorithm. Practical differences vs §3 query
strings:

- ``+`` decodes to a literal space (RFC 3986 reserves ``+`` for plus).
- Pairs are separated by ``&`` (or ``;`` for legacy compatibility).
- Each pair is ``name=value``; missing ``=`` is treated as ``name=""``.
- Percent-decoding is applied to *both* names and values, after the
  pair split.

This module ships:

- ``urldecode`` — RFC 3986 percent-decode + ``+``→space (the form-data
  variant). Returns the decoded ``String``; bad ``%XX`` escapes raise.
- ``FormData`` — multimap-of-strings (one key may map to multiple
  values, e.g. checkboxes), backed by parallel lists for stable
  insertion order.
- ``parse_form_urlencoded`` — bytes/string → ``FormData``; the
  ``Form`` extractor in [`extract.mojo`](extract.mojo) is the typed
  handler-side wrapper.
"""

from std.collections import Optional


@always_inline
def _hex_nibble(c: UInt8) raises -> Int:
    """Return the integer value of a single hex nibble.

    Args:
        c: ASCII byte (``'0'``-``'9'``, ``'a'``-``'f'``, ``'A'``-``'F'``).

    Returns:
        Integer 0-15.

    Raises:
        Error: When ``c`` is not a valid hex digit.
    """
    if c >= 48 and c <= 57:  # '0'..'9'
        return Int(c) - 48
    if c >= 97 and c <= 102:  # 'a'..'f'
        return Int(c) - 87
    if c >= 65 and c <= 70:  # 'A'..'F'
        return Int(c) - 55
    raise Error("urldecode: invalid percent-escape")


def urldecode(s: String) raises -> String:
    """Percent-decode ``s`` and convert ``+`` to space.

    Implements the WHATWG application/x-www-form-urlencoded byte
    decode: each ``%XX`` triple becomes the byte ``XX``, each ``+``
    becomes a single 0x20, every other byte is preserved verbatim.

    Args:
        s: The encoded string (ASCII, possibly with percent-escapes).

    Returns:
        The decoded ``String``.

    Raises:
        Error: When a ``%`` escape is truncated or contains a non-hex
               digit.
    """
    var n = s.byte_length()
    var src = s.unsafe_ptr()
    var out = List[UInt8]()
    out.reserve(n)
    var i = 0
    while i < n:
        var c = src[i]
        if c == 43:  # '+'
            out.append(UInt8(32))
            i += 1
        elif c == 37:  # '%'
            if i + 2 >= n:
                raise Error("urldecode: truncated percent-escape")
            var hi = _hex_nibble(src[i + 1])
            var lo = _hex_nibble(src[i + 2])
            out.append(UInt8(hi * 16 + lo))
            i += 3
        else:
            out.append(c)
            i += 1
    return String(unsafe_from_utf8=Span[UInt8, _](out))


def urlencode(s: String) -> String:
    """Percent-encode ``s`` for use in form bodies / query strings.

    Encodes per the WHATWG application/x-www-form-urlencoded byte
    encode: unreserved characters (``A-Z``, ``a-z``, ``0-9``, ``-``,
    ``_``, ``.``, ``~``) pass through; spaces become ``+``; every
    other byte becomes ``%XX``. Suitable for both names and values.

    Args:
        s: The string to encode (any UTF-8 bytes).

    Returns:
        The percent-encoded ``String``.
    """
    comptime HEX = "0123456789ABCDEF"
    var n = s.byte_length()
    var src = s.unsafe_ptr()
    var hex_p = HEX.unsafe_ptr()
    var out = List[UInt8]()
    out.reserve(n)
    for i in range(n):
        var c = src[i]
        var unreserved = (
            (c >= 48 and c <= 57)
            or (c >= 65 and c <= 90)
            or (c >= 97 and c <= 122)
            or c == 45
            or c == 46
            or c == 95
            or c == 126
        )
        if unreserved:
            out.append(c)
        elif c == 32:  # ' '
            out.append(UInt8(43))
        else:
            out.append(UInt8(37))  # '%'
            out.append(hex_p[Int(c) >> 4])
            out.append(hex_p[Int(c) & 15])
    return String(unsafe_from_utf8=Span[UInt8, _](out))


struct FormData(Copyable, Defaultable, Movable):
    """A name → value(s) multimap, in insertion order.

    Backs the ``Form`` extractor; mirrors the API of ``HeaderMap`` so
    handlers can write the same code shape against headers, query
    strings, and form bodies.

    Internally two parallel lists keep insertion order stable
    (lookups are O(n), n is typically tiny — sub-100 fields). For
    larger forms the dict-of-lists layout would be a future
    optimisation; the bench harness has not pushed past 32 fields.
    """

    var _keys: List[String]
    var _values: List[String]

    def __init__(out self):
        self._keys = List[String]()
        self._values = List[String]()

    def get(self, name: String) -> String:
        """Return the first value for ``name`` (case-sensitive), else ``""``."""
        for i in range(len(self._keys)):
            if self._keys[i] == name:
                return self._values[i]
        return ""

    def get_optional(self, name: String) -> Optional[String]:
        """Return ``Some(value)`` if ``name`` is present, ``None`` otherwise."""
        for i in range(len(self._keys)):
            if self._keys[i] == name:
                return Optional[String](self._values[i])
        return Optional[String]()

    def get_all(self, name: String) -> List[String]:
        """Return every value bound to ``name`` in insertion order."""
        var out = List[String]()
        for i in range(len(self._keys)):
            if self._keys[i] == name:
                out.append(self._values[i])
        return out^

    def append(mut self, name: String, value: String):
        """Append ``(name, value)``; existing bindings are preserved."""
        self._keys.append(name)
        self._values.append(value)

    def contains(self, name: String) -> Bool:
        """Return ``True`` if any binding for ``name`` exists."""
        for i in range(len(self._keys)):
            if self._keys[i] == name:
                return True
        return False

    def len(self) -> Int:
        """Return the total number of bindings (counting duplicate keys)."""
        return len(self._keys)

    def keys(self) -> List[String]:
        """Return the list of keys (with duplicates) in insertion order."""
        return self._keys.copy()

    def values(self) -> List[String]:
        """Return the list of values in insertion order, parallel to ``keys()``.
        """
        return self._values.copy()

    def to_urlencoded(self) -> String:
        """Serialise back to ``application/x-www-form-urlencoded``.

        Round-trips ``parse_form_urlencoded`` for any well-formed
        input. Uses ``+`` for spaces and ``%XX`` for everything else
        outside the unreserved set.
        """
        var out = String(capacity=len(self._keys) * 16)
        for i in range(len(self._keys)):
            if i > 0:
                out += "&"
            out += urlencode(self._keys[i])
            out += "="
            out += urlencode(self._values[i])
        return out^


def parse_form_urlencoded(body: String) raises -> FormData:
    """Parse ``application/x-www-form-urlencoded`` bytes into a ``FormData``.

    Pair separators are ``&`` and ``;`` (legacy HTML forms still emit
    the latter). Empty pairs are skipped silently. ``name=`` keeps an
    empty-string value; ``name`` (no ``=``) also keeps an empty-string
    value.

    Args:
        body: Form body as a ``String``. Empty input produces an empty
              ``FormData`` (no error).

    Returns:
        Populated ``FormData``.

    Raises:
        Error: If a percent-escape is malformed inside a name or
               value (delegated from ``urldecode``).
    """
    var out = FormData()
    var n = body.byte_length()
    if n == 0:
        return out^
    var src = body.unsafe_ptr()
    var pos = 0
    while pos < n:
        var pair_end = n
        for i in range(pos, n):
            var c = src[i]
            if c == 38 or c == 59:  # '&' or ';'
                pair_end = i
                break
        if pair_end > pos:
            var eq = pair_end
            for i in range(pos, pair_end):
                if src[i] == 61:  # '='
                    eq = i
                    break
            var raw_name = String(unsafe_from_utf8=body.as_bytes()[pos:eq])
            var raw_value: String
            if eq < pair_end:
                raw_value = String(
                    unsafe_from_utf8=body.as_bytes()[eq + 1 : pair_end]
                )
            else:
                raw_value = ""
            out.append(urldecode(raw_name), urldecode(raw_value))
        pos = pair_end + 1
    return out^
