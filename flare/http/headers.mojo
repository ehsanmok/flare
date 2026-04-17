"""HTTP header collection with case-insensitive key lookup.

Lookups use inline case-insensitive byte comparison (no pre-computed
lowercase mirror). Original casing is preserved for wire serialisation.
"""

from std.format import Writable, Writer


@always_inline
def _eq_icase(a: String, b: String) -> Bool:
    """Case-insensitive ASCII string comparison without allocation."""
    if a.byte_length() != b.byte_length():
        return False
    var ap = a.unsafe_ptr()
    var bp = b.unsafe_ptr()
    for i in range(a.byte_length()):
        var ac = ap[i]
        var bc = bp[i]
        if ac >= 65 and ac <= 90:
            ac = ac + 32
        if bc >= 65 and bc <= 90:
            bc = bc + 32
        if ac != bc:
            return False
    return True


@always_inline
def _lower(s: String) -> String:
    """Return ASCII-lowercase copy of ``s``."""
    var out = String(capacity=s.byte_length())
    for i in range(s.byte_length()):
        var c = s.unsafe_ptr()[i]
        if c >= 65 and c <= 90:
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out


struct HeaderInjectionError(Copyable, Movable, Writable):
    """Raised when a header key or value contains CR or LF bytes."""

    var field: String
    var value: String

    def __init__(out self, field: String, value: String):
        self.field = field
        self.value = value

    def write_to[W: Writer](self, mut writer: W):
        writer.write(
            "HeaderInjectionError: field='",
            self.field,
            "' value='",
            self.value,
            "'",
        )


@always_inline
def _check_injection(key: String, value: String) raises:
    """Raise ``HeaderInjectionError`` if key or value contain CR/LF."""
    for i in range(key.byte_length()):
        var c = key.unsafe_ptr()[i]
        if c == 13 or c == 10:
            raise HeaderInjectionError(key, value)
    for i in range(value.byte_length()):
        var c = value.unsafe_ptr()[i]
        if c == 13 or c == 10:
            raise HeaderInjectionError(key, value)


struct HeaderMap(Movable, Writable):
    """An ordered, case-insensitive HTTP header collection.

    Keys are stored in their original casing. Lookups use inline
    case-insensitive byte comparison -- no pre-computed lowercase list.

    This type is ``Movable`` but not ``Copyable``.
    Use ``copy()`` when an explicit copy is needed.

    Example:
        ```mojo
        var h = HeaderMap()
        h.set("Content-Type", "application/json")
        print(h.get("content-type"))  # application/json
        ```
    """

    var _keys: List[String]
    var _values: List[String]

    def __init__(out self):
        self._keys = List[String]()
        self._values = List[String]()

    def set_unchecked(mut self, key: String, lk: String, value: String):
        """Set a header without injection checks.

        The ``lk`` parameter is accepted for API compatibility but ignored;
        lookup uses inline case-insensitive comparison on ``key``.

        Args:
            key:   Header name.
            lk:    Ignored (kept for backward compat).
            value: Header value.
        """
        for i in range(len(self._keys)):
            if _eq_icase(self._keys[i], key):
                self._keys[i] = key
                self._values[i] = value
                return
        self._keys.append(key)
        self._values.append(value)

    def copy(self) -> HeaderMap:
        """Return a deep copy of this ``HeaderMap``."""
        var out = HeaderMap()
        for i in range(len(self._keys)):
            out._keys.append(self._keys[i])
            out._values.append(self._values[i])
        return out^

    def set(mut self, key: String, value: String) raises:
        """Set a header, replacing any existing value with the same key.

        Args:
            key:   Header name (case-insensitive; stored in original casing).
            value: Header value.

        Raises:
            HeaderInjectionError: If ``key`` or ``value`` contains ``\\r`` or ``\\n``.
        """
        _check_injection(key, value)
        for i in range(len(self._keys)):
            if _eq_icase(self._keys[i], key):
                self._keys[i] = key
                self._values[i] = value
                return
        self._keys.append(key)
        self._values.append(value)

    def append(mut self, key: String, value: String) raises:
        """Append a header without replacing existing values.

        Args:
            key:   Header name.
            value: Header value.

        Raises:
            HeaderInjectionError: If ``key`` or ``value`` contains ``\\r`` or ``\\n``.
        """
        _check_injection(key, value)
        self._keys.append(key)
        self._values.append(value)

    def get(self, key: String) -> String:
        """Return the first value for ``key``, or ``""`` if absent.

        Args:
            key: Header name (case-insensitive).

        Returns:
            The header value, or ``""`` if not present.
        """
        for i in range(len(self._keys)):
            if _eq_icase(self._keys[i], key):
                return self._values[i]
        return ""

    def get_all(self, key: String) -> List[String]:
        """Return all values for ``key`` in insertion order.

        Args:
            key: Header name (case-insensitive).

        Returns:
            All matching values; empty list if absent.
        """
        var out = List[String]()
        for i in range(len(self._keys)):
            if _eq_icase(self._keys[i], key):
                out.append(self._values[i])
        return out^

    def contains(self, key: String) -> Bool:
        """Return True if the header is present.

        Args:
            key: Header name (case-insensitive).

        Returns:
            True if at least one entry with this key exists.
        """
        for i in range(len(self._keys)):
            if _eq_icase(self._keys[i], key):
                return True
        return False

    def remove(mut self, key: String) -> Bool:
        """Remove all entries with the given key.

        Args:
            key: Header name (case-insensitive).

        Returns:
            True if at least one entry was removed.
        """
        var new_keys = List[String]()
        var new_values = List[String]()
        var removed = False
        for i in range(len(self._keys)):
            if _eq_icase(self._keys[i], key):
                removed = True
            else:
                new_keys.append(self._keys[i])
                new_values.append(self._values[i])
        self._keys = new_keys^
        self._values = new_values^
        return removed

    def len(self) -> Int:
        """Return the total number of header entries (including duplicates)."""
        return len(self._keys)

    def write_to[W: Writer](self, mut writer: W):
        for i in range(len(self._keys)):
            writer.write(self._keys[i], ": ", self._values[i], "\r\n")

    def encode_to(self, mut buf: List[UInt8]):
        """Serialise all headers as wire bytes into ``buf``.

        Appends ``key: value\\r\\n`` for each header.
        """
        for i in range(len(self._keys)):
            var k = self._keys[i]
            var kp = k.unsafe_ptr()
            var kn = k.byte_length()
            for j in range(kn):
                buf.append(kp[j])
            buf.append(58)
            buf.append(32)
            var v = self._values[i]
            var vp = v.unsafe_ptr()
            var vn = v.byte_length()
            for j in range(vn):
                buf.append(vp[j])
            buf.append(13)
            buf.append(10)
