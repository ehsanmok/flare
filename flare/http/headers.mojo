"""HTTP header collection with case-insensitive key lookup.

All keys are normalised to lowercase for comparison (RFC 7230 §3.2).
The original casing is preserved in the ``_keys`` list for serialisation.
"""

from format import Writable, Writer


@always_inline
fn _lower(s: String) -> String:
    """Return ASCII-lowercase copy of ``s``."""
    var out = String(capacity=len(s))
    for i in range(len(s)):
        var c = s.unsafe_ptr()[i]
        if c >= 65 and c <= 90:  # 'A'..'Z'
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out


struct HeaderInjectionError(Copyable, Movable, Stringable, Writable):
    """Raised when a header key or value contains CR or LF bytes."""

    var field: String
    var value: String

    fn __init__(out self, field: String, value: String):
        self.field = field
        self.value = value

    fn write_to[W: Writer](self, mut writer: W):
        writer.write(
            "HeaderInjectionError: field='",
            self.field,
            "' value='",
            self.value,
            "'",
        )

    fn __str__(self) -> String:
        return (
            "HeaderInjectionError: field='"
            + self.field
            + "' value='"
            + self.value
            + "'"
        )


@always_inline
fn _check_injection(key: String, value: String) raises:
    """Raise ``HeaderInjectionError`` if key or value contain CR/LF."""
    for i in range(len(key)):
        var c = key.unsafe_ptr()[i]
        if c == 13 or c == 10:  # CR or LF
            raise HeaderInjectionError(key, value)
    for i in range(len(value)):
        var c = value.unsafe_ptr()[i]
        if c == 13 or c == 10:
            raise HeaderInjectionError(key, value)


struct HeaderMap(Movable, Stringable, Writable):
    """An ordered, case-insensitive HTTP header collection.

    Keys are stored in their original casing but all lookups are
    case-insensitive per RFC 7230 §3.2.  Lookups use lowercase
    comparison on ``_lower_keys``; original casing is kept in ``_keys``
    for wire serialisation.

    This type is ``Movable`` (owns heap-allocated lists) but not
    ``Copyable`` to avoid accidental deep copies in hot paths.
    Use ``copy()`` when an explicit copy is needed.

    Example:
        ```mojo
        var h = HeaderMap()
        h.set("Content-Type", "application/json")
        print(h.get("content-type"))  # application/json
        ```
    """

    var _keys: List[String]
    var _lower_keys: List[
        String
    ]  # lowercase mirror for O(n) case-insensitive lookup
    var _values: List[String]

    fn __init__(out self):
        self._keys = List[String]()
        self._lower_keys = List[String]()
        self._values = List[String]()

    fn __moveinit__(out self, deinit take: HeaderMap):
        self._keys = take._keys^
        self._lower_keys = take._lower_keys^
        self._values = take._values^

    fn copy(self) -> HeaderMap:
        """Return a deep copy of this ``HeaderMap``.

        Returns:
            A new ``HeaderMap`` with the same headers.
        """
        var out = HeaderMap()
        for i in range(len(self._keys)):
            out._keys.append(self._keys[i])
            out._lower_keys.append(self._lower_keys[i])
            out._values.append(self._values[i])
        return out^

    fn set(mut self, key: String, value: String) raises:
        """Set a header, replacing any existing value with the same key.

        Args:
            key:   Header name (case-insensitive; stored in original casing).
            value: Header value.

        Raises:
            HeaderInjectionError: If ``key`` or ``value`` contains ``\\r`` or ``\\n``.
        """
        _check_injection(key, value)
        var lk = _lower(key)
        for i in range(len(self._lower_keys)):
            if self._lower_keys[i] == lk:
                self._keys[i] = key
                self._values[i] = value
                return
        self._keys.append(key)
        self._lower_keys.append(lk)
        self._values.append(value)

    fn append(mut self, key: String, value: String) raises:
        """Append a header without replacing existing values.

        Useful for multi-value headers such as ``Set-Cookie``.

        Args:
            key:   Header name.
            value: Header value.

        Raises:
            HeaderInjectionError: If ``key`` or ``value`` contains ``\\r`` or ``\\n``.
        """
        _check_injection(key, value)
        self._keys.append(key)
        self._lower_keys.append(_lower(key))
        self._values.append(value)

    fn get(self, key: String) -> String:
        """Return the first value for ``key``, or ``""`` if absent.

        Args:
            key: Header name (case-insensitive).

        Returns:
            The header value, or ``""`` if not present.
        """
        var lk = _lower(key)
        for i in range(len(self._lower_keys)):
            if self._lower_keys[i] == lk:
                return self._values[i]
        return ""

    fn get_all(self, key: String) -> List[String]:
        """Return all values for ``key`` in insertion order.

        Args:
            key: Header name (case-insensitive).

        Returns:
            All matching values; empty list if absent.
        """
        var lk = _lower(key)
        var out = List[String]()
        for i in range(len(self._lower_keys)):
            if self._lower_keys[i] == lk:
                out.append(self._values[i])
        return out^

    fn contains(self, key: String) -> Bool:
        """Return True if the header is present.

        Args:
            key: Header name (case-insensitive).

        Returns:
            True if at least one entry with this key exists.
        """
        var lk = _lower(key)
        for i in range(len(self._lower_keys)):
            if self._lower_keys[i] == lk:
                return True
        return False

    fn remove(mut self, key: String) -> Bool:
        """Remove all entries with the given key.

        Args:
            key: Header name (case-insensitive).

        Returns:
            True if at least one entry was removed.
        """
        var lk = _lower(key)
        var new_keys = List[String]()
        var new_lower = List[String]()
        var new_values = List[String]()
        var removed = False
        for i in range(len(self._lower_keys)):
            if self._lower_keys[i] == lk:
                removed = True
            else:
                new_keys.append(self._keys[i])
                new_lower.append(self._lower_keys[i])
                new_values.append(self._values[i])
        self._keys = new_keys^
        self._lower_keys = new_lower^
        self._values = new_values^
        return removed

    fn len(self) -> Int:
        """Return the total number of header entries (including duplicates)."""
        return len(self._keys)

    fn write_to[W: Writer](self, mut writer: W):
        for i in range(len(self._keys)):
            writer.write(self._keys[i], ": ", self._values[i], "\r\n")

    fn __str__(self) -> String:
        var s = String()
        for i in range(len(self._keys)):
            s += self._keys[i] + ": " + self._values[i] + "\r\n"
        return s
