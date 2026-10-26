"""Which strings may cross into C as NUL-terminated ``char*``.

C reads a ``char*`` up to its first NUL. Two Mojo strings do not survive
that: one holding a NUL byte, which C reads cut short (``"localhost\\0.evil"``
resolves as ``localhost``), and the empty string, whose
``as_c_string_span().ptr()`` is not always a pointer to ``""`` (issue #42
handed OpenSSL a path read from unrelated static data). :func:`c_str_verdict`
decides, for every string flare passes to C this way, whether it is passed,
passed as NULL, or refused; each call site says what an empty value means
to its C parameter. ``formal/Flare/Kernels/CStr.lean`` proves that whatever
is passed is read by C as exactly the Mojo string.
"""


comptime CSTR_PASS: Int = 0
"""Pass the string's NUL-terminated bytes."""
comptime CSTR_NULL: Int = 1
"""Pass NULL: the string is empty and the C side reads NULL as a default."""
comptime CSTR_REJECT: Int = 2
"""Refuse: the string holds a NUL, or is empty where C needs a value."""

comptime EMPTY_REJECT: Int = 0
"""An empty value is invalid for this parameter."""
comptime EMPTY_NULL: Int = 1
"""An empty value is passed as NULL ("use the default")."""
comptime EMPTY_PASS: Int = 2
"""An empty value is passed as ``""`` (a meaningful empty key)."""


def c_str_verdict(s: Span[UInt8, _], empty: Int) -> Int:
    """Decide how ``s`` crosses into C as a ``char*``.

    Args:
        s: The string's bytes, without a terminator.
        empty: What an empty value means to the C parameter: one of
            ``EMPTY_REJECT``, ``EMPTY_NULL``, ``EMPTY_PASS``.

    Returns:
        ``CSTR_PASS``, ``CSTR_NULL`` or ``CSTR_REJECT``.
    """
    if len(s) == 0:
        if empty == EMPTY_NULL:
            return CSTR_NULL
        return CSTR_PASS if empty == EMPTY_PASS else CSTR_REJECT
    for i in range(len(s)):
        if s[i] == 0:
            return CSTR_REJECT
    return CSTR_PASS


def c_str_addr(mut s: String, empty: Int, what: String) raises -> Int:
    """The address to hand C for ``s``: its NUL-terminated buffer, or 0.

    ``s`` is NUL-terminated in place (an empty one is first replaced by a
    fresh empty string, whose terminator is its own), so the caller must
    keep it alive until the C call returns (``_ = s^``).

    Raises:
        Error: ``s`` holds a NUL byte, or is empty and ``empty`` is
            ``EMPTY_REJECT``. The message names ``what``, not the bytes.
    """
    var v = c_str_verdict(s.as_bytes(), empty)
    if v == CSTR_NULL:
        return 0
    if v == CSTR_REJECT:
        raise Error(what + ": empty or contains a NUL byte")
    if s.byte_length() == 0:
        s = String(unsafe_from_utf8=Span(List[UInt8]()))
    return Int(s.as_c_string_span().ptr())
