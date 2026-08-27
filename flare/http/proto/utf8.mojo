"""Lossy UTF-8 decoding for caller-supplied byte bodies.

``String(unsafe_from_utf8=Span)`` is the wrong tool for bytes that
arrive off the wire: it runs the stdlib UTF-8 validator internally
despite its name (see ``proto/ascii.mojo``), and on malformed input that
validator passes the bytes through in the default build -- yielding an
ill-formed ``String`` -- and aborts the process under ``-D ASSERT=all``.
Since a peer chooses the bytes, neither outcome is acceptable on
``Request.text()`` / ``Response.text()`` / ``MultipartPart.text()``.

:func:`utf8_lossy_string` gives those call sites a total function
instead: well-formed input is copied verbatim, and each maximal
ill-formed subpart becomes one U+FFFD REPLACEMENT CHARACTER (Unicode 15
§3.9, "U+FFFD Substitution of Maximal Subparts"). The result is always
well-formed UTF-8, so it can never abort and never produces an
ill-formed ``String``.

Protocols that must *reject* invalid UTF-8 rather than substitute --
WebSocket TEXT frames under RFC 6455 §8.1 -- keep validating and
raising instead; see ``WsFrame.text_payload``.
"""


@always_inline
def _is_cont(b: UInt8) -> Bool:
    """Return True if ``b`` is a UTF-8 continuation byte (10xxxxxx)."""
    return b >= 0x80 and b <= 0xBF


@always_inline
def _step(data: Span[UInt8, _], i: Int, n: Int) -> Int:
    """Classify the UTF-8 sequence starting at ``data[i]``.

    Accepts exactly what RFC 3629 allows, matching the validator in
    ``flare/io/byte_cursor.mojo``: overlong encodings, UTF-16
    surrogates (U+D800..U+DFFF) and codepoints above U+10FFFF are all
    ill-formed.

    Args:
        data: Source bytes.
        i: Index of the sequence's lead byte.
        n: ``len(data)``, hoisted by the caller.

    Returns:
        A positive length (1..4) when a well-formed sequence starts at
        ``i``. Otherwise the negated length of the maximal subpart to
        replace with a single U+FFFD -- that is, the lead byte plus
        however many continuation bytes were themselves well-formed.
    """
    var b = data[i]
    if b <= 0x7F:
        return 1

    if b >= 0xC2 and b <= 0xDF:
        if i + 1 < n and _is_cont(data[i + 1]):
            return 2
        return -1

    if b >= 0xE0 and b <= 0xEF:
        # E0 forbids A0-BF's overlong range; ED forbids the surrogates.
        var lo = UInt8(0x80)
        var hi = UInt8(0xBF)
        if b == 0xE0:
            lo = UInt8(0xA0)
        if b == 0xED:
            hi = UInt8(0x9F)
        if i + 1 >= n or data[i + 1] < lo or data[i + 1] > hi:
            return -1
        if i + 2 >= n or not _is_cont(data[i + 2]):
            return -2
        return 3

    if b >= 0xF0 and b <= 0xF4:
        # F0 forbids the overlong range; F4 caps at U+10FFFF.
        var lo = UInt8(0x80)
        var hi = UInt8(0xBF)
        if b == 0xF0:
            lo = UInt8(0x90)
        if b == 0xF4:
            hi = UInt8(0x8F)
        if i + 1 >= n or data[i + 1] < lo or data[i + 1] > hi:
            return -1
        if i + 2 >= n or not _is_cont(data[i + 2]):
            return -2
        if i + 3 >= n or not _is_cont(data[i + 3]):
            return -3
        return 4

    # 80-C1 (bare continuation or overlong lead) and F5-FF.
    return -1


def utf8_lossy_string(data: Span[UInt8, _]) -> String:
    """Decode ``data`` as UTF-8, substituting U+FFFD for bad sequences.

    Args:
        data: Source bytes, typically a caller-supplied message body.

    Returns:
        ``data`` as a ``String``, always well-formed UTF-8. Each maximal
        ill-formed subpart is replaced by one U+FFFD.
    """
    var n = len(data)
    if n == 0:
        return String("")

    var i = 0
    var first_bad = -1
    while i < n:
        var w = _step(data, i, n)
        if w < 0:
            first_bad = i
            break
        i += w

    if first_bad < 0:
        # ponytail: the happy path validates twice, here and again inside
        # the constructor. Swap in String(unsafe_uninit_length=n) + memcpy
        # (as proto/ascii.mojo does) if text() ever lands on a hot path.
        return String(unsafe_from_utf8=data)

    var out = List[UInt8](capacity=n + 3)
    for k in range(first_bad):
        out.append(data[k])

    i = first_bad
    while i < n:
        var w = _step(data, i, n)
        if w < 0:
            out.append(UInt8(0xEF))
            out.append(UInt8(0xBF))
            out.append(UInt8(0xBD))
            i += -w
        else:
            for k in range(i, i + w):
                out.append(data[k])
            i += w

    return String(unsafe_from_utf8=Span[UInt8, _](out))
