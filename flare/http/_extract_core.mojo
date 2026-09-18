"""``flare.http._extract_core`` -- extractor trait + scalar parsers.

The :class:`Extractor` trait plus the ``_parse_int_param`` /
``_parse_float64_param`` / ``_parse_bool_param`` scalar parsers that the
concrete extractors in :mod:`flare.http.extract` build on. Split out so
``extract.mojo`` stays within the file-size budget;
``flare.http.extract`` re-exports :class:`Extractor` so existing
``from flare.http.extract import Extractor`` call sites keep resolving.
"""

from .request import Request


@always_inline
def _parse_int_param(s: String) raises -> Int:
    """Parse an HTTP path / query / header value into an ``Int``.

    Accepts an optional leading ``-``. Raises on empty input, non-
    digit bytes, or a lone ``-``. The error message includes the
    rejected input so a 400 response surfaces what the client sent.
    """
    var n = s.byte_length()
    if n == 0:
        raise Error("expected integer, got empty string")
    var p = s.unsafe_ptr()
    var i = 0
    var neg = False
    if p[unsafe_offset=0] == 45:  # '-'
        neg = True
        i = 1
    if i == n:
        raise Error("expected integer, got '" + s + "'")
    var acc = 0
    while i < n:
        var c = Int(p[unsafe_offset=i])
        if c < 48 or c > 57:
            raise Error("expected integer, got '" + s + "'")
        acc = acc * 10 + (c - 48)
        i += 1
    return -acc if neg else acc


@always_inline
def _parse_float64_param(s: String) raises -> Float64:
    """Parse an HTTP path / query / header value into a ``Float64``.

    Delegates to Mojo's built-in ``Float64`` constructor so NaN,
    Infinity, malformed exponents are caught.
    """
    if s.byte_length() == 0:
        raise Error("expected float, got empty string")
    try:
        return Float64(s)
    except:
        raise Error("expected float, got '" + s + "'")


@always_inline
def _parse_bool_param(s: String) raises -> Bool:
    """Parse an HTTP path / query / header value into a ``Bool``.

    Accepts ``true`` / ``false`` / ``1`` / ``0`` / ``yes`` / ``no``
    case-insensitively (same vocabulary the wider HTTP ecosystem
    uses for ``Accept`` quality flags and similar).
    """
    var n = s.byte_length()
    if n == 0:
        raise Error("expected bool, got empty string")
    var lower = String(capacity=n)
    var p = s.unsafe_ptr()
    for i in range(n):
        var c = p[unsafe_offset=i]
        if c >= 65 and c <= 90:
            c = c + 32
        lower += chr(Int(c))
    if lower == "true" or lower == "1" or lower == "yes":
        return True
    if lower == "false" or lower == "0" or lower == "no":
        return False
    raise Error("expected bool, got '" + s + "'")


# ── Extractor trait ─────────────────────────────────────────────────────────


trait Extractor(Copyable, Defaultable, Deinitable):
    """Anything that can extract itself from a ``Request`` in place.

    ``Extracted[H]`` default-constructs the handler struct ``H`` and then
    calls ``apply(req)`` on each field in declaration order. Implementors
    should replace their default value with the parsed request value
    during ``apply``; raising propagates as a 400 through ``Extracted``.
    """

    def apply(mut self, req: Request) raises:
        ...
