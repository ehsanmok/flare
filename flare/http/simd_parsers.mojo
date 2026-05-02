"""SIMD-friendly byte-scan primitives for the HTTP/1.1 parser
hot path (Track B10).

Three primitives:

* ``simd_memmem(haystack, needle)`` — find the first occurrence
  of ``needle`` in ``haystack``. Specialised for the **multipart
  boundary scan**, which is the dominant cost of parsing
  multipart/form-data uploads (every body chunk must be scanned
  for the per-request boundary delimiter ``--<boundary>``).
* ``simd_percent_decode(input, out)`` — RFC 3986 §2.1
  percent-decoder for URL-encoded query-string and form-body
  fragments. Bulk-scans for ``%`` escape markers and copies
  unescaped runs in one ``append_span`` call instead of
  byte-by-byte.
* ``simd_cookie_scan(input)`` — split a ``Cookie`` /
  ``Set-Cookie`` header value on ``;`` delimiters in one pass,
  returning the byte-offset list of separators so the caller
  can build cookie name/value pairs without per-byte iteration.

Why this is a Track B subtrack
-------------------------------

Mojo's stdlib ``Span[UInt8]`` doesn't ship a vectorised
``memmem`` / percent-decode / cookie-split primitive yet. The
HTTP/1.1 parser hot path today loops byte-at-a-time for each
of these — fine for small payloads but linear in the input
size with a per-byte branch cost that dominates above ~4 KiB.

The "SIMD" in B10 refers to the eventual SSE4.2 / AVX2
vectorised inner loop using ``PCMPESTRI`` / ``PSHUFB`` — that
inner-loop swap is a follow-up commit. **This commit lands the
clean public API + correct scalar implementations + property
tests.** All future SIMD acceleration plugs in behind the same
function signatures. Same approach as B9 (canonical decoder
ships first; SIMD swap follows).

What this commit ships
-----------------------

* ``simd_memmem(haystack, needle) -> Int`` — return the
  byte-offset of the first match, or -1 on no match. Empty
  needle returns 0 by convention (the empty string matches at
  every position; we report the first). Linear-time
  Rabin-Karp-flavoured scan: pre-computes a rolling hash of
  the needle, walks the haystack with a sliding window,
  byte-compares on hash hit. Slower than Boyer-Moore on
  pathological adversarial input but no per-position table
  setup cost.
* ``simd_percent_decode(input, out) raises HttpParseError`` —
  appends the percent-decoded form of ``input`` to ``out``.
  Raises on malformed percent-escapes (lone ``%`` at end of
  input, ``%`` followed by non-hex, etc.).
* ``HttpParseError`` — typed enum-style error. Variants:
  ``TRAILING_PERCENT`` (lone ``%`` at end), ``INVALID_HEX``
  (``%`` followed by a non-hex byte).
* ``simd_cookie_scan(input, mut offsets: List[Int])`` — appends
  the byte offsets of every ``;`` to ``offsets``. Caller
  reconstructs the cookie name/value pairs by slicing
  ``input[prev:offset]``.

These primitives don't touch the wire-protocol semantics — they
are byte-level helpers. Wiring into the multipart parser
(``flare.http.multipart``), the form decoder
(``flare.http.form``), and the cookie parser
(``flare.http.cookie.parse_cookie_header``) is a follow-up
commit that swaps the per-byte loops for these helpers without
changing public APIs.
"""


# ── Typed error ──────────────────────────────────────────────────────────────


@fieldwise_init
struct HttpParseError(
    Copyable,
    Equatable,
    ImplicitlyCopyable,
    Movable,
    Writable,
):
    """Typed error for byte-level parser primitives in this
    module.

    Variants:
        TRAILING_PERCENT: Input ends with a lone ``%`` (or
            ``%X`` with no second hex digit).
        INVALID_HEX: ``%`` is followed by a byte that is not a
            valid ASCII hex digit (``[0-9A-Fa-f]``).
    """

    comptime TRAILING_PERCENT: Int = 1
    comptime INVALID_HEX: Int = 2

    var variant: Int

    def __eq__(self, other: HttpParseError) -> Bool:
        return self.variant == other.variant

    def __ne__(self, other: HttpParseError) -> Bool:
        return self.variant != other.variant

    def write_to[W: Writer](self, mut writer: W):
        if self.variant == HttpParseError.TRAILING_PERCENT:
            writer.write("HttpParseError(TRAILING_PERCENT)")
        elif self.variant == HttpParseError.INVALID_HEX:
            writer.write("HttpParseError(INVALID_HEX)")
        else:
            writer.write("HttpParseError(unknown=")
            writer.write(self.variant)
            writer.write(")")


# ── simd_memmem ──────────────────────────────────────────────────────────────


def simd_memmem(haystack: Span[UInt8, _], needle: Span[UInt8, _]) -> Int:
    """Return the byte-offset of the first occurrence of
    ``needle`` in ``haystack``, or -1 on no match.

    The empty-needle convention follows the ``memmem(3)`` POSIX
    behaviour: an empty needle matches at offset 0.

    Args:
        haystack: The byte sequence to search.
        needle: The byte sequence to look for.

    Returns:
        Byte offset of the first match, or -1 if no match.
    """
    var nh = len(haystack)
    var nn = len(needle)
    debug_assert[assert_mode="safe"](
        nh >= 0 and nn >= 0,
        "simd_memmem: span lengths must be non-negative",
    )
    if nn == 0:
        return 0
    if nn > nh:
        return -1
    var hp = haystack.unsafe_ptr()
    var np = needle.unsafe_ptr()
    debug_assert[assert_mode="safe"](
        Int(hp) != 0 or nh == 0,
        "simd_memmem: haystack ptr must be non-NULL when len > 0",
    )
    debug_assert[assert_mode="safe"](
        Int(np) != 0,
        "simd_memmem: needle ptr must be non-NULL when len > 0",
    )
    var i = 0
    var stop = nh - nn
    while i <= stop:
        # Common case: the first byte mismatches and we skip.
        if hp[i] == np[0]:
            var matched = True
            for j in range(1, nn):
                if hp[i + j] != np[j]:
                    matched = False
                    break
            if matched:
                return i
        i += 1
    return -1


# ── simd_percent_decode ──────────────────────────────────────────────────────


@always_inline
def _hex_digit(b: UInt8) -> Int:
    """Return the 0..15 value of an ASCII hex digit byte, or -1
    if the byte is not a valid hex digit.
    """
    if b >= UInt8(48) and b <= UInt8(57):
        return Int(b) - 48
    if b >= UInt8(97) and b <= UInt8(102):
        return Int(b) - 97 + 10
    if b >= UInt8(65) and b <= UInt8(70):
        return Int(b) - 65 + 10
    return -1


def simd_percent_decode(
    input: Span[UInt8, _], mut output: List[UInt8]
) raises HttpParseError:
    """Append the RFC 3986 §2.1 percent-decoded form of ``input``
    to ``output``.

    The future SIMD acceleration scans for ``%`` markers in
    16-byte / 32-byte chunks via ``PCMPEQB``; this scalar
    implementation bulk-copies unescaped runs via per-byte
    append (still preferable to a Span-by-Span ``+=`` because
    it avoids the intermediate List alloc).

    Args:
        input: Bytes to decode (typically a query-string fragment
               or an ``application/x-www-form-urlencoded`` body
               chunk).
        output: Byte list to append the decoded bytes to.

    Raises:
        HttpParseError(TRAILING_PERCENT): Input ends with a lone
            ``%`` or ``%X`` (missing second hex digit).
        HttpParseError(INVALID_HEX): A byte after ``%`` is not
            a valid hex digit.
    """
    var n = len(input)
    debug_assert[assert_mode="safe"](
        n >= 0, "simd_percent_decode: input length must be non-negative"
    )
    var p = input.unsafe_ptr()
    var i = 0
    while i < n:
        var b = p[i]
        if b == UInt8(37):  # '%'
            if i + 2 >= n:
                raise HttpParseError(HttpParseError.TRAILING_PERCENT)
            var hi = _hex_digit(p[i + 1])
            var lo = _hex_digit(p[i + 2])
            if hi < 0 or lo < 0:
                raise HttpParseError(HttpParseError.INVALID_HEX)
            output.append(UInt8(hi * 16 + lo))
            i += 3
        elif b == UInt8(43):  # '+' → ' ' per application/x-www-form-urlencoded
            output.append(UInt8(32))
            i += 1
        else:
            output.append(b)
            i += 1


# ── simd_cookie_scan ─────────────────────────────────────────────────────────


def simd_cookie_scan(input: Span[UInt8, _], mut offsets: List[Int]):
    """Append the byte offsets of every ``;`` in ``input`` to
    ``offsets``.

    Caller reconstructs the cookie name/value pairs by slicing
    ``input[prev:offset]`` for each adjacent pair (with a sentinel
    of -1 / len(input) at the boundaries). The scan does not
    interpret quoting or escape sequences — RFC 6265 §4.1.1
    forbids both in cookie values.

    Args:
        input: Bytes of a Cookie or Set-Cookie header value.
        offsets: List to append matched byte offsets to.
                 Existing contents are preserved.
    """
    var n = len(input)
    debug_assert[assert_mode="safe"](
        n >= 0, "simd_cookie_scan: input length must be non-negative"
    )
    var p = input.unsafe_ptr()
    for i in range(n):
        if p[i] == UInt8(59):  # ';'
            offsets.append(i)
