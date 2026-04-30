"""SIMD-parametric byte scanners for the HTTP/1.1 parser hot path.

The parser walked header bytes with plain scalar loops. For
short requests that's free; for long keep-alive pipelines with
16+ headers it adds up. This module provides SIMD-width-parametric
replacements for the two hottest scanners:

- ``find_crlfcrlf[W]`` — locate the end-of-headers terminator.
- ``scan_content_length[W]`` — find ``Content-Length:`` in the header
  block and parse its decimal value.

Both take the SIMD lane count ``W`` as a compile-time parameter so the
call site can pick ``W`` once based on ``CompilationTarget``:

- ``32``: NEON (aarch64, 16 bytes, but the Mojo SIMD stride maps fine
  to 32-wide pseudo-lanes via its vectorised ops) and x86-64 AVX2.
- ``64``: AVX-512.

The default flare build uses ``W = 32``, which is a win everywhere.
Users who want AVX-512 can force ``W = 64`` by rebuilding the server.

Both functions degrade gracefully: if the input is shorter than ``W``
bytes, they fall through to a pure scalar path that matches the
previous implementations byte-for-byte.
"""

from std.memory import pack_bits
from std.bit import count_trailing_zeros


comptime SIMD_SCAN_WIDTH: Int = 32
"""Default SIMD stride for the HTTP header scanner.

Set at compile time; 32 is the right value for every platform flare
currently ships on (NEON aarch64, x86-64 AVX2). Override at the call
site with the explicit ``[W=64]`` parameter on AVX-512 hosts.
"""


# ── CR scan helpers ─────────────────────────────────────────────────────────


@always_inline
def _check_crlfcrlf(p: UnsafePointer[UInt8, _], pos: Int, n: Int) -> Bool:
    """Check whether ``p[pos:pos+4]`` is CRLFCRLF, bounds-safe against ``n``."""
    if pos + 3 >= n:
        return False
    return (
        p[pos] == 13
        and p[pos + 1] == 10
        and p[pos + 2] == 13
        and p[pos + 3] == 10
    )


def find_crlfcrlf[
    W: Int = SIMD_SCAN_WIDTH
](data: List[UInt8], start: Int) -> Int:
    """SIMD scan for ``\\r\\n\\r\\n`` in ``data[start:]``.

    Parameters:
        W: SIMD lane count. Compile-time constant; pick ``32`` or
            ``64`` based on target vector width.

    Args:
        data: Byte buffer to scan.
        start: Offset to begin scanning at (negative treated as 0).

    Returns:
        Byte offset just past the terminator (``i + 4``), or ``-1`` if
        not found. Matches the legacy scalar semantics exactly.
    """
    var n = len(data)
    if n < 4:
        return -1
    var s = start if start >= 0 else 0
    if n - s < W:
        return _scalar_find_crlfcrlf(data, s)
    var p = data.unsafe_ptr()
    var i = s

    comptime if W == 32:
        while i + W + 3 <= n:
            var chunk = (p + i).load[width=W]()
            var cr_mask = chunk.eq(13)
            if cr_mask.reduce_or():
                var bits = pack_bits[dtype=DType.uint32](cr_mask)
                while bits != 0:
                    var off = Int(count_trailing_zeros(bits))
                    var pos = i + off
                    if _check_crlfcrlf(p, pos, n):
                        return pos + 4
                    bits &= bits - 1
            i += W
    elif W == 64:
        while i + W + 3 <= n:
            var chunk = (p + i).load[width=W]()
            var cr_mask = chunk.eq(13)
            if cr_mask.reduce_or():
                var bits = pack_bits[dtype=DType.uint64](cr_mask)
                while bits != 0:
                    var off = Int(count_trailing_zeros(bits))
                    var pos = i + off
                    if _check_crlfcrlf(p, pos, n):
                        return pos + 4
                    bits &= bits - 1
            i += W
    else:
        # Unsupported width at comptime — fall through to scalar.
        return _scalar_find_crlfcrlf(data, s)

    # Scalar tail for the last (n - i) < W bytes.
    while i + 3 < n:
        if _check_crlfcrlf(p, i, n):
            return i + 4
        i += 1
    return -1


@always_inline
def _scalar_find_crlfcrlf(data: List[UInt8], start: Int) -> Int:
    """Scalar reference used when the buffer is shorter than ``W`` or
    when an unsupported ``W`` is selected.
    """
    var n = len(data)
    if n < 4:
        return -1
    var p = data.unsafe_ptr()
    for i in range(start, n - 3):
        if p[i] == 13 and p[i + 1] == 10 and p[i + 2] == 13 and p[i + 3] == 10:
            return i + 4
    return -1


# ── Content-Length scan ─────────────────────────────────────────────────────


@always_inline
def _match_content_length_prefix(
    p: UnsafePointer[UInt8, _], pos: Int, header_end: Int
) -> Bool:
    """Case-insensitive compare against ``"content-length:"`` at ``pos``.

    ``pos + 15 <= header_end`` is assumed by the caller; this function
    does not re-check the bound.
    """
    var needle = "content-length:"
    var np = needle.unsafe_ptr()
    for j in range(15):
        var c = p[pos + j]
        if c >= 65 and c <= 90:
            c = c + 32
        if c != np[j]:
            return False
    return True


def scan_content_length[
    W: Int = SIMD_SCAN_WIDTH
](data: List[UInt8], header_end: Int) -> Int:
    """SIMD scan for ``Content-Length:`` + parse the decimal value.

    Parameters:
        W: SIMD lane count for the outer scan. Same shape as
            ``find_crlfcrlf``.

    Args:
        data: Byte buffer (header region + maybe body bytes).
        header_end: Offset past the ``\\r\\n\\r\\n`` terminator; the
            scan stops before this so header-collision with the body is
            impossible.

    Returns:
        The parsed ``Content-Length`` integer, or ``0`` when no header
        is found. Ignores malformed values (matches legacy scalar
        behaviour — the caller treats 0 as "no body").
    """
    var needle_len = 15  # "content-length:"
    if header_end < needle_len:
        return 0
    var p = data.unsafe_ptr()
    var i = 0
    var end = header_end - needle_len + 1

    # We SIMD-scan for 'c' / 'C' bytes as candidate start positions.
    # Every match is followed by the full 15-byte case-insensitive
    # compare — same cost profile as the legacy byte-by-byte scalar
    # scan but with W-wide rejection when no 'c' / 'C' is in the chunk.

    comptime if W == 32:
        while i + W <= end:
            var chunk = (p + i).load[width=W]()
            # Candidate if byte == 'c' (0x63) or 'C' (0x43).
            var lc = chunk.eq(99)
            var uc = chunk.eq(67)
            var cand = lc | uc
            if cand.reduce_or():
                var bits = pack_bits[dtype=DType.uint32](cand)
                while bits != 0:
                    var off = Int(count_trailing_zeros(bits))
                    var pos = i + off
                    if pos >= end:
                        break
                    if _match_content_length_prefix(p, pos, header_end):
                        return _parse_decimal(p, pos + needle_len, header_end)
                    bits &= bits - 1
            i += W
    elif W == 64:
        while i + W <= end:
            var chunk = (p + i).load[width=W]()
            var lc = chunk.eq(99)
            var uc = chunk.eq(67)
            var cand = lc | uc
            if cand.reduce_or():
                var bits = pack_bits[dtype=DType.uint64](cand)
                while bits != 0:
                    var off = Int(count_trailing_zeros(bits))
                    var pos = i + off
                    if pos >= end:
                        break
                    if _match_content_length_prefix(p, pos, header_end):
                        return _parse_decimal(p, pos + needle_len, header_end)
                    bits &= bits - 1
            i += W

    # Scalar tail.
    while i < end:
        if _match_content_length_prefix(p, i, header_end):
            return _parse_decimal(p, i + needle_len, header_end)
        i += 1
    return 0


@always_inline
def _parse_decimal(p: UnsafePointer[UInt8, _], start: Int, end: Int) -> Int:
    """Skip leading SP / HTAB, parse an unsigned decimal up to ``end``."""
    var pos = start
    while pos < end and (p[pos] == 32 or p[pos] == 9):
        pos += 1
    var result = 0
    while pos < end and p[pos] >= 48 and p[pos] <= 57:
        result = result * 10 + Int(p[pos]) - 48
        pos += 1
    return result
