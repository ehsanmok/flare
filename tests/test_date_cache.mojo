"""Tests for ``flare.runtime.DateCache``."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.runtime import DateCache, libc_nanosleep_ms


def _slice_str(s: String, start: Int, end: Int) -> String:
    """Helper: build a fresh String from the byte range [start, end)
    of ``s``. The Mojo nightly we're pinned to does not expose
    byte-positional slicing through ``s[a:b]``; callers go through
    this byte-level helper instead.
    """
    var sp = s.unsafe_ptr()
    var buf = List[UInt8]()
    buf.resize(end - start, UInt8(0))
    for i in range(end - start):
        buf[i] = sp[start + i]
    return String(unsafe_from_utf8=Span[UInt8, _](buf))


def test_cache_primes_on_construction() raises:
    """Construction renders the buffer immediately.

    ``current_bytes()`` is safe to call without a manual ``refresh()``.
    """
    var cache = DateCache()
    var bytes = cache.current_bytes()
    assert_equal(len(bytes), 29)


def test_cache_layout_imf_fixdate_shape() raises:
    """The cached buffer matches RFC 9110 §5.6.7 IMF-fixdate shape:
    ``Sun, 06 Nov 1994 08:49:37 GMT`` — exactly 29 bytes, comma at
    position 3, two spaces at positions 4 / 7 / 11 / 16 / 25,
    colons at 19 / 22, ``GMT`` at 26-28.
    """
    var cache = DateCache()
    var bytes = cache.current_bytes()
    assert_equal(len(bytes), 29)
    assert_equal(Int(bytes[3]), 44)
    assert_equal(Int(bytes[4]), 32)
    assert_equal(Int(bytes[7]), 32)
    assert_equal(Int(bytes[11]), 32)
    assert_equal(Int(bytes[16]), 32)
    assert_equal(Int(bytes[19]), 58)
    assert_equal(Int(bytes[22]), 58)
    assert_equal(Int(bytes[25]), 32)
    assert_equal(Int(bytes[26]), 71)
    assert_equal(Int(bytes[27]), 77)
    assert_equal(Int(bytes[28]), 84)


def test_weekday_in_known_set() raises:
    """The 3-byte weekday at positions [0:3] is one of the known
    short names (Sun / Mon / Tue / Wed / Thu / Fri / Sat).
    """
    var cache = DateCache()
    var s = cache.current_string()
    var head = _slice_str(s, 0, 3)
    assert_true(
        head == "Sun"
        or head == "Mon"
        or head == "Tue"
        or head == "Wed"
        or head == "Thu"
        or head == "Fri"
        or head == "Sat"
    )


def test_month_in_known_set() raises:
    """The 3-byte month at positions [8:11] is one of the known
    short names.
    """
    var cache = DateCache()
    var s = cache.current_string()
    var month = _slice_str(s, 8, 11)
    assert_true(
        month == "Jan"
        or month == "Feb"
        or month == "Mar"
        or month == "Apr"
        or month == "May"
        or month == "Jun"
        or month == "Jul"
        or month == "Aug"
        or month == "Sep"
        or month == "Oct"
        or month == "Nov"
        or month == "Dec"
    )


def test_year_at_or_after_2026() raises:
    """The cache is rendered against the current wall clock; the
    year decoded from positions [12:16] must be >= 2026 (when this
    test was written).
    """
    var cache = DateCache()
    var s = cache.current_string()
    var year_s = _slice_str(s, 12, 16)
    var year_int = Int(year_s)
    assert_true(year_int >= 2026)


def test_hour_minute_second_in_range() raises:
    """The HH/MM/SS triplets parse as valid wall-clock values
    (0-23 / 0-59 / 0-60 — leap second tolerated).
    """
    var cache = DateCache()
    var s = cache.current_string()
    var hh = Int(_slice_str(s, 17, 19))
    var mm = Int(_slice_str(s, 20, 22))
    var ss = Int(_slice_str(s, 23, 25))
    assert_true(hh >= 0 and hh <= 23)
    assert_true(mm >= 0 and mm <= 59)
    assert_true(ss >= 0 and ss <= 60)


def test_refresh_is_noop_within_same_second() raises:
    """Within a single second, ``refresh()`` does not advance
    ``epoch_second()`` and the buffer pointer's contents stay
    identical.
    """
    var cache = DateCache()
    var first = cache.current_string()
    var second_marker = cache.epoch_second()
    cache.refresh()
    cache.refresh()
    cache.refresh()
    var second = cache.current_string()
    assert_equal(cache.epoch_second(), second_marker)
    assert_equal(first, second)


def test_refresh_advances_after_one_second() raises:
    """Sleep just over a second; ``refresh()`` should bump
    ``epoch_second()`` and re-render the buffer.

    Sleep precision is ~few ms; a 1500 ms sleep makes second
    advancement deterministic.
    """
    var cache = DateCache()
    var before = cache.epoch_second()
    var before_str = cache.current_string()
    _ = libc_nanosleep_ms(1500)
    cache.refresh()
    var after = cache.epoch_second()
    var after_str = cache.current_string()
    assert_true(after > before)
    var changed = False
    for i in range(17, 25):
        if before_str.unsafe_ptr()[i] != after_str.unsafe_ptr()[i]:
            changed = True
            break
    assert_true(changed)


def test_current_bytes_and_string_agree() raises:
    """``current_bytes()`` and ``current_string()`` must produce
    byte-identical content.
    """
    var cache = DateCache()
    var bytes = cache.current_bytes()
    var s = cache.current_string()
    assert_equal(len(bytes), s.byte_length())
    var sp = s.unsafe_ptr()
    for i in range(len(bytes)):
        assert_equal(Int(bytes[i]), Int(sp[i]))


def test_format_known_unix_seconds() raises:
    """Spot-check a known Unix-epoch second against its expected
    IMF-fixdate rendering.

    ``1234567890`` = ``Fri, 13 Feb 2009 23:31:30 GMT`` per any
    standard date library (``date -ud @1234567890``).
    """
    from flare.runtime.date_cache import _format_imf_fixdate

    var buf = List[UInt8]()
    buf.resize(29, UInt8(0))
    _format_imf_fixdate(1234567890, buf.unsafe_ptr())
    var s = String(unsafe_from_utf8=Span[UInt8, _](buf))
    assert_equal(s, String("Fri, 13 Feb 2009 23:31:30 GMT"))


def test_format_y2038_cusp() raises:
    """The 32-bit Unix-epoch wraparound is at ``2147483647`` →
    ``Tue, 19 Jan 2038 03:14:07 GMT``. The cache uses 64-bit
    arithmetic throughout, so values past Y2038 must format
    correctly.
    """
    from flare.runtime.date_cache import _format_imf_fixdate

    var buf = List[UInt8]()
    buf.resize(29, UInt8(0))
    _format_imf_fixdate(2147483647, buf.unsafe_ptr())
    var s = String(unsafe_from_utf8=Span[UInt8, _](buf))
    assert_equal(s, String("Tue, 19 Jan 2038 03:14:07 GMT"))

    _format_imf_fixdate(2147483648, buf.unsafe_ptr())
    var s2 = String(unsafe_from_utf8=Span[UInt8, _](buf))
    assert_equal(s2, String("Tue, 19 Jan 2038 03:14:08 GMT"))


def test_format_distant_future() raises:
    """Year 2100 cusp; verifies the civil-from-days inverse handles
    the non-leap centurial correctly.
    """
    from flare.runtime.date_cache import _format_imf_fixdate

    var buf = List[UInt8]()
    buf.resize(29, UInt8(0))
    # 2100-03-01 00:00:00 UTC = 4107542400 (Python:
    # ``datetime(2100, 3, 1, tzinfo=timezone.utc).timestamp()``).
    _format_imf_fixdate(4107542400, buf.unsafe_ptr())
    var s = String(unsafe_from_utf8=Span[UInt8, _](buf))
    assert_equal(s, String("Mon, 01 Mar 2100 00:00:00 GMT"))


def test_format_leap_day_2024() raises:
    """2024-02-29 was a Thursday. ``1709164800`` = midnight UTC of
    that day. Confirms Feb-29 month-shift handling in the
    civil-from-days routine.
    """
    from flare.runtime.date_cache import _format_imf_fixdate

    var buf = List[UInt8]()
    buf.resize(29, UInt8(0))
    _format_imf_fixdate(1709164800, buf.unsafe_ptr())
    var s = String(unsafe_from_utf8=Span[UInt8, _](buf))
    assert_equal(s, String("Thu, 29 Feb 2024 00:00:00 GMT"))


def test_format_unix_epoch() raises:
    """Unix epoch zero is a Thursday: ``Thu, 01 Jan 1970 00:00:00 GMT``.

    Boundary case for the day-of-week math.
    """
    from flare.runtime.date_cache import _format_imf_fixdate

    var buf = List[UInt8]()
    buf.resize(29, UInt8(0))
    _format_imf_fixdate(0, buf.unsafe_ptr())
    var s = String(unsafe_from_utf8=Span[UInt8, _](buf))
    assert_equal(s, String("Thu, 01 Jan 1970 00:00:00 GMT"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
