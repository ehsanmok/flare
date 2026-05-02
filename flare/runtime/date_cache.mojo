"""Per-worker monotonic Date-header cache (Track B7).

`Date: <IMF-fixdate>` per RFC 9110 §6.6.1 / RFC 5322 §3.3:

    Sun, 06 Nov 1994 08:49:37 GMT       ; 29 bytes, fixed width

Naive implementations call ``time(NULL) + gmtime_r(...) + strftime(...)``
once per response, paying ~3 syscalls / library calls + a TZ lookup on
every keep-alive request. Under TFB plaintext at 220K req/s + 4 workers,
that's ~880K Date-header formats / s — measurable.

This cache amortises the formatting cost to **once per second per
worker**: each access compares a cached "epoch second" against the
current ``CLOCK_REALTIME`` second; on a miss it re-formats the buffer
in place, on a hit it returns the same 29-byte buffer immediately.

Per-worker, not shared: each reactor worker holds its own ``DateCache``
in worker-local storage. There is no cross-thread contention, no atomic,
no mutex. The trade-off is ``num_workers`` formats / s instead of one;
at the v0.7 worker counts (1–32) that's negligible.

Algorithm: branch-free Howard Hinnant ``civil_from_days`` inverse for
the year/month/day decomposition (same routine
``flare.http.structured_logger`` uses for ISO-8601 timestamps and
``flare.http.conditional`` uses for HTTP-date parsing), then a 29-byte
direct write into a stack / heap buffer. No allocations on the hot
path past first construction.

The cache exposes ``current_bytes`` (returns a borrow over the cached
buffer) and ``current_string`` (allocates a fresh `String` copy when
the caller needs ownership). Middleware that emits ``Date`` headers
into a wire buffer should prefer ``current_bytes`` to avoid a per-
request copy — the underlying 29-byte buffer is stable until the
next ``refresh()`` call from the same worker.

Example:

    var cache = DateCache()
    cache.refresh()  # idempotent; no-op when already on the current second
    var buf = cache.current_bytes()  # Span[UInt8, ...]
    # ... copy buf into wire buffer with memcpy ...

The cache is **not** thread-safe. Each worker constructs its own.
"""

from std.ffi import c_int, external_call
from std.memory import UnsafePointer, stack_allocation


comptime _IMF_FIXDATE_LEN: Int = 29
"""Length of an IMF-fixdate string (RFC 5322 §3.3).

    Sun, 06 Nov 1994 08:49:37 GMT  (29 bytes)
    """

comptime _SECS_PER_DAY: Int = 86400


# ── Lookup tables ─────────────────────────────────────────────────────────────


@always_inline
def _day_of_week_short(dow: Int) -> SIMD[DType.uint8, 4]:
    """Return the 3-byte short weekday name + a trailing comma byte for
    ``dow`` (0=Sun ... 6=Sat).

    Packed into a 4-byte SIMD so the call site can store with a single
    aligned write. The ``,`` byte is included because ``Day, ``-shaped
    output writes "Sun," / "Mon," / ... at the same offset.
    """
    if dow == 0:
        return SIMD[DType.uint8, 4](
            UInt8(83), UInt8(117), UInt8(110), UInt8(44)
        )  # 'S','u','n',','
    elif dow == 1:
        return SIMD[DType.uint8, 4](
            UInt8(77), UInt8(111), UInt8(110), UInt8(44)
        )  # 'M','o','n',','
    elif dow == 2:
        return SIMD[DType.uint8, 4](
            UInt8(84), UInt8(117), UInt8(101), UInt8(44)
        )  # 'T','u','e',','
    elif dow == 3:
        return SIMD[DType.uint8, 4](
            UInt8(87), UInt8(101), UInt8(100), UInt8(44)
        )  # 'W','e','d',','
    elif dow == 4:
        return SIMD[DType.uint8, 4](
            UInt8(84), UInt8(104), UInt8(117), UInt8(44)
        )  # 'T','h','u',','
    elif dow == 5:
        return SIMD[DType.uint8, 4](
            UInt8(70), UInt8(114), UInt8(105), UInt8(44)
        )  # 'F','r','i',','
    else:
        return SIMD[DType.uint8, 4](
            UInt8(83), UInt8(97), UInt8(116), UInt8(44)
        )  # 'S','a','t',','


@always_inline
def _month_short(m: Int) -> SIMD[DType.uint8, 4]:
    """Return the 3-byte short month name + trailing space for month
    ``m`` (1=Jan ... 12=Dec).

    Trailing space included so the caller can do a single 4-byte
    aligned store at the ``DD ``-month-`` HH`` boundary.
    """
    if m == 1:
        return SIMD[DType.uint8, 4](
            UInt8(74), UInt8(97), UInt8(110), UInt8(32)
        )  # 'J','a','n',' '
    elif m == 2:
        return SIMD[DType.uint8, 4](
            UInt8(70), UInt8(101), UInt8(98), UInt8(32)
        )  # 'F','e','b',' '
    elif m == 3:
        return SIMD[DType.uint8, 4](
            UInt8(77), UInt8(97), UInt8(114), UInt8(32)
        )  # 'M','a','r',' '
    elif m == 4:
        return SIMD[DType.uint8, 4](
            UInt8(65), UInt8(112), UInt8(114), UInt8(32)
        )  # 'A','p','r',' '
    elif m == 5:
        return SIMD[DType.uint8, 4](
            UInt8(77), UInt8(97), UInt8(121), UInt8(32)
        )  # 'M','a','y',' '
    elif m == 6:
        return SIMD[DType.uint8, 4](
            UInt8(74), UInt8(117), UInt8(110), UInt8(32)
        )  # 'J','u','n',' '
    elif m == 7:
        return SIMD[DType.uint8, 4](
            UInt8(74), UInt8(117), UInt8(108), UInt8(32)
        )  # 'J','u','l',' '
    elif m == 8:
        return SIMD[DType.uint8, 4](
            UInt8(65), UInt8(117), UInt8(103), UInt8(32)
        )  # 'A','u','g',' '
    elif m == 9:
        return SIMD[DType.uint8, 4](
            UInt8(83), UInt8(101), UInt8(112), UInt8(32)
        )  # 'S','e','p',' '
    elif m == 10:
        return SIMD[DType.uint8, 4](
            UInt8(79), UInt8(99), UInt8(116), UInt8(32)
        )  # 'O','c','t',' '
    elif m == 11:
        return SIMD[DType.uint8, 4](
            UInt8(78), UInt8(111), UInt8(118), UInt8(32)
        )  # 'N','o','v',' '
    else:
        return SIMD[DType.uint8, 4](
            UInt8(68), UInt8(101), UInt8(99), UInt8(32)
        )  # 'D','e','c',' '


@always_inline
def _write_two_digits(
    p: UnsafePointer[UInt8, _], offset: Int, n: Int
) where type_of(p).mut:
    """Write a zero-padded two-digit decimal at ``p + offset``.

    Caller guarantees ``0 <= n < 100``; the assert verifies
    that contract under ``-D ASSERT=safe`` so a regression in
    the civil-from-days arithmetic is caught at the write site
    instead of becoming garbled wire bytes.
    """
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 2 <= _IMF_FIXDATE_LEN,
        "_write_two_digits: offset out of range; got ",
        offset,
    )
    debug_assert[assert_mode="safe"](
        n >= 0 and n < 100,
        "_write_two_digits: n must be in 0..=99; got ",
        n,
    )
    (p + offset).init_pointee_copy(UInt8(48 + n // 10))
    (p + offset + 1).init_pointee_copy(UInt8(48 + n % 10))


@always_inline
def _write_four_digits(
    p: UnsafePointer[UInt8, _], offset: Int, n: Int
) where type_of(p).mut:
    """Write a zero-padded four-digit decimal at ``p + offset``.

    Caller guarantees ``0 <= n < 10000``.
    """
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 4 <= _IMF_FIXDATE_LEN,
        "_write_four_digits: offset out of range; got ",
        offset,
    )
    debug_assert[assert_mode="safe"](
        n >= 0 and n < 10000,
        "_write_four_digits: n must be in 0..=9999; got ",
        n,
    )
    var thousands = n // 1000
    var hundreds = (n % 1000) // 100
    var tens = (n % 100) // 10
    var ones = n % 10
    (p + offset).init_pointee_copy(UInt8(48 + thousands))
    (p + offset + 1).init_pointee_copy(UInt8(48 + hundreds))
    (p + offset + 2).init_pointee_copy(UInt8(48 + tens))
    (p + offset + 3).init_pointee_copy(UInt8(48 + ones))


# ── Time helpers ──────────────────────────────────────────────────────────────


@always_inline
def _realtime_seconds() -> Int:
    """Return the current ``CLOCK_REALTIME`` epoch second.

    ``CLOCK_REALTIME`` is constant 0 on Linux + macOS (the value is
    portable across both platforms).

    The 16-byte stack scratch buffer is zero-initialised so a
    rare ``clock_gettime`` failure (sandbox / cgroup denial /
    EINVAL) returns the Unix epoch (0) rather than a UB read of
    uninitialised stack memory. The accompanying
    ``debug_assert[assert_mode="safe"]`` makes that failure
    visible in tests + ``ASSERT=safe`` builds without aborting
    release builds — see
    ``.cursor/rules/sanitizers-and-bounds-checking.mdc`` §4.6.
    """
    var buf = stack_allocation[16, UInt8]()
    for i in range(16):
        (buf + i).init_pointee_copy(UInt8(0))
    var rc = external_call["clock_gettime", c_int](
        c_int(0), buf.bitcast[NoneType]()
    )
    debug_assert[assert_mode="safe"](
        Int(rc) == 0, "clock_gettime(CLOCK_REALTIME) failed; rc=", Int(rc)
    )
    var sec: Int64 = 0
    for i in range(8):
        sec |= Int64(Int((buf + i).load())) << Int64(8 * i)
    return Int(sec)


def _format_imf_fixdate(
    unix_secs: Int, p: UnsafePointer[UInt8, _]
) where type_of(p).mut:
    """Format ``unix_secs`` as a 29-byte IMF-fixdate at ``p[0:29]``.

    Layout:

        Sun, 06 Nov 1994 08:49:37 GMT
        0123456789012345678901234567 8
        0         1         2

    Branch-free civil-from-days arithmetic via Howard Hinnant's
    inverse, identical to the routine used in
    ``flare.http.structured_logger`` for ISO-8601 timestamps.
    """
    var days = unix_secs // _SECS_PER_DAY
    var sod = unix_secs - days * _SECS_PER_DAY  # second-of-day
    var hh = sod // 3600
    var mm = (sod % 3600) // 60
    var ss = sod % 60

    # Day-of-week. Unix epoch (1970-01-01) was a Thursday → dow_offset=4.
    var dow_raw = (days + 4) % 7
    if dow_raw < 0:
        dow_raw += 7

    # Howard Hinnant civil_from_days inverse:
    days = days + 719468
    var era = (days if days >= 0 else days - 146096) // 146097
    var doe = days - era * 146097  # [0, 146096]
    var yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    var y = yoe + era * 400
    var doy = doe - (365 * yoe + yoe // 4 - yoe // 100)  # [0, 365]
    var mp = (5 * doy + 2) // 153  # [0, 11]
    var d = doy - (153 * mp + 2) // 5 + 1  # [1, 31]
    var m = mp + 3 if mp < 10 else mp - 9  # [1, 12]
    if m <= 2:
        y += 1

    # "Day, " (4-byte day-of-week + comma at offset 3, then a space at 4).
    var dow_simd = _day_of_week_short(dow_raw)
    (p + 0).init_pointee_copy(dow_simd[0])
    (p + 1).init_pointee_copy(dow_simd[1])
    (p + 2).init_pointee_copy(dow_simd[2])
    (p + 3).init_pointee_copy(dow_simd[3])
    (p + 4).init_pointee_copy(UInt8(32))  # space

    _write_two_digits(p, 5, d)
    (p + 7).init_pointee_copy(UInt8(32))  # space

    var mon_simd = _month_short(m)
    (p + 8).init_pointee_copy(mon_simd[0])
    (p + 9).init_pointee_copy(mon_simd[1])
    (p + 10).init_pointee_copy(mon_simd[2])
    (p + 11).init_pointee_copy(mon_simd[3])  # trailing space

    _write_four_digits(p, 12, y)
    (p + 16).init_pointee_copy(UInt8(32))

    _write_two_digits(p, 17, hh)
    (p + 19).init_pointee_copy(UInt8(58))  # ':'
    _write_two_digits(p, 20, mm)
    (p + 22).init_pointee_copy(UInt8(58))
    _write_two_digits(p, 23, ss)
    (p + 25).init_pointee_copy(UInt8(32))
    (p + 26).init_pointee_copy(UInt8(71))  # 'G'
    (p + 27).init_pointee_copy(UInt8(77))  # 'M'
    (p + 28).init_pointee_copy(UInt8(84))  # 'T'


# ── DateCache ────────────────────────────────────────────────────────────────


struct DateCache(Movable):
    """Per-worker IMF-fixdate cache.

    Holds a 29-byte buffer rendered for the most-recently-observed
    ``CLOCK_REALTIME`` second. ``refresh()`` recomputes the buffer
    iff the wall-clock second has advanced; subsequent
    ``current_bytes`` / ``current_string`` calls return the cached
    formatting.

    Construction primes the buffer immediately so
    ``current_bytes()`` is always safe to call.

    The cache is **per-worker**, not process-shared. Each reactor
    worker constructs its own; there's no atomic / mutex / lock.

    Fields:
        _buf: ``List[UInt8]`` of fixed length 29 holding the
              currently-cached IMF-fixdate bytes.
        _epoch_second: The Unix-epoch second the buffer was rendered
                       for. ``-1`` until the first ``refresh()``.

    Usage:

        ```mojo
        var cache = DateCache()
        # ... per-request:
        cache.refresh()
        var date_bytes = cache.current_bytes()
        # memcpy date_bytes into the wire buffer
        ```
    """

    var _buf: List[UInt8]
    var _epoch_second: Int

    def __init__(out self):
        """Construct a primed cache rendered for the current second."""
        self._buf = List[UInt8]()
        self._buf.resize(_IMF_FIXDATE_LEN, UInt8(0))
        self._epoch_second = -1
        self.refresh()

    def refresh(mut self):
        """Re-render the buffer iff the wall-clock second has advanced.

        This is the only operation that calls ``clock_gettime`` —
        per-request consumers that just want the cached bytes call
        ``current_bytes()`` directly without a refresh check (they
        accept up-to-1-second staleness, the cost of *not* doing
        ``clock_gettime`` per request).

        Server hot paths typically call ``refresh()`` once per
        reactor tick (or once per ``N`` requests) and then read
        the cached bytes for every response within that window.
        """
        var now = _realtime_seconds()
        if now == self._epoch_second:
            return
        self._epoch_second = now
        _format_imf_fixdate(now, self._buf.unsafe_ptr())

    def current_bytes(self) -> Span[UInt8, origin_of(self._buf)]:
        """Return a borrow over the cached 29-byte IMF-fixdate buffer.

        The returned span is stable until the next ``refresh()``
        call on this cache from this worker.
        """
        return Span[UInt8, origin_of(self._buf)](self._buf)

    def current_string(self) -> String:
        """Return a freshly-allocated ``String`` copy of the cached
        IMF-fixdate.

        Most hot paths should prefer ``current_bytes()`` + memcpy
        into the wire buffer; this convenience helper is for callers
        that want a ``String`` (e.g. assigning into a ``HeaderMap``).
        """
        return String(unsafe_from_utf8=self.current_bytes())

    def epoch_second(self) -> Int:
        """Return the Unix-epoch second the buffer is currently
        rendered for, or ``-1`` if the cache has not been refreshed.

        Mostly useful for tests that pin the freshness invariant.
        """
        return self._epoch_second
