"""Tests for :class:`flare.http2.Http2Config` and
:meth:`H2Connection.with_config`.

Exercises three angles:

1. The default ``Http2Config()`` produces the same observable
   SETTINGS shape as the v0.6 ``H2Connection()`` (no behavioural
   regression for callers that don't configure anything).
2. ``Http2Config.validate`` enforces the RFC 9113 §6.5.2 +
   RFC 9113 §6.9.2 + RFC 7541 §4.2 numeric bounds.
3. A non-default config propagates through to the underlying
   ``Connection`` fields the reactor wiring reads —
   ``max_concurrent_streams``, ``initial_window_size``,
   ``max_frame_size``, the HPACK decoder's ``max_size``, and is
   reflected in the SETTINGS frame the driver emits after the
   preface.
"""

from std.collections import Dict

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

from flare.http2 import (
    H2Connection,
    H2_DEFAULT_FRAME_SIZE,
    H2_PREFACE,
    Http2Config,
    parse_frame,
)


# ── Defaults ────────────────────────────────────────────────────────────────


def test_default_config_matches_rfc_and_v0_6_shape() raises:
    """``Http2Config()`` defaults match RFC 9113 / RFC 7541 + the
    v0.6 ``Connection`` defaults so a caller upgrading from
    ``H2Connection()`` to ``H2Connection.with_config(Http2Config())``
    sees no observable change."""
    var cfg = Http2Config()
    assert_equal(cfg.max_concurrent_streams, 100)
    assert_equal(cfg.initial_window_size, 65535)
    assert_equal(cfg.max_frame_size, 16384)
    assert_equal(cfg.max_header_list_size, 8192)
    assert_equal(cfg.header_table_size, 4096)
    assert_false(cfg.allow_huffman_decode)


def test_default_config_validates() raises:
    """Defaults pass ``validate()`` — boot path can rely on
    ``Http2Config()`` constructing a valid config without an
    explicit validate call."""
    var cfg = Http2Config()
    cfg.validate()


def test_with_config_default_emits_extra_max_header_list_size() raises:
    """``H2Connection()`` (bare) emits one SETTINGS pair
    (MAX_CONCURRENT_STREAMS = 100). ``H2Connection.with_config(
    Http2Config())`` emits two: the same MAX_CONCURRENT_STREAMS = 100
    plus the defensive default MAX_HEADER_LIST_SIZE = 8192. The
    extra pair (id 0x6, value 8192) is the additive contract: bare
    callers stay on the original wire bytes; opt-in via
    ``Http2Config`` advertises the new cap."""
    var preface = List[UInt8](String(H2_PREFACE).as_bytes())

    var c1 = H2Connection()
    c1.feed(Span[UInt8, _](preface))
    var b1 = c1.drain()
    var f1 = parse_frame(Span[UInt8, _](b1)).value().copy()
    assert_equal(Int(f1.header.length), 6)
    var sid1 = (Int(f1.payload[0]) << 8) | Int(f1.payload[1])
    var sval1 = (
        (Int(f1.payload[2]) << 24)
        | (Int(f1.payload[3]) << 16)
        | (Int(f1.payload[4]) << 8)
        | Int(f1.payload[5])
    )
    assert_equal(sid1, 0x3)  # SETTINGS_MAX_CONCURRENT_STREAMS
    assert_equal(sval1, 100)

    var c2 = H2Connection.with_config(Http2Config())
    c2.feed(Span[UInt8, _](preface))
    var b2 = c2.drain()
    var f2 = parse_frame(Span[UInt8, _](b2)).value().copy()
    assert_equal(Int(f2.header.length), 12)
    # First pair: same MAX_CONCURRENT_STREAMS = 100
    var sid2a = (Int(f2.payload[0]) << 8) | Int(f2.payload[1])
    var sval2a = (
        (Int(f2.payload[2]) << 24)
        | (Int(f2.payload[3]) << 16)
        | (Int(f2.payload[4]) << 8)
        | Int(f2.payload[5])
    )
    assert_equal(sid2a, 0x3)
    assert_equal(sval2a, 100)
    # Second pair: MAX_HEADER_LIST_SIZE = 8192 (the new defensive default)
    var sid2b = (Int(f2.payload[6]) << 8) | Int(f2.payload[7])
    var sval2b = (
        (Int(f2.payload[8]) << 24)
        | (Int(f2.payload[9]) << 16)
        | (Int(f2.payload[10]) << 8)
        | Int(f2.payload[11])
    )
    assert_equal(sid2b, 0x6)  # SETTINGS_MAX_HEADER_LIST_SIZE
    assert_equal(sval2b, 8192)


def test_with_config_zero_header_list_byte_matches_h2connection() raises:
    """``H2Connection.with_config(Http2Config(..., max_header_list_size
    = 0, ...))`` is byte-for-byte identical to the bare
    ``H2Connection()``. The zero-value escape hatch lets a caller opt
    out of the defensive default if wire-level compatibility with a
    strict downstream expectation matters."""
    var preface = List[UInt8](String(H2_PREFACE).as_bytes())

    var c1 = H2Connection()
    c1.feed(Span[UInt8, _](preface))
    var b1 = c1.drain()

    var cfg = Http2Config()
    cfg.max_header_list_size = 0
    var c2 = H2Connection.with_config(cfg^)
    c2.feed(Span[UInt8, _](preface))
    var b2 = c2.drain()

    assert_equal(len(b1), len(b2))
    for i in range(len(b1)):
        assert_equal(Int(b1[i]), Int(b2[i]))


# ── Validate: RFC bounds ────────────────────────────────────────────────────


def test_validate_rejects_negative_max_concurrent_streams() raises:
    var cfg = Http2Config()
    cfg.max_concurrent_streams = -1
    with assert_raises(contains="max_concurrent_streams"):
        cfg.validate()


def test_validate_rejects_initial_window_size_overflow() raises:
    """RFC 9113 §6.9.2: max stream window-size value is 2^31 - 1."""
    var cfg = Http2Config()
    cfg.initial_window_size = 0x80000000
    with assert_raises(contains="2^31-1"):
        cfg.validate()


def test_validate_accepts_initial_window_size_at_boundary() raises:
    """RFC 9113 §6.9.2 boundary: 2^31 - 1 is legal."""
    var cfg = Http2Config()
    cfg.initial_window_size = 0x7FFFFFFF
    cfg.validate()


def test_validate_rejects_max_frame_size_below_floor() raises:
    """RFC 9113 §6.5.2: SETTINGS_MAX_FRAME_SIZE must be >= 16384.
    A peer that announces a smaller value is a protocol violation;
    the local config has the same floor for symmetry."""
    var cfg = Http2Config()
    cfg.max_frame_size = 16383
    with assert_raises(contains="16384"):
        cfg.validate()


def test_validate_accepts_max_frame_size_at_floor() raises:
    var cfg = Http2Config()
    cfg.max_frame_size = H2_DEFAULT_FRAME_SIZE
    cfg.validate()


def test_validate_rejects_max_frame_size_above_ceiling() raises:
    """RFC 9113 §6.5.2: SETTINGS_MAX_FRAME_SIZE max is 2^24 - 1."""
    var cfg = Http2Config()
    cfg.max_frame_size = 16777216
    with assert_raises(contains="2^24-1"):
        cfg.validate()


def test_validate_accepts_max_frame_size_at_ceiling() raises:
    var cfg = Http2Config()
    cfg.max_frame_size = 16777215
    cfg.validate()


def test_validate_rejects_negative_max_header_list_size() raises:
    var cfg = Http2Config()
    cfg.max_header_list_size = -7
    with assert_raises(contains="max_header_list_size"):
        cfg.validate()


def test_validate_rejects_negative_header_table_size() raises:
    var cfg = Http2Config()
    cfg.header_table_size = -1
    with assert_raises(contains="header_table_size"):
        cfg.validate()


# ── Propagation: config -> underlying Connection fields ─────────────────────


def test_with_config_propagates_to_connection_fields() raises:
    """Each ``Http2Config`` field (apart from
    ``allow_huffman_decode`` and ``max_header_list_size``, which the
    reactor wiring reads off the driver directly) lands on the
    underlying ``Connection`` so the SETTINGS exchange + the HPACK
    decoder ack budget the configured values."""
    var cfg = Http2Config(
        max_concurrent_streams=200,
        initial_window_size=131072,
        max_frame_size=32768,
        max_header_list_size=16384,
        header_table_size=8192,
        allow_huffman_decode=False,
    )
    var conn = H2Connection.with_config(cfg^)
    assert_equal(conn.conn.max_concurrent_streams, 200)
    assert_equal(conn.conn.initial_window_size, 131072)
    assert_equal(conn.conn.send_window, 131072)
    assert_equal(conn.conn.recv_window, 131072)
    assert_equal(conn.conn.max_frame_size, 32768)
    assert_equal(conn.conn.hpack_decoder.max_size, 8192)
    assert_equal(conn.config.max_header_list_size, 16384)
    assert_false(conn.config.allow_huffman_decode)


def test_with_config_full_emits_all_non_default_settings() raises:
    """A non-default ``Http2Config`` advertises one SETTINGS pair
    per field that diverges from the RFC default plus the always-
    advertised ``MAX_CONCURRENT_STREAMS``: HEADER_TABLE_SIZE,
    MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE,
    and MAX_HEADER_LIST_SIZE — five pairs (30 bytes payload)."""
    var cfg = Http2Config(
        max_concurrent_streams=200,
        initial_window_size=131072,
        max_frame_size=32768,
        max_header_list_size=16384,
        header_table_size=8192,
        allow_huffman_decode=False,
    )
    var conn = H2Connection.with_config(cfg^)
    var preface = List[UInt8](String(H2_PREFACE).as_bytes())
    conn.feed(Span[UInt8, _](preface))
    var bytes = conn.drain()
    var f = parse_frame(Span[UInt8, _](bytes)).value().copy()
    assert_equal(Int(f.header.type.value), 0x4)
    assert_equal(Int(f.header.length), 30)

    # Walk all five (id, value) pairs.
    var seen = Dict[Int, Int]()
    var i = 0
    while i + 6 <= len(f.payload):
        var sid = (Int(f.payload[i]) << 8) | Int(f.payload[i + 1])
        var sval = (
            (Int(f.payload[i + 2]) << 24)
            | (Int(f.payload[i + 3]) << 16)
            | (Int(f.payload[i + 4]) << 8)
            | Int(f.payload[i + 5])
        )
        seen[sid] = sval
        i += 6
    assert_equal(len(seen), 5)
    assert_equal(seen[0x1], 8192)  # HEADER_TABLE_SIZE
    assert_equal(seen[0x3], 200)  # MAX_CONCURRENT_STREAMS
    assert_equal(seen[0x4], 131072)  # INITIAL_WINDOW_SIZE
    assert_equal(seen[0x5], 32768)  # MAX_FRAME_SIZE
    assert_equal(seen[0x6], 16384)  # MAX_HEADER_LIST_SIZE


def test_with_config_validates_inputs() raises:
    """``with_config`` validates before propagating; an invalid
    config raises before any side effect on the underlying
    ``Connection``."""
    var cfg = Http2Config()
    cfg.max_frame_size = 16383
    with assert_raises(contains="16384"):
        var _unused = H2Connection.with_config(cfg^)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
