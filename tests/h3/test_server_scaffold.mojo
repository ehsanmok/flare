"""Unit tests for the HTTP/3 server connection scaffold
(``flare.h3.server``).

The full driver -- per-stream :class:`flare.h3.H3RequestReader`
-> :trait:`Handler` -> :func:`flare.h3.encode_response_headers`
wiring, control-stream lifecycle, settings exchange, push,
GOAWAY -- ships in a focused follow-up commit. This suite pins
the carrier shapes + the typed boundary the ALPN dispatcher and
the H3 bench harness will build against.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.h3 import (
    H3Connection,
    H3ConnectionConfig,
    H3StreamType,
)


def test_stream_type_codepoints() raises:
    """RFC 9114 §6.2 unidirectional stream type codepoints."""
    assert_equal(H3StreamType.CONTROL, 0x00)
    assert_equal(H3StreamType.PUSH, 0x01)
    assert_equal(H3StreamType.QPACK_ENCODER, 0x02)
    assert_equal(H3StreamType.QPACK_DECODER, 0x03)


def test_config_defaults() raises:
    """:class:`H3ConnectionConfig` defaults match the production
    posture: 64 KiB max field section, static-only QPACK,
    CONNECT-Protocol advertised, no GOAWAY soft cap."""
    var cfg = H3ConnectionConfig()
    assert_equal(cfg.max_field_section_size, UInt64(65536))
    assert_equal(cfg.qpack_max_table_capacity, UInt64(0))
    assert_equal(cfg.qpack_blocked_streams, UInt64(0))
    assert_true(cfg.enable_connect_protocol)
    assert_equal(cfg.goaway_threshold_streams, UInt64((1 << 63) - 1))


def test_h3_connection_defaults() raises:
    """A fresh :class:`H3Connection` carries the default config
    and is in the pre-SETTINGS state."""
    var c = H3Connection()
    assert_equal(c.config.max_field_section_size, UInt64(65536))
    assert_false(c.peer_settings_received)
    assert_false(c.goaway_emitted)
    assert_equal(c.active_request_count(), 0)
    assert_equal(c.control_stream_id, -1)
    assert_equal(c.qpack_encoder_stream_id, -1)
    assert_equal(c.qpack_decoder_stream_id, -1)


def test_with_config_overrides() raises:
    """:meth:`H3Connection.with_config` copies in a non-default
    config carrier; the rest of the driver state stays at the
    fresh-construction values."""
    var cfg = H3ConnectionConfig()
    cfg.max_field_section_size = UInt64(1024)
    cfg.enable_connect_protocol = False
    var c = H3Connection.with_config(cfg)
    assert_equal(c.config.max_field_section_size, UInt64(1024))
    assert_false(c.config.enable_connect_protocol)
    assert_false(c.peer_settings_received)


def test_open_request_stream_tracks_state() raises:
    """Opening a stream allocates a per-stream reader; the
    driver reports the stream via :meth:`has_stream` and the
    count via :meth:`active_request_count`."""
    var c = H3Connection()
    assert_false(c.has_stream(0))
    c.open_request_stream(0)
    assert_true(c.has_stream(0))
    assert_equal(c.active_request_count(), 1)
    c.open_request_stream(4)
    assert_equal(c.active_request_count(), 2)


def test_open_request_stream_is_idempotent() raises:
    """Re-opening the same stream ID is a no-op so the QUIC
    reactor can fire the open event redundantly without
    leaking parser state."""
    var c = H3Connection()
    c.open_request_stream(0)
    c.open_request_stream(0)
    c.open_request_stream(0)
    assert_equal(c.active_request_count(), 1)


def test_close_request_stream_releases() raises:
    """:meth:`close_request_stream` drops the per-stream reader
    so the driver doesn't keep parser state for a stream that's
    already responded with FIN."""
    var c = H3Connection()
    c.open_request_stream(0)
    c.open_request_stream(4)
    c.close_request_stream(0)
    assert_false(c.has_stream(0))
    assert_true(c.has_stream(4))
    assert_equal(c.active_request_count(), 1)


def test_close_request_stream_unknown_id_is_noop() raises:
    """Closing a stream the driver never saw is a no-op (the
    reactor occasionally races a close event past a stream the
    driver already retired itself)."""
    var c = H3Connection()
    c.close_request_stream(0)
    assert_equal(c.active_request_count(), 0)


def test_goaway_rejects_new_streams() raises:
    """Once GOAWAY is emitted, ``open_request_stream`` raises
    so the reactor surfaces the rejection back to the QUIC
    layer as H3_REQUEST_CANCELLED."""
    var c = H3Connection()
    c.goaway_emitted = True
    var raised = False
    try:
        c.open_request_stream(0)
    except:
        raised = True
    assert_true(raised, "expected open after GOAWAY to raise")


def test_feed_stream_chunk_allocates_stream_implicitly() raises:
    """:meth:`feed_stream_chunk` allocates the per-stream
    carrier on first chunk so the QUIC reactor doesn't have to
    pre-announce the open-stream signal."""
    var c = H3Connection()
    var chunk = List[UInt8]()
    c.feed_stream_chunk(0, chunk^)
    assert_true(c.has_stream(0))


def test_take_response_frames_empty_when_no_emit() raises:
    """:meth:`take_response_frames` returns an empty buffer for
    a stream that hasn't had :meth:`emit_response` called yet
    (the reactor calls this repeatedly until it returns
    empty)."""
    var c = H3Connection()
    c.open_request_stream(0)
    var drained = c.take_response_frames(0)
    assert_equal(len(drained), 0)


def main() raises:
    test_stream_type_codepoints()
    test_config_defaults()
    test_h3_connection_defaults()
    test_with_config_overrides()
    test_open_request_stream_tracks_state()
    test_open_request_stream_is_idempotent()
    test_close_request_stream_releases()
    test_close_request_stream_unknown_id_is_noop()
    test_goaway_rejects_new_streams()
    test_feed_stream_chunk_allocates_stream_implicitly()
    test_take_response_frames_empty_when_no_emit()
    print("test_h3_server_scaffold: 11 passed")
