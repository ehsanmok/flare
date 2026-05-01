"""Tests for :mod:`flare.http.sse` — Server-Sent Events.

Coverage:

1. ``SseEvent`` constructors (``data`` / ``named``) populate the
   fields correctly.
2. ``format_sse_event`` produces spec-correct wire bytes:
   - data only.
   - data with ``\\n`` is split into multiple ``data:`` lines
     (WHATWG §9.2.4).
   - id / event-type / retry are emitted only when set, in the
     order ``id`` → ``event`` → ``retry`` → ``data*`` →
     terminator.
3. ``SseChannel`` FIFO semantics: push N, pull N, each pull
   returns the next event's wire bytes; closing then draining
   yields ``None``; an open-ended (un-closed) channel with empty
   buffer yields the heartbeat comment line.
4. ``SseChannel.next`` short-circuits to ``None`` when cancel
   is set (matches the reactor's per-stream Cancel propagation).
5. ``sse_response`` builds a Response with the spec-correct
   headers (Content-Type, Cache-Control, Connection,
   X-Accel-Buffering) and the inline SSE bytes.
6. ``sse_response`` raises on an open-ended channel (caller
   wanted ``SseStreamingResponse`` instead).
7. ``SseStreamingResponse.of`` carries a ChunkedBody-wrapped
   channel that the reactor's streaming path can drive.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

from flare.http.body import drain_body
from flare.http.cancel import Cancel, CancelCell, CancelReason
from flare.http.sse import (
    SseChannel,
    SseEvent,
    SseStreamingResponse,
    format_sse_event,
    sse_response,
)


def _bytes_to_str(b: List[UInt8]) -> String:
    var out = String(capacity=len(b) + 1)
    for i in range(len(b)):
        out += chr(Int(b[i]))
    return out^


# ── SseEvent constructors ─────────────────────────────────────────────────


def test_event_message_constructor() raises:
    var e = SseEvent.message("hello")
    assert_equal(e.data, "hello")
    assert_equal(e.event_type, "")
    assert_equal(e.id, "")
    assert_equal(e.retry_ms, -1)


def test_event_named_constructor() raises:
    var e = SseEvent.named("tick", "data-payload")
    assert_equal(e.event_type, "tick")
    assert_equal(e.data, "data-payload")


# ── format_sse_event wire shape ───────────────────────────────────────────


def test_format_data_only() raises:
    var e = SseEvent.message("hello")
    var got = _bytes_to_str(format_sse_event(e))
    assert_equal(got, "data: hello\n\n")


def test_format_data_with_newlines_splits_into_multiple_data_lines() raises:
    """WHATWG §9.2.4: each line of data gets its own ``data:`` prefix."""
    var e = SseEvent.message("line0\nline1\nline2")
    var got = _bytes_to_str(format_sse_event(e))
    assert_equal(got, "data: line0\ndata: line1\ndata: line2\n\n")


def test_format_with_id_and_event_type() raises:
    var e = SseEvent("payload", "myevent", "evt-7", -1)
    var got = _bytes_to_str(format_sse_event(e))
    assert_equal(got, "id: evt-7\nevent: myevent\ndata: payload\n\n")


def test_format_with_retry() raises:
    var e = SseEvent("payload", "", "", 5000)
    var got = _bytes_to_str(format_sse_event(e))
    assert_equal(got, "retry: 5000\ndata: payload\n\n")


def test_format_emits_field_order_id_event_retry_data() raises:
    """Field order is fixed for spec-conformance; clients tolerate
    any order, but flare's order is stable so wire dumps diff
    cleanly across versions."""
    var e = SseEvent("payload", "evt", "abc", 1000)
    var got = _bytes_to_str(format_sse_event(e))
    assert_equal(got, "id: abc\nevent: evt\nretry: 1000\ndata: payload\n\n")


# ── SseChannel FIFO ───────────────────────────────────────────────────────


def test_channel_push_then_drain_emits_in_order() raises:
    var ch = SseChannel()
    ch.push(SseEvent.message("a"))
    ch.push(SseEvent.message("b"))
    ch.push(SseEvent.message("c"))
    ch.close()
    var sentinel = Cancel.never()
    var c0 = ch.next(sentinel).value().copy()
    assert_equal(_bytes_to_str(c0), "data: a\n\n")
    var c1 = ch.next(sentinel).value().copy()
    assert_equal(_bytes_to_str(c1), "data: b\n\n")
    var c2 = ch.next(sentinel).value().copy()
    assert_equal(_bytes_to_str(c2), "data: c\n\n")
    var done = ch.next(sentinel)
    assert_false(Bool(done))


def test_channel_pending_count_decreases_with_each_pull() raises:
    var ch = SseChannel()
    ch.push(SseEvent.message("x"))
    ch.push(SseEvent.message("y"))
    assert_equal(ch.pending(), 2)
    var sentinel = Cancel.never()
    var _u = ch.next(sentinel)
    assert_equal(ch.pending(), 1)


def test_channel_open_emits_heartbeat_when_buffer_empty() raises:
    """An un-closed channel with no buffered events should keep the
    connection warm with a comment-line heartbeat."""
    var ch = SseChannel()
    var sentinel = Cancel.never()
    var got = ch.next(sentinel).value().copy()
    assert_equal(_bytes_to_str(got), ": keep-alive\n\n")


def test_channel_cancel_short_circuits_to_none() raises:
    """Mojo nightly note: cell.handle() returns a Cancel that holds
    the cell's heap address; the cell must be kept alive past the
    ch.next(handle) call or Mojo's ASAP destructor frees the
    underlying Int and the read is UB. Pin via cell.reset() after
    the assertion to extend the lifetime."""
    var ch = SseChannel()
    ch.push(SseEvent.message("never-pulled"))
    var cell = CancelCell()
    cell.flip(CancelReason.SHUTDOWN)
    var handle = cell.handle()
    var got = ch.next(handle)
    assert_false(Bool(got))
    cell.reset()


# ── sse_response (synchronous) ────────────────────────────────────────────


def test_sse_response_sets_spec_headers() raises:
    var ch = SseChannel()
    ch.push(SseEvent.message("hi"))
    ch.close()
    var resp = sse_response(ch)
    assert_equal(resp.status, 200)
    assert_equal(resp.headers.get("content-type"), "text/event-stream")
    assert_equal(resp.headers.get("cache-control"), "no-cache")
    assert_equal(resp.headers.get("connection"), "keep-alive")
    assert_equal(resp.headers.get("x-accel-buffering"), "no")


def test_sse_response_inline_body_carries_event_bytes() raises:
    var ch = SseChannel()
    ch.push(SseEvent.message("first"))
    ch.push(SseEvent.message("second"))
    ch.close()
    var resp = sse_response(ch)
    assert_equal(_bytes_to_str(resp.body), "data: first\n\ndata: second\n\n")
    assert_equal(resp.headers.get("content-length"), String(len(resp.body)))


def test_sse_response_raises_on_open_ended_channel() raises:
    """Caller forgot to close — would loop forever on heartbeats.
    Fail loudly with the right next-action."""
    var ch = SseChannel()
    ch.push(SseEvent.message("x"))
    # No ch.close() — channel is open-ended.
    with assert_raises(contains="open-ended"):
        var _u = sse_response(ch)


# ── SseStreamingResponse ──────────────────────────────────────────────────


def test_streaming_response_has_spec_headers() raises:
    var ch = SseChannel()
    ch.close()
    var sr = SseStreamingResponse.of(ch)
    assert_equal(sr.response.status, 200)
    assert_equal(sr.response.headers.get("content-type"), "text/event-stream")


def test_streaming_response_body_drains_via_chunked_body() raises:
    """The ChunkedBody[SseChannel] wraps a copy of the channel, so
    drain_body works the same way as example 24's Counter source."""
    var ch = SseChannel()
    ch.push(SseEvent.message("alpha"))
    ch.push(SseEvent.message("beta"))
    ch.close()
    var sr = SseStreamingResponse.of(ch)
    var drained = drain_body(sr.body, Cancel.never())
    assert_equal(_bytes_to_str(drained), "data: alpha\n\ndata: beta\n\n")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
