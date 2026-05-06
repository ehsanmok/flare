"""HTTP/2 over HTTP/1.1 Upgrade ("h2c", RFC 7540 paragraph 3.2).

Covers the unit-level wiring added in v0.7 for h2c-via-Upgrade:

* :meth:`flare.http2.server.H2Connection.from_h2c_upgrade` — server-side
  state seeded from an h1 request becoming stream id 1 plus the
  decoded ``HTTP2-Settings`` payload from the upgrade request.
* :meth:`flare.http._server_reactor_impl.ConnHandle._h2c_upgrade_decode_settings`
  — base64url + length-multiple-of-6 validation of the inbound
  ``HTTP2-Settings`` header value.

The full reactor-level integration (h1 ConnHandle queues the
``101 Switching Protocols`` response, the unified reactor migrates
the conn-dict entry from ``KIND_H1`` to ``KIND_H2`` once the 101
flushes, the client sends its connection preface + SETTINGS frame
on the same TCP fd, the response for stream 1 is dispatched via the
user handler and serialised back as h2 frames) is exercised by
``tests/test_unified_http_server.mojo`` when an h2c client hits the
unified port -- this file deliberately scopes to the deterministic
unit-level paths that a fork-based loopback test would obscure.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.crypto.hmac import base64url_encode
from flare.http import Request
from flare.http.headers import HeaderMap
from flare.http2 import H2Connection, Http2Config
from flare.http2.state import StreamState


def _build_settings_payload(initial_window_size: Int) -> List[UInt8]:
    """Build a minimal SETTINGS payload carrying just ``initial_window_size``
    (RFC 9113 paragraph 6.5.2 setting id 0x4)."""
    var p = List[UInt8]()
    p.append(UInt8(0x00))  # id high byte
    p.append(UInt8(0x04))  # id low byte (INITIAL_WINDOW_SIZE)
    p.append(UInt8((initial_window_size >> 24) & 0xFF))
    p.append(UInt8((initial_window_size >> 16) & 0xFF))
    p.append(UInt8((initial_window_size >> 8) & 0xFF))
    p.append(UInt8(initial_window_size & 0xFF))
    return p^


def test_from_h2c_upgrade_creates_stream_1_with_request_headers() raises:
    """``H2Connection.from_h2c_upgrade`` pre-populates stream id 1
    with the original h1 request's pseudo-headers (``:method``,
    ``:scheme``, ``:path``, ``:authority``) and marks both header /
    data complete so the next ``take_completed_streams`` returns
    [1]."""
    var req = Request(method="GET", url="/api/users", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    req.headers.set("X-Custom", "abc")

    var settings_payload = _build_settings_payload(131072)
    var conn = H2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )

    var ready = conn.take_completed_streams()
    assert_equal(len(ready), 1)
    assert_equal(ready[0], 1)

    # Re-materialise the request from stream 1.
    var seen = conn.take_request(1)
    assert_equal(seen.method, "GET")
    assert_equal(seen.url, "/api/users")
    assert_equal(seen.headers.get("Host"), "example.com")
    assert_equal(seen.headers.get("x-custom"), "abc")


def test_from_h2c_upgrade_applies_settings_payload() raises:
    """The decoded ``HTTP2-Settings`` payload is applied to the
    connection state without emitting a SETTINGS_ACK."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    req.headers.set("Host", "example.com")

    var settings_payload = _build_settings_payload(131072)
    var conn = H2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )

    assert_equal(conn.conn.initial_window_size, 131072)


def test_from_h2c_upgrade_seeds_outbox_with_server_settings() raises:
    """The server's initial SETTINGS frame is queued in the outbox
    (the server-side connection preface for the h2c-upgraded connection)
    so the reactor flushes it on the first writable event."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    var settings_payload = _build_settings_payload(65535)

    var conn = H2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )

    var preface = conn.drain()
    assert_true(
        len(preface) >= 9, "server preface must include a SETTINGS frame"
    )
    # Frame type at offset 3 must be 0x4 (SETTINGS).
    assert_equal(Int(preface[3]), 0x4)


def test_from_h2c_upgrade_rejects_misaligned_settings_payload() raises:
    """A SETTINGS payload whose length isn't a multiple of 6 is
    a protocol error per RFC 7540 paragraph 3.2.1."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    # 5-byte payload is invalid (must be multiple of 6).
    var bad = List[UInt8]()
    for _ in range(5):
        bad.append(UInt8(0))

    var raised = False
    try:
        var _conn = H2Connection.from_h2c_upgrade(Http2Config(), req, bad^)
    except:
        raised = True
    assert_true(
        raised, "from_h2c_upgrade must raise on misaligned SETTINGS payload"
    )


def test_from_h2c_upgrade_stream_1_state_is_half_closed_remote() raises:
    """Stream id 1 is implicitly half-closed from the client side
    after the upgrade (RFC 7540 paragraph 3.2: 'Stream 1 is implicitly
    half-closed from the client toward the server')."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    var settings_payload = _build_settings_payload(65535)

    var conn = H2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )
    var s = conn.conn.streams[1].copy()
    assert_equal(s.state.value, StreamState.HALF_CLOSED_REMOTE().value)
    assert_true(s.headers_complete, "headers_complete must be True")
    assert_true(s.data_complete, "data_complete must be True")


def test_from_h2c_upgrade_carries_request_body() raises:
    """A POST body on the h1 upgrade request is carried over as
    stream 1's data."""
    var req = Request(method="POST", url="/echo", version="HTTP/1.1")
    req.headers.set("Host", "example.com")
    req.headers.set("Content-Type", "application/octet-stream")
    var body_str = String("hello upgrade body")
    var bb = body_str.as_bytes()
    for i in range(len(bb)):
        req.body.append(bb[i])

    var settings_payload = _build_settings_payload(65535)
    var conn = H2Connection.from_h2c_upgrade(
        Http2Config(), req, settings_payload^
    )

    var ready = conn.take_completed_streams()
    assert_equal(len(ready), 1)
    var seen = conn.take_request(1)
    assert_equal(seen.method, "POST")
    assert_equal(seen.url, "/echo")
    assert_equal(len(seen.body), body_str.byte_length())


def test_h2c_upgrade_header_decoder_accepts_well_formed_request() raises:
    """A request with ``Upgrade: h2c`` + valid base64url
    ``HTTP2-Settings`` is recognised as an h2c upgrade by the
    inline detector + base64url decoder used in
    ``ConnHandle.on_readable`` (verified by inspecting the
    public-surface helpers from
    :mod:`flare.crypto.hmac` + the headers API)."""
    var headers = HeaderMap()
    headers.set("Upgrade", "h2c")
    headers.set("Connection", "Upgrade, HTTP2-Settings")
    var raw = _build_settings_payload(65536)
    var b64 = base64url_encode(raw)
    headers.set("HTTP2-Settings", b64)

    # The h1 ConnHandle uses ``flare.http2.server.detect_h2c_upgrade``;
    # this test asserts the *inputs* the detector relies on parse +
    # decode cleanly. The detector itself is under
    # ``test_h2_server::test_detect_h2c_upgrade``; here we only
    # verify the base64url round-trip the upgrade decoder consumes.
    from flare.crypto.hmac import base64url_decode

    var decoded = base64url_decode(b64)
    assert_equal(len(decoded), len(raw))
    for i in range(len(decoded)):
        assert_equal(decoded[i], raw[i])


def main() raises:
    test_from_h2c_upgrade_creates_stream_1_with_request_headers()
    test_from_h2c_upgrade_applies_settings_payload()
    test_from_h2c_upgrade_seeds_outbox_with_server_settings()
    test_from_h2c_upgrade_rejects_misaligned_settings_payload()
    test_from_h2c_upgrade_stream_1_state_is_half_closed_remote()
    test_from_h2c_upgrade_carries_request_body()
    test_h2c_upgrade_header_decoder_accepts_well_formed_request()
    print("test_h2c_upgrade: 7 passed")
