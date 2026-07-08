"""Regression test for the ``flare.http.wire`` neutral re-export layer.

The shared handler-facing types (``Request``, ``Response``,
``HeaderMap``, ``Method``, ``Status``) are reachable through
``flare.http.wire`` so the HTTP/2 server adapter (and the future
HTTP/3 server adapter) can import them without pulling in the
parent ``flare.http`` namespace -- the cycle the §11.7 inspection
flagged.

The test imports every symbol the wire package re-exports and
exercises each one minimally. If a leaf module changes its public
surface, this test breaks first.

The companion lint job (``pixi run check-no-http-http2-cycle``)
enforces statically that ``flare/http2/**`` and ``flare/http3/**``
only reach into the ``flare.http`` namespace through this package
(or through ``flare.http.proto``). This test exercises the same
public surface from the user's side.
"""

from std.testing import assert_equal, assert_true

from flare.http.wire import (
    HeaderInjectionError,
    HeaderMap,
    Method,
    Request,
    Response,
    Status,
)


def test_method_constants_match_rfc9110() raises:
    # RFC 9110 §9.3 method tokens. Method is a tiny enum-shaped
    # container; the canonical strings live in flare.http.request.
    assert_equal(Method.GET, "GET")
    assert_equal(Method.POST, "POST")
    assert_equal(Method.PUT, "PUT")
    assert_equal(Method.DELETE, "DELETE")
    assert_equal(Method.HEAD, "HEAD")
    assert_equal(Method.OPTIONS, "OPTIONS")
    assert_equal(Method.PATCH, "PATCH")


def test_status_constants_match_rfc9110() raises:
    # RFC 9110 §15 status codes. Status is a thin namespace over
    # integer constants.
    assert_equal(Int(Status.OK), 200)
    assert_equal(Int(Status.CREATED), 201)
    assert_equal(Int(Status.NO_CONTENT), 204)
    assert_equal(Int(Status.NOT_MODIFIED), 304)
    assert_equal(Int(Status.BAD_REQUEST), 400)
    assert_equal(Int(Status.NOT_FOUND), 404)
    assert_equal(Int(Status.INTERNAL_SERVER_ERROR), 500)


def test_header_map_roundtrip() raises:
    var h = HeaderMap()
    h.set("Content-Type", "application/json")
    h.set("X-Request-Id", "abc-123")
    # Case-insensitive read per RFC 9110 §5.1; ``HeaderMap.get``
    # returns the value (or empty string if missing).
    assert_equal(h.get("content-type"), "application/json")
    assert_equal(h.get("X-REQUEST-ID"), "abc-123")
    assert_equal(h.get("missing"), "")


def test_header_injection_rejected() raises:
    # CR / LF in header value is the canonical request-smuggling
    # primitive; HeaderMap rejects it at insertion time and raises
    # HeaderInjectionError. The wire layer re-exports the error
    # type so handlers can catch it through the neutral path.
    var h = HeaderMap()
    var raised = False
    try:
        h.set("X-Forwarded-For", "1.2.3.4\r\nX-Injected: yes")
    except err:
        raised = True
    assert_true(raised)
    # HeaderInjectionError is constructible through the wire
    # namespace -- this anchors the re-export so future renames
    # break the test before they break downstream catch paths.
    var marker = HeaderInjectionError("field", "value")
    assert_equal(marker.field, "field")


def test_request_response_construct_through_wire() raises:
    # Request and Response are wire-agnostic by design: the same
    # struct is built from an h1 message parser, an h2 HEADERS
    # frame plus DATA frames, or an h3 request-stream reader, and
    # the same Response is serialized back through any of those
    # wires. We just confirm the types are bound through the wire
    # namespace and minimally constructible.
    var req = Request(method=Method.GET, url="/items?page=1")
    assert_equal(req.method, "GET")
    assert_equal(req.url, "/items?page=1")

    var body = List[UInt8]()
    for b in String("ok").as_bytes():
        body.append(b)
    var resp = Response(status=Status.OK, body=body^)
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), 2)


def main() raises:
    test_method_constants_match_rfc9110()
    test_status_constants_match_rfc9110()
    test_header_map_roundtrip()
    test_header_injection_rejected()
    test_request_response_construct_through_wire()
    print("test_wire_reexports: OK")
