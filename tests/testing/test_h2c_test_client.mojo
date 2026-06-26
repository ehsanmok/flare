"""Unit tests for ``flare.testing.H2cTestClient``.

Unlike ``TestClient`` (which calls ``handler.serve`` on a synthesized
:class:`Request` directly), :class:`H2cTestClient` drives the request
through the real HTTP/2 client + server drivers in process -- preface,
SETTINGS, HPACK-encoded HEADERS, DATA -- so the h2 framing + HPACK path
is exercised end to end with no TLS or socket. These tests lock in that
the handler-facing request/response shape survives the round trip.
"""

from std.testing import assert_equal

from flare.http.handler import Handler
from flare.http.headers import HeaderMap
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok
from flare.testing import H2cTestClient


@fieldwise_init
struct EchoMethodHandler(Copyable, Handler, Movable):
    """Returns the request method + path in the body, echoes body
    length and a custom header, so the h2c round trip can be asserted."""

    var label: String

    def serve(self, req: Request) raises -> Response:
        var body = self.label + ":" + req.method + ":" + req.url
        var resp = ok(body)
        if req.body and len(req.body) > 0:
            resp.headers.set(String("x-body-len"), String(len(req.body)))
        try:
            var custom = req.headers.get(String("x-test-header"))
            if custom.byte_length() > 0:
                resp.headers.set(String("x-echoed-header"), custom)
        except _:
            pass
        return resp^


def _bytes_of(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var p = s.unsafe_ptr()
    for i in range(s.byte_length()):
        out.append(p[i])
    return out^


def test_get_round_trips_over_h2() raises:
    var client = H2cTestClient(EchoMethodHandler(label=String("echo")))
    var resp = client.get(String("/users/42"))
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), String("echo:GET:/users/42"))


def test_post_body_flows_over_h2() raises:
    var client = H2cTestClient(EchoMethodHandler(label=String("e")))
    var body = _bytes_of(String("hello world"))
    var resp = client.post(String("/submit"), body=body^)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), String("e:POST:/submit"))
    assert_equal(resp.headers.get(String("x-body-len")), String("11"))


def test_put_patch_delete_over_h2() raises:
    var client = H2cTestClient(EchoMethodHandler(label=String("ep")))
    var put_body = _bytes_of(String("x"))
    var resp_put = client.put(String("/r"), body=put_body^)
    assert_equal(resp_put.text(), String("ep:PUT:/r"))
    var patch_body = _bytes_of(String("yz"))
    var resp_patch = client.patch(String("/r"), body=patch_body^)
    assert_equal(resp_patch.text(), String("ep:PATCH:/r"))
    var resp_delete = client.delete(String("/r"))
    assert_equal(resp_delete.text(), String("ep:DELETE:/r"))


def test_custom_header_flows_over_h2() raises:
    var client = H2cTestClient(EchoMethodHandler(label=String("h")))
    var hdrs = HeaderMap()
    hdrs.set(String("x-test-header"), String("hello-from-test"))
    var resp = client.get(String("/"), headers=hdrs^)
    assert_equal(
        resp.headers.get(String("x-echoed-header")),
        String("hello-from-test"),
    )


def main() raises:
    test_get_round_trips_over_h2()
    test_post_body_flows_over_h2()
    test_put_patch_delete_over_h2()
    test_custom_header_flows_over_h2()
    print("test_h2c_test_client: OK")
