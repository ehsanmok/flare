"""Unit tests for ``flare.testing.TestClient``.

Exercises every HTTP method shape against a small in-process
handler so the synthesise/run/return shape is locked in before
the cookbook + docs grow examples around it.
"""

from std.testing import assert_equal, assert_true

from flare.http.handler import Handler
from flare.http.headers import HeaderMap
from flare.http.request import Request
from flare.http.response import Response, Status
from flare.http.server import ok
from flare.testing import TestClient


@fieldwise_init
struct EchoMethodHandler(Copyable, Handler):
    """Returns the request method in the body so tests can
    confirm the TestClient dispatched correctly."""

    var label: String

    def serve(self, req: Request) raises -> Response:
        var body = self.label + ":" + req.method + ":" + req.url
        var resp = ok(body)
        if req.body and len(req.body) > 0:
            # Echo the body length so POST/PUT/PATCH tests can
            # confirm the body actually made it through.
            resp.headers.set(String("x-body-len"), String(len(req.body)))
        # Also echo a custom header so the headers= kwarg can be
        # asserted on.
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


def test_get_dispatches_correctly() raises:
    var client = TestClient(EchoMethodHandler(label=String("echo")))
    var resp = client.get(String("/users/42"))
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), String("echo:GET:/users/42"))


def test_post_body_flows_through() raises:
    var client = TestClient(EchoMethodHandler(label=String("e")))
    var body = _bytes_of(String("hello world"))
    var resp = client.post(String("/submit"), body=body^)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), String("e:POST:/submit"))
    assert_equal(resp.headers.get(String("x-body-len")), String("11"))


def test_put_patch_delete_dispatch() raises:
    var client = TestClient(EchoMethodHandler(label=String("ep")))
    var put_body = _bytes_of(String("x"))
    var resp_put = client.put(String("/r"), body=put_body^)
    assert_equal(resp_put.text(), String("ep:PUT:/r"))
    var patch_body = _bytes_of(String("yz"))
    var resp_patch = client.patch(String("/r"), body=patch_body^)
    assert_equal(resp_patch.text(), String("ep:PATCH:/r"))
    var resp_delete = client.delete(String("/r"))
    assert_equal(resp_delete.text(), String("ep:DELETE:/r"))


def test_head_options_dispatch() raises:
    var client = TestClient(EchoMethodHandler(label=String("ho")))
    var resp_head = client.head(String("/"))
    assert_equal(resp_head.text(), String("ho:HEAD:/"))
    var resp_opts = client.options(String("/"))
    assert_equal(resp_opts.text(), String("ho:OPTIONS:/"))


def test_custom_headers_flow_through() raises:
    var client = TestClient(EchoMethodHandler(label=String("h")))
    var hdrs = HeaderMap()
    hdrs.set(String("x-test-header"), String("hello-from-test"))
    var resp = client.get(String("/"), headers=hdrs^)
    assert_equal(
        resp.headers.get(String("x-echoed-header")),
        String("hello-from-test"),
    )


def main() raises:
    test_get_dispatches_correctly()
    test_post_body_flows_through()
    test_put_patch_delete_dispatch()
    test_head_options_dispatch()
    test_custom_headers_flow_through()
    print("test_test_client: OK")
