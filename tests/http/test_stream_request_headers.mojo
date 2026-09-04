"""Shared streaming request-header normalization contracts."""

from std.testing import assert_equal, TestSuite
from flare.http.headers import HeaderMap
from flare.http._client.stream_request import prepare_stream_headers


def test_request_header_normalization() raises:
    var headers = HeaderMap()
    headers.set("Connection", "X-Hop")
    headers.set("X-Hop", "remove")
    headers.append("Content-Length", "123")
    headers.append("Content-Length", "456")
    headers.append("Authorization", "first")
    headers.append("Authorization", "second")
    headers.set("Accept-Encoding", "gzip")
    var prepared = prepare_stream_headers(headers, 3, "agent", "Bearer stored")
    assert_equal(prepared.get("X-Hop"), "")
    assert_equal(prepared.get("Content-Length"), "3")
    assert_equal(len(prepared.get_all("Content-Length")), 1)
    assert_equal(len(prepared.get_all("Authorization")), 1)
    assert_equal(prepared.get("Authorization"), "Bearer stored")
    assert_equal(prepared.get("Accept-Encoding"), "gzip")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
