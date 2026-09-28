"""Tests for ``flare.http.fs`` (— track H, FileServer + Range).

Covers:

- ``parse_range`` happy path + suffix range + open-ended range +
  inverted range raises + multi-range raises + bad units raises.
- Path safety: ``..`` traversal, NUL byte, absolute path rejection.
- ``FileServer.serve``: GET 200, HEAD 200 with empty body, missing
  file 404, ``Range: bytes=0-3`` returns 206 + ``Content-Range``,
  unsupported method returns 405.

The handler reads from a real temp directory we populate inline.
"""

from std.os import mkdir, path as os_path
from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.http import (
    ByteRange,
    FileServer,
    Method,
    Request,
    parse_range,
)


def _tmpdir(name: String) raises -> String:
    """Create a unique throwaway directory under /tmp for this test run."""
    var dir = String("/tmp/flare_fs_test_") + name
    if not os_path.exists(dir):
        mkdir(dir)
    return dir^


def _write(path: String, body: String) raises:
    with open(path, "w") as f:
        f.write(body)


# ── parse_range ────────────────────────────────────────────────────────────


def test_parse_range_simple() raises:
    var r = parse_range("bytes=0-3", 100)
    assert_true(Bool(r))
    var br = r.value().copy()
    assert_equal(br.start, 0)
    assert_equal(br.end, 3)


def test_parse_range_open_ended() raises:
    var r = parse_range("bytes=10-", 100)
    var br = r.value().copy()
    assert_equal(br.start, 10)
    assert_equal(br.end, 99)


def test_parse_range_suffix() raises:
    var r = parse_range("bytes=-20", 100)
    var br = r.value().copy()
    assert_equal(br.start, 80)
    assert_equal(br.end, 99)


def test_parse_range_empty_returns_none() raises:
    var r = parse_range("", 100)
    assert_false(Bool(r))


def test_parse_range_inverted_raises() raises:
    with assert_raises():
        _ = parse_range("bytes=10-5", 100)


def test_parse_range_out_of_bounds_raises() raises:
    with assert_raises():
        _ = parse_range("bytes=200-300", 100)


def test_parse_range_multi_raises() raises:
    with assert_raises():
        _ = parse_range("bytes=0-3,5-7", 100)


def test_parse_range_bad_unit_raises() raises:
    with assert_raises():
        _ = parse_range("pages=0-3", 100)


# ── FileServer ─────────────────────────────────────────────────────────────


def test_fileserver_get_ok() raises:
    var dir = _tmpdir("c1")
    _write(dir + "/hello.txt", "hello world")
    var fs = FileServer.new(dir)
    var req = Request(method=Method.GET, url="/hello.txt")
    var resp = fs.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "hello world")
    assert_equal(resp.headers.get("content-type"), "text/plain; charset=utf-8")
    assert_equal(resp.headers.get("accept-ranges"), "bytes")
    assert_equal(resp.headers.get("content-length"), "11")


def test_fileserver_head_returns_empty_body() raises:
    var dir = _tmpdir("c2")
    _write(dir + "/h.txt", "hello world")
    var fs = FileServer.new(dir)
    var req = Request(method=Method.HEAD, url="/h.txt")
    var resp = fs.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), 0)
    # HEAD must echo the GET Content-Length per RFC 9110.
    assert_equal(resp.headers.get("content-length"), "11")


def test_fileserver_missing_returns_404() raises:
    var dir = _tmpdir("c3")
    var fs = FileServer.new(dir)
    var req = Request(method=Method.GET, url="/nope.txt")
    var resp = fs.serve(req)
    assert_equal(resp.status, 404)


def test_fileserver_range_returns_206() raises:
    var dir = _tmpdir("c4")
    _write(dir + "/r.txt", "abcdefghijklmno")  # 15 bytes
    var fs = FileServer.new(dir)
    var req = Request(method=Method.GET, url="/r.txt")
    req.headers.set("Range", "bytes=0-3")
    var resp = fs.serve(req)
    assert_equal(resp.status, 206)
    assert_equal(resp.text(), "abcd")
    assert_equal(resp.headers.get("content-range"), "bytes 0-3/15")
    assert_equal(resp.headers.get("content-length"), "4")


def test_fileserver_traversal_blocked() raises:
    var dir = _tmpdir("c5")
    var fs = FileServer.new(dir)
    var req = Request(method=Method.GET, url="/../etc/passwd")
    var resp = fs.serve(req)
    assert_equal(resp.status, 404)


def test_fileserver_nul_byte_blocked() raises:
    var dir = _tmpdir("c6")
    var fs = FileServer.new(dir)
    var req = Request(method=Method.GET, url="/path\0backdoor")
    var resp = fs.serve(req)
    assert_equal(resp.status, 404)


def test_fileserver_method_not_allowed() raises:
    var dir = _tmpdir("c7")
    var fs = FileServer.new(dir)
    var req = Request(method=Method.POST, url="/x.txt")
    var resp = fs.serve(req)
    assert_equal(resp.status, 405)
    assert_equal(resp.headers.get("allow"), "GET, HEAD")


def test_fileserver_invalid_range_returns_416() raises:
    var dir = _tmpdir("c8")
    _write(dir + "/r2.txt", "12345")
    var fs = FileServer.new(dir)
    var req = Request(method=Method.GET, url="/r2.txt")
    req.headers.set("Range", "bytes=100-200")
    var resp = fs.serve(req)
    assert_equal(resp.status, 416)
    assert_equal(resp.headers.get("content-range"), "bytes */5")


def test_fileserver_index_html_for_dir() raises:
    var dir = _tmpdir("c9")
    _write(dir + "/index.html", "<h1>Index</h1>")
    var fs = FileServer.new(dir)
    var req = Request(method=Method.GET, url="/")
    var resp = fs.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "<h1>Index</h1>")
    assert_equal(resp.headers.get("content-type"), "text/html; charset=utf-8")


# ── Paths, not path-plus-query; regular files under root only ─────────────


def test_fileserver_ignores_the_query_string() raises:
    var dir = _tmpdir("q1")
    _write(dir + "/app.js", "js")
    var fs = FileServer.new(dir)
    var resp = fs.serve(Request(method=Method.GET, url="/app.js?v=3#x"))
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "js")


def test_fileserver_directory_is_404_not_500() raises:
    var dir = _tmpdir("q2")
    var sub = dir + "/sub"
    if not os_path.exists(sub):
        mkdir(sub)
    var fs = FileServer.new(dir)
    assert_equal(fs.serve(Request(method=Method.GET, url="/sub")).status, 404)


def test_fileserver_symlink_out_of_root_is_404() raises:
    from std.ffi import external_call, c_int

    var outside = _tmpdir("q3_outside")
    _write(outside + "/secret.txt", "secret")
    var dir = _tmpdir("q3")
    var link = dir + "/leak.txt"
    if not os_path.exists(link):
        var target = outside + "/secret.txt"
        var link_c = link.copy()
        _ = external_call["symlink", c_int](
            target.as_c_string_span(), link_c.as_c_string_span()
        )
    var fs = FileServer.new(dir)
    assert_equal(
        fs.serve(Request(method=Method.GET, url="/leak.txt")).status, 404
    )


def test_fileserver_empty_root_serves_nothing() raises:
    var fs = FileServer.new("")
    assert_equal(
        fs.serve(Request(method=Method.GET, url="/etc/passwd")).status, 404
    )


def test_fileserver_sets_last_modified() raises:
    var dir = _tmpdir("q4")
    _write(dir + "/m.txt", "m")
    var fs = FileServer.new(dir)
    var lm = fs.serve(Request(method=Method.GET, url="/m.txt")).headers.get(
        "last-modified"
    )
    assert_equal(lm.byte_length(), 29)
    assert_true(lm.endswith(" GMT"), lm)


def main() raises:
    test_parse_range_simple()
    test_parse_range_open_ended()
    test_parse_range_suffix()
    test_parse_range_empty_returns_none()
    test_parse_range_inverted_raises()
    test_parse_range_out_of_bounds_raises()
    test_parse_range_multi_raises()
    test_parse_range_bad_unit_raises()
    test_fileserver_get_ok()
    test_fileserver_head_returns_empty_body()
    test_fileserver_missing_returns_404()
    test_fileserver_range_returns_206()
    test_fileserver_traversal_blocked()
    test_fileserver_nul_byte_blocked()
    test_fileserver_ignores_the_query_string()
    test_fileserver_directory_is_404_not_500()
    test_fileserver_symlink_out_of_root_is_404()
    test_fileserver_empty_root_serves_nothing()
    test_fileserver_sets_last_modified()
    test_fileserver_method_not_allowed()
    test_fileserver_invalid_range_returns_416()
    test_fileserver_index_html_for_dir()
    print("test_fs: 22 passed")
