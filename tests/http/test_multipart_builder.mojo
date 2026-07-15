"""Round-trip tests for the client multipart/form-data builder.

Builds a body with ``MultipartFormBuilder`` and parses it back with
the server-side ``parse_multipart_form_data`` to prove the client
and server halves agree on the RFC 7578 wire format.
"""

from std.testing import assert_equal, assert_true

from flare.http import MultipartFormBuilder
from flare.http.multipart import parse_multipart_form_data


def test_multipart_field_roundtrip() raises:
    var mp = MultipartFormBuilder("----testBoundary123")
    mp.field("title", "hello world")
    mp.field("count", "42")
    var ct = mp.content_type()
    var body = mp.finish()

    var form = parse_multipart_form_data(body, ct)
    var title = form.get("title")
    assert_true(Bool(title))
    assert_equal(title.value().text(), "hello world")
    var count = form.get("count")
    assert_true(Bool(count))
    assert_equal(count.value().text(), "42")


def test_multipart_file_roundtrip() raises:
    var mp = MultipartFormBuilder("----testBoundaryFile")
    mp.field("name", "avatar")
    var data = List[UInt8](String("PNGDATA").as_bytes())
    mp.file("upload", "a.png", "image/png", data^)
    var ct = mp.content_type()
    var body = mp.finish()

    var form = parse_multipart_form_data(body, ct)
    var up = form.file("upload")
    assert_true(Bool(up))
    assert_equal(up.value().filename, "a.png")
    assert_equal(up.value().content_type, "image/png")
    assert_equal(up.value().text(), "PNGDATA")


def test_multipart_content_type_carries_boundary() raises:
    var mp = MultipartFormBuilder("----bnd")
    assert_equal(mp.content_type(), "multipart/form-data; boundary=----bnd")


def main() raises:
    test_multipart_field_roundtrip()
    print("OK test_multipart_field_roundtrip")
    test_multipart_file_roundtrip()
    print("OK test_multipart_file_roundtrip")
    test_multipart_content_type_carries_boundary()
    print("OK test_multipart_content_type_carries_boundary")
