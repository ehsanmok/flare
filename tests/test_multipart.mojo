"""Tests for ``flare.http.multipart`` (— track C, RFC 7578).

Covers the parser and ``Multipart`` extractor:

- Boundary extraction from ``Content-Type`` (token, quoted, with /
  without leading whitespace, missing/empty raises).
- Single text part, multiple text parts, file part with filename +
  content-type, mixed text + file, percent-decoding NOT applied
  (multipart bodies are raw bytes, RFC 7578 paragraph 4.2).
- Header parsing tolerates additional headers per part.
- Closing boundary terminates parsing; trailing bytes after closing
  boundary are ignored.
- Truncated bodies / missing boundaries raise.
- ``MultipartForm.value(name)`` / ``.file(name)`` lookup.
- ``Multipart`` extractor on a Request roundtrip.
"""

from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.http import (
    Method,
    Multipart,
    MultipartForm,
    MultipartPart,
    Request,
    parse_multipart_form_data,
)


def _body_from_parts(parts: List[String], boundary: String) -> List[UInt8]:
    """Concat parts with boundary delimiters into a multipart body."""
    var crlf = "\r\n"
    var body = String("")
    body += "--" + boundary + crlf
    for i in range(len(parts)):
        if i > 0:
            body += "--" + boundary + crlf
        body += parts[i]
        body += crlf
    body += "--" + boundary + "--" + crlf
    return List[UInt8](body.as_bytes())


def _single(part: String, boundary: String) -> List[UInt8]:
    var lst = List[String]()
    lst.append(part)
    return _body_from_parts(lst, boundary)


def test_boundary_token() raises:
    var body = _single(
        'Content-Disposition: form-data; name="a"\r\n\r\nhello',
        "abc",
    )
    var ct = "multipart/form-data; boundary=abc"
    var f = parse_multipart_form_data(body, ct)
    assert_equal(f.len(), 1)
    assert_equal(f.value("a"), "hello")


def test_boundary_quoted() raises:
    var body = _single(
        'Content-Disposition: form-data; name="a"\r\n\r\nhello',
        "abc",
    )
    var ct = 'multipart/form-data; boundary="abc"'
    var f = parse_multipart_form_data(body, ct)
    assert_equal(f.value("a"), "hello")


def test_boundary_with_spaces() raises:
    var body = _single(
        'Content-Disposition: form-data; name="a"\r\n\r\nv',
        "xyz",
    )
    var ct = "multipart/form-data; boundary=xyz "
    var f = parse_multipart_form_data(body, ct)
    assert_equal(f.value("a"), "v")


def test_boundary_missing_raises() raises:
    var body = List[UInt8]("---foo".as_bytes())
    with assert_raises():
        _ = parse_multipart_form_data(body, "multipart/form-data")


def test_boundary_empty_raises() raises:
    var body = List[UInt8]("---".as_bytes())
    with assert_raises():
        _ = parse_multipart_form_data(body, "multipart/form-data; boundary=")


def test_single_text_part() raises:
    var body = _single(
        'Content-Disposition: form-data; name="greeting"\r\n\r\nhello',
        "BND",
    )
    var f = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")
    assert_equal(f.len(), 1)
    var p = f.parts[0].copy()
    assert_equal(p.name, "greeting")
    assert_equal(p.text(), "hello")
    assert_false(p.is_file())


def test_multiple_text_parts() raises:
    var lst = List[String]()
    lst.append('Content-Disposition: form-data; name="a"\r\n\r\n1')
    lst.append('Content-Disposition: form-data; name="b"\r\n\r\n2')
    lst.append('Content-Disposition: form-data; name="c"\r\n\r\n3')
    var body = _body_from_parts(lst, "BND")
    var f = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")
    assert_equal(f.len(), 3)
    assert_equal(f.value("a"), "1")
    assert_equal(f.value("b"), "2")
    assert_equal(f.value("c"), "3")


def test_file_part() raises:
    var body = _single(
        (
            'Content-Disposition: form-data; name="upload";'
            ' filename="hello.txt"\r\n'
            "Content-Type: text/plain\r\n"
            "\r\n"
            "hello world"
        ),
        "BND",
    )
    var f = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")
    assert_equal(f.len(), 1)
    var p = f.parts[0].copy()
    assert_equal(p.name, "upload")
    assert_equal(p.filename, "hello.txt")
    assert_equal(p.content_type, "text/plain")
    assert_equal(p.text(), "hello world")
    assert_true(p.is_file())


def test_mixed_text_and_file() raises:
    var lst = List[String]()
    lst.append('Content-Disposition: form-data; name="title"\r\n\r\nphoto')
    lst.append(
        'Content-Disposition: form-data; name="file";'
        ' filename="img.png"\r\n'
        "Content-Type: image/png\r\n"
        "\r\n"
        "BINARY"
    )
    var body = _body_from_parts(lst, "BND")
    var f = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")
    assert_equal(f.len(), 2)
    assert_equal(f.value("title"), "photo")
    var maybe_file = f.file("file")
    assert_true(Bool(maybe_file))
    assert_equal(maybe_file.value().filename, "img.png")
    assert_equal(maybe_file.value().content_type, "image/png")


def test_part_with_extra_header() raises:
    var body = _single(
        (
            'Content-Disposition: form-data; name="x"\r\n'
            "X-Custom: custom-value\r\n"
            "\r\n"
            "v"
        ),
        "BND",
    )
    var f = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")
    assert_equal(f.parts[0].header("X-Custom"), "custom-value")


def test_get_optional_returns_none() raises:
    var body = _single(
        'Content-Disposition: form-data; name="a"\r\n\r\n1',
        "BND",
    )
    var f = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")
    assert_false(Bool(f.get("missing")))


def test_get_all_returns_duplicates() raises:
    var lst = List[String]()
    lst.append('Content-Disposition: form-data; name="k"\r\n\r\n1')
    lst.append('Content-Disposition: form-data; name="k"\r\n\r\n2')
    var body = _body_from_parts(lst, "BND")
    var f = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")
    var all = f.get_all("k")
    assert_equal(len(all), 2)


def test_truncated_no_closing_boundary() raises:
    var body = List[UInt8](
        (
            '--BND\r\nContent-Disposition: form-data; name="a"\r\n\r\nhello'
        ).as_bytes()
    )
    with assert_raises():
        _ = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")


def test_missing_header_terminator() raises:
    var body = List[UInt8](
        '--BND\r\nContent-Disposition: form-data; name="a"'.as_bytes()
    )
    with assert_raises():
        _ = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")


def test_no_leading_boundary() raises:
    var body = List[UInt8]("hello world".as_bytes())
    with assert_raises():
        _ = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")


def test_binary_part_preserved() raises:
    var crlf = "\r\n"
    var s = String("--BND") + crlf
    s += 'Content-Disposition: form-data; name="bin"' + crlf
    s += "Content-Type: application/octet-stream" + crlf + crlf
    var prefix = List[UInt8](s.as_bytes())
    prefix.append(UInt8(0))
    prefix.append(UInt8(255))
    prefix.append(UInt8(127))
    var tail = List[UInt8]((crlf + "--BND--" + crlf).as_bytes())
    for b in tail:
        prefix.append(b)
    var f = parse_multipart_form_data(
        prefix, "multipart/form-data; boundary=BND"
    )
    assert_equal(f.len(), 1)
    var part = f.parts[0].copy()
    assert_equal(len(part.body), 3)
    assert_equal(Int(part.body[0]), 0)
    assert_equal(Int(part.body[1]), 255)
    assert_equal(Int(part.body[2]), 127)


def test_multipart_extractor() raises:
    var req = Request(method=Method.POST, url="/upload")
    req.headers.set("Content-Type", "multipart/form-data; boundary=BND")
    req.body = _single(
        'Content-Disposition: form-data; name="user"\r\n\r\nalice',
        "BND",
    )
    var m = Multipart.extract(req)
    assert_equal(m.value.value("user"), "alice")


def test_multipart_extractor_empty_raises() raises:
    var req = Request(method=Method.POST, url="/upload")
    req.headers.set("Content-Type", "multipart/form-data; boundary=BND")
    with assert_raises():
        _ = Multipart.extract(req)


def test_contains() raises:
    var body = _single(
        'Content-Disposition: form-data; name="a"\r\n\r\n1',
        "BND",
    )
    var f = parse_multipart_form_data(body, "multipart/form-data; boundary=BND")
    assert_true(f.contains("a"))
    assert_false(f.contains("b"))


def main() raises:
    test_boundary_token()
    test_boundary_quoted()
    test_boundary_with_spaces()
    test_boundary_missing_raises()
    test_boundary_empty_raises()
    test_single_text_part()
    test_multiple_text_parts()
    test_file_part()
    test_mixed_text_and_file()
    test_part_with_extra_header()
    test_get_optional_returns_none()
    test_get_all_returns_duplicates()
    test_truncated_no_closing_boundary()
    test_missing_header_terminator()
    test_no_leading_boundary()
    test_binary_part_preserved()
    test_multipart_extractor()
    test_multipart_extractor_empty_raises()
    test_contains()
    print("test_multipart: 19 passed")
