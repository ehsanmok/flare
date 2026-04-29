"""Example 29: ``multipart/form-data`` upload (RFC 7578).

Demonstrates the v0.6 multipart-parsing surface:

- ``parse_multipart_form_data`` — bytes + ``Content-Type`` boundary
  -> ``MultipartForm`` containing each ``MultipartPart`` (text or
  file) in receive order.
- ``MultipartForm.value(name)`` / ``.file(name)`` — typed lookup.
- ``Multipart`` extractor — typed-handler integration.

Pure parser demo; no live network. Run:
    pixi run example-multipart-upload
"""

from flare.http import (
    Method,
    Multipart,
    MultipartForm,
    Request,
    parse_multipart_form_data,
)


def _build_demo_body() -> List[UInt8]:
    """Build a small multipart body with one text field + one file part."""
    var crlf = "\r\n"
    var s = String("--BND") + crlf
    s += 'Content-Disposition: form-data; name="caption"' + crlf + crlf
    s += "sunset on the beach" + crlf
    s += "--BND" + crlf
    s += 'Content-Disposition: form-data; name="photo"; filename="x.jpg"'
    s += crlf
    s += "Content-Type: image/jpeg" + crlf + crlf
    s += "<JPEG bytes here>" + crlf
    s += "--BND--" + crlf
    return List[UInt8](s.as_bytes())


def main() raises:
    print("=== flare Example 29: Multipart upload ===")
    print()

    # ── 1. Parse a known-good multipart body ───────────────────────────────
    print("── 1. parse_multipart_form_data ──")
    var body = _build_demo_body()
    var ct = "multipart/form-data; boundary=BND"
    var form = parse_multipart_form_data(body, ct)
    print("  parts     :", form.len())
    print("  caption   :", form.value("caption"))
    var maybe_photo = form.file("photo")
    if maybe_photo:
        var p = maybe_photo.value().copy()
        print("  filename  :", p.filename)
        print("  type      :", p.content_type)
        print("  size      :", len(p.body), "bytes")
    print()

    # ── 2. Multipart extractor on a Request ────────────────────────────────
    print("── 2. Multipart extractor ──")
    var req = Request(method=Method.POST, url="/upload")
    req.headers.set("Content-Type", ct)
    req.body = body.copy()
    var m = Multipart.extract(req)
    print("  via extractor    :", m.value.len(), "parts")
    print("  via extractor[0] :", m.value.parts[0].name)
    print()

    print("=== Example 29 complete ===")
