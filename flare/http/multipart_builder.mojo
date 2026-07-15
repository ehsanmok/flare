"""Client-side ``multipart/form-data`` request-body builder (RFC 7578).

The server side parses multipart bodies (``parse_multipart_form_data``
+ the ``Multipart`` extractor); this is the matching client half:
assemble text fields and file parts into a body plus the
``Content-Type: multipart/form-data; boundary=...`` header value, then
hand both to ``RequestBuilder.body`` / ``HttpClient.send``.

    var mp = MultipartFormBuilder()
    mp.field("title", "hello")
    mp.file("upload", "a.txt", "text/plain", data)
    var ct = mp.content_type()
    var b = RequestBuilder(Method.POST, url)
    b.body(mp.finish(), ct)
    var resp = client.send(b^.build())
"""

from std.random import random_ui64


struct MultipartFormBuilder(Movable):
    """Accumulates multipart/form-data parts; ``finish()`` yields the body."""

    var _boundary: String
    var _body: List[UInt8]

    def __init__(out self):
        """Start a builder with a unique random boundary."""
        self._boundary = "----flareBoundary" + String(
            random_ui64(0, 0xFFFFFFFFFFFF)
        )
        self._body = List[UInt8]()

    def __init__(out self, boundary: String):
        """Start a builder with a caller-fixed boundary (deterministic
        for tests). The caller must ensure it does not occur in any
        part's payload."""
        self._boundary = boundary
        self._body = List[UInt8]()

    def _append_str(mut self, s: String):
        for b in s.as_bytes():
            self._body.append(b)

    def _append_delimiter(mut self):
        self._append_str("--" + self._boundary + "\r\n")

    def field(mut self, name: String, value: String):
        """Add a plain text form field."""
        self._append_delimiter()
        self._append_str(
            'Content-Disposition: form-data; name="' + name + '"\r\n\r\n'
        )
        self._append_str(value)
        self._append_str("\r\n")

    def file(
        mut self,
        name: String,
        filename: String,
        content_type: String,
        var data: List[UInt8],
    ):
        """Add a file part (``content_type`` empty defaults to
        ``application/octet-stream``)."""
        self._append_delimiter()
        self._append_str(
            'Content-Disposition: form-data; name="'
            + name
            + '"; filename="'
            + filename
            + '"\r\n'
        )
        var ct = (
            content_type if content_type != "" else "application/octet-stream"
        )
        self._append_str("Content-Type: " + ct + "\r\n\r\n")
        for b in data:
            self._body.append(b)
        self._append_str("\r\n")

    def content_type(self) -> String:
        """The ``Content-Type`` header value carrying the boundary.
        Read this before calling :meth:`finish` (which consumes)."""
        return "multipart/form-data; boundary=" + self._boundary

    def finish(mut self) -> List[UInt8]:
        """Append the closing delimiter and return the body bytes.
        Leaves the builder empty (do not reuse after)."""
        self._append_str("--" + self._boundary + "--\r\n")
        var out = self._body^
        self._body = List[UInt8]()
        return out^
