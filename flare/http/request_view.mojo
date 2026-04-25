"""Zero-copy HTTP request view (v0.5.0 Step 2 / Track 1.1).

``RequestView[origin]`` borrows method, URL, headers, and body
from the connection's ``read_buf`` rather than owning them. For a
13-byte plaintext request the difference is invisible (a few
``String`` allocations vs. a few offsets); for a 1MB / 16MB
multipart upload it's the difference between one ``memcpy`` of
the whole body and zero.

Pieces in place after this commit:

- ``RequestView[origin]`` value type (this file).
- ``parse_request_view(data: Span[UInt8, origin]) raises ->
  RequestView[origin]`` parser that scans the request line +
  headers + body slice without per-header / per-token
  allocations.
- ``RequestView.into_owned() raises -> Request`` materialises a
  v0.4.x ``Request`` for handlers that need to keep request
  state past one event-loop iteration.

Pieces that **come later** (deferred to S3 follow-up — explicit
notes in the relevant commit bodies):

- A ``ViewHandler`` trait whose ``serve_view`` takes
  ``RequestView[origin]`` directly. Today's ``Handler.serve``
  signature stays as-is; the reactor's read path can adopt a
  view-based ``run_reactor_loop_view`` once the trait surface
  lands.
- Replacing ``_parse_http_request_bytes`` with the view parser
  inside the cancel-aware reactor path. The view parser exists
  here as a standalone public function; the reactor will adopt
  it once the trait integration is settled.

This intentional split keeps the diff reviewable. The shape and
public API of ``RequestView`` are stable from this commit
forward; the integration step is purely "switch the reactor's
internal call site," which lands without breaking handlers.

Closes the *type* portion of Track 1.1; the integration portion
moves to a follow-up alongside the reactor surgery.

Example:

    var raw = "GET /a?q=1 HTTP/1.1\r\nHost: x\r\n\r\n".as_bytes()
    var view = parse_request_view(Span[UInt8, _](raw))
    print(view.method)              # GET
    print(view.url)                 # /a?q=1
    print(view.headers.get("Host")) # x
    print(len(view.body))           # 0

    # Materialise an owned ``Request`` if you need one:
    var owned = view.into_owned()
"""

from std.collections import Dict
from std.memory import memcpy

from .header_view import HeaderMapView, parse_header_view
from .headers import HeaderMap
from .request import Request
from ..net import IpAddr, SocketAddr


# ── Helpers ─────────────────────────────────────────────────────────────────


comptime _SP: UInt8 = 32
comptime _CR: UInt8 = 13
comptime _LF: UInt8 = 10


@always_inline
def _find_byte(data: Span[UInt8, _], start: Int, target: UInt8) -> Int:
    """Return index of first ``target`` at or after ``start``, or
    -1 if not found."""
    var n = len(data)
    var p = data.unsafe_ptr()
    var i = start
    while i < n:
        if p[i] == target:
            return i
        i += 1
    return -1


@always_inline
def _scan_content_length(view: HeaderMapView) -> Int:
    """Return the ``Content-Length`` value, or 0 if absent /
    malformed. Defensive — out-of-range values floor to 0."""
    var v = view.get("Content-Length")
    var n = v.byte_length()
    if n == 0:
        return 0
    var p = v.unsafe_ptr()
    var acc = 0
    for i in range(n):
        var c = Int(p[i])
        if c < 48 or c > 57:
            return 0
        acc = acc * 10 + (c - 48)
    return acc


# ── RequestView ─────────────────────────────────────────────────────────────


struct RequestView[origin: Origin](Movable):
    """Borrowed HTTP request.

    Stores **one** ``Span[UInt8, origin]`` (the underlying buffer)
    plus offset-and-length pairs for the URL, body, and the
    individual headers. Per-field accessors (``url()``,
    ``body()``, ``header(name)``) reconstruct the borrowed slice
    on demand from the buffer. This avoids Mojo's borrow-checker
    rejection of "two ``[origin]``-tied fields aliasing the same
    memory" that a flatter design (one ``StringSlice`` for URL +
    one ``Span`` for body + one ``HeaderMapView`` for headers)
    triggers.

    Fields:
        method:        ASCII method token (``"GET"``, ``"POST"``,
                       ...). Owned ``String``.
        version:       HTTP version (``"HTTP/1.1"``). Owned.
        peer:          Kernel-reported peer ``SocketAddr``.
        expose_errors: Whether 4xx response bodies may echo
                       handler-error messages.
        buf:           Underlying byte buffer borrowed from the
                       caller (typically ``ConnHandle.read_buf``).
        url_start / url_len:   Byte range of the request URL
                               within ``buf``.
        body_start / body_len: Byte range of the request body
                               within ``buf``.
        header_offsets:        Flat ``List[Int]`` of stride 4
                               (name_start, name_len, value_start,
                               value_len) — the same shape
                               ``HeaderMapView`` uses internally.
    """

    var method: String
    var version: String
    var peer: SocketAddr
    var expose_errors: Bool
    var buf: Span[UInt8, Self.origin]
    var url_start: Int
    var url_len: Int
    var body_start: Int
    var body_len: Int
    var header_offsets: List[Int]

    @always_inline
    def __init__(
        out self,
        method: String,
        version: String,
        peer: SocketAddr,
        expose_errors: Bool,
        buf: Span[UInt8, Self.origin],
        url_start: Int,
        url_len: Int,
        body_start: Int,
        body_len: Int,
        var header_offsets: List[Int],
    ):
        self.method = method
        self.version = version
        self.peer = peer
        self.expose_errors = expose_errors
        self.buf = buf
        self.url_start = url_start
        self.url_len = url_len
        self.body_start = body_start
        self.body_len = body_len
        self.header_offsets = header_offsets^

    @always_inline
    def url(self) -> StringSlice[Self.origin]:
        """Borrowed URL slice."""
        return StringSlice[Self.origin](
            unsafe_from_utf8=self.buf[
                self.url_start : self.url_start + self.url_len
            ]
        )

    @always_inline
    def body(self) -> Span[UInt8, Self.origin]:
        """Borrowed body slice."""
        return self.buf[self.body_start : self.body_start + self.body_len]

    def headers(self) -> HeaderMapView[Self.origin]:
        """Build a ``HeaderMapView`` over this view's headers.

        Cheap: copies the offsets list (typically a few ints) and
        re-binds the buffer span. The returned view shares the
        same ``origin``.
        """
        var offsets_copy = self.header_offsets.copy()
        return HeaderMapView[Self.origin](buf=self.buf, offsets=offsets_copy^)

    def into_owned(self) raises -> Request:
        """Materialise a v0.4.x ``Request`` whose fields are owned
        copies of the borrowed bytes.

        Use when a handler needs to keep request state past one
        event-loop iteration (background work, audit logging,
        cross-request bookkeeping). Allocates: one ``String`` for
        the URL, one ``HeaderMap`` worth of headers, one
        ``List[UInt8]`` for the body.
        """
        var body_owned = List[UInt8](capacity=self.body_len)
        body_owned.resize(self.body_len, UInt8(0))
        if self.body_len > 0:
            memcpy(
                dest=body_owned.unsafe_ptr(),
                src=self.buf.unsafe_ptr() + self.body_start,
                count=self.body_len,
            )
        var url_owned = String(
            unsafe_from_utf8=self.buf[
                self.url_start : self.url_start + self.url_len
            ]
        )
        var req = Request(
            method=self.method,
            url=url_owned,
            body=body_owned^,
            version=self.version,
            peer=self.peer,
            expose_errors=self.expose_errors,
        )
        req.headers = self.headers().into_owned()
        return req^


# ── Parser ──────────────────────────────────────────────────────────────────


def parse_request_view[
    origin: Origin
](
    data: Span[UInt8, origin],
    max_header_size: Int = 8_192,
    max_body_size: Int = 10 * 1024 * 1024,
    max_uri_length: Int = 8_192,
    peer: SocketAddr = SocketAddr(IpAddr("127.0.0.1", False), UInt16(0)),
    expose_errors: Bool = False,
) raises -> RequestView[origin]:
    """Parse an HTTP/1.1 request from a byte buffer into a
    ``RequestView`` borrowing into the buffer.

    Mirrors ``_parse_http_request_bytes`` in shape and validation
    rules but produces a borrowed view: no per-header ``String``
    allocation, no body copy. The body slice points into ``data``.

    Args:
        data:            Raw HTTP/1.1 request bytes (request line +
                         headers + body, terminated or not).
        max_header_size: Cap on header bytes; raises if exceeded.
        max_body_size:   Cap on body length; raises if Content-Length
                         exceeds.
        max_uri_length:  Cap on URI length; raises if exceeded.
        peer:            Kernel-reported peer address; threaded onto
                         the view.
        expose_errors:   Whether 4xx response bodies may echo handler
                         error messages.

    Returns:
        A ``RequestView`` borrowing every byte-range field from
        ``data``. The view's lifetime is tied to ``data``'s
        ``origin``.

    Raises:
        Error: On malformed request line (no spaces / wrong
            number of components), URI exceeding the cap, headers
            exceeding the cap, body exceeding the cap, or the
            ``HeaderMapView`` parser rejecting a header line.
    """
    var n = len(data)
    if n == 0:
        raise Error("empty request")

    # Request line: METHOD SP URI SP VERSION CRLF
    var line_end = _find_byte(data, 0, _LF)
    if line_end < 0:
        raise Error("missing request line terminator")
    var line_end_excl = line_end
    if line_end_excl > 0 and data[line_end_excl - 1] == _CR:
        line_end_excl -= 1

    var sp1 = _find_byte(data, 0, _SP)
    if sp1 < 0 or sp1 >= line_end_excl:
        raise Error("malformed request line: missing METHOD/URL space")
    var sp2 = _find_byte(data, sp1 + 1, _SP)

    var url_start: Int
    var url_len: Int
    var version: String
    if sp2 < 0 or sp2 >= line_end_excl:
        url_start = sp1 + 1
        url_len = line_end_excl - url_start
        version = "HTTP/1.1"
    else:
        url_start = sp1 + 1
        url_len = sp2 - url_start
        version = String(unsafe_from_utf8=data[sp2 + 1 : line_end_excl])

    if url_len > max_uri_length:
        raise Error(
            "request URI exceeds limit of " + String(max_uri_length) + " bytes"
        )

    var method = String(unsafe_from_utf8=data[0:sp1])

    # Headers: from after the request line's CRLF to the empty
    # CRLF that terminates the header block.
    var headers_start = line_end + 1
    if headers_start > n:
        headers_start = n
    # parse_header_view stops at the first empty line and reports
    # how many bytes it consumed via the view's offsets only —
    # we need to scan ahead to find where the header block ends.
    # Find CRLFCRLF (or LF LF) marker.
    var headers_end = _find_crlfcrlf(data, headers_start)
    if headers_end < 0:
        # No body separator; treat the rest as headers (parser
        # will stop at the first malformed line anyway).
        headers_end = n
    var header_bytes = headers_end - headers_start
    if header_bytes > max_header_size:
        raise Error(
            "request headers exceed limit of "
            + String(max_header_size)
            + " bytes"
        )

    # Parse headers via the existing ``parse_header_view`` helper.
    # We only care about the offsets it produces — those map back
    # into ``data`` 1:1 because we passed ``data[headers_start:
    # headers_end]`` and shift each offset back by ``headers_start``.
    var hv = parse_header_view(data[headers_start:headers_end])
    var n_headers = hv.len()
    var header_offsets = List[Int]()
    for i in range(n_headers):
        # parse_header_view's offsets are relative to its slice;
        # rebase to the full ``data`` buffer.
        header_offsets.append(hv._offsets[i * 4] + headers_start)
        header_offsets.append(hv._offsets[i * 4 + 1])
        header_offsets.append(hv._offsets[i * 4 + 2] + headers_start)
        header_offsets.append(hv._offsets[i * 4 + 3])

    # ``_find_crlfcrlf`` returns the index just past the empty
    # terminator line — i.e. the start of the body. ``headers_end``
    # therefore IS body_start; no extra advance needed.
    var body_start = headers_end

    var content_length = _scan_content_length(hv)
    if content_length > max_body_size:
        raise Error(
            "request body exceeds limit of " + String(max_body_size) + " bytes"
        )

    var body_end = body_start + content_length
    if body_end > n:
        body_end = n

    return RequestView[origin](
        method=method,
        version=version,
        peer=peer,
        expose_errors=expose_errors,
        buf=data,
        url_start=url_start,
        url_len=url_len,
        body_start=body_start,
        body_len=body_end - body_start,
        header_offsets=header_offsets^,
    )


@always_inline
def _find_crlfcrlf(data: Span[UInt8, _], start: Int) -> Int:
    """Return the index of the empty CRLF / LF-only line that
    terminates a header block (the byte just past the empty
    line's last LF — i.e. the start of the body), or ``-1`` if
    not found.

    Mirrors ``flare.http._scan.find_crlfcrlf`` semantics on a
    ``Span``: returns ``i + 1`` for the position past the empty
    LF (or ``i + 1`` past the second LF in the CRLFCRLF case).

    Accepts CRLF and bare LF terminators.
    """
    var n = len(data)
    var p = data.unsafe_ptr()
    var i = start
    while i < n:
        if p[i] == _LF:
            var prev = i - 1
            if prev >= start and p[prev] == _LF:
                # ...\\n\\n at (prev, i): body starts at i + 1.
                return i + 1
            if prev - 1 >= start and p[prev] == _CR and p[prev - 1] == _LF:
                # ...\\n\\r\\n at (prev-1, prev, i): body starts
                # at i + 1.
                return i + 1
            if (
                prev - 2 >= start
                and p[prev] == _CR
                and p[prev - 1] == _LF
                and p[prev - 2] == _CR
            ):
                # ...\\r\\n\\r\\n at (prev-2, prev-1, prev, i):
                # body starts at i + 1.
                return i + 1
        i += 1
    return -1
