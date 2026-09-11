"""HTTP/1.1 request parsers extracted from ``flare.http.server``.

The byte-buffer request parsers: the full RFC 7230 / 9112 path
(``_parse_http_request_bytes``), the minimal-headers fast path
(``_parse_http_request_bytes_minimal``), and the legacy stream-reading
wrapper (``_parse_http_request``). The byte-level lexing primitives
they build on live in :mod:`flare.http._server.parse_util`.
``flare.http.server`` re-exports every name here so existing call sites
keep importing them from ``flare.http.server``.
"""

from std.memory import unsafe_memcpy

from ..intern import intern_method_bytes
from ..request import Request
from ..headers import HeaderMap
from ..proto.ascii import ascii_eq_ignore_case
from ..proto.h1_leniency import H1LeniencyConfig
from ...net import IpAddr, SocketAddr
from ...tcp import TcpStream

from .parse_util import (
    _ascii_safe,
    _ascii_strip_slice,
    _ascii_unchecked_string,
    _find_crlfcrlf,
    _is_token_char,
    _parse_int_str,
    _read_line_buf,
    _read_line_buf_lenient,
    _scan_content_length,
)


def _is_valid_http_version(v: String) raises -> Bool:
    """RFC 9112 sec 2.3: ``HTTP/<DIGIT>.<DIGIT>`` and nothing else.

    Without this any third token parses as a version, so a garbage
    request line is answered 404 instead of 400 -- and a peer that
    opened with something like an invalid HTTP/2 preface is left
    holding a keep-alive connection it cannot interpret."""
    if v.byte_length() != 8:
        return False
    var p = v.unsafe_ptr()
    if (
        p[unsafe_offset=0] != UInt8(ord("H"))
        or p[unsafe_offset=1] != UInt8(ord("T"))
        or p[unsafe_offset=2] != UInt8(ord("T"))
        or p[unsafe_offset=3] != UInt8(ord("P"))
        or p[unsafe_offset=4] != UInt8(ord("/"))
        or p[unsafe_offset=6] != UInt8(ord("."))
    ):
        return False
    if p[unsafe_offset=5] < UInt8(ord("0")) or p[unsafe_offset=5] > UInt8(
        ord("9")
    ):
        return False
    if p[unsafe_offset=7] < UInt8(ord("0")) or p[unsafe_offset=7] > UInt8(
        ord("9")
    ):
        return False
    return True


def _parse_http_request_bytes(
    data: Span[UInt8, _],
    max_header_size: Int = 8_192,
    max_body_size: Int = 10 * 1024 * 1024,
    max_uri_length: Int = 8_192,
    peer: SocketAddr = SocketAddr(IpAddr("127.0.0.1", False), UInt16(0)),
    expose_errors: Bool = False,
    leniency: H1LeniencyConfig = H1LeniencyConfig(),
) raises -> Request:
    """Parse an HTTP/1.1 request from a byte buffer.

    Validates header names per RFC 7230 token rules and header values for
    illegal control characters. Parses HTTP version for keep-alive semantics.

    Args:
        data: Raw HTTP/1.1 request bytes.
        max_header_size: Maximum bytes for all header lines combined.
        max_body_size: Maximum bytes for the request body.
        max_uri_length: Maximum bytes for the request URI.
        peer: Kernel-reported peer ``SocketAddr`` captured at
                         accept; copied into the parsed ``Request`` so
                         handlers can read ``req.peer``. Defaults to
                         ``127.0.0.1:0`` for callers that don't have a
                         live connection (tests, fuzzers).
        expose_errors: Whether the parsed request will allow handler /
                         extractor error messages into its 4xx / 5xx
                         response body. Threaded onto
                         ``Request.expose_errors``. Defaults to
                         ``False`` (production-safe).
        leniency: Per-flag relaxations of the strict RFC 9112 grammar.
            See :class:`flare.http.proto.H1LeniencyConfig`. Defaults to
            strict (every flag off).

    Returns:
        A parsed ``Request`` with version set from the request line.

    Raises:
        Error: On malformed request line, invalid tokens, or limit violations.
    """
    var pos = 0
    var n = len(data)

    # 0. RFC 9112 §2.2: leading whitespace before the request line.
    # Strict default rejects any byte the SHOULD-ignore rule covers
    # (CR / LF / SP / HTAB) so the HTTP/2 preface peek isn't masked
    # by a noise prefix; the leniency flag opts back into the
    # SHOULD-ignore behaviour.
    if leniency.allow_leading_whitespace_before_request_line:
        while pos < n:
            var c = data[pos]
            if c == 13 or c == 10 or c == 32 or c == 9:
                pos += 1
            else:
                break

    # 1. Request line: METHOD SP URI SP VERSION CRLF
    var req_line = _read_line_buf_lenient(
        data, pos, leniency.allow_lf_only_line_endings
    )
    if req_line.byte_length() == 0:
        raise Error("empty request line")

    var sp1 = -1
    for i in range(req_line.byte_length()):
        if req_line.unsafe_ptr()[unsafe_offset=i] == 32:
            sp1 = i
            break
    if sp1 < 0:
        raise Error("malformed request line: " + _ascii_safe(req_line))
    # B3: try the StaticString intern table first — covers the 9
    # RFC 7231 method names (~99 % of real-world traffic is GET /
    # POST). On a hit, the returned String's backing comes from
    # a process-lifetime constant rather than from per-request
    # request buffer bytes, so the second String wrap is elided.
    var method_bytes = req_line.as_bytes()[:sp1]
    var interned = intern_method_bytes(method_bytes)
    var method: String
    if interned:
        method = interned.value()
    else:
        method = _ascii_unchecked_string(method_bytes)

    # RFC 9110 §9.1: methods are case-sensitive tokens. The strict
    # default rejects any lowercase letter in the method name; the
    # leniency flag normalises mixed-case methods to upper-case.
    var has_lowercase = False
    for i in range(method.byte_length()):
        var mc = method.unsafe_ptr()[unsafe_offset=i]
        if mc >= UInt8(ord("a")) and mc <= UInt8(ord("z")):
            has_lowercase = True
            break
    if has_lowercase:
        if not leniency.allow_mixed_case_method:
            raise Error(
                "method '"
                + _ascii_safe(method)
                + "' has lowercase letters (RFC 9110 §9.1"
                " methods are case-sensitive); set"
                " H1LeniencyConfig.allow_mixed_case_method to accept"
            )
        var all_letters = method.byte_length() > 0
        for i in range(method.byte_length()):
            var mc = method.unsafe_ptr()[unsafe_offset=i]
            if not (
                (mc >= UInt8(ord("A")) and mc <= UInt8(ord("Z")))
                or (mc >= UInt8(ord("a")) and mc <= UInt8(ord("z")))
            ):
                all_letters = False
                break
        if all_letters:
            method = method.upper()

    var sp2 = -1
    for i in range(sp1 + 1, req_line.byte_length()):
        if req_line.unsafe_ptr()[unsafe_offset=i] == 32:
            sp2 = i
            break
    var path: String
    var version: String
    if sp2 < 0:
        path = _ascii_unchecked_string(req_line.as_bytes()[sp1 + 1 :])
        version = "HTTP/1.1"
    else:
        path = _ascii_unchecked_string(req_line.as_bytes()[sp1 + 1 : sp2])
        version = _ascii_unchecked_string(req_line.as_bytes()[sp2 + 1 :])

    if not _is_valid_http_version(version):
        raise Error("malformed HTTP version in request line: " + version)

    if (
        not leniency.allow_oversized_request_uri
        and path.byte_length() > max_uri_length
    ):
        raise Error(
            "request URI exceeds limit of " + String(max_uri_length) + " bytes"
        )

    # 2. Headers with RFC 7230 token validation
    var headers = HeaderMap()
    var header_bytes = 0
    var prev_header_name = String("")
    var prev_header_value = String("")
    var have_prev = False
    var content_length_seen: Int = -1

    while True:
        var line = _read_line_buf_lenient(
            data, pos, leniency.allow_lf_only_line_endings
        )
        header_bytes += line.byte_length()
        if (
            not leniency.allow_oversized_header_list
            and header_bytes > max_header_size
        ):
            raise Error(
                "request headers exceed limit of "
                + String(max_header_size)
                + " bytes"
            )
        if line.byte_length() == 0:
            break

        # RFC 9112 §5.2 obs-fold: a continuation line starts with
        # SP / HTAB and folds into the previous header value.
        # Strict rejects (smuggling primitive); the leniency flag
        # appends the trimmed continuation to the prior value.
        var first = line.unsafe_ptr()[unsafe_offset=0]
        if first == 32 or first == 9:
            if not leniency.allow_obs_fold or not have_prev:
                raise Error("obs-fold rejected (request smuggling vector)")
            var folded = _ascii_strip_slice(line.as_bytes())
            prev_header_value = prev_header_value + " " + folded
            headers.set(prev_header_name, prev_header_value)
            continue

        var colon = -1
        for i in range(line.byte_length()):
            if line.unsafe_ptr()[unsafe_offset=i] == 58:
                colon = i
                break
        if colon < 0:
            continue

        # RFC 9112 §5.1: no whitespace before the colon. Strict
        # rejects; lenient strips trailing whitespace from the
        # field-name slice.
        var name_end = colon
        if leniency.allow_ows_around_colon:
            while name_end > 0:
                var nc = line.unsafe_ptr()[unsafe_offset=name_end - 1]
                if nc == 32 or nc == 9:
                    name_end -= 1
                else:
                    break

        var name_valid = True
        for i in range(name_end):
            if not _is_token_char(line.unsafe_ptr()[unsafe_offset=i]):
                name_valid = False
                break
        if not name_valid:
            raise Error("invalid character in header name")

        var k = _ascii_strip_slice(line.as_bytes()[:name_end])
        var v = _ascii_strip_slice(line.as_bytes()[colon + 1 :])

        # RFC 9112 §5.5: bare CR / LF / NUL always rejected (those
        # are the smuggling-class bytes). High-bit obs-text is
        # gated on the leniency flag — strict rejects; lenient
        # treats the bytes as opaque.
        for i in range(v.byte_length()):
            var vc = v.unsafe_ptr()[unsafe_offset=i]
            if vc == 0 or vc == 10 or vc == 13:
                raise Error("invalid control character in header value")
            if vc >= 128 and not leniency.accept_obs_text_in_field_value:
                raise Error("obs-text byte in header value rejected")

        # RFC 9112 §6.3.5: duplicate ``Content-Length`` headers are
        # smuggling vectors unless every value agrees. Strict
        # treats the second occurrence as malformed; the leniency
        # flag accepts when the values match.
        if ascii_eq_ignore_case(k, "content-length"):
            var n = _parse_int_str(v)
            if content_length_seen >= 0 and n != content_length_seen:
                raise Error(
                    "duplicate Content-Length headers with conflicting values"
                )
            if (
                content_length_seen >= 0
                and not leniency.allow_multiple_content_length
            ):
                raise Error("duplicate Content-Length headers rejected")
            content_length_seen = n

        headers.set(k, v)
        prev_header_name = k
        prev_header_value = v
        have_prev = True

    # RFC 9112 §6.3: ``Transfer-Encoding`` + ``Content-Length`` is
    # ambiguous. Strict rejects (smuggling-safe); the leniency
    # flag prefers the chunked framing per the RFC and discards
    # the Content-Length value. The server today does not decode
    # chunked request bodies, so the lenient path produces a
    # zero-body request; the flag still has parser-time effect
    # because it controls whether the request is rejected at all.
    var te = headers.get("Transfer-Encoding").lower()
    if "chunked" in te:
        if content_length_seen >= 0:
            if not leniency.allow_te_chunked_when_cl_present:
                raise Error(
                    "Transfer-Encoding: chunked + Content-Length is ambiguous"
                )
            content_length_seen = 0
            _ = headers.remove("Content-Length")

    # 3. Body (Content-Length)
    var body = List[UInt8]()
    if content_length_seen > 0:
        var content_length = content_length_seen
        if content_length > max_body_size:
            raise Error(
                "request body exceeds limit of "
                + String(max_body_size)
                + " bytes"
            )
        if content_length > 0:
            var end = pos + content_length
            if end > len(data):
                end = len(data)
            # Bulk-copy the body in one resize + memcpy. Per-byte
            # ``body.append`` was a measurable hot-path cost on POSTs.
            var n2 = end - pos
            if n2 > 0:
                body.resize(n2, UInt8(0))
                unsafe_memcpy(
                    dest=body.unsafe_ptr(),
                    src=data.unsafe_ptr().unsafe_offset(pos),
                    count=n2,
                )

    var req = Request(
        method=method,
        url=path,
        body=body^,
        version=version,
        peer=peer,
        expose_errors=expose_errors,
    )
    req.headers = headers^
    return req^


def _parse_http_request_bytes_minimal(
    data: Span[UInt8, _],
    header_end: Int,
    content_length: Int,
    max_body_size: Int = 10 * 1024 * 1024,
    max_uri_length: Int = 8_192,
    peer: SocketAddr = SocketAddr(IpAddr("127.0.0.1", False), UInt16(0)),
    expose_errors: Bool = False,
) raises -> Request:
    """Minimal-headers parser that constructs only the request
    line + body, leaving the ``HeaderMap`` empty.

    Designed for ``ServerConfig.skip_header_decode_for_short_-
    requests=True`` callers. The caller has already located the
    end-of-headers via ``_find_crlfcrlf`` and the
    ``Content-Length`` via ``_scan_content_length``, so we don't
    re-scan; we just split the request line and copy the body.

    Drops per-request work compared to
    :func:`_parse_http_request_bytes`:
    * No ``HeaderMap`` allocation.
    * No per-header CRLF/colon scan loop.
    * No per-header name/value ``String`` allocations.
    * No RFC 7230 token / value validation per header.

    Returns a ``Request`` whose ``headers`` is an empty
    ``HeaderMap``. The keep-alive policy decision in the
    dispatch must use a separate raw-bytes scan
    (:func:`flare.http._server_reactor_impl._wants_close`) when
    this parser is used; the dispatch already does this via the
    ``skip_header_decode_for_short_requests`` config bit.

    Args:
        data: Raw HTTP/1.1 request bytes (header block + body).
        header_end: Byte index past the ``\\r\\n\\r\\n``
            header terminator (= start of body).
        content_length: Pre-scanned Content-Length value (0 if
            absent or zero).
        max_body_size: Body size cap; raises if Content-Length
            exceeds it.
        max_uri_length: URI length cap; raises if path exceeds.
        peer: Kernel-reported peer address (passed through).
        expose_errors: Threaded onto Request.expose_errors.

    Returns:
        Parsed Request with empty headers.
    """
    var pos = 0

    # 1. Request line only.
    var req_line = _read_line_buf(data, pos)
    if req_line.byte_length() == 0:
        raise Error("empty request line")

    var sp1 = -1
    for i in range(req_line.byte_length()):
        if req_line.unsafe_ptr()[unsafe_offset=i] == 32:
            sp1 = i
            break
    if sp1 < 0:
        raise Error("malformed request line: " + _ascii_safe(req_line))
    var interned = intern_method_bytes(req_line.as_bytes()[:sp1])
    var method: String
    if interned:
        method = interned.value()
    else:
        method = _ascii_unchecked_string(req_line.as_bytes()[:sp1])

    var sp2 = -1
    for i in range(sp1 + 1, req_line.byte_length()):
        if req_line.unsafe_ptr()[unsafe_offset=i] == 32:
            sp2 = i
            break
    var path: String
    var version: String
    if sp2 < 0:
        path = _ascii_unchecked_string(req_line.as_bytes()[sp1 + 1 :])
        version = "HTTP/1.1"
    else:
        path = _ascii_unchecked_string(req_line.as_bytes()[sp1 + 1 : sp2])
        version = _ascii_unchecked_string(req_line.as_bytes()[sp2 + 1 :])

    if not _is_valid_http_version(version):
        raise Error("malformed HTTP version in request line: " + version)

    if path.byte_length() > max_uri_length:
        raise Error(
            "request URI exceeds limit of " + String(max_uri_length) + " bytes"
        )

    # 2. SKIP headers entirely. The caller passed in the
    # already-scanned content_length + header_end so we don't
    # need to walk the header block.

    # 3. Body (caller-supplied Content-Length).
    var body = List[UInt8]()
    if content_length > 0:
        if content_length > max_body_size:
            raise Error(
                "request body exceeds limit of "
                + String(max_body_size)
                + " bytes"
            )
        var body_start = header_end
        var body_end = body_start + content_length
        if body_end > len(data):
            body_end = len(data)
        var n = body_end - body_start
        if n > 0:
            body.resize(n, UInt8(0))
            unsafe_memcpy(
                dest=body.unsafe_ptr(),
                src=data.unsafe_ptr().unsafe_offset(body_start),
                count=n,
            )

    var req = Request(
        method=method,
        url=path,
        body=body^,
        version=version,
        peer=peer,
        expose_errors=expose_errors,
    )
    # headers stays as the default empty HeaderMap; callers must
    # use config.skip_header_decode_for_short_requests=True only
    # when their handler doesn't read req.headers.
    return req^


# ── Legacy compatibility aliases ──────────────────────────────────────────────


def _parse_http_request(
    mut stream: TcpStream,
    max_header_size: Int,
    max_body_size: Int,
) raises -> Request:
    """Parse an HTTP/1.1 request from a TCP stream using buffered reads.

    Kept for backward compatibility with existing test code.
    """
    var buf = List[UInt8](capacity=8192)
    var read_buf = List[UInt8](capacity=8192)
    read_buf.resize(8192, 0)

    while True:
        var n = stream.read(read_buf.unsafe_ptr(), 8192)
        if n == 0:
            raise Error("empty request: connection closed")
        for i in range(n):
            buf.append(read_buf[i])
        var hdr_end = _find_crlfcrlf(buf, 0)
        if hdr_end >= 0:
            var cl = _scan_content_length(buf, hdr_end)
            var total = hdr_end + cl
            while len(buf) < total:
                n = stream.read(read_buf.unsafe_ptr(), 8192)
                if n == 0:
                    break
                for i in range(n):
                    buf.append(read_buf[i])
            return _parse_http_request_bytes(
                Span[UInt8, _](buf)[:total],
                max_header_size,
                max_body_size,
                peer=stream.peer_addr(),
            )
        if len(buf) > max_header_size + max_body_size:
            raise Error("request too large")
