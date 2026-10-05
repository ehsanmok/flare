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
from ..proto.chunked import TE_CHUNKED, classify_transfer_coding
from .._scan import parse_content_length
from ...io.byte_cursor import _is_valid_utf8
from ...net import IpAddr, SocketAddr
from ...tcp import TcpStream

from .parse_util import (
    _ascii_safe,
    _is_valid_http_version,
    _ascii_strip_slice,
    _ascii_unchecked_string,
    _find_crlfcrlf,
    _is_field_value_char,
    _is_token_char,
    _parse_int_str,
    _read_line_buf,
    _read_line_buf_lenient,
    _scan_content_length,
)


def _check_field_value(v: String, accept_obs_text: Bool) raises:
    """Refuse a field value that RFC 9110 sec 5.5 does not allow.

    Runs on the value of a field's first line and on every obs-fold
    continuation (RFC 9112 sec 5.2: the unfolded value is still a field
    value; the continuation used to skip this check).

    Bare CR / LF / NUL are always rejected (the smuggling-class bytes);
    so is every other control byte (0x01-0x08, 0x0B-0x1F, DEL), which is
    outside field-vchar. High-bit obs-text is gated on
    ``accept_obs_text``. obs-text is opaque octets on the wire, but the
    value is stored as a ``String``, which must hold valid UTF-8, so
    obs-text that is not valid UTF-8 is refused too.

    Raises:
        Error: On the first offending byte.
    """
    var has_obs_text = False
    for i in range(v.byte_length()):
        var vc = v.unsafe_ptr()[unsafe_offset=i]
        if vc == 0 or vc == 10 or vc == 13:
            raise Error("invalid control character in header value")
        if vc >= 128:
            if not accept_obs_text:
                raise Error("obs-text byte in header value rejected")
            has_obs_text = True
        elif not _is_field_value_char(vc):
            raise Error("invalid control character in header value")
    if has_obs_text and not _is_valid_utf8(v.as_bytes()):
        raise Error("obs-text header value is not valid UTF-8")


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
    if sp1 <= 0:
        raise Error("malformed request line: " + _ascii_safe(req_line))
    # RFC 9110 sec 9.1: a method is a token. Without this a request
    # line such as ``TRANSFER-ENCODING:CHUNKED / HTTP/1.1`` or one with
    # control bytes in the method reached routing and the handler.
    for i in range(sp1):
        if not _is_token_char(req_line.unsafe_ptr()[unsafe_offset=i]):
            raise Error("invalid character in request method")
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

    # RFC 9112 sec 3.2: the request-target is visible ASCII. A CR, a
    # control byte or a high byte here reached ``req.url`` wrapped by
    # ``_ascii_unchecked_string``, i.e. as a String that need not be
    # valid UTF-8, and from there any log line or redirect built from it.
    if path.byte_length() == 0:
        raise Error("empty request target")
    for i in range(path.byte_length()):
        var tc = path.unsafe_ptr()[unsafe_offset=i]
        if tc < 33 or tc > 126:
            raise Error("invalid character in request target")

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
    var te_joined = String("")
    var te_seen = False

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
            if have_prev:
                headers.append(prev_header_name, prev_header_value)
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
            # A continuation is field content like any other line's value
            # (RFC 9112 sec 5.2): it gets the same byte checks.
            _check_field_value(folded, leniency.accept_obs_text_in_field_value)
            prev_header_value = prev_header_value + " " + folded
            continue

        var colon = -1
        for i in range(line.byte_length()):
            if line.unsafe_ptr()[unsafe_offset=i] == 58:
                colon = i
                break
        if colon < 0:
            # A field line with no colon is malformed (RFC 9112 sec 5).
            # Skipping it let `Transfer-Encoding chunked` vanish here
            # while a more forgiving front end honoured it.
            raise Error("header line without a colon")

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

        if name_end == 0:
            raise Error("empty header field name")
        var name_valid = True
        for i in range(name_end):
            if not _is_token_char(line.unsafe_ptr()[unsafe_offset=i]):
                name_valid = False
                break
        if not name_valid:
            raise Error("invalid character in header name")

        var k = _ascii_strip_slice(line.as_bytes()[:name_end])
        var v = _ascii_strip_slice(line.as_bytes()[colon + 1 :])

        _check_field_value(v, leniency.accept_obs_text_in_field_value)

        # RFC 9112 §6.3.5: duplicate ``Content-Length`` headers are
        # smuggling vectors unless every value agrees. Strict
        # treats the second occurrence as malformed; the leniency
        # flag accepts when the values match.
        if ascii_eq_ignore_case(k, "content-length"):
            var n = parse_content_length(v)
            if n < 0:
                raise Error("malformed Content-Length: " + v)
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

        if ascii_eq_ignore_case(k, "transfer-encoding"):
            if te_seen:
                te_joined += ","
            te_joined += v
            te_seen = True

        # Fields are appended, not set: a repeated field keeps every
        # value (Cookie, Accept, ...), and ``get`` still answers with the
        # first one. The previous field is committed only now, once we
        # know this line is not an obs-fold continuation of it.
        if have_prev:
            headers.append(prev_header_name, prev_header_value)
        prev_header_name = k
        prev_header_value = v
        have_prev = True

    # RFC 9112 sec 3.2: a request with more than one Host field gets a
    # 400. With last-wins storage the second Host silently replaced the
    # first, and a proxy that routed on the first sent flare a request
    # for a different virtual host than the one it checked.
    if len(headers.get_all("host")) > 1:
        raise Error("more than one Host header")

    # RFC 9112 §6.3: ``Transfer-Encoding`` + ``Content-Length`` is
    # ambiguous. Strict rejects (smuggling-safe); the leniency
    # flag prefers the chunked framing per the RFC and discards
    # the Content-Length value. The server today does not decode
    # chunked request bodies, so the lenient path produces a
    # zero-body request; the flag still has parser-time effect
    # because it controls whether the request is rejected at all.
    #
    # Every Transfer-Encoding line counts (RFC 9110 sec 5.3), not the
    # last one ``headers.set`` happened to keep: the reactor frames on
    # the same joined list, and a parser that saw only the last line
    # could be talked into CL.TE with ``TE: chunked`` + ``TE: identity``.
    if te_seen:
        var framing = classify_transfer_coding(te_joined)
        if framing != TE_CHUNKED:
            raise Error(
                "unsupported or malformed Transfer-Encoding: " + te_joined
            )
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
                # The caller framed fewer bytes than this request
                # declares. Truncating silently would leave the rest
                # of the body in the connection's buffer, where it is
                # parsed as the next request.
                raise Error(
                    "request body shorter than its Content-Length ("
                    + String(len(data) - pos)
                    + " of "
                    + String(content_length)
                    + " bytes)"
                )
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
            # Same rule as the full parser: never serve a truncated
            # body, the remainder would be read as the next request.
            raise Error("request body shorter than its Content-Length")
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
            if cl < 0:
                raise Error("malformed Content-Length")
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
