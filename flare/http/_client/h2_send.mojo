"""HTTP/2 + h2c request drivers extracted from ``flare.http.client``.

The send-side helpers that used to trail the ``HttpClient`` struct in
``client.mojo``: request-header construction, the ALPN-h2 and
h2c-prior-knowledge send paths over TLS / TCP, and the h2c-via-Upgrade
driver. These are called from :meth:`HttpClient._do_request`;
``flare.http.client`` imports them back so the struct keeps compiling
unchanged. Response parsing for the upgrade path is reused from
:mod:`flare.http._client.parse`.
"""

from ..response import Response
from ..headers import HeaderMap
from ..url import Url
from ...tcp import TcpStream
from ...tls import TlsStream
from ...net import NetworkError
from ...http2.client import (
    Http2ClientConfig,
    Http2ClientConnection,
    _h2_response_to_http,
    build_h2c_settings_payload,
)
from ...http2.hpack import HpackHeader
from ...crypto.hmac import base64url_encode

from .parse import _parse_http_response


comptime _H2_READ_BUF_SIZE: Int = 16384
"""Per-syscall recv buffer size for the h2 read pump. Matches the
RFC 9113 §6.5.2 default ``max_frame_size``."""


def _build_h2_request_headers(
    extra_headers: HeaderMap,
    user_agent: String,
    auth_header: String,
) raises -> List[HpackHeader]:
    """Translate :class:`HeaderMap` to a list of :class:`HpackHeader`
    suitable for :meth:`Http2ClientConnection.send_request`.

    Lower-cases header names per RFC 9113 §8.1.2 and strips the
    connection-level headers RFC 9113 §8.2.2 forbids on h2.
    Appends ``user-agent`` and ``authorization`` from the
    HttpClient instance fields if they are not already present
    on the request's HeaderMap.
    """
    var extra = List[HpackHeader]()
    for i in range(extra_headers.len()):
        var k = extra_headers._keys[i]
        var v = extra_headers._values[i]
        var lk = String(capacity=k.byte_length() + 1)
        var kp = k.unsafe_ptr()
        for j in range(k.byte_length()):
            var c = Int(kp[j])
            if c >= 65 and c <= 90:
                lk += chr(c + 32)
            else:
                lk += chr(c)
        if (
            lk == "connection"
            or lk == "transfer-encoding"
            or lk == "keep-alive"
            or lk == "proxy-connection"
            or lk == "upgrade"
            or lk == "host"
        ):
            continue
        extra.append(HpackHeader(lk^, v))
    if extra_headers.get("User-Agent").byte_length() == 0:
        extra.append(HpackHeader("user-agent", user_agent))
    if (
        auth_header.byte_length() > 0
        and extra_headers.get("Authorization").byte_length() == 0
    ):
        extra.append(HpackHeader("authorization", auth_header))
    return extra^


def _h2_authority(u: Url) -> String:
    """Build the ``:authority`` pseudo-header value (host[:port] for
    non-default ports)."""
    var authority = u.host
    if (u.scheme == "http" and u.port != 80) or (
        u.scheme == "https" and u.port != 443
    ):
        authority = authority + ":" + String(Int(u.port))
    return authority^


def _send_h2_over_tls(
    var stream: TlsStream,
    method: String,
    u: Url,
    extra_headers: HeaderMap,
    body: List[UInt8],
    user_agent: String,
    auth_header: String,
) raises -> Response:
    """Drive a single HTTP/2 request over an already-handshaken TLS
    stream and return the response.

    Used by :meth:`HttpClient._do_request` when the server selected
    ALPN ``h2``. The caller is responsible for owning the
    :class:`TlsStream` -- this helper consumes it (sends GOAWAY +
    closes on the way out) and returns the lowered
    :class:`flare.http.Response`.
    """
    var conn = Http2ClientConnection()
    var extra = _build_h2_request_headers(
        extra_headers, user_agent, auth_header
    )
    var sid = conn.next_stream_id()
    conn.send_request(
        sid,
        method,
        u.scheme,
        _h2_authority(u),
        u.request_target(),
        extra,
        Span[UInt8, _](body),
    )
    var out_bytes = conn.drain()
    if len(out_bytes) > 0:
        stream.write_all(Span[UInt8, _](out_bytes))
    var buf = List[UInt8](capacity=_H2_READ_BUF_SIZE)
    buf.resize(_H2_READ_BUF_SIZE, UInt8(0))
    while not conn.response_ready(sid):
        if conn.goaway_received():
            stream.close()
            raise NetworkError(
                "HttpClient(h2): peer sent GOAWAY before responding to stream "
                + String(sid)
            )
        var n = stream.read(buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
        if n == 0:
            stream.close()
            raise NetworkError(
                "HttpClient(h2): peer closed connection mid-response on stream "
                + String(sid)
            )
        # Mojo 1.0.0b1: name the slice's lifetime via ``buf``
        # itself; ``buf[:n]`` was an anonymous temporary whose
        # storage could be freed before ``feed`` returned.
        conn.feed(Span[UInt8, _](ptr=buf.unsafe_ptr(), length=n))
        var ack_bytes = conn.drain()
        if len(ack_bytes) > 0:
            stream.write_all(Span[UInt8, _](ack_bytes))
    var maybe_err = conn.stream_error(sid)
    if Bool(maybe_err):
        stream.close()
        raise NetworkError(
            "HttpClient(h2): peer sent RST_STREAM (error code "
            + String(maybe_err.value())
            + ") on stream "
            + String(sid)
        )
    var h2_resp = conn.take_response(sid)
    try:
        conn.send_goaway(sid, 0)
        var goaway_bytes = conn.drain()
        if len(goaway_bytes) > 0:
            stream.write_all(Span[UInt8, _](goaway_bytes))
    except:
        pass
    stream.close()
    return _h2_response_to_http(h2_resp^)


def _send_h2_over_tcp(
    var stream: TcpStream,
    method: String,
    u: Url,
    extra_headers: HeaderMap,
    body: List[UInt8],
    user_agent: String,
    auth_header: String,
) raises -> Response:
    """Drive a single HTTP/2 cleartext (h2c) request over a plain
    TCP stream via prior knowledge.

    Mirror of :func:`_send_h2_over_tls`, used when the caller
    constructed :class:`HttpClient` with ``prefer_h2c=True`` and
    targeted an ``http://`` URL. RFC 9113 §3.4: the client sends
    the connection preface immediately (no ``Upgrade`` dance);
    if the server doesn't speak h2, the connection just dies.
    """
    var conn = Http2ClientConnection()
    var extra = _build_h2_request_headers(
        extra_headers, user_agent, auth_header
    )
    var sid = conn.next_stream_id()
    conn.send_request(
        sid,
        method,
        u.scheme,
        _h2_authority(u),
        u.request_target(),
        extra,
        Span[UInt8, _](body),
    )
    var out_bytes = conn.drain()
    if len(out_bytes) > 0:
        stream.write_all(Span[UInt8, _](out_bytes))
    var buf = List[UInt8](capacity=_H2_READ_BUF_SIZE)
    buf.resize(_H2_READ_BUF_SIZE, UInt8(0))
    while not conn.response_ready(sid):
        if conn.goaway_received():
            stream.close()
            raise NetworkError(
                "HttpClient(h2c): peer sent GOAWAY before responding to stream "
                + String(sid)
            )
        var n = stream.read(buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
        if n == 0:
            stream.close()
            raise NetworkError(
                "HttpClient(h2c): peer closed connection mid-response on"
                " stream "
                + String(sid)
            )
        # Mojo 1.0.0b1 Span lifetime: same fix as the h2-over-tls
        # path -- bind to the named ``buf`` rather than the
        # slice temporary.
        conn.feed(Span[UInt8, _](ptr=buf.unsafe_ptr(), length=n))
        var ack_bytes = conn.drain()
        if len(ack_bytes) > 0:
            stream.write_all(Span[UInt8, _](ack_bytes))
    var maybe_err = conn.stream_error(sid)
    if Bool(maybe_err):
        stream.close()
        raise NetworkError(
            "HttpClient(h2c): peer sent RST_STREAM (error code "
            + String(maybe_err.value())
            + ") on stream "
            + String(sid)
        )
    var h2_resp = conn.take_response(sid)
    try:
        conn.send_goaway(sid, 0)
        var goaway_bytes = conn.drain()
        if len(goaway_bytes) > 0:
            stream.write_all(Span[UInt8, _](goaway_bytes))
    except:
        pass
    stream.close()
    return _h2_response_to_http(h2_resp^)


def _send_h2c_via_upgrade(
    var stream: TcpStream,
    method: String,
    u: Url,
    extra_headers: HeaderMap,
    body: List[UInt8],
    user_agent: String,
    auth_header: String,
) raises -> Response:
    """Negotiate HTTP/2 cleartext via the RFC 7540 §3.2 ``Upgrade``
    dance and run the request.

    Wire flow:

    1. Client sends an HTTP/1.1 request decorated with
       ``Connection: Upgrade, HTTP2-Settings``,
       ``Upgrade: h2c``, and
       ``HTTP2-Settings: <base64url(SETTINGS-payload)>``.
    2. The server either:
       a. Accepts: replies ``101 Switching Protocols``
          + ``Connection: Upgrade`` + ``Upgrade: h2c``
          and treats the original request as stream id 1; or
       b. Declines: replies as a plain HTTP/1.1 response.
    3. On 101, the client sends the h2 connection preface
       (``PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n`` + a SETTINGS
       frame) and reads the response on stream id 1 over the same
       TCP fd; the original request body has already been delivered
       on the h1 wire so stream 1 is HALF_CLOSED_LOCAL from the
       client's perspective.
    4. On non-101 the helper parses the h1 response and returns it
       as-is so the caller sees a normal :class:`Response`.

    Used by :meth:`HttpClient._do_request` when the user constructed
    :class:`HttpClient` with ``h2c_upgrade=True`` and targeted an
    ``http://`` URL. Orthogonal to ``prefer_h2c`` (prior-knowledge
    path).
    """
    var h2_cfg = Http2ClientConfig()
    var settings_payload = build_h2c_settings_payload(h2_cfg)
    var settings_b64 = base64url_encode(settings_payload^)
    var wire = method + " " + u.request_target() + " HTTP/1.1\r\n"
    var host_header = u.host
    if u.port != 80:
        host_header = host_header + ":" + String(Int(u.port))
    wire += "Host: " + host_header + "\r\n"
    wire += "User-Agent: " + user_agent + "\r\n"
    wire += "Connection: Upgrade, HTTP2-Settings\r\n"
    wire += "Upgrade: h2c\r\n"
    wire += "HTTP2-Settings: " + settings_b64 + "\r\n"
    wire += "Accept: */*\r\n"
    if auth_header.byte_length() > 0:
        wire += "Authorization: " + auth_header + "\r\n"
    for i in range(extra_headers.len()):
        var k = extra_headers._keys[i]
        var lk = k.lower()
        if (
            lk == "host"
            or lk == "connection"
            or lk == "upgrade"
            or lk == "http2-settings"
        ):
            continue
        # Only skip caller's Authorization when _auth_header is already set
        if lk == "authorization" and auth_header.byte_length() > 0:
            continue
        wire += k + ": " + extra_headers._values[i] + "\r\n"
    if len(body) > 0:
        wire += "Content-Length: " + String(len(body)) + "\r\n"
    wire += "\r\n"

    var wire_bytes = wire.as_bytes()
    stream.write_all(Span[UInt8, _](wire_bytes))
    if len(body) > 0:
        stream.write_all(Span[UInt8, _](body))

    var raw = List[UInt8]()
    var hdr_end = -1
    var buf = List[UInt8](capacity=_H2_READ_BUF_SIZE)
    buf.resize(_H2_READ_BUF_SIZE, UInt8(0))
    while hdr_end < 0:
        var n = stream.read(buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
        if n == 0:
            stream.close()
            raise NetworkError(
                "HttpClient(h2c-upgrade): peer closed connection before"
                " response headers"
            )
        for i in range(n):
            raw.append(buf[i])
        if len(raw) >= 4:
            var k = 0
            while k + 3 < len(raw):
                if (
                    raw[k] == 0x0D
                    and raw[k + 1] == 0x0A
                    and raw[k + 2] == 0x0D
                    and raw[k + 3] == 0x0A
                ):
                    hdr_end = k + 4
                    break
                k += 1

    var status = _parse_status_line(raw)
    if status != 101:
        var rest = raw.copy()
        var body_buf = List[UInt8](capacity=_H2_READ_BUF_SIZE)
        body_buf.resize(_H2_READ_BUF_SIZE, UInt8(0))
        while True:
            var n = stream.read(body_buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
            if n == 0:
                break
            for i in range(n):
                rest.append(body_buf[i])
        stream.close()
        return _parse_http_response(rest)

    var h2_conn = Http2ClientConnection.from_h2c_upgrade(h2_cfg^)
    var preface_bytes = h2_conn.drain()
    if len(preface_bytes) > 0:
        stream.write_all(Span[UInt8, _](preface_bytes))

    if hdr_end < len(raw):
        var leftover = List[UInt8]()
        for i in range(hdr_end, len(raw)):
            leftover.append(raw[i])
        if len(leftover) > 0:
            h2_conn.feed(Span[UInt8, _](leftover))
            var ack_bytes = h2_conn.drain()
            if len(ack_bytes) > 0:
                stream.write_all(Span[UInt8, _](ack_bytes))

    while not h2_conn.response_ready(1):
        if h2_conn.goaway_received():
            stream.close()
            raise NetworkError(
                "HttpClient(h2c-upgrade): peer sent GOAWAY before responding"
                " to stream 1"
            )
        var n = stream.read(buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
        if n == 0:
            stream.close()
            raise NetworkError(
                "HttpClient(h2c-upgrade): peer closed connection mid-response"
                " on stream 1"
            )
        # Mojo 1.0.0b1 stricter destructor scheduling: ``buf[:n]``
        # allocated a temporary ``List`` whose backing storage was
        # destroyed before ``feed`` returned, which the kernel /
        # heap could re-use, doubling the response body on the
        # next ``read`` slice. Construct the ``Span`` directly
        # over ``buf``'s backing storage so the lifetime is the
        # named ``buf`` (which lives across the whole loop), not
        # the slice's anonymous temporary.
        h2_conn.feed(Span[UInt8, _](ptr=buf.unsafe_ptr(), length=n))
        var ack_bytes = h2_conn.drain()
        if len(ack_bytes) > 0:
            stream.write_all(Span[UInt8, _](ack_bytes))

    var maybe_err = h2_conn.stream_error(1)
    if Bool(maybe_err):
        stream.close()
        raise NetworkError(
            "HttpClient(h2c-upgrade): peer sent RST_STREAM (error code "
            + String(maybe_err.value())
            + ") on stream 1"
        )
    var h2_resp = h2_conn.take_response(1)
    try:
        h2_conn.send_goaway(1, 0)
        var goaway_bytes = h2_conn.drain()
        if len(goaway_bytes) > 0:
            stream.write_all(Span[UInt8, _](goaway_bytes))
    except:
        pass
    stream.close()
    return _h2_response_to_http(h2_resp^)


def _parse_status_line(raw: List[UInt8]) raises -> Int:
    """Extract the status code from the leading status-line of a
    raw HTTP/1.1 response buffer.

    Returns just the numeric status (e.g. ``101`` or ``200``); the
    caller decides whether to switch protocols or fall through to a
    full h1 response parse. Used only by the h2c-via-Upgrade
    helper -- the regular response parser is :func:`_parse_http_response`.
    """
    var line_end = 0
    while line_end + 1 < len(raw):
        if raw[line_end] == 0x0D and raw[line_end + 1] == 0x0A:
            break
        line_end += 1
    if line_end + 1 >= len(raw):
        raise NetworkError("HttpClient(h2c-upgrade): no CRLF after status-line")
    var sl = String("")
    for i in range(line_end):
        sl += chr(Int(raw[i]))
    var sp1 = sl.find(" ")
    if sp1 < 0:
        raise NetworkError("HttpClient(h2c-upgrade): malformed status-line")
    var sp2 = sl.find(" ", start=sp1 + 1)
    var code_end = sp2
    if code_end < 0:
        code_end = sl.byte_length()
    var code_str = String("")
    var slp = sl.unsafe_ptr()
    for i in range(sp1 + 1, code_end):
        code_str += chr(Int(slp[i]))
    try:
        return Int(code_str)
    except:
        raise NetworkError(
            "HttpClient(h2c-upgrade): non-numeric status code in status-line"
        )
