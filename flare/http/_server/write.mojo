"""HTTP/1.1 response serialization extracted from ``flare.http.server``.

``_write_response_buffered`` (one-buffer-one-write serializer), the
allocation-free ``itoa`` / byte-append primitives it relies on, the
status-reason table, and the legacy stream writer. ``flare.http.server``
re-exports every name here (including the ``_ascii_lower`` alias the
reactor and gRPC adapter import from ``flare.http.server``).
"""

from std.memory import memcpy, stack_allocation

from ..response import Response
from ..headers import _eq_icase
from ...tcp import TcpStream

# ``_ascii_lower`` lives in ``flare.http.proto.ascii`` (canonical
# sans-I/O helper); aliased here under the original private name and
# re-exported from ``flare.http.server`` so every existing call site --
# the reactor, the gRPC adapter, and the tests -- keeps working without
# an audit pass.
from ..proto.ascii import ascii_lower as _ascii_lower


def _write_response_buffered(
    mut stream: TcpStream, resp: Response, keep_alive: Bool
) raises:
    """Serialise ``resp`` into a single buffer and write it in one call.

    Args:
        stream: Open ``TcpStream`` for the client connection.
        resp: The response to send.
        keep_alive: If True, sends ``Connection: keep-alive``; otherwise ``close``.

    Raises:
        NetworkError: On I/O failure.
    """
    var reason = resp.reason
    if reason.byte_length() == 0:
        reason = _status_reason(resp.status)

    var body_len = len(resp.body)

    var estimated = 64 + body_len
    for i in range(resp.headers.len()):
        estimated += (
            resp.headers._keys[i].byte_length()
            + resp.headers._values[i].byte_length()
            + 4
        )
    var wire = List[UInt8](capacity=estimated)

    _append_str(wire, "HTTP/1.1 ")
    _append_str(wire, String(resp.status))
    _append_str(wire, " ")
    _append_str(wire, reason)
    _append_str(wire, "\r\n")

    for i in range(resp.headers.len()):
        var k = resp.headers._keys[i]
        var kl = _ascii_lower(k)
        if kl == "content-length" or kl == "connection":
            continue
        _append_str(wire, k)
        _append_str(wire, ": ")
        _append_str(wire, resp.headers._values[i])
        _append_str(wire, "\r\n")

    _append_str(wire, "Content-Length: ")
    _append_str(wire, String(body_len))
    _append_str(wire, "\r\n")

    if keep_alive:
        _append_str(wire, "Connection: keep-alive\r\n")
    else:
        _append_str(wire, "Connection: close\r\n")

    _append_str(wire, "\r\n")

    for i in range(body_len):
        wire.append(resp.body[i])

    stream.write_all(Span[UInt8, _](wire))


@always_inline
def _append_str(mut buf: List[UInt8], s: String):
    """Append all bytes of ``s`` to ``buf``.

    Bulk extend via resize + pointer copy. The naive per-byte
    ``buf.append(...)`` loop was called O(100) times per serialized
    response (status line + each header + body) which added measurable
    cost at 100K+ req/s.
    """
    var n = s.byte_length()
    if n == 0:
        return
    var old_len = len(buf)
    buf.resize(old_len + n, UInt8(0))
    memcpy(dest=buf.unsafe_ptr() + old_len, src=s.unsafe_ptr(), count=n)


@always_inline
def _append_int(mut buf: List[UInt8], var n: Int):
    """Append the ASCII decimal form of ``n`` to ``buf``.

    Hot path on every serialised response (status line + Content-Length).
    Stack-buffer ``itoa`` keeps it allocation-free; the previous
    ``String(int)`` path forced a per-call heap allocation just to throw
    the bytes back into the wire buffer.
    """
    if n == 0:
        buf.append(UInt8(48))  # '0'
        return
    var negative = n < 0
    if negative:
        n = -n
    # 20 digits is enough for Int64 (-9223372036854775808 → 19 digits + sign).
    var tmp = stack_allocation[20, UInt8]()
    var i = 0
    while n > 0:
        tmp[i] = UInt8(48 + (n % 10))
        n = n // 10
        i += 1
    var old_len = len(buf)
    var sign = 1 if negative else 0
    buf.resize(old_len + sign + i, UInt8(0))
    var p = buf.unsafe_ptr() + old_len
    if negative:
        p[0] = UInt8(45)  # '-'
        p += 1
    # ``tmp`` holds the digits in reverse order; flip them on the way out.
    for k in range(i):
        p[k] = tmp[i - 1 - k]


def _status_reason(code: Int) -> String:
    """Return the canonical reason phrase for a known HTTP status code."""
    if code == 200:
        return "OK"
    if code == 201:
        return "Created"
    if code == 202:
        return "Accepted"
    if code == 204:
        return "No Content"
    if code == 301:
        return "Moved Permanently"
    if code == 302:
        return "Found"
    if code == 304:
        return "Not Modified"
    if code == 307:
        return "Temporary Redirect"
    if code == 308:
        return "Permanent Redirect"
    if code == 400:
        return "Bad Request"
    if code == 401:
        return "Unauthorized"
    if code == 403:
        return "Forbidden"
    if code == 404:
        return "Not Found"
    if code == 405:
        return "Method Not Allowed"
    if code == 408:
        return "Request Timeout"
    if code == 409:
        return "Conflict"
    if code == 413:
        return "Content Too Large"
    if code == 414:
        return "URI Too Long"
    if code == 422:
        return "Unprocessable Entity"
    if code == 500:
        return "Internal Server Error"
    if code == 501:
        return "Not Implemented"
    if code == 502:
        return "Bad Gateway"
    if code == 503:
        return "Service Unavailable"
    if code == 504:
        return "Gateway Timeout"
    return "Unknown"


def _write_response(mut stream: TcpStream, resp: Response) raises:
    """Legacy response writer. Delegates to buffered version with Connection: close.
    """
    _write_response_buffered(stream, resp, keep_alive=False)


def frame_h1_stream_head_into(
    mut out: List[UInt8], resp: Response, keep_alive: Bool
):
    """Append the HTTP/1.1 head (status line + headers + blank line) of a
    *streaming* response to ``out``.

    This is the h1 member of the per-wire streaming-response head framers:
    the reusable framing adapter behind :meth:`StreamConn.send_response`
    and any HTTPS front that streams over :class:`TlsConnHandle` (the head
    bytes are transport-agnostic -- write them via ``send`` on plaintext or
    ``SSL_write`` on TLS). The sibling wires frame their heads through their
    own codecs: **h2** via HPACK (``encode_headers`` in the h2 server) and
    **h3** via QPACK (``encode_response_headers`` in the h3 response
    writer); those are frames on a multiplexed connection, not raw bytes,
    so they live with their drivers rather than here.

    Framing rules (streaming-specific, distinct from the buffered
    serialiser):

    - Any inbound ``Connection`` header is dropped; ``Connection`` is set
      solely from ``keep_alive``.
    - ``Content-Length`` is emitted from ``len(resp.body)`` **only** when
      the response declares neither ``Transfer-Encoding`` nor
      ``Content-Length`` -- a chunked / SSE front sets ``Transfer-Encoding``
      itself and streams the body via ``send``, so this must not force a
      length onto it.

    The fixed body (if any) is the caller's to append after the head.
    """
    var reason = resp.reason
    if reason.byte_length() == 0:
        reason = _status_reason(resp.status)
    _append_str(out, "HTTP/1.1 ")
    _append_str(out, String(resp.status))
    _append_str(out, " ")
    _append_str(out, reason)
    _append_str(out, "\r\n")
    for i in range(resp.headers.len()):
        var k = resp.headers._keys[i]
        if _eq_icase(k, "connection"):
            continue
        _append_str(out, k)
        _append_str(out, ": ")
        _append_str(out, resp.headers._values[i])
        _append_str(out, "\r\n")
    if not resp.headers.contains(
        "transfer-encoding"
    ) and not resp.headers.contains("content-length"):
        _append_str(out, "Content-Length: ")
        _append_str(out, String(len(resp.body)))
        _append_str(out, "\r\n")
    if keep_alive:
        _append_str(out, "Connection: keep-alive\r\n")
    else:
        _append_str(out, "Connection: close\r\n")
    _append_str(out, "\r\n")
