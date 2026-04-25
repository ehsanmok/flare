"""Streaming response serializer (v0.5.0 follow-up / Track 4
part 2 / C5).

Renders a ``StreamingResponse[B: Body]`` to wire bytes per
RFC 7230 §3 (status line + headers) + RFC 7230 §4.1 (chunked
transfer-coding) when ``B.content_length()`` is unknown, or
plain Content-Length framing when it's known.

The reactor's view-aware write loop (a focused follow-up) calls
this serializer per writable edge to pull-and-write one chunk
at a time. Callers that don't need the streaming benefit
(every existing handler that returns a v0.4.x ``Response``)
keep the buffer-then-send path through the existing
``_serialize_response`` in ``flare/http/_server_reactor_impl``.

Why a standalone serializer rather than a parallel reactor:

C3's experience showed that adding a parallel reactor entry
parametric over a trait-method-with-origin is currently slow to
specialise in Mojo. The streaming serializer here is a plain
function — no parametric trait dispatch, no per-handler
specialization explosion — so it compiles fast and is easy to
test independently. The reactor adoption that calls this
serializer is a small follow-up commit (~30 lines of glue) that
the user can review separately once Mojo's specialization
slowness is resolved or the team commits to the slower compile
times.

Wire-framing semantics:

- ``body.content_length()`` returns ``Some(n)``:
  - Header line: ``Content-Length: n\\r\\n``.
  - Body bytes: emit each chunk inline until ``next_chunk``
    returns None. Total emitted bytes equal n by contract.

- ``body.content_length()`` returns ``None``:
  - Header line: ``Transfer-Encoding: chunked\\r\\n``.
  - Body bytes: per chunk, emit ``hex_length\\r\\n`` + chunk +
    ``\\r\\n``. Final terminator: ``0\\r\\n\\r\\n``.

The serializer is cancel-aware: if ``cancel.cancelled()`` flips
between chunks, the write loop emits the final chunked
terminator and returns — the connection closes cleanly without
breaking the framing contract. Callers that need to abort
mid-chunk should close the underlying socket; the framing
guarantee covers cooperative cancel only.
"""

from std.collections import Optional

from .body import Body
from .cancel import Cancel
from .streaming_response import StreamingResponse


# ── Status reason resolution ───────────────────────────────────────────────


@always_inline
def _default_reason(status: Int) -> String:
    """Fallback reason phrase for a status code when the response
    didn't supply one. Conservative subset; unknown codes get a
    generic class-level label."""
    if status == 200:
        return "OK"
    if status == 201:
        return "Created"
    if status == 204:
        return "No Content"
    if status == 301:
        return "Moved Permanently"
    if status == 302:
        return "Found"
    if status == 304:
        return "Not Modified"
    if status == 307:
        return "Temporary Redirect"
    if status == 308:
        return "Permanent Redirect"
    if status == 400:
        return "Bad Request"
    if status == 401:
        return "Unauthorized"
    if status == 403:
        return "Forbidden"
    if status == 404:
        return "Not Found"
    if status == 405:
        return "Method Not Allowed"
    if status == 408:
        return "Request Timeout"
    if status == 413:
        return "Content Too Large"
    if status == 414:
        return "URI Too Long"
    if status == 431:
        return "Request Header Fields Too Large"
    if status == 500:
        return "Internal Server Error"
    if status == 502:
        return "Bad Gateway"
    if status == 503:
        return "Service Unavailable"
    if status == 504:
        return "Gateway Timeout"
    if status >= 200 and status < 300:
        return "OK"
    if status >= 300 and status < 400:
        return "Redirect"
    if status >= 400 and status < 500:
        return "Client Error"
    return "Server Error"


# ── Hex helper ─────────────────────────────────────────────────────────────


@always_inline
def _hex_digit(d: Int) -> String:
    """Single lowercase hex digit for ``d`` in ``0..15``."""
    if d < 10:
        return chr(ord("0") + d)
    return chr(ord("a") + (d - 10))


@always_inline
def _hex_lower(n: Int) -> String:
    """Lowercase hex of ``n`` (no leading ``0x``). Used for
    chunk-size lines per RFC 7230 §4.1.

    n must be non-negative.
    """
    if n == 0:
        return "0"
    var out = String("")
    var v = n
    while v > 0:
        var d = v & 0xF
        out = _hex_digit(d) + out
        v = v >> 4
    return out^


# ── Header writer ──────────────────────────────────────────────────────────


def _write_status_line(
    mut wire: List[UInt8],
    version: String,
    status: Int,
    reason: String,
):
    """Emit ``HTTP/1.1 <status> <reason>\\r\\n`` into ``wire``."""
    var ver = version if version.byte_length() > 0 else "HTTP/1.1"
    var reason_str = reason if reason.byte_length() > 0 else _default_reason(
        status
    )
    var line = (
        ver
        + " "
        + String(status)
        + " "
        + reason_str
        + "\r\n"
    )
    for b in line.as_bytes():
        wire.append(b)


def _write_header_line(
    mut wire: List[UInt8], name: String, value: String
):
    """Emit ``Name: Value\\r\\n`` into ``wire``."""
    var line = name + ": " + value + "\r\n"
    for b in line.as_bytes():
        wire.append(b)


# ── Public entry: serialize a streaming response ──────────────────────────


def serialize_streaming_response[
    B: Body
](
    var resp: StreamingResponse[B],
    cancel: Cancel,
    keep_alive: Bool = True,
) raises -> List[UInt8]:
    """Render ``resp`` to wire bytes — status line + headers +
    body (Content-Length or chunked framing).

    Args:
        resp:       Streaming response with a ``Body`` impl.
                    Ownership transferred; the body is consumed
                    chunk by chunk.
        cancel:     Per-request cancel token. The body's
                    ``next_chunk(cancel)`` polls this; flipping
                    it mid-stream stops chunk emission cleanly
                    (chunked framing's terminator is still
                    written so the framing contract holds).
        keep_alive: When ``True``, the response carries
                    ``Connection: keep-alive``; when ``False``,
                    ``Connection: close``. The reactor sets this
                    based on the request's connection
                    disposition.

    Returns:
        The wire bytes ready for ``send`` over the connection.

    Raises:
        Error: Any error from ``body.next_chunk`` propagates.
    """
    var wire = List[UInt8]()

    # Status line.
    _write_status_line(wire, resp.version, resp.status, resp.reason)

    # Body framing decision: known length -> Content-Length;
    # unknown -> Transfer-Encoding: chunked.
    var content_length_opt = resp.body.content_length()
    var is_chunked = not content_length_opt

    # User-supplied headers (skip Content-Length and
    # Transfer-Encoding — we set them ourselves). HeaderMap
    # stores keys / values as parallel Lists; iterate by index.
    for i in range(len(resp.headers._keys)):
        var k = resp.headers._keys[i]
        if (
            k == "Content-Length"
            or k == "content-length"
            or k == "Transfer-Encoding"
            or k == "transfer-encoding"
        ):
            continue
        _write_header_line(wire, k, resp.headers._values[i])

    # Framing header.
    if is_chunked:
        _write_header_line(wire, "Transfer-Encoding", "chunked")
    else:
        _write_header_line(
            wire, "Content-Length", String(content_length_opt.value())
        )

    # Connection disposition.
    if keep_alive:
        _write_header_line(wire, "Connection", "keep-alive")
    else:
        _write_header_line(wire, "Connection", "close")

    # End-of-headers.
    wire.append(UInt8(13))  # CR
    wire.append(UInt8(10))  # LF

    # Body — pull chunks until ``next_chunk`` returns None or
    # cancel flips. Chunk framing per RFC 7230 §4.1.
    while True:
        if cancel.cancelled():
            break
        var chunk_opt = resp.body.next_chunk(cancel)
        if not chunk_opt:
            break
        var chunk = chunk_opt.value().copy()
        if is_chunked:
            # ``hex_length\r\n``
            var size_line = _hex_lower(len(chunk)) + "\r\n"
            for b in size_line.as_bytes():
                wire.append(b)
            # chunk bytes
            for b in chunk:
                wire.append(b)
            # CRLF
            wire.append(UInt8(13))
            wire.append(UInt8(10))
        else:
            # Inline framing — just the bytes.
            for b in chunk:
                wire.append(b)

    # Chunked terminator: ``0\r\n\r\n``.
    if is_chunked:
        wire.append(UInt8(ord("0")))
        wire.append(UInt8(13))
        wire.append(UInt8(10))
        wire.append(UInt8(13))
        wire.append(UInt8(10))

    return wire^
