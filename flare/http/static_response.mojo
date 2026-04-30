"""Pre-encoded literal HTTP responses for the fastest possible fast path.

Handlers that always return the same bytes (health checks, TFB
plaintext, fixed "hello" endpoints) pay for no reason on every request:

- A ``Response`` struct is constructed.
- Headers are looked up / appended.
- Status line, header block, and body are re-serialised on every call.

``StaticResponse`` does all of that once at module-initialisation time
and hands the reactor a frozen buffer. ``HttpServer.serve_static[resp]``
then skips the parser's handler-dispatch step entirely and ``memcpy``s
the buffer straight into the per-connection write queue.

## Shape

```mojo
from flare.http import StaticResponse, precompute_response

var HELLO = precompute_response(
    status=200,
    content_type="text/plain; charset=utf-8",
    body="Hello, World!",
)
# HELLO holds two wire-form buffers:
# keepalive — with "Connection: keep-alive"
# close — with "Connection: close"
# The reactor picks the right one per request based on Connection:.
```

## Semantics

Every request still gets parsed far enough to find the ``\r\n\r\n``
header terminator and any declared ``Content-Length`` (so the server
can skip the body bytes before starting the next pipelined request on
a keep-alive connection). The parser does **not** build a ``Request``
struct and never calls a handler.

HTTP/1.0 close semantics, ``Connection: close``, and the
``max_keepalive_requests`` cap are all still honoured — the only
saving is that we don't re-build identical bytes per request.

The pre-encoded buffer is a plain ``List[UInt8]`` rather than an
``InlineArray`` so the reactor can ``memcpy`` from it at the same cost
as a ``stack_allocation`` source.
"""

from std.memory import memcpy

from .headers import HeaderMap


struct StaticResponse(Copyable, Movable):
    """A pair of pre-encoded HTTP/1.1 response buffers.

    ``keepalive_bytes`` is emitted when the connection will stay open
    after this response; ``close_bytes`` is emitted when the server has
    decided to close after this write (HTTP/1.0 without ``keep-alive``,
    explicit ``Connection: close`` request, ``max_keepalive_requests``
    cap reached, or server shutdown).

    Both buffers end at the final body byte; the reactor concatenates
    nothing — it copies the buffer verbatim into the socket write queue.
    """

    var keepalive_bytes: List[UInt8]
    var close_bytes: List[UInt8]
    var body_length: Int
    """Exposed so the config-gate logic (e.g. ``Content-Length >
    max_body_size``) can re-check the precomputed size if it ever needs
    to — the reactor only reads ``keepalive_bytes`` / ``close_bytes``."""

    def __init__(
        out self,
        var keepalive_bytes: List[UInt8],
        var close_bytes: List[UInt8],
        body_length: Int,
    ):
        self.keepalive_bytes = keepalive_bytes^
        self.close_bytes = close_bytes^
        self.body_length = body_length

    def copy(self) -> Self:
        return Self(
            keepalive_bytes=self.keepalive_bytes.copy(),
            close_bytes=self.close_bytes.copy(),
            body_length=self.body_length,
        )


@always_inline
def _append_str(mut buf: List[UInt8], s: String):
    """Append all bytes of ``s`` to ``buf`` via bulk memcpy."""
    var n = s.byte_length()
    if n == 0:
        return
    var old = len(buf)
    buf.resize(old + n, UInt8(0))
    memcpy(dest=buf.unsafe_ptr() + old, src=s.unsafe_ptr(), count=n)


def _status_reason(code: Int) -> String:
    """Canonical reason phrase for well-known codes; empty string fallback."""
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
    if code == 400:
        return "Bad Request"
    if code == 401:
        return "Unauthorized"
    if code == 403:
        return "Forbidden"
    if code == 404:
        return "Not Found"
    if code == 500:
        return "Internal Server Error"
    if code == 503:
        return "Service Unavailable"
    return ""


def _encode(
    status: Int,
    reason: String,
    content_type: String,
    body: String,
    keep_alive: Bool,
) -> List[UInt8]:
    """Build the full HTTP/1.1 wire form for one (status, headers, body)
    triple in a single bulk-allocated ``List[UInt8]``.
    """
    var body_n = body.byte_length()
    var estimated = 128 + content_type.byte_length() + body_n
    var buf = List[UInt8](capacity=estimated)

    _append_str(buf, "HTTP/1.1 ")
    _append_str(buf, String(status))
    _append_str(buf, " ")
    _append_str(buf, reason)
    _append_str(buf, "\r\n")

    _append_str(buf, "Content-Type: ")
    _append_str(buf, content_type)
    _append_str(buf, "\r\n")

    _append_str(buf, "Content-Length: ")
    _append_str(buf, String(body_n))
    _append_str(buf, "\r\n")

    if keep_alive:
        _append_str(buf, "Connection: keep-alive\r\n")
    else:
        _append_str(buf, "Connection: close\r\n")

    _append_str(buf, "\r\n")

    # Body.
    if body_n > 0:
        var old = len(buf)
        buf.resize(old + body_n, UInt8(0))
        memcpy(
            dest=buf.unsafe_ptr() + old,
            src=body.unsafe_ptr(),
            count=body_n,
        )
    return buf^


def precompute_response(
    status: Int,
    content_type: String,
    body: String,
) -> StaticResponse:
    """Build a pre-encoded static response for a known ``(status, body)``.

    Returns a ``StaticResponse`` holding both the ``Connection:
    keep-alive`` and ``Connection: close`` wire forms. The reactor
    picks one per request based on the parsed ``Connection:`` header.

    Args:
        status: HTTP status code (200, 204, 404, …). Reason phrase
            is looked up from the built-in table; callers who need a
            custom reason should pass their own ``StaticResponse``
            instance.
        content_type: Full ``Content-Type`` header value
            (e.g. ``"text/plain; charset=utf-8"``).
        body: Response body (UTF-8 string). ``Content-Length``
            is derived from its byte length.

    Returns:
        A ``StaticResponse`` ready to hand to
        ``HttpServer.serve_static[resp]()``.
    """
    var reason = _status_reason(status)
    var ka = _encode(status, reason, content_type, body, keep_alive=True)
    var cl = _encode(status, reason, content_type, body, keep_alive=False)
    return StaticResponse(
        keepalive_bytes=ka^,
        close_bytes=cl^,
        body_length=body.byte_length(),
    )
