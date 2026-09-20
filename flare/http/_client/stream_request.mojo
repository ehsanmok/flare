"""Request-head preparation shared by every streaming wire.

One function decides what a streaming request's headers look like, so
HTTP/1.1, HTTP/2 and HTTP/3 cannot drift apart on which fields are
stripped, which are added, and which are refused outright.

Three rules, and the reasons they are rules:

- **Framing fields are stripped.** ``Content-Length``,
  ``Transfer-Encoding``, ``Connection``, ``Upgrade``, ``TE``,
  ``Trailer``, ``Proxy-Connection`` and ``Keep-Alive`` describe how
  *this* hop frames the message. On h2 and h3 they are forbidden
  outright (RFC 9113 sec 8.2.2); on h1 the caller does not get to
  hand-roll them because the writer owns framing.
- **``Accept-Encoding: identity`` by default.** A streaming download
  that arrives gzipped would have to be inflated before the caller sees
  a byte, which defeats the point. A caller who wants compression can
  set the header explicitly and decode it themselves.
- **Anything that could smuggle is refused, not sanitised.** A field
  name that is not a token, a value carrying CR, LF or NUL, a CONNECT
  method, an ``Expect`` header: these raise rather than being quietly
  fixed up, because silently rewriting a request is how two parsers end
  up disagreeing.
"""

from ..headers import HeaderMap
from ..url import Url


def _is_stripped(name: String) -> Bool:
    """Whether ``name`` is a field the caller does not get to set.

    Framing belongs to the writer, and ``host`` is derived from the URL
    -- a mismatch between it and the authority is a routing ambiguity.
    """
    return (
        name == "content-length"
        or name == "transfer-encoding"
        or name == "connection"
        or name == "upgrade"
        or name == "te"
        or name == "trailer"
        or name == "proxy-connection"
        or name == "keep-alive"
        or name == "host"
    )


def _is_token(name: String) -> Bool:
    """Whether ``name`` is an RFC 9110 sec 5.6.2 token."""
    if name.byte_length() == 0:
        return False
    for b in name.as_bytes():
        var c = Int(b)
        var alnum = (
            (c >= 48 and c <= 57)
            or (c >= 65 and c <= 90)
            or (c >= 97 and c <= 122)
        )
        var sep = (
            c == 33
            or (c >= 35 and c <= 39)
            or c == 42
            or c == 43
            or c == 45
            or c == 46
            or c == 94
            or c == 95
            or c == 96
            or c == 124
            or c == 126
        )
        if not (alnum or sep):
            return False
    return True


def _is_safe_value(value: String) -> Bool:
    """Whether ``value`` is free of CR, LF and NUL."""
    for b in value.as_bytes():
        var c = Int(b)
        if c == 13 or c == 10 or c == 0:
            return False
    return True


def prepare_stream_headers(
    method: String,
    u: Url,
    extra: HeaderMap,
    user_agent: String,
    body_size: Int = -1,
) raises -> HeaderMap:
    """Build the header set for a streaming request on any wire.

    Args:
        method: Request method, uppercased by the caller.
        u: Parsed request URL; supplies the authority.
        extra: Caller-supplied headers. Framing fields are dropped and
            unsafe ones are refused.
        user_agent: Value for ``user-agent`` when the caller set none.
        body_size: Known request-body length, or ``-1`` when the body is
            streamed with no length known up front.

    Returns:
        The headers to send, lowercased, with no framing fields.

    Raises:
        Error: On a CONNECT method, an ``Expect`` header, a field name
            that is not a token, or a value containing CR, LF or NUL.
    """
    var m = method.upper()
    if m == "CONNECT":
        raise Error(
            "streaming request: CONNECT is a tunnel, not a request with a"
            " body; use the proxy support instead"
        )

    var out = HeaderMap()
    var saw_ua = False
    var saw_accept_encoding = False

    for i in range(extra.len()):
        var raw = extra._keys[i]
        var value = extra._values[i]
        var name = raw.lower()
        if not _is_token(name):
            raise Error("streaming request: header name is not a token: " + raw)
        if name == "expect":
            raise Error(
                "streaming request: Expect is not supported; the writer"
                " does not implement 100-continue"
            )
        if _is_stripped(name):
            continue
        if not _is_safe_value(value):
            raise Error(
                "streaming request: header value contains CR, LF or NUL: "
                + name
            )
        out.append(name, value)
        if name == "user-agent":
            saw_ua = True
        if name == "accept-encoding":
            saw_accept_encoding = True

    if not saw_ua and user_agent != "":
        out.set("user-agent", user_agent)
    if not saw_accept_encoding:
        # A streamed body arrives decoded, chunk by chunk. Negotiating a
        # content coding would mean buffering the whole thing to inflate
        # it, which is the opposite of what the caller asked for.
        out.set("accept-encoding", "identity")
    if body_size >= 0:
        out.set("content-length", String(body_size))
    return out^
