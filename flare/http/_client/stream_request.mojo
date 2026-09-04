"""Request preparation and HTTP/1 upgrade for exclusive streaming exchanges."""

from ..headers import HeaderMap
from ..url import Url
from ...crypto.hmac import base64url_encode
from ...http2.client import (
    Http2ClientConfig,
    Http2ClientConnection,
    build_h2c_settings_payload,
)
from ...qpack import QpackHeader
from .download import HttpDownload, _find_crlf2
from .h2_transport import _H2Transport
from .h2_stream import Http2Download
from .stream_response import HttpStreamResponse
from .h2_send import _h2_authority


def _valid_token(value: String) -> Bool:
    if value.byte_length() == 0:
        return False
    var punctuation = String("!#$%&'*+-.^_`|~")
    for b in value.as_bytes():
        var n = Int(b)
        if (48 <= n <= 57) or (65 <= n <= 90) or (97 <= n <= 122):
            continue
        if punctuation.find(chr(n)) < 0:
            return False
    return True


def prepare_stream_headers(
    supplied: HeaderMap,
    body_size: Int,
    user_agent: String,
    auth: String,
) raises -> HeaderMap:
    """Normalize generated fields once, identically on all three wires.

    A negative body size denotes an unknown-length upload. Caller framing is
    never forwarded; the selected wire driver generates framing itself.
    """
    var headers = supplied.copy()
    var nominated = headers.get_all("Connection")
    for value in nominated:
        for token in value.split(","):
            _ = headers.remove(String(token.strip()))
    for name in [
        "Host",
        "Connection",
        "Content-Length",
        "Transfer-Encoding",
        "Keep-Alive",
        "Proxy-Connection",
        "Upgrade",
        "HTTP2-Settings",
    ]:
        _ = headers.remove(name)
    if headers.contains("Expect"):
        raise Error(
            "HTTP streaming: Expect/100-continue negotiation is not supported"
        )
    if not headers.contains("User-Agent"):
        headers.set("User-Agent", user_agent)
    if not headers.contains("Accept"):
        headers.set("Accept", "*/*")
    if not headers.contains("Accept-Encoding"):
        headers.set("Accept-Encoding", "identity")
    if auth.byte_length() > 0:
        _ = headers.remove("Authorization")
        headers.set("Authorization", auth)
    if body_size >= 0:
        headers.set("Content-Length", String(body_size))
    if headers.contains("TE"):
        var te = headers.get("TE").lower()
        _ = headers.remove("TE")
        if te == "trailers":
            headers.set("TE", "trailers")
    for i in range(headers.len()):
        var key = headers._keys[i]
        var value = headers._values[i]
        if (
            not _valid_token(key)
            or value.find("\r") >= 0
            or value.find("\n") >= 0
        ):
            raise Error("HTTP streaming: invalid request header")
    return headers^


def stream_h1_head(
    method: String,
    u: Url,
    headers: HeaderMap,
    upload: Bool = False,
    upgrade: Bool = False,
) raises -> String:
    if not _valid_token(method) or method.upper() == "CONNECT":
        raise Error("HTTP streaming: unsupported request method")
    var target = u.request_target()
    for b in target.as_bytes():
        if b <= 32 or b == 127:
            raise Error("HTTP streaming: invalid request target")
    var wire = (
        method
        + " "
        + u.request_target()
        + " HTTP/1.1\r\nHost: "
        + _h2_authority(u)
        + "\r\n"
    )
    for i in range(headers.len()):
        wire += headers._keys[i] + ": " + headers._values[i] + "\r\n"
    if upload:
        wire += "Transfer-Encoding: chunked\r\n"
    if upgrade:
        var cfg = Http2ClientConfig()
        var settings = build_h2c_settings_payload(cfg)
        wire += (
            "Connection: Upgrade, HTTP2-Settings\r\nUpgrade:"
            " h2c\r\nHTTP2-Settings: "
            + base64url_encode(settings^)
            + "\r\n"
        )
    else:
        wire += "Connection: close\r\n"
    return wire + "\r\n"


def stream_qpack_headers(headers: HeaderMap) -> List[QpackHeader]:
    var fields = List[QpackHeader]()
    for i in range(headers.len()):
        var key = headers._keys[i].lower()
        if key == "te" and headers._values[i].lower() != "trailers":
            continue
        fields.append(QpackHeader(key^, headers._values[i]))
    return fields^


def finish_stream_h1(
    var transport: _H2Transport, method: String, upgrade: Bool
) raises -> HttpStreamResponse:
    if not upgrade:
        return HttpStreamResponse(
            HttpDownload[_H2Transport](transport^, method)
        )
    var raw = List[UInt8]()
    var scratch = List[UInt8]()
    scratch.resize(16384, 0)
    var end = -1
    var informational_bytes = 0
    while True:
        end = _find_crlf2(raw)
        while end < 0:
            if informational_bytes + len(raw) >= 65536:
                raise Error("HTTP streaming: upgrade response head above limit")
            var n = transport.read(scratch.unsafe_ptr(), len(scratch))
            if n == 0:
                raise Error("HTTP streaming: EOF during upgrade")
            for i in range(n):
                raw.append(scratch[i])
            end = _find_crlf2(raw)
        if informational_bytes + end + 4 > 65536:
            raise Error("HTTP streaming: upgrade response head above limit")
        var head = String(unsafe_from_utf8=Span(raw)[:end])
        # Informational responses may precede the upgrade decision.
        if head.startswith("HTTP/1.1 1") and not head.startswith(
            "HTTP/1.1 101 "
        ):
            informational_bytes += end + 4
            var rest = List[UInt8](Span(raw)[end + 4 :])
            raw = rest^
            continue
        break
    var head = String(unsafe_from_utf8=Span(raw)[:end])
    if not head.startswith("HTTP/1.1 101 "):
        return HttpStreamResponse(
            HttpDownload[_H2Transport](transport^, method, initial=raw^)
        )
    var parsed = head.lower()
    if parsed.find("upgrade: h2c") < 0:
        raise Error("HTTP streaming: invalid h2c upgrade response")
    var conn = Http2ClientConnection.from_h2c_upgrade(Http2ClientConfig())
    var s = conn.conn.streams[1].copy()
    s.response_body_allowed = method.upper() != "HEAD"
    conn.conn.streams[1] = s^
    conn.enable_response_streaming(1)
    if end + 4 < len(raw):
        conn.feed(Span(raw)[end + 4 :])
    return HttpStreamResponse(Http2Download(transport^, conn^, 1))
