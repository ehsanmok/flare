# PLATFORM: any
"""H1-04: with allow_lf_only_line_endings the reactor and the parser split
header lines differently, so a Transfer-Encoding line after a bare LF is
invisible to the reactor (request smuggling / desync).

Lean: Flare.Bugs.H1_04.counterexample (counterexample) and
Flare.Bugs.H1_04.fixed_agrees (fix meets spec).
flare/http/proto/chunked.mojo:127-153 (request_te_framing splits lines on
CRLF only) vs flare/http/_server/parse_util.mojo:165-208 (the lenient line
reader splits on LF) @59bda50, both fed the same bytes by
flare/http/_reactor/conn_handle.mojo:622-654 and 807-816.

Spec (RFC 9112 sec 2.2, sec 6.3): a recipient that accepts a bare LF as a
line terminator must do so for framing as well as for parsing; the framer
and the parser must agree on which header lines exist.

Expected: "Host: a\\nTransfer-Encoding: chunked\\r\\n" is two header lines
for both, so the reactor frames the body as chunked.
Actual: request_te_framing sees one line "Host: a\\nTransfer-Encoding:
chunked" and returns TE_ABSENT, the reactor frames the request at the end
of the head, while the parser accepts it with Transfer-Encoding: chunked.
The chunked body is then parsed as the next request.

Minimal fix: request_te_framing ends a header line at LF (dropping a
preceding CR), the way the lenient parser does; the strict parser rejects
bare LF anyway.
"""

from flare.http.proto.chunked import request_te_framing, TE_ABSENT, TE_CHUNKED
from flare.http._scan import scan_content_length, find_crlfcrlf
from flare.http._server.parse import _parse_http_request_bytes
from flare.http.proto.h1_leniency import H1LeniencyConfig


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def main() raises:
    var req = _bytes(
        "POST /upload HTTP/1.1\r\nHost: a\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n0\r\n\r\n"
    )
    var leniency = H1LeniencyConfig(allow_lf_only_line_endings=True)
    var hend = find_crlfcrlf(req, 0)
    var te = request_te_framing(
        Span[UInt8, _](req), hend, leniency.allow_te_chunked_when_cl_present
    )
    var reactor_chunked = te == TE_CHUNKED
    var body_total = hend
    if not reactor_chunked:
        body_total = hend + scan_content_length(req, hend)
    var parsed = _parse_http_request_bytes(
        Span[UInt8, _](req)[:body_total], leniency=leniency
    )
    var parser_te = parsed.headers.get("transfer-encoding")
    print("reactor TE verdict:", te, "body_total:", body_total, "of", len(req))
    print("parser Transfer-Encoding:", parser_te)
    if parser_te == "chunked" and not reactor_chunked:
        print(
            "BUG REPRODUCED: reactor framed by Content-Length (TE verdict "
            + String(te) + ", body_total " + String(body_total)
            + ") while the parser accepted Transfer-Encoding: chunked; "
            + String(len(req) - body_total)
            + " body bytes are left to be parsed as the next request"
        )
        raise Error("H1-04")
    print("OK: reactor and parser agree on chunked framing")
