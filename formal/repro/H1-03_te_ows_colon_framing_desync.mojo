# PLATFORM: any
# RESOLVED: H1-03 fixed on fix/formal-findings
"""H1-03: with allow_ows_around_colon the reactor and the parser disagree on
Transfer-Encoding framing (request smuggling / desync).

Lean: Flare.Bugs.H1_03.counterexample (counterexample) and
Flare.Bugs.H1_03.fixed_agrees (fix meets spec).
flare/http/proto/chunked.mojo:139-148 (request_te_framing requires ':'
right after the name) vs flare/http/_server/parse.mojo:249-255 (the lenient
parser strips SP/HTAB before ':') @59bda50; both are fed the same bytes by
flare/http/_reactor/conn_handle.mojo:622-654 and 807-816.

Spec (RFC 9112 sec 6.3, sec 11.2): the component that decides where a
request ends and the component that interprets it must use the same
framing. ServerConfig.h1_leniency is public and allow_ows_around_colon is
documented as safe behind a trusted upstream that emits "Header :value".

Expected: for "Transfer-Encoding : chunked" the reactor frames the body as
chunked, the way the parser reads the header.
Before the fix: Actual: request_te_framing returns TE_ABSENT and scan_content_length 0, so
the reactor dispatches the head with an empty body while the parser
accepts it with Transfer-Encoding: chunked. The chunked body bytes stay in
the read buffer and are parsed as the next request, so one request produces
two responses (the second a 400).

Minimal fix: in request_te_framing skip SP/HTAB between the field name and
':' (the strict parser rejects such lines anyway, so strict mode is
unchanged).
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
        "POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n"
        "5\r\nhello\r\n0\r\n\r\n"
    )
    var leniency = H1LeniencyConfig(allow_ows_around_colon=True)
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
        raise Error("H1-03")
    print("OK: reactor and parser agree on chunked framing")
