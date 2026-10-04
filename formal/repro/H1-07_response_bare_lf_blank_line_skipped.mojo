# PLATFORM: any
"""H1-07: the client splits a response head on bare LF but skips empty lines,
so bytes an LF-terminating recipient treats as body become header fields.

Lean: Flare.Bugs.H1_07.counterexample (headImpl returns the
"Set-Cookie" line, lfHead ends the head before it) and
Flare.L3.H1.ClientResponse.headFixed_agrees (fix meets spec).
flare/http/_client/parse.mojo:283-306 (_split_lines ends a line at a bare
LF) and 106-110 (`if len(raw) == 0: continue`) @59bda50.

Expected (RFC 9112 §2.2): a recipient may treat a bare LF as a line
terminator, but then the first empty line ends the head; or it rejects
the bare LF. Either way "HTTP/1.1 200 OK\\nX: a\\n\\nSet-Cookie: s=evil"
has no Set-Cookie field: that line is body to any LF-recognising peer
(a cache or proxy in front of the client).
Actual: the head runs to the first CRLFCRLF, the empty line is skipped,
and the response carries Set-Cookie: s=evil.

Minimal fix: in _parse_response_head, raise on a bare LF in the head and
on an empty line before its end.
"""

from flare.http._client.parse import _parse_http_response


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def main() raises:
    var raw = _bytes(
        "HTTP/1.1 200 OK\nX: a\n\nSet-Cookie: s=evil\r\nContent-Length:"
        " 4\r\n\r\nbody"
    )
    var verdict: String
    var cookie = String("")
    try:
        var resp = _parse_http_response(raw)
        cookie = resp.headers.get("set-cookie")
        verdict = (
            "accepted status=" + String(resp.status) + " set-cookie=" + cookie
        )
    except e:
        verdict = "raised: " + String(e)
    print(verdict)
    if cookie == "s=evil":
        print(
            "BUG REPRODUCED: header after an LF-terminated empty line was"
            " parsed (" + verdict + ")"
        )
        raise Error("H1-07")
    print("OK: bare-LF head is refused or ends at the empty line (" + verdict + ")")
