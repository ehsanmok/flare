# PLATFORM: any
# RESOLVED: H1-08 fixed on fix/formal-findings
"""H1-08: the client truncates a status code of more than three digits.

Lean: Flare.Bugs.H1_08.counterexample (parseStatusOld "HTTP/1.1 2041 OK" =
some 204) and Flare.L3.H1.ClientResponse.parseStatus_delimited (fix
meets spec: an accepted code is three digits between SP and SP or end).
flare/http/_client/parse.mojo:318-352 (_parse_status_line reads
rest[0:3] and takes the reason from rest[4:] without checking rest[3])
@59bda50.

Expected (RFC 9112 §4): status-line = HTTP-version SP 3DIGIT SP
reason-phrase; "HTTP/1.1 2041 OK" is malformed and must be refused.
Before the fix: Actual: it parses as 204, and 204 means no body (RFC 9112 §6.3), so the
"hello" that follows is left on the connection. A 1004 is read as 100
and skipped as an interim response.

Minimal fix: in _parse_status_line, raise if
`rest.byte_length() > 3 and rest.as_bytes()[3] != 32`.
"""

from flare.http._client.parse import _parse_http_response


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def main() raises:
    var raw = _bytes("HTTP/1.1 2041 OK\r\nContent-Length: 5\r\n\r\nhello")
    var verdict: String
    var status = -1
    try:
        var resp = _parse_http_response(raw)
        status = resp.status
        verdict = (
            "accepted status=" + String(resp.status) + " body_len="
            + String(len(resp.body))
        )
    except e:
        verdict = "raised: " + String(e)
    print(verdict)
    if status >= 0:
        print(
            "BUG REPRODUCED: four-digit status code accepted ("
            + verdict + ")"
        )
        raise Error("H1-08")
    print("OK: four-digit status code refused (" + verdict + ")")
