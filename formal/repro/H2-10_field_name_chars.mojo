# PLATFORM: any
# RESOLVED: H2-10 fixed on fix/formal-findings
"""H2-10: validate_request_fields accepts field names containing octets
0x80-0xFF and regular field names containing a colon.

Lean: Flare.Bugs.H2_10.bug (counterexample) and Flare.Bugs.H2_10.fixed
(the fixed predicate equals the RFC 9113 sec 8.2.1 name rule).
flare/http2/state.mojo:1727-1733 @59bda50: the name loop rejects only
'A'-'Z', octets <= 0x20 and 0x7F.

RFC 9113 sec 8.2.1: "A field name MUST NOT contain characters in the
ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff (all ranges inclusive)." and
"With the exception of pseudo-header fields ..., field names MUST NOT
include a colon (ASCII COLON, 0x3a)." sec 8.1.1: such a request is
malformed, and the server must answer it with a stream error.

Trace: a GET (:method, :scheme, :path) plus one regular field, named
(a) "xé" (octets 78 C3 A9) and (b) "a:b", each with value "1".

Expected: validate_request_fields returns False for both. Before the fix: True
for both, so the request is served.

Minimal fix: in the name loop also reject c >= 0x7F, and reject ':' at
any position other than 0.
"""

from flare.http2.hpack import HpackHeader
from flare.http2.state import validate_request_fields


def _ok_with(name: String) -> Bool:
    var h = List[HpackHeader]()
    h.append(HpackHeader(":method", "GET"))
    h.append(HpackHeader(":scheme", "http"))
    h.append(HpackHeader(":path", "/"))
    h.append(HpackHeader(name, "1"))
    return validate_request_fields(h, False, False)


def main() raises:
    if not _ok_with("x-ok"):
        raise Error("setup: baseline request rejected")
    var a = _ok_with("xé")
    var b = _ok_with("a:b")
    if a or b:
        print(
            "BUG REPRODUCED: validate_request_fields accepted name 'x\\xc3\\xa9':",
            a,
            "; name 'a:b':",
            b,
            "(RFC 9113 sec 8.2.1 makes both malformed)",
        )
        raise Error("H2-10")
    print("OK: names with non-ASCII octets or an inner colon are rejected")
