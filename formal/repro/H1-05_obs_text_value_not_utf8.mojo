# PLATFORM: any
"""H1-05: obs-text header values become Strings that are not valid UTF-8.

Lean: Flare.Bugs.H1_05.counterexample (counterexample) and
Flare.Bugs.H1_05.fixed_utf8 (fix meets spec).
flare/http/_server/parse.mojo:268-285 @59bda50 (value accepted byte by byte),
flare/http/_server/parse_util.mojo:65-89 (`_ascii_strip_slice` builds it
with `_ascii_unchecked_string`).

Spec: flare/http/proto/ascii.mojo:63-70, the contract of
_ascii_unchecked_string: "the bytes MUST already be valid ASCII (each byte
< 0x80) ... we never get here with a non-ASCII byte". A Mojo String must
hold valid UTF-8. With H1LeniencyConfig.accept_obs_text_in_field_value the
parser admits bytes >= 0x80 (RFC 9110 sec 5.5 obs-text), so both promises
break.

Expected: the value is rejected, or stored as valid UTF-8.
Actual: headers.get("x") is a String whose bytes are [0xFF].

Minimal fix: in the obs-text branch, raise unless the value is valid UTF-8
(or build it with a validating constructor).
"""

from flare.http._server.parse import _parse_http_request_bytes
from flare.http.proto.h1_leniency import H1LeniencyConfig
from flare.ws.frame import _is_valid_utf8


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def main() raises:
    var req = _bytes("GET / HTTP/1.1\r\nHost: a\r\nX: ")
    req.append(0xFF)
    for b in _bytes("\r\n\r\n"):
        req.append(b)
    var leniency = H1LeniencyConfig(accept_obs_text_in_field_value=True)
    var stored_invalid = False
    var shown = String("")
    try:
        var parsed = _parse_http_request_bytes(
            Span[UInt8, _](req), leniency=leniency
        )
        var v = parsed.headers.get("x")
        var vb = List[UInt8]()
        for b in v.as_bytes():
            vb.append(b)
            shown += String(Int(b)) + " "
        stored_invalid = not _is_valid_utf8(vb)
    except:
        pass
    if stored_invalid:
        print(
            "BUG REPRODUCED: header value String holds bytes [ " + shown
            + "], which is not valid UTF-8"
        )
        raise Error("H1-05")
    print("OK: obs-text value rejected or stored as valid UTF-8")
