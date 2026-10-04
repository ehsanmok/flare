# PLATFORM: any
"""H1-10: with allow_obs_fold, an obs-fold continuation line is appended to
the header value without the byte check every other value gets.

Lean: Flare.Bugs.H1_10.counterexample (fields stores "a \\x01\\x7f") and
Flare.L3.H1.ObsFold.fieldsFixed_valid (fix meets spec: every stored value
passes valueOk); Flare.L3.H1.ObsFold.fold_unfold proves the unfolding
itself is RFC 9112 §5.2's (each fold becomes one SP).
flare/http/_server/parse.mojo:222-232 (`folded = _ascii_strip_slice(line)`;
`prev_header_value += " " + folded`, no per-byte loop) versus 277-285 (the
check on a first-line value) @59bda50.

Expected (RFC 9110 §5.5, RFC 9112 §5.2): the unfolded value is
field-content; control bytes other than HTAB (here 0x01 and DEL) are
rejected in every leniency mode, as they are on a field's first line.
Actual: "X: a\\r\\n \\x01\\x7f" is accepted and the handler sees
x = "a \\x01\\x7f" (and, with high bytes, a String that is not UTF-8,
bypassing the obs-text gate too).

Minimal fix: run the value byte loop of lines 277-285 on `folded` before
appending it.
"""

from flare.http._server.parse import _parse_http_request_bytes
from flare.http.proto.h1_leniency import H1LeniencyConfig


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def main() raises:
    var leniency = H1LeniencyConfig(allow_obs_fold=True)
    # Control: the same bytes on a first line are refused in this mode.
    var ctrl = _bytes("GET / HTTP/1.1\r\nHost: a\r\nX: a ")
    ctrl.append(0x01)
    ctrl.append(0x7F)
    for b in _bytes("\r\n\r\n"):
        ctrl.append(b)
    var ctrl_refused = False
    try:
        _ = _parse_http_request_bytes(Span[UInt8, _](ctrl), leniency=leniency)
    except:
        ctrl_refused = True
    if not ctrl_refused:
        print("inconclusive: control request was accepted")
        raise Error("inconclusive")

    # A legitimate fold is honoured (the flag really is on).
    var good = _bytes("GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n  b\r\n\r\n")
    var good_v = String("")
    try:
        var p = _parse_http_request_bytes(Span[UInt8, _](good), leniency=leniency)
        good_v = p.headers.get("x")
    except e:
        print("inconclusive: plain obs-fold refused: " + String(e))
        raise Error("inconclusive")
    if good_v != "a b":
        print("inconclusive: plain obs-fold gave '" + good_v + "'")
        raise Error("inconclusive")

    var req = _bytes("GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n ")
    req.append(0x01)
    req.append(0x7F)
    for b in _bytes("\r\n\r\n"):
        req.append(b)
    var shown = String("")
    var accepted = False
    try:
        var parsed = _parse_http_request_bytes(
            Span[UInt8, _](req), leniency=leniency
        )
        accepted = True
        for b in parsed.headers.get("x").as_bytes():
            shown += String(Int(b)) + " "
    except e:
        shown = "raised: " + String(e)
    if accepted:
        print(
            "BUG REPRODUCED: folded value accepted with control bytes, x = [ "
            + shown + "] (the same bytes on a first line are refused)"
        )
        raise Error("H1-10")
    print("OK: control bytes in a continuation line refused (" + shown + ")")
