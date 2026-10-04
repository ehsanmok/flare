# PLATFORM: any
"""H1-02: a bare LF inside a chunk extension or trailer line is accepted.

Lean: Flare.Bugs.H1_02.counterexample (counterexample) and
Flare.Bugs.H1_02.fixed_agrees_lfTolerant (fix meets spec).
flare/http/proto/chunked.mojo:239-266 and 270-290 @59bda50.

Spec: RFC 9112 sec 7.1.1 limits chunk-ext to tokens and quoted strings,
which never contain LF, and RFC 9112 sec 2.2 lets a recipient treat a bare
LF as a line terminator. So a chunk line holding a bare LF must be rejected,
or a front end that splits lines on LF frames the body differently from
flare (request smuggling). flare's own H1LeniencyConfig docs say strict
chunk-extension rules apply.

Expected: scan_chunked_end(b"0;\\n\\r\\nX: y\\r\\n\\r\\n") is
CHUNKED_MALFORMED.
Actual: flare looks only for CRLF and skips everything after ``;``. It reads
"0;\\n" as the last-chunk line, "X: y" as a trailer, and ends the body at
13, while an LF-splitting front end reads "0;" LF and the empty line CRLF,
ends the body at 5, and reads the remaining bytes as the next request.

Minimal fix: a chunk-size line or trailer line whose content contains LF is
CHUNKED_MALFORMED.
"""

from flare.http.proto.chunked import scan_chunked_end, CHUNKED_MALFORMED


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def main() raises:
    var body = _bytes("0;\n\r\nX: y\r\n\r\n")
    var r = scan_chunked_end(Span[UInt8, _](body), 0, 1 << 20)
    # An LF-splitting recipient reads "0;" LF, then the empty line "\r\n":
    # its body ends at offset 5.
    if r != CHUNKED_MALFORMED:
        print(
            "BUG REPRODUCED: scan_chunked_end accepted a chunk extension with"
            " a bare LF, body end " + String(r)
            + " (an LF-splitting recipient ends the body at 5)"
        )
        raise Error("H1-02")
    print("OK: bare LF inside a chunk line is rejected")
