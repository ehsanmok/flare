# PLATFORM: any
# RESOLVED: APP-24 fixed on fix/formal-findings
"""APP-24: urldecode returns a String holding ill-formed UTF-8.

Lean: Flare.Bugs.APP_24.urldecode_violates_spec (counterexample: "%F0"
decodes to the lone byte 0xF0), Flare.Bugs.APP_24.parseForm_F0 (reachable
from a form body), Flare.Bugs.APP_24.urldecodeFixed_meets_spec (fix).
flare/http/form.mojo:87 @59bda50 (urldecode), reached from
parse_form_urlencoded (form.mojo:262) and the Form extractor
(extract.mojo:771).

Expected: decoding attacker-chosen escapes never yields a String that
violates Mojo's String invariant (valid UTF-8). Either reject (raise, as
urldecode already does for bad escapes) or substitute U+FFFD as WHATWG
URL 5.1 ("UTF-8 decode without BOM") specifies.
Before the fix: urldecode("%F0") returns a String whose single byte is 0xF0,
built with String(unsafe_from_utf8=...), whose Safety clause requires
valid UTF-8. Codepoint iteration over it reads past the buffer.

Minimal fix: form.mojo:87 `return String(from_utf8=Span[UInt8, _](out))`
(raises on ill-formed UTF-8) or `String(from_utf8_lossy=...)` (WHATWG).
"""

from flare.http import parse_form_urlencoded, urldecode


def _invalid(s: String) -> Bool:
    try:
        _ = String(from_utf8=s.as_bytes())
        return False
    except:
        return True


def main() raises:
    var bad_direct: Bool
    try:
        var d = urldecode("%F0")
        bad_direct = _invalid(d)
    except:
        bad_direct = False  # rejected: fixed (raising variant)

    var bad_form: Bool
    try:
        var fd = parse_form_urlencoded("a=%F0")
        bad_form = _invalid(fd.get("a"))
    except:
        bad_form = False

    if bad_direct or bad_form:
        print(
            (
                "BUG REPRODUCED: urldecode('%F0') /"
                " parse_form_urlencoded('a=%F0') produced a String that is not"
                " valid UTF-8 (direct:"
            ),
            bad_direct,
            ", form:",
            bad_form,
            ")",
        )
        raise Error("APP-24")
    print("OK: urldecode never yields ill-formed UTF-8 for '%F0'")
