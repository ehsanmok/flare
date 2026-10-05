# PLATFORM: any
# RESOLVED: APP-02 fixed on fix/formal-findings
"""APP-02: _wants_close matches "connection:" anywhere and stops at the first hit.

Lean: Flare.Bugs.APP_02.wantsClose_misses_close (counterexample) and
Flare.Bugs.APP_02.wantsCloseFixed_meets_spec (fix meets spec).
flare/http/_reactor/keepalive_scan.mojo:400-484 @59bda50 (the
``while i < n - nn`` scan, lines 432-480).

Spec (RFC 9112 sec 9.6, RFC 9110 sec 7.6.1): a request whose
``Connection`` field carries the ``close`` option must not be followed
by further requests on that connection; the server closes after the
response.

Expected: _wants_close(b"GET / HTTP/1.1\\r\\nX-Connection: x\\r\\n"
"Connection: close\\r\\n\\r\\n") == True.
Before the fix: False. The scan looks for the bytes ``connection:`` at every
offset, not only at the start of a header line, so it first matches
inside ``X-Connection:``. Its value is not ``close``, and the scan
``break``s after the first match, so the real ``Connection: close`` line
is never examined. The static fast path and the
``skip_header_decode_for_short_requests`` path keep the connection
alive (``Connection: keep-alive`` in the response) against the
client's ``close``.

Minimal fix: only test for ``connection:`` at a line start (i == first
line start or data[i-1] == LF) and keep scanning after a match instead
of ``break``ing (OR the per-line verdicts).
"""

from flare.http._reactor.keepalive_scan import _wants_close


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def main() raises:
    var req = String(
        "GET / HTTP/1.1\r\nHost: a\r\nX-Connection: x\r\nConnection:"
        " close\r\n\r\n"
    )
    var data = _bytes(req)
    var got = _wants_close(data, len(data))
    if not got:
        print(
            "BUG REPRODUCED: _wants_close returned False for a request"
            " carrying 'Connection: close' after an 'X-Connection' header"
        )
        raise Error("APP-02")
    print("OK: _wants_close honours 'Connection: close' after X-Connection")
