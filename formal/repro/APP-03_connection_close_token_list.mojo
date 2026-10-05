# PLATFORM: any
# RESOLVED: APP-03 fixed on fix/formal-findings
"""APP-03: a ``close`` option inside a Connection token list is ignored.

Lean: Flare.Bugs.APP_03.computeCloseAfterOld_misses_close (counterexample)
and Flare.Bugs.APP_03.computeCloseAfterFixed_meets_spec (fix meets
spec).
flare/http/_reactor/keepalive_scan.mojo:357-397 @59bda50
(``_compute_close_after``); the same exact-value compare is in
``_wants_close`` (keepalive_scan.mojo:451-478).

Spec (RFC 9110 sec 7.6.1: ``Connection = #connection-option``; RFC 9112
sec 9.6): when the ``close`` connection option is present the server
closes after the response and processes no further requests.

Expected: _compute_close_after({Connection: "keep-alive, close"},
"HTTP/1.1") == True (and likewise for "TE, close").
Before the fix: False. The value is compared as a whole against "close" /
"keep-alive"; a list value matches neither, and HTTP/1.1 defaults to
keep-alive, so the connection stays open and later requests are served.

Minimal fix: split the value on ',' , trim OWS, lowercase each token,
and return True if any token is "close" (for HTTP/1.0: True unless a
token is "keep-alive").
"""

from flare.http.headers import HeaderMap
from flare.http._reactor.keepalive_scan import _compute_close_after


def main() raises:
    var h = HeaderMap()
    h.set("Connection", "keep-alive, close")
    var got = _compute_close_after(h, "HTTP/1.1")
    var h2 = HeaderMap()
    h2.set("Connection", "TE, close")
    var got2 = _compute_close_after(h2, "HTTP/1.1")
    if not got or not got2:
        print(
            (
                "BUG REPRODUCED: _compute_close_after kept the connection alive"
                " for Connection: 'keep-alive, close' ->"
            ),
            got,
            "and 'TE, close' ->",
            got2,
        )
        raise Error("APP-03")
    print("OK: a close token inside a Connection list closes the connection")
