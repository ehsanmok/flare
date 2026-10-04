# PLATFORM: any
"""APP-23: Url.parse does not end the authority at '?' (host confusion).

Lean: Flare.Bugs.APP_23.host_confusion (counterexample) and
Flare.Bugs.APP_23.implFixed_meets_spec (fix meets spec); general theorem
Flare.L4.Url.parseWith_fixedSplit_hostInAuthority.
flare/http/url.mojo:101-123 @59bda50.

Input: "http://evil.com?@good.com/", a valid RFC 3986 URI whose
authority is "evil.com" and whose query is "@good.com/".

Expected (RFC 3986 sec 3.2, WHATWG URL, curl): host "evil.com",
path "/", query "@good.com/".
Actual: the authority is cut only at the first '/', so it becomes
"evil.com?@good.com"; the userinfo strip then drops "evil.com?@" and
the host is "good.com" (query ""). A validator that checks Url.parse(u).host
against an allowlist approves a URL that browsers and curl send to
evil.com. Second witness: "http://good.com?x=/y" gives host "good.com?x=".

Minimal fix: take the fragment at the FIRST '#' (_find instead of
_rfind) and end the authority at the first '/' or '?', whichever
comes first.
"""

from flare.http import Url


def main() raises:
    var u = Url.parse("http://evil.com?@good.com/")
    var v = Url.parse("http://good.com?x=/y")
    if u.host != "evil.com" or u.query != "@good.com/" or v.host != "good.com":
        print(
            "BUG REPRODUCED: Url.parse('http://evil.com?@good.com/').host =",
            "'" + u.host + "'",
            "(query '" + u.query + "'),",
            "Url.parse('http://good.com?x=/y').host =",
            "'" + v.host + "';",
            "RFC 3986 hosts are 'evil.com' and 'good.com'",
        )
        raise Error("APP-23")
    print(
        "OK: authority ends at '?': hosts",
        u.host,
        "and",
        v.host,
        "query",
        u.query,
    )
