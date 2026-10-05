# PLATFORM: any
# RESOLVED: APP-25 fixed on fix/formal-findings
"""APP-25: Url.parse strips userinfo at the first '@', leaving '@' in the host.

Lean: Flare.Bugs.APP_25.host_has_at (counterexample) and
Flare.Bugs.APP_25.implFixed_meets_spec (fix meets spec); general theorem
Flare.L4.Url.parseWith_fixedStrip_noAt.
flare/http/url.mojo:143-148 @59bda50.

Input: "http://a@evil.com@good.com/" (not a valid RFC 3986 URI: userinfo
cannot hold an unescaped '@').

Expected: either a UrlParseError, or the host WHATWG browsers and curl
pick, "good.com" (split at the LAST '@'). In no case a host containing
'@' (RFC 3986 sec 3.2.2: no host form allows it).
Before the fix: host "evil.com@good.com".

Minimal fix: `_rfind(authority, "@")` instead of `_find(authority, "@")`
(or raise when more than one '@' is present).
"""

from flare.http import Url


def main() raises:
    var u = Url.parse("http://a@evil.com@good.com/")
    if u.host.find("@") >= 0:
        print(
            "BUG REPRODUCED: Url.parse('http://a@evil.com@good.com/').host =",
            "'" + u.host + "'",
            "contains '@' (WHATWG/curl host: 'good.com')",
        )
        raise Error("APP-25")
    print("OK: host has no '@':", u.host)
