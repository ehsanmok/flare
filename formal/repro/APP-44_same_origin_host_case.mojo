# PLATFORM: any
# RESOLVED: APP-44 fixed on fix/formal-findings
"""APP-44: _same_origin compares hosts case-sensitively, so
http://API.example.com and http://api.example.com are different
origins; same_origin_only then rejects a same-site redirect.

Lean: Flare.Bugs.APP_44.host_case_not_same_origin (counterexample),
Flare.Bugs.APP_44.sameOriginFixed_case (fix meets spec);
model Flare.L4.Redirect.sameOrigin.
flare/http/redirect_policy.mojo:188-198 @59bda50 (`a.host != b.host`),
Url.parse keeps host case (flare/http/url.mojo:172-192).

Spec: RFC 6454 §4 step 5 (host is lowercased when computing the
origin) and RFC 3986 §3.2.2 / §6.2.2.1 (host is case-insensitive).

Expected: _same_origin("http://API.example.com/", "http://api.example.com/x")
is True and RedirectPolicy.same_origin_only().decide(...) FOLLOWs.
Before the fix: False and REJECT ("cross-origin redirect refused"). The error
direction is fail-safe (credentials are stripped, never leaked), so
severity is low: a spurious refusal, and Authorization is dropped on a
same-origin hop. The same unnormalised host keys the client pools
(flare/http/client_pool.mojo:191-201, client.mojo:2459), giving one
pool bucket per spelling.

Minimal fix: compare `a.host.lower() != b.host.lower()` (or lowercase
the host in Url.parse).
"""

from flare.http.redirect_policy import (
    RedirectAction,
    RedirectPolicy,
    _same_origin,
)


def main() raises:
    var same = _same_origin("http://API.example.com/", "http://api.example.com/x")
    var d = RedirectPolicy.same_origin_only().decide(
        "http://API.example.com/", "GET", 302, "http://api.example.com/x", 0
    )
    if not same or d.action != RedirectAction.FOLLOW:
        print(
            "BUG REPRODUCED: _same_origin(API.example.com, api.example.com) =",
            same,
            "; same_origin_only decide action =",
            d.action,
            "(0=FOLLOW, 2=REJECT)",
        )
        raise Error("APP-44")
    print("OK: host comparison is case-insensitive")
