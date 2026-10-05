# PLATFORM: any
# RESOLVED: APP-43 fixed on fix/formal-findings
"""APP-43: a scheme-relative (network-path) Location such as
"//cdn.example.net/img" is resolved as a path on the current origin.

Lean: Flare.Bugs.APP_43.network_path_resolved_as_path (counterexample),
Flare.Bugs.APP_43.resolveFixed_network_path (fix meets spec);
model Flare.L4.Redirect.resolveLocation.
flare/http/redirect_policy.mojo:171-172 @59bda50
(`if location[0] == '/': return origin + location`).

Spec: RFC 9110 §10.2.2 (Location is a URI-reference) and RFC 3986
§4.2/§5.2.2: a reference starting with "//" is a network-path
reference; its authority replaces the base authority and only the
scheme is inherited.

Expected: _resolve_location("https://api.example.com/a",
"//cdn.example.net/img") == "https://cdn.example.net/img", and
RedirectPolicy.decide follows to that URL (cross-origin, so
Authorization is not forwarded).
Before the fix: "https://api.example.com:443//cdn.example.net/img"; decide
treats the hop as same-origin, so the redirect lands on the wrong
resource (and same_origin_only does not reject it).

Minimal fix: in _resolve_location, before the "/" branch:
    if location.startswith("//"):
        return base.scheme + ":" + location
"""

from flare.http.redirect_policy import (
    RedirectAction,
    RedirectPolicy,
    _resolve_location,
)


def main() raises:
    var got = _resolve_location(
        "https://api.example.com/a", "//cdn.example.net/img"
    )
    var d = RedirectPolicy.follow_all().decide(
        "https://api.example.com/a", "GET", 302, "//cdn.example.net/img", 0
    )
    if got != "https://cdn.example.net/img":
        print(
            "BUG REPRODUCED: '//cdn.example.net/img' against"
            " https://api.example.com/a resolved to",
            got,
            "; decide next_url",
            d.next_url,
            "forward_authorization",
            d.forward_authorization,
        )
        raise Error("APP-43")
    print("OK: network-path Location resolved to", got)
