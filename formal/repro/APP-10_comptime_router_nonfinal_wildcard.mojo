# PLATFORM: any
# RESOLVED: APP-10 fixed on fix/formal-findings
"""APP-10: ComptimeRouter accepts a non-final `*` and ignores the rest of the pattern.

Lean: Flare.Bugs.APP_10.matchOne_violates_spec (counterexample),
Flare.Bugs.APP_10.comptime_misroutes, Flare.Bugs.APP_10.router_rejects and
Flare.Bugs.APP_10.fixed_meets_spec (fix meets spec).
flare/http/routes.mojo:264-274 @59bda50 (`_match_one`); the runtime Router
rejects the same pattern at flare/http/router.mojo:148-151.

Expected: the pattern "/files/*/meta" is invalid (the runtime Router raises
"wildcard '*' must be the last segment in a route"), so it must never match;
GET /files/a is a 404.
Before the fix: ComptimeRouter compiles the table and `_match_one` treats the
middle `*` as a tail wildcard, returning True as soon as it reaches it, so
GET /files/a (no "meta" segment) is dispatched to the handler with
param("*") == "a".

Minimal fix: in `_match_one`, before capturing the tail, return False when
the wildcard is not the last pattern segment
(`if j != len(pat_segs) - 1: return False`); better, reject such a table at
compile time.
"""

from flare.http import (
    ComptimeRoute,
    ComptimeRouter,
    Request,
    Response,
    Method,
    ok,
)


def _meta(req: Request) raises -> Response:
    return ok("meta:" + req.param("*"))


comptime _ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET, "/files/*/meta", _meta),
]


def main() raises:
    var r = ComptimeRouter[_ROUTES]()
    var resp = r.serve(Request(method=Method.GET, url="/files/a"))
    if resp.status != 404:
        print(
            (
                "BUG REPRODUCED: pattern /files/*/meta matched GET /files/a"
                " with status"
            ),
            resp.status,
            "body",
            resp.text(),
        )
        raise Error("APP-10")
    print("OK: GET /files/a is", resp.status, "for pattern /files/*/meta")
