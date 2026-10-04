# PLATFORM: any
"""APP-45: relative Location references are not resolved per RFC 3986
§5.2: a query-only reference drops the last path segment.

Dot segments are also kept verbatim ("../g" against http://h/b/c/d
gives http://h:80/b/c/../g); that second deviation is proved in Lean,
but this repro checks only the query-only case so the fix stays small.

Lean: Flare.Bugs.APP_45.query_only_reference_wrong,
Flare.Bugs.APP_45.dot_segments_kept (counterexamples),
Flare.Bugs.APP_45.resolveFixed_query_only (fix meets spec for the
query-only case); model Flare.L4.Redirect.resolveLocation.
flare/http/redirect_policy.mojo:173-185 @59bda50.

Spec: RFC 3986 §5.2.2 (T.path = Base.path when R.path is empty;
otherwise merge + remove_dot_segments), §5.4.1 examples:
base http://a/b/c/d;p?q, "?y" -> http://a/b/c/d;p?y,
"../g" -> http://a/b/g.

Expected: "?page=2" against http://h/list/items -> http://h:80/list/items?page=2
(the redirect re-requests the same resource with a new query).
Actual: http://h:80/list/?page=2 (a different resource).

Minimal fix: in _resolve_location, before the directory merge:
    if location.startswith("?"):
        return origin + base.path + location
(full fix: also apply remove_dot_segments, RFC 3986 §5.2.4).
"""

from flare.http.redirect_policy import _resolve_location


def main() raises:
    var q = _resolve_location("http://h/list/items", "?page=2")
    if q != "http://h:80/list/items?page=2":
        print("BUG REPRODUCED: '?page=2' against http://h/list/items ->", q)
        raise Error("APP-45")
    print("OK: query-only reference resolved per RFC 3986:", q)
