import Flare.L4_App.ComptimeRouter

/-!
# APP-10: `ComptimeRouter` accepts a non-final `*` and ignores the rest of the pattern

flare/http/routes.mojo:264-274 @59bda50. `_match_one` treats a `*` segment
as "capture the rest and succeed" wherever it appears, and nothing in
`ComptimeRouter` rejects a pattern whose `*` is not last. The runtime
`Router` raises `wildcard '*' must be the last segment in a route` for the
same pattern (router.mojo:148-151), and the routes.mojo docstrings promise
"Same semantics as the runtime Router's `_match`" with a *trailing* `*`.

So `ComptimeRoute(GET, "/files/*/meta", h)` compiles, and `GET /files/a`
(no `meta` segment at all) is dispatched to `h` with `*` = `a`; so is
`GET /files/a/b/c`.

Spec (router.mojo:6-10, routes.mojo:255-258; `Flare.L4.Router.specMatch`):
a `*` matches the non-empty rest of the path only as the final segment; a
pattern with a non-final `*` is invalid and matches nothing.

Status: resolved. `_match_one` returns `False` for a `*` that is not the last
pattern segment, so such a pattern matches nothing (404). The model
`matchOne` / `scanCT` / `serveCT` are the shipped ones, `matchOneOld` /
`scanCTOld` / `serveCTOld` the pre-fix ones. Regression tests:
`tests/http/test_routes_comptime.mojo::test_non_final_wildcard_matches_nothing`
and `::test_final_wildcard_still_captures_rest`.
-/
namespace Flare.Bugs.APP_10

open Flare.L4.Router Flare.L4.ComptimeRouter

def pat : Str := "/files/*/meta".toList

/-- The runtime router refuses to register the pattern. -/
theorem router_rejects : (match compile pat with | .error _ => true | .ok _ => false) = true := by
  native_decide

/-- The pre-fix comptime router dispatches `GET /files/a` to the route. -/
theorem comptime_misroutes :
    serveCTOld [⟨"GET".toList, pat, 7⟩] ⟨"GET".toList, "/files/a".toList, []⟩ =
      .handler 7 ⟨"GET".toList, "/files/a".toList, [("*".toList, "a".toList)]⟩ := by
  native_decide

/-- Headline counterexample `¬ spec (impl x)`: the pre-fix `_match_one` disagrees with
the matching spec on the classified pattern. -/
theorem matchOne_violates_spec :
    matchOneOld ["files".toList, "a".toList] (splitStatic pat) ≠
      specMatch ((splitStatic pat).map classify) ["files".toList, "a".toList] := by
  native_decide

/-- The shipped matcher meets the spec on every pattern, valid or not
(`Flare.L4.ComptimeRouter.matchOne_eq_spec`). -/
theorem fixed_meets_spec (us raw : List Str) (hn : NF us) :
    matchOne us raw = specMatch (raw.map classify) us :=
  matchOne_eq_spec us raw hn

theorem fixed_on_example :
    matchOne ["files".toList, "a".toList] (splitStatic pat) = none := by
  native_decide

/-- The shipped router answers `GET /files/a` with a 404. -/
theorem fixed_serves_404 :
    serveCT [⟨"GET".toList, pat, 7⟩] ⟨"GET".toList, "/files/a".toList, []⟩ =
      .notFound "/files/a".toList := by
  native_decide

end Flare.Bugs.APP_10
