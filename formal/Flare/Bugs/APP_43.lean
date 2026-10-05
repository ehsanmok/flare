import Flare.L4_App.Redirect

/-!
# APP-43: a network-path `Location` (`//host/path`) is resolved as a path on the current origin

flare/http/redirect_policy.mojo:171-172 @59bda50, pre-fix
(`if location[0] == '/': return origin + location`). A reference that starts
with `//` is a network-path reference: its authority replaces the base
authority and only the scheme is inherited. flare appends it to the current
origin, so `//cdn.example.net/img` against `https://api.example.com/a`
becomes `https://api.example.com:443//cdn.example.net/img`. `decide` then
treats the hop as same-origin (wrong resource; `same_origin_only` does not
refuse it; `Authorization` is forwarded to the original host, which is not
a leak).

Spec: RFC 9110 §10.2.2 (Location is a URI-reference), RFC 3986 §4.2 and
§5.2.2 (if the reference has an authority, `T.authority = R.authority`,
`T.scheme = Base.scheme`).

Status: resolved. `_resolve_location` returns `base.scheme + ":" + location`
for a reference starting with `//` (flare/http/redirect_policy.mojo:176-177);
the shipped model is `Flare.L4.Redirect.resolveLocation`. The counterexamples
below are about the explicitly pre-fix `resolveLocationOld`. Regression tests:
tests/http/test_redirect_policy.mojo::
test_network_path_location_replaces_the_authority and
test_network_path_location_is_cross_origin_for_same_origin_only.
-/
namespace Flare.Bugs.APP_43

open Flare.L4.Redirect

def base : Str := "https://api.example.com/a".toList
def loc : Str := "//cdn.example.net/img".toList

/-- Counterexample (pre-fix `resolveLocationOld`): the resolved target keeps
the base host. -/
theorem network_path_resolved_as_path :
    resolveLocationOld base loc = some "https://api.example.com:443//cdn.example.net/img".toList ∧
    originOf "https://api.example.com:443//cdn.example.net/img".toList =
      some ("https".toList, "api.example.com".toList, 443) := by
  native_decide

/-- `¬ spec (impl x)`: the spec origin of the target is
`(https, cdn.example.net, 443)`. -/
theorem violates_spec :
    ((resolveLocationOld base loc).bind originOf) ≠ some ("https".toList, "cdn.example.net".toList, 443) := by
  native_decide

/-- **Fix meets spec**: the shipped resolver meets RFC 3986 §5.2.2 for
network-path references on every base that parses: the result is
`Base.scheme ":" reference`, so the authority, path and query all come from
the reference. -/
theorem resolveLocation_network_path (b rest : Str) (u : Url) (hb : parse b = some u) :
    resolveLocation b ('/' :: '/' :: rest) = some (u.scheme ++ ':' :: '/' :: '/' :: rest) := by
  simp [resolveLocation, hb]

/-- On every other reference the shipped resolver agrees with the pre-fix
one. -/
theorem resolveLocation_other (b l : Str) (hl : ¬ ∃ rest, l = '/' :: '/' :: rest) :
    resolveLocation b l = resolveLocationOld b l := by
  rcases l with _ | ⟨c, _ | ⟨d, t⟩⟩
  · rfl
  · by_cases hc : c = '/'
    · subst hc; simp [resolveLocation, resolveLocationOld]
    · simp [resolveLocation, resolveLocationOld, hc]
  · by_cases hc : c = '/'
    · by_cases hd : d = '/'
      · exact absurd ⟨t, by simp [hc, hd]⟩ hl
      · simp [resolveLocation, resolveLocationOld, hc, hd]
    · simp [resolveLocation, resolveLocationOld, hc]

theorem fixed_on_example :
    (resolveLocation base loc).bind originOf = some ("https".toList, "cdn.example.net".toList, 443) := by
  native_decide

end Flare.Bugs.APP_43
