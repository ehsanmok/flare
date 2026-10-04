import Flare.L4_App.Redirect

/-!
# APP-43: a network-path `Location` (`//host/path`) is resolved as a path on the current origin

flare/http/redirect_policy.mojo:171-172 @59bda50
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
-/
namespace Flare.Bugs.APP_43

open Flare.L4.Redirect

def base : Str := "https://api.example.com/a".toList
def loc : Str := "//cdn.example.net/img".toList

/-- Counterexample: the resolved target keeps the base host. -/
theorem network_path_resolved_as_path :
    resolveLocation base loc = some "https://api.example.com:443//cdn.example.net/img".toList ∧
    originOf "https://api.example.com:443//cdn.example.net/img".toList =
      some ("https".toList, "api.example.com".toList, 443) := by
  native_decide

/-- `¬ spec (impl x)`: the spec origin of the target is
`(https, cdn.example.net, 443)`. -/
theorem violates_spec :
    ((resolveLocation base loc).bind originOf) ≠ some ("https".toList, "cdn.example.net".toList, 443) := by
  native_decide

/-- Minimal fix: a reference starting with `//` takes the base scheme only.
mirrors the fix applied in the flip check (redirect_policy.mojo:171) -/
def resolveFixed (b l : Str) : Option Str :=
  match l with
  | '/' :: '/' :: _ => (parse b).map fun u => u.scheme ++ ':' :: l
  | _ => resolveLocation b l

/-- The fixed resolver meets RFC 3986 §5.2.2 for network-path references on
every base that parses: the result is `Base.scheme ":" reference`, so the
authority, path and query all come from the reference. On every other
reference it is unchanged. -/
theorem resolveFixed_network_path (b rest : Str) (u : Url) (hb : parse b = some u) :
    resolveFixed b ('/' :: '/' :: rest) = some (u.scheme ++ ':' :: '/' :: '/' :: rest) := by
  simp [resolveFixed, hb]

theorem resolveFixed_other (b l : Str) (hl : ¬ ∃ rest, l = '/' :: '/' :: rest) :
    resolveFixed b l = resolveLocation b l := by
  unfold resolveFixed
  split
  · exact absurd ⟨_, rfl⟩ hl
  · rfl

theorem fixed_on_example :
    (resolveFixed base loc).bind originOf = some ("https".toList, "cdn.example.net".toList, 443) := by
  native_decide

end Flare.Bugs.APP_43
