import Flare.L4_App.Cors

/-!
# APP-21: CORS allowlist is order dependent under credentials

flare/http/cors.mojo:89-98 @59bda50. `_origin_allowed` returns
`not allow_credentials` as soon as it meets `*`, so with credentials a `*`
listed before an explicit origin rejects that origin, while the same list in
the other order accepts it. Fetch allowlist semantics are a set property.

Status: resolved. `_origin_allowed` now `continue`s past `*` when credentials
are on (and still returns `True` for `*` without credentials). The model
`originAllowed` is the shipped check, `originAllowedOld` the pre-fix one.
Regression tests:
`tests/http/test_cors.mojo::test_credentials_allowlist_is_order_independent`
and `::test_wildcard_without_credentials_still_first_match`.
-/
namespace Flare.Bugs.APP_21

open Flare.L4.Cors

def cfgWith (os : List String) : Config :=
  { origins := os, methods := ["GET"], allowHeaders := [], exposed := [],
    maxAge := 600, creds := true }

def good : String := "https://app.example.com"

/-- Counterexample (pre-fix): listed origin rejected because `*` comes first. -/
theorem star_first_rejects :
    originAllowedOld good (cfgWith ["*", good]) = false ∧ allowedSpec (cfgWith ["*", good]) good := by
  refine ⟨by decide, ?_⟩
  unfold allowedSpec; decide

/-- Order dependence (pre-fix): permuting the list flips the decision. -/
theorem order_dependent :
    (cfgWith ["*", good]).origins.Perm (cfgWith [good, "*"]).origins ∧
    originAllowedOld good (cfgWith ["*", good]) = false ∧
    originAllowedOld good (cfgWith [good, "*"]) = true := by
  refine ⟨List.Perm.swap _ _ _, by decide, by decide⟩

/-- `¬ spec (impl x)` for the pre-fix check. -/
theorem violates_spec :
    ¬ (originAllowedOld good (cfgWith ["*", good]) = true ↔ allowedSpec (cfgWith ["*", good]) good) := by
  rw [star_first_rejects.1]; simp [star_first_rejects.2]

/-- The shipped check (skips `*` under credentials instead of returning) meets
the spec for every configuration and is therefore order independent. -/
theorem fixed_meets_spec (o : String) (cfg : Config) :
    originAllowed o cfg = true ↔ allowedSpec cfg o :=
  originAllowed_iff o cfg

theorem fixed_order_independent (o : String) (cfg cfg' : Config)
    (hp : cfg.origins.Perm cfg'.origins) (hc : cfg.creds = cfg'.creds) :
    originAllowed o cfg = originAllowed o cfg' := by
  have := (originAllowed_iff o cfg).trans
    ((allowedSpec_perm cfg cfg' o hp hc).trans (originAllowed_iff o cfg').symm)
  cases h1 : originAllowed o cfg <;> cases h2 : originAllowed o cfg' <;> simp_all

end Flare.Bugs.APP_21
