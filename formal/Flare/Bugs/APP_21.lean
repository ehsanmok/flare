import Flare.L4_App.Cors

/-!
# APP-21: CORS allowlist is order dependent under credentials

flare/http/cors.mojo:89-98 @59bda50. `_origin_allowed` returns
`not allow_credentials` as soon as it meets `*`, so with credentials a `*`
listed before an explicit origin rejects that origin, while the same list in
the other order accepts it. Fetch allowlist semantics are a set property.
-/
namespace Flare.Bugs.APP_21

open Flare.L4.Cors

def cfgWith (os : List String) : Config :=
  { origins := os, methods := ["GET"], allowHeaders := [], exposed := [],
    maxAge := 600, creds := true }

def good : String := "https://app.example.com"

/-- Counterexample: listed origin rejected because `*` comes first. -/
theorem star_first_rejects :
    originAllowed good (cfgWith ["*", good]) = false ∧ allowedSpec (cfgWith ["*", good]) good := by
  refine ⟨by decide, ?_⟩
  unfold allowedSpec; decide

/-- Order dependence: permuting the list flips the decision. -/
theorem order_dependent :
    (cfgWith ["*", good]).origins.Perm (cfgWith [good, "*"]).origins ∧
    originAllowed good (cfgWith ["*", good]) = false ∧
    originAllowed good (cfgWith [good, "*"]) = true := by
  refine ⟨List.Perm.swap _ _ _, by decide, by decide⟩

/-- `¬ spec (impl x)`. -/
theorem violates_spec :
    ¬ (originAllowed good (cfgWith ["*", good]) = true ↔ allowedSpec (cfgWith ["*", good]) good) := by
  rw [star_first_rejects.1]; simp [star_first_rejects.2]

/-- Fix: skip `*` under credentials instead of returning; meets the spec for
every configuration and is therefore order independent. -/
theorem fixed_meets_spec (o : String) (cfg : Config) :
    originAllowedFixed o cfg = true ↔ allowedSpec cfg o :=
  originAllowedFixed_iff o cfg

theorem fixed_order_independent (o : String) (cfg cfg' : Config)
    (hp : cfg.origins.Perm cfg'.origins) (hc : cfg.creds = cfg'.creds) :
    originAllowedFixed o cfg = originAllowedFixed o cfg' := by
  have := (originAllowedFixed_iff o cfg).trans
    ((allowedSpec_perm cfg cfg' o hp hc).trans (originAllowedFixed_iff o cfg').symm)
  cases h1 : originAllowedFixed o cfg <;> cases h2 : originAllowedFixed o cfg' <;> simp_all

end Flare.Bugs.APP_21
