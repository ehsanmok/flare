import Flare.L4_App.Cors

/-!
# APP-22: CORS responses without `Vary: Origin`

flare/http/cors.mojo:160-171 @59bda50. `Vary: Origin` is appended only when
the middleware attaches `Access-Control-Allow-Origin`. Requests without
`Origin`, and requests from a rejected origin, get the inner response
unchanged. The ACAO value therefore depends on `Origin` while some responses
to the same resource do not say so. Fetch §3.2.5 ("CORS protocol and HTTP
caches"): if ACAO is not a constant `*` / static origin sent on every
response, `Vary: Origin` is to be used, "in all responses (including the
non-CORS one)"; otherwise a cache can store the ACAO-less response and
serve it to a CORS request (or vice versa).
-/
namespace Flare.Bugs.APP_22

open Flare.L4.Cors

def cfg : Config :=
  { origins := ["https://a.example", "https://b.example"], methods := ["GET"],
    allowHeaders := [], exposed := [], maxAge := 600, creds := false }

def inner : Resp := ⟨200, []⟩

def reqFrom (o : String) : Req := { method := "GET", origin := o, acrm := "", acrh := "" }

/-- Spec: two requests that differ only in `Origin` and receive different
ACAO values must both carry `Vary: Origin`. -/
def VaryConsistent (f : Req → Resp) : Prop :=
  ∀ o1 o2, acao (f (reqFrom o1)) ≠ acao (f (reqFrom o2)) →
    hasVaryOrigin (f (reqFrom o1)) ∧ hasVaryOrigin (f (reqFrom o2))

/-- Counterexample: ACAO differs between no-`Origin` and an allowed origin,
yet the no-`Origin` response has no `Vary: Origin`. -/
theorem missing_vary :
    acao (serve cfg inner (reqFrom "")) = none ∧
    acao (serve cfg inner (reqFrom "https://a.example")) = some "https://a.example" ∧
    ¬ hasVaryOrigin (serve cfg inner (reqFrom "")) := by
  refine ⟨by decide, by decide, by decide⟩

theorem violates_spec : ¬ VaryConsistent (serve cfg inner) := by
  intro h
  have := h "" "https://a.example" (by decide)
  exact absurd this.1 (by decide)

/-- Fix: append `Vary: Origin` on every response; meets the spec for every
configuration, inner response and request. -/
theorem fixed_meets_spec (c : Config) (i : Resp) : VaryConsistent (serveFixed c i) :=
  fun _ _ _ => ⟨serveFixed_vary c i _, serveFixed_vary c i _⟩

end Flare.Bugs.APP_22
