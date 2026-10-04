import Flare.L4_App.Redirect

/-!
# APP-44: `_same_origin` compares hosts case-sensitively

flare/http/redirect_policy.mojo:188-198 @59bda50 (`a.host != b.host`), and
`Url.parse` keeps the host's case (flare/http/url.mojo:172-192). So
`http://API.example.com/` and `http://api.example.com/x` are different
origins: `RedirectPolicy.same_origin_only()` refuses the redirect, and with
the default policy `Authorization` is dropped on what is a same-origin hop.
The error direction is fail-safe (credentials are never sent further than
intended). The same unnormalised host keys the client connection pool
(flare/http/client_pool.mojo:191-201), one bucket per spelling.

Spec: RFC 6454 §4 step 5 (the host is lowercased when computing an origin),
RFC 3986 §3.2.2 and §6.2.2.1 (hosts are case-insensitive).
-/
namespace Flare.Bugs.APP_44

open Flare.L4.Redirect

def a : Str := "http://API.example.com/".toList
def b : Str := "http://api.example.com/x".toList

/-- ASCII lowercase. -/
def lowerS (s : Str) : Str := s.map Char.toLower

/-- Spec origin: (scheme, lowercased host, port). -/
def specOrigin (u : Str) : Option (Str × Str × Nat) :=
  (parse u).map fun v => (v.scheme, lowerS v.host, v.port)

/-- Counterexample: same spec origin, flare says "not same origin", and
`same_origin_only` rejects the redirect. -/
theorem host_case_not_same_origin :
    specOrigin a = specOrigin b ∧ (specOrigin a).isSome ∧ sameOrigin a b = some false ∧
    ((decideR ⟨10, 1, false⟩ a "GET".toList 302 b 0).map Decision.action) = some .reject := by
  native_decide

/-- Fix: compare lowercased hosts. -/
def sameOriginFixed (x y : Str) : Option Bool := do
  let u ← parse x
  let v ← parse y
  return (u.scheme = v.scheme ∧ lowerS u.host = lowerS v.host ∧ u.port = v.port : Bool)

/-- The fixed comparison is exactly equality of spec origins, for every
pair of URLs that parse. -/
theorem sameOriginFixed_case (x y : Str) (u v : Url) (hx : parse x = some u)
    (hy : parse y = some v) :
    sameOriginFixed x y = some (decide (specOrigin x = specOrigin y)) := by
  simp [sameOriginFixed, specOrigin, hx, hy]

theorem fixed_on_example : sameOriginFixed a b = some true := by
  native_decide

end Flare.Bugs.APP_44
