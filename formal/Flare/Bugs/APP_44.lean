import Flare.L4_App.Redirect

/-!
# APP-44: `_same_origin` compares hosts case-sensitively

flare/http/redirect_policy.mojo:188-198 @59bda50, pre-fix (`a.host != b.host`), and
`Url.parse` keeps the host's case (flare/http/url.mojo:172-192). So
`http://API.example.com/` and `http://api.example.com/x` are different
origins: `RedirectPolicy.same_origin_only()` refuses the redirect, and with
the default policy `Authorization` is dropped on what is a same-origin hop.
The error direction is fail-safe (credentials are never sent further than
intended). The same unnormalised host keys the client connection pool
(flare/http/client_pool.mojo:191-201), one bucket per spelling.

Spec: RFC 6454 §4 step 5 (the host is lowercased when computing an origin),
RFC 3986 §3.2.2 and §6.2.2.1 (hosts are case-insensitive).

Status: resolved. `_same_origin` compares `a.host.lower()` with
`b.host.lower()` (flare/http/redirect_policy.mojo:202); the shipped model is
`Flare.L4.Redirect.sameOrigin`, whose origin tuple (`originOf`) now lowercases
the host. The counterexample below is about the explicitly pre-fix
`sameOriginOld`. Regression test: tests/http/test_redirect_policy.mojo::
test_same_origin_ignores_host_case. (The client pool still keys on the
unnormalised host; that is not part of this finding.)
-/
namespace Flare.Bugs.APP_44

open Flare.L4.Redirect

def a : Str := "http://API.example.com/".toList
def b : Str := "http://api.example.com/x".toList

/-- ASCII lowercase. -/
def lowerS (s : Str) : Str := lowerStr s

/-- Spec origin: (scheme, lowercased host, port). -/
def specOrigin (u : Str) : Option (Str × Str × Nat) :=
  (parse u).map fun v => (v.scheme, lowerS v.host, v.port)

/-- Counterexample (pre-fix `sameOriginOld`): same spec origin, but the code
said "not same origin". -/
theorem host_case_not_same_origin :
    specOrigin a = specOrigin b ∧ (specOrigin a).isSome ∧ sameOriginOld a b = some false := by
  native_decide

/-- **Fix meets spec**: the shipped comparison is exactly equality of spec
origins, for every pair of URLs that parse. -/
theorem sameOrigin_case (x y : Str) (u v : Url) (hx : parse x = some u)
    (hy : parse y = some v) :
    sameOrigin x y = some (decide (specOrigin x = specOrigin y)) := by
  simp [sameOrigin, specOrigin, lowerS, hx, hy]

/-- With the shipped comparison `same_origin_only` follows the redirect. -/
theorem fixed_on_example :
    sameOrigin a b = some true ∧
    ((decideR ⟨10, 1, false⟩ a "GET".toList 302 b 0).map Decision.action) = some .follow := by
  native_decide

end Flare.Bugs.APP_44
