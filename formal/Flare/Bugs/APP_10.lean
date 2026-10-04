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
-/
namespace Flare.Bugs.APP_10

open Flare.L4.Router Flare.L4.ComptimeRouter

def pat : Str := "/files/*/meta".toList

/-- The runtime router refuses to register the pattern. -/
theorem router_rejects : (match compile pat with | .error _ => true | .ok _ => false) = true := by
  native_decide

/-- The comptime router dispatches `GET /files/a` to the route. -/
theorem comptime_misroutes :
    serveCT [⟨"GET".toList, pat, 7⟩] ⟨"GET".toList, "/files/a".toList, []⟩ =
      .handler 7 ⟨"GET".toList, "/files/a".toList, [("*".toList, "a".toList)]⟩ := by
  native_decide

/-- Headline counterexample `¬ spec (impl x)`: `_match_one` disagrees with
the matching spec on the classified pattern. -/
theorem matchOne_violates_spec :
    matchOne ["files".toList, "a".toList] (splitStatic pat) ≠
      specMatch ((splitStatic pat).map classify) ["files".toList, "a".toList] := by
  native_decide

/-- Minimal fix: a `*` that is not the last pattern segment never matches
(`if j != len(pat_segs) - 1: return False`). -/
def matchOneFixed : List Str → List Str → Option Binds
  | us, [] => if us.isEmpty then some [] else none
  | us, seg :: ps =>
    if isWild seg then
      (if !ps.isEmpty then none else if us.isEmpty then none else some [(['*'], joinTail [] us)])
    else
      match us with
      | [] => none
      | u :: us =>
        if isParam seg then (matchOneFixed us ps).map ((paramName seg, u) :: ·)
        else if u = seg then matchOneFixed us ps else none

/-- The fixed matcher meets the spec on every pattern, valid or not. -/
theorem fixed_meets_spec (us raw : List Str) (hn : NF us) :
    matchOneFixed us raw = specMatch (raw.map classify) us := by
  induction raw generalizing us with
  | nil => cases us <;> simp [matchOneFixed, specMatch]
  | cons s ps ih =>
    cases hw : isWild s
    · cases hp : isParam s
      · rw [List.map_cons, classify_of_lit s hw hp]
        cases us with
        | nil => simp [matchOneFixed, specMatch, hw]
        | cons u us =>
          have hn' : NF us := fun x hx => hn x (List.mem_cons_of_mem _ hx)
          simp only [matchOneFixed, hw, hp, Bool.false_eq_true, if_false, specMatch, ih us hn']
          by_cases h : u = s
          · subst h; simp
          · simp [h, Ne.symm h]
      · rw [List.map_cons, classify_of_param s hp]
        cases us with
        | nil => simp [matchOneFixed, specMatch, hw]
        | cons u us =>
          have hn' : NF us := fun x hx => hn x (List.mem_cons_of_mem _ hx)
          simp [matchOneFixed, specMatch, hw, hp, ih us hn']
    · rw [List.map_cons, (isWild_iff s).1 hw]
      cases ps with
      | nil =>
        cases us with
        | nil => simp [matchOneFixed, specMatch, hw]
        | cons u us =>
          simp only [matchOneFixed, hw, if_true, List.isEmpty_nil, Bool.not_true,
            Bool.false_eq_true, if_false, List.isEmpty_cons, List.map_nil, specMatch]
          rw [joinTail_nil _ _ (hn u List.mem_cons_self).1]
      | cons p ps' =>
        cases us <;> simp [matchOneFixed, specMatch, hw]

theorem fixed_on_example :
    matchOneFixed ["files".toList, "a".toList] (splitStatic pat) = none := by
  native_decide

end Flare.Bugs.APP_10
