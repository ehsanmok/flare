import Flare.L4_App.Router

/-!
# `ComptimeRouter` (flare/http/routes.mojo)

`ComptimeRouter[routes]` keeps each pattern as its raw split segments
(`_split_static`) and classifies them on the fly in `_match_one`. It has no
mounts and no fallback. This module proves it routes exactly like the runtime
`Router` built from the same table, and isolates the one difference: the
runtime router rejects a non-final `*` at registration (`_compile_segments`
raises); the comptime router accepts the table, and since the APP-10 fix
`_match_one` makes such a pattern match nothing (before the fix it treated the
middle `*` as a tail wildcard, silently ignoring every pattern segment after
it, `Flare.Bugs.APP_10`). `matchOneOld` / `scanCTOld` / `serveCTOld` are the
pre-fix functions.
-/
namespace Flare.L4.ComptimeRouter

open Flare.L4.Router

/-- `ComptimeRoute`: (method, pattern, handler); the handler is an id here.
mirrors flare/http/routes.mojo:66-78 @59bda50 -/
structure CRoute where
  method : Str
  pattern : Str
  hid : Nat
  deriving DecidableEq, Repr

/-- `_split_static`, `_split_path` and `_path_only` in routes.mojo are
byte-for-byte copies of the router.mojo helpers, so the router model's
`splitPath` / `pathOnly` are reused.
mirrors flare/http/routes.mojo:91-151 @59bda50 -/
abbrev splitStatic := splitPath

/-- mirrors flare/http/routes.mojo:157-162 @59bda50 -/
def isParam (s : Str) : Bool :=
  match s with
  | ':' :: _ :: _ => true
  | _ => false

/-- mirrors flare/http/routes.mojo:165-168 @59bda50 -/
def isWild (s : Str) : Bool := s == ['*']

/-- mirrors flare/http/routes.mojo:171-174 @59bda50 -/
def paramName (s : Str) : Str := s.drop 1

/-- `_match_one` before the APP-10 fix: a `*` captures the rest wherever it
appears.
mirrors flare/http/routes.mojo:250-284 @59bda50 -/
def matchOneOld : List Str → List Str → Option Binds
  | us, [] => if us.isEmpty then some [] else none
  | us, seg :: ps =>
    if isWild seg then
      (if us.isEmpty then none else some [(['*'], joinTail [] us)])
    else
      match us with
      | [] => none
      | u :: us =>
        if isParam seg then (matchOneOld us ps).map ((paramName seg, u) :: ·)
        else if u = seg then matchOneOld us ps else none

/-- `_match_one` as shipped (fixed, APP-10): a `*` that is not the last pattern
segment never matches (`if j != len(pat_segs) - 1: return False`).
mirrors flare/http/routes.mojo:250-290 (fixed, APP-10) -/
def matchOne : List Str → List Str → Option Binds
  | us, [] => if us.isEmpty then some [] else none
  | us, seg :: ps =>
    if isWild seg then
      (if !ps.isEmpty then none else if us.isEmpty then none else some [(['*'], joinTail [] us)])
    else
      match us with
      | [] => none
      | u :: us =>
        if isParam seg then (matchOne us ps).map ((paramName seg, u) :: ·)
        else if u = seg then matchOne us ps else none

/-- Result of the unrolled `comptime for` loop. -/
inductive CScan where
  | hit (hid : Nat) (ps : Binds)
  | miss (allowed : List Str)

/-- The unrolled route loop before the APP-10 fix (uses `matchOneOld`).
mirrors flare/http/routes.mojo:214-240 @59bda50 -/
def scanCTOld (segsIn : List Str) (method : Str) : List CRoute → List Str → CScan
  | [], allowed => .miss allowed
  | c :: cs, allowed =>
    match matchOneOld segsIn (splitStatic c.pattern) with
    | none => scanCTOld segsIn method cs allowed
    | some ps =>
      if c.method = method then .hit c.hid ps
      else scanCTOld segsIn method cs (if allowed.contains c.method then allowed else allowed ++ [c.method])

/-- The unrolled route loop of `ComptimeRouter.serve`.
mirrors flare/http/routes.mojo:214-240 @59bda50 (unchanged by APP-10; the
fix is in `_match_one`) -/
def scanCT (segsIn : List Str) (method : Str) : List CRoute → List Str → CScan
  | [], allowed => .miss allowed
  | c :: cs, allowed =>
    match matchOne segsIn (splitStatic c.pattern) with
    | none => scanCT segsIn method cs allowed
    | some ps =>
      if c.method = method then .hit c.hid ps
      else scanCT segsIn method cs (if allowed.contains c.method then allowed else allowed ++ [c.method])

/-- `ComptimeRouter.serve`. `_not_found` / `_method_not_allowed` in
routes.mojo build the same responses as `not_found` / router
`_method_not_allowed`, so the router's `Outcome` is reused.
mirrors flare/http/routes.mojo:199-244 @59bda50 -/
def serveCT (routes : List CRoute) (req : Req) : Outcome :=
  let segsIn := splitPath (pathOnly req.url)
  match scanCT segsIn req.method routes [] with
  | .hit hid ps => .handler hid { req with params := req.params ++ ps }
  | .miss allowed => if allowed.isEmpty then .notFound req.url else .notAllowed allowed

/-- `ComptimeRouter.serve` before the APP-10 fix. -/
def serveCTOld (routes : List CRoute) (req : Req) : Outcome :=
  let segsIn := splitPath (pathOnly req.url)
  match scanCTOld segsIn req.method routes [] with
  | .hit hid ps => .handler hid { req with params := req.params ++ ps }
  | .miss allowed => if allowed.isEmpty then .notFound req.url else .notAllowed allowed

/-- The runtime route the same table entry would produce (classification
without the registration-time wildcard check). -/
def toRoute (c : CRoute) : Route := ⟨c.method, (splitPath c.pattern).map classify, c.hid⟩

theorem isWild_iff (s : Str) : isWild s = true ↔ classify s = .wild := by
  rw [classify_wild_iff]; simp [isWild]

theorem classify_of_param (s : Str) (h : isParam s = true) : classify s = .param (paramName s) := by
  unfold isParam at h
  split at h
  · simp [classify, paramName]
  · cases h

theorem classify_of_lit (s : Str) (hw : isWild s = false) (hp : isParam s = false) :
    classify s = .lit s := by
  unfold classify
  split
  · simp [isWild] at hw
  · rename_i n
    cases n with
    | nil => simp
    | cons c cs => simp [isParam] at hp
  · rfl

/-- The pre-fix `_match_one` on raw segments is `_match` on the classified
segments, for every pattern (well formed or not). -/
theorem matchOneOld_eq (us raw : List Str) :
    matchOneOld us raw = matchSegs us (raw.map classify) := by
  induction raw generalizing us with
  | nil => cases us <;> simp [matchOneOld, matchSegs]
  | cons s ps ih =>
    cases hw : isWild s
    · cases hp : isParam s
      · rw [List.map_cons, classify_of_lit s hw hp]
        cases us with
        | nil => simp [matchOneOld, matchSegs, hw]
        | cons u us => simp [matchOneOld, matchSegs, ih, hw, hp]
      · rw [List.map_cons, classify_of_param s hp]
        cases us with
        | nil => simp [matchOneOld, matchSegs, hw]
        | cons u us => simp [matchOneOld, matchSegs, ih, hw, hp]
    · rw [List.map_cons, (isWild_iff s).1 hw]
      cases us <;> simp [matchOneOld, matchSegs, hw]

/-- **Shipped `_match_one` meets the matching spec** on every pattern, valid or
not, for normalised request segments (fixed, APP-10). -/
theorem matchOne_eq_spec (us raw : List Str) (hn : NF us) :
    matchOne us raw = specMatch (raw.map classify) us := by
  induction raw generalizing us with
  | nil => cases us <;> simp [matchOne, specMatch]
  | cons s ps ih =>
    cases hw : isWild s
    · cases hp : isParam s
      · rw [List.map_cons, classify_of_lit s hw hp]
        cases us with
        | nil => simp [matchOne, specMatch, hw]
        | cons u us =>
          have hn' : NF us := fun x hx => hn x (List.mem_cons_of_mem _ hx)
          simp only [matchOne, hw, hp, Bool.false_eq_true, if_false, specMatch, ih us hn']
          by_cases h : u = s
          · subst h; simp
          · simp [h, Ne.symm h]
      · rw [List.map_cons, classify_of_param s hp]
        cases us with
        | nil => simp [matchOne, specMatch, hw]
        | cons u us =>
          have hn' : NF us := fun x hx => hn x (List.mem_cons_of_mem _ hx)
          simp [matchOne, specMatch, hw, hp, ih us hn']
    · rw [List.map_cons, (isWild_iff s).1 hw]
      cases ps with
      | nil =>
        cases us with
        | nil => simp [matchOne, specMatch, hw]
        | cons u us =>
          simp only [matchOne, hw, if_true, List.isEmpty_nil, Bool.not_true,
            Bool.false_eq_true, if_false, List.isEmpty_cons, List.map_nil, specMatch]
          rw [joinTail_nil _ _ (hn u List.mem_cons_self).1]
      | cons p ps' =>
        cases us <;> simp [matchOne, specMatch, hw]

/-- A `*` that is not the last pattern segment matches nothing. -/
theorem matchOne_nonfinal_wild (us : List Str) (s : Str) (ps : List Str) (hw : isWild s = true)
    (hps : ps ≠ []) : matchOne us (s :: ps) = none := by
  cases ps with
  | nil => exact absurd rfl hps
  | cons p ps => cases us <;> simp [matchOne, hw]

/-- On valid patterns the shipped `_match_one` is `_match`. -/
theorem matchOne_eq (us raw : List Str) (hw : wf (raw.map classify) = true) (hn : NF us) :
    matchOne us raw = matchSegs us (raw.map classify) := by
  rw [matchOne_eq_spec us raw hn, matchSegs_eq_spec _ _ hw hn]

theorem scanCT_eq (segsIn : List Str) (hn : NF segsIn) (method : Str) :
    ∀ (cs : List CRoute) (acc : List Str),
      (∀ c ∈ cs, wf ((splitPath c.pattern).map classify) = true) →
      scanCT segsIn method cs acc =
        match scan segsIn method (cs.map toRoute) acc with
        | .hit r ps => .hit r.hid ps
        | .miss a => .miss a
  | [], acc, _ => rfl
  | c :: cs, acc, hok => by
    have hc := hok c List.mem_cons_self
    have ih := scanCT_eq segsIn hn method cs
    simp only [scanCT, List.map_cons, scan, matchOne_eq _ _ hc hn]
    simp only [toRoute]
    cases matchSegs segsIn (List.map classify (splitPath c.pattern)) with
    | none => exact ih acc (fun x hx => hok x (List.mem_cons_of_mem _ hx))
    | some ps =>
      simp only
      by_cases he : c.method = method
      · simp [he]
      · simp only [he, if_false]; exact ih _ (fun x hx => hok x (List.mem_cons_of_mem _ hx))

/-- **ComptimeRouter ≡ Router**: on any table whose patterns are valid, the
comptime router returns exactly what the runtime router with the same routes
(no mounts, no fallback) returns. -/
theorem serveCT_eq_serve (routes : List CRoute)
    (hok : ∀ c ∈ routes, wf ((splitPath c.pattern).map classify) = true) (req : Req) :
    serveCT routes req = serve (.mk (routes.map toRoute) .nil none) req := by
  simp only [serveCT, serve, scanCT_eq _ (splitPath_nf _) _ routes [] hok]
  cases scan (splitPath (pathOnly req.url)) req.method (routes.map toRoute) [] with
  | hit r ps => rfl
  | miss a =>
    simp only [serveMounts]

/-- The pre-fix router was equivalent to the runtime router on every table,
valid or not, because it copied the runtime matcher's tail-wildcard step. -/
theorem scanCTOld_eq (segsIn : List Str) (method : Str) :
    ∀ (cs : List CRoute) (acc : List Str),
      scanCTOld segsIn method cs acc =
        match scan segsIn method (cs.map toRoute) acc with
        | .hit r ps => .hit r.hid ps
        | .miss a => .miss a
  | [], acc => rfl
  | c :: cs, acc => by
    simp only [scanCTOld, List.map_cons, scan, matchOneOld_eq]
    have ih := scanCTOld_eq segsIn method cs
    simp only [toRoute]
    cases matchSegs segsIn (List.map classify (splitPath c.pattern)) with
    | none => exact ih acc
    | some ps =>
      simp only
      by_cases he : c.method = method
      · simp [he]
      · simp only [he, if_false]; exact ih _

/-- Registering a table on a fresh `Router`, route by route. -/
def registerAll : Router → List CRoute → Except String Router
  | r, [] => .ok r
  | r, c :: cs =>
    match r.add c.method c.pattern c.hid with
    | .ok r' => registerAll r' cs
    | .error e => .error e

theorem registerAll_ok (cs : List CRoute) (pre : List Route)
    (hok : ∀ c ∈ cs, wf ((splitPath c.pattern).map classify) = true) :
    registerAll (.mk pre .nil none) cs = .ok (.mk (pre ++ cs.map toRoute) .nil none) := by
  induction cs generalizing pre with
  | nil => simp [registerAll]
  | cons c cs ih =>
    have hne : ∀ s ∈ splitPath c.pattern, s ≠ [] := fun s hs => (splitPath_nf _ s hs).1
    obtain ⟨segs, hs⟩ := (compileRaw_ok_iff _ hne).2 (hok c List.mem_cons_self)
    have hseg := compileRaw_ok_map _ _ hne hs
    simp only [registerAll, Router.add, compile, hs]
    rw [ih _ (fun x hx => hok x (List.mem_cons_of_mem _ hx))]
    subst hseg
    simp [toRoute]

/-- **Router ≡ ComptimeRouter on valid patterns**: when every pattern is one
the runtime router accepts, registering the table on a `Router` succeeds
and the resulting router answers every request exactly like
`ComptimeRouter[table]`. -/
theorem router_equiv_comptime (cs : List CRoute)
    (hok : ∀ c ∈ cs, wf ((splitPath c.pattern).map classify) = true) :
    ∃ r, registerAll (.mk [] .nil none) cs = .ok r ∧ ∀ req, serve r req = serveCT cs req := by
  refine ⟨_, registerAll_ok cs [] hok, fun req => ?_⟩
  rw [serveCT_eq_serve cs hok]; rfl

end Flare.L4.ComptimeRouter
