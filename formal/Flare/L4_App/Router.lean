import Flare.Core

/-!
# Runtime `Router` (flare/http/router.mojo)

Model of flare's runtime HTTP router: path splitting, pattern compilation,
segment matching, the dispatch precedence of `Router.serve` (direct routes in
registration order, then mounts in mount order, then 405, then the custom
fallback, then 404), and the prefix stripping done by `_MountedRouter.serve`.

Strings are `List Char` (`Str`): every byte the router inspects (`/`, `?`,
`:`, `*`) is ASCII, and the router never decodes UTF-8 or percent-escapes, so
a character list is an exact stand-in for the byte slices the Mojo code cuts.

Handlers are opaque: a route carries a handler id (`hid`) and the model's
result (`Outcome`) says which handler runs on which child request, or which
synthetic response (405 / fallback / 404) the router builds. The distinction
between `FnHandler` routes and boxed struct-handler routes (`handler_kind`)
does not influence routing and is erased.
-/
namespace Flare.L4.Router

abbrev Str := List Char

/-! ## Path splitting -/

/-- Inner loop of `_split_path`. `cur` is the window `path[start:i]`
(reversed); a `/` flushes it when non-empty (`i > start`), the end of input
flushes it when non-empty (`start < n`).
mirrors flare/http/router.mojo:124-133 @59bda50 -/
def splitLoop : Str → Str → List Str
  | [], cur => if cur.isEmpty then [] else [cur.reverse]
  | c :: cs, cur =>
    if c = '/' then
      (if cur.isEmpty then splitLoop cs [] else cur.reverse :: splitLoop cs [])
    else splitLoop cs (c :: cur)

/-- `_split_path`: a leading `/` is skipped (`start = 1`), then `splitLoop`.
mirrors flare/http/router.mojo:111-133 @59bda50 -/
def splitPath (p : Str) : List Str :=
  match p with
  | '/' :: rest => splitLoop rest []
  | _ => splitLoop p []

/-- Spec helper: RFC 3986 §3.3 decomposition of a path into the segments
between consecutive `/` characters, as (first segment, remaining segments).
Written independently of flare. -/
def rawSegs : Str → Str × List Str
  | [] => ([], [])
  | c :: cs =>
    if c = '/' then ([], (rawSegs cs).1 :: (rawSegs cs).2)
    else (c :: (rawSegs cs).1, (rawSegs cs).2)

/-- Spec of `_split_path` (from its docstring): the RFC 3986 segments with
the empty ones (from leading, trailing or repeated `/`) dropped. -/
def segSpec (p : Str) : List Str :=
  ((rawSegs p).1 :: (rawSegs p).2).filter (fun s => !s.isEmpty)

/-- Normal form of a segment list: every segment non-empty and `/`-free. -/
def NF (segs : List Str) : Prop := ∀ s ∈ segs, s ≠ [] ∧ '/' ∉ s

/-- Join segments with `/` (no leading slash). -/
def joinSlash : List Str → Str
  | [] => []
  | [s] => s
  | s :: t => s ++ '/' :: joinSlash t

/-- Render a segment list as an absolute path. -/
def render (segs : List Str) : Str := '/' :: joinSlash segs

theorem splitLoop_eq (cs cur : Str) :
    splitLoop cs cur =
      ((cur.reverse ++ (rawSegs cs).1) :: (rawSegs cs).2).filter (fun s => !s.isEmpty) := by
  induction cs generalizing cur with
  | nil =>
    cases cur <;> simp [splitLoop, rawSegs]
  | cons c cs ih =>
    by_cases hc : c = '/'
    · subst hc
      cases cur with
      | nil => simp [splitLoop, rawSegs, ih, List.filter_cons]
      | cons x xs => simp [splitLoop, rawSegs, ih, List.filter_cons]
    · simp only [splitLoop, hc, if_false, ih, rawSegs]
      simp

/-- `_split_path` meets its spec. -/
theorem splitPath_eq_spec (p : Str) : splitPath p = segSpec p := by
  unfold splitPath segSpec
  split
  · rename_i rest
    rw [splitLoop_eq]
    simp [rawSegs, List.filter]
  · rw [splitLoop_eq]; simp

theorem rawSegs_noSlash (p : Str) :
    '/' ∉ (rawSegs p).1 ∧ ∀ s ∈ (rawSegs p).2, '/' ∉ s := by
  induction p with
  | nil => simp [rawSegs]
  | cons c cs ih =>
    by_cases hc : c = '/'
    · simp only [rawSegs, hc, if_true]
      refine ⟨by simp, ?_⟩
      intro s hs
      simp only [List.mem_cons] at hs
      rcases hs with rfl | hs
      · exact ih.1
      · exact ih.2 s hs
    · simp only [rawSegs, hc, if_false]
      refine ⟨?_, ih.2⟩
      simp only [List.mem_cons, not_or]
      exact ⟨fun h => hc h.symm, ih.1⟩

theorem rawSegs_sub (p : Str) :
    (∀ c ∈ (rawSegs p).1, c ∈ p) ∧ ∀ s ∈ (rawSegs p).2, ∀ c ∈ s, c ∈ p := by
  induction p with
  | nil => simp [rawSegs]
  | cons c cs ih =>
    by_cases hc : c = '/'
    · simp only [rawSegs, hc, if_true]
      refine ⟨by simp, ?_⟩
      intro s hs x hx
      simp only [List.mem_cons] at hs
      rcases hs with rfl | hs
      · exact List.mem_cons_of_mem _ (ih.1 x hx)
      · exact List.mem_cons_of_mem _ (ih.2 s hs x hx)
    · simp only [rawSegs, hc, if_false]
      refine ⟨?_, fun s hs x hx => List.mem_cons_of_mem _ (ih.2 s hs x hx)⟩
      intro x hx
      simp only [List.mem_cons] at hx
      rcases hx with rfl | hx
      · exact List.mem_cons_self
      · exact List.mem_cons_of_mem _ (ih.1 x hx)

/-- Normal form: `_split_path` never yields an empty segment or one that
contains `/`. -/
theorem splitPath_nf (p : Str) : NF (splitPath p) := by
  rw [splitPath_eq_spec]
  intro s hs
  simp only [segSpec, List.mem_filter, List.mem_cons] at hs
  obtain ⟨hs, hne⟩ := hs
  refine ⟨by intro h; subst h; simp at hne, ?_⟩
  rcases hs with rfl | hs
  · exact (rawSegs_noSlash p).1
  · exact (rawSegs_noSlash p).2 s hs

/-- Every character of every segment comes from the input. -/
theorem splitPath_sub (p : Str) : ∀ s ∈ splitPath p, ∀ c ∈ s, c ∈ p := by
  rw [splitPath_eq_spec]
  intro s hs c hc
  simp only [segSpec, List.mem_filter, List.mem_cons] at hs
  rcases hs.1 with rfl | hs'
  · exact (rawSegs_sub p).1 c hc
  · exact (rawSegs_sub p).2 s hs' c hc

theorem splitLoop_append_noSlash (s rest cur : Str) (h : '/' ∉ s) :
    splitLoop (s ++ rest) cur = splitLoop rest (s.reverse ++ cur) := by
  induction s generalizing cur with
  | nil => simp
  | cons c cs ih =>
    have hc : c ≠ '/' := fun e => h (e ▸ List.mem_cons_self)
    have hcs : '/' ∉ cs := fun e => h (List.mem_cons_of_mem _ e)
    simp only [List.cons_append, splitLoop, hc, if_false]
    rw [ih _ hcs]; simp

theorem splitLoop_joinSlash (segs : List Str) (h : NF segs) :
    splitLoop (joinSlash segs) [] = segs := by
  induction segs with
  | nil => simp [joinSlash, splitLoop]
  | cons s t ih =>
    have hs := h s List.mem_cons_self
    have ht : NF t := fun x hx => h x (List.mem_cons_of_mem _ hx)
    cases t with
    | nil =>
      simp only [joinSlash]
      have := splitLoop_append_noSlash s [] [] hs.2
      simp only [List.append_nil] at this
      rw [this]
      simp [splitLoop, hs.1]
    | cons t1 t2 =>
      simp only [joinSlash]
      rw [splitLoop_append_noSlash _ _ _ hs.2]
      simp only [List.append_nil, splitLoop, if_true, List.isEmpty_reverse]
      have hne : s.isEmpty = false := by cases s <;> simp_all
      simp only [hne, List.reverse_reverse]
      rw [ih ht]; simp

/-- Round trip: splitting a rendered normal-form segment list gives it back. -/
theorem splitPath_render (segs : List Str) (h : NF segs) : splitPath (render segs) = segs := by
  simp only [render, splitPath]
  exact splitLoop_joinSlash segs h

/-- `_split_path` is idempotent through rendering (it computes a normal
form). -/
theorem splitPath_idem (p : Str) : splitPath (render (splitPath p)) = splitPath p :=
  splitPath_render _ (splitPath_nf p)

theorem splitLoop_trailing (p cur : Str) : splitLoop (p ++ ['/']) cur = splitLoop p cur := by
  induction p generalizing cur with
  | nil => cases cur <;> simp [splitLoop]
  | cons c cs ih =>
    simp only [List.cons_append, splitLoop]
    split <;> simp [ih]

theorem splitLoop_dslash (a b cur : Str) :
    splitLoop (a ++ '/' :: '/' :: b) cur = splitLoop (a ++ '/' :: b) cur := by
  induction a generalizing cur with
  | nil => cases cur <;> simp [splitLoop]
  | cons c cs ih =>
    simp only [List.cons_append, splitLoop]
    split <;> simp [ih]

/-- A trailing `/` never changes the segments (`/users/` ≡ `/users`). -/
theorem splitPath_trailing (p : Str) : splitPath (p ++ ['/']) = splitPath p := by
  cases p with
  | nil => simp [splitPath, splitLoop]
  | cons c cs =>
    by_cases hc : c = '/'
    · subst hc; simp [splitPath, splitLoop_trailing]
    · have e1 : splitPath (c :: cs ++ ['/']) = splitLoop (c :: cs ++ ['/']) [] := by
        simp [splitPath, hc]
      have e2 : splitPath (c :: cs) = splitLoop (c :: cs) [] := by simp [splitPath, hc]
      rw [e1, e2, splitLoop_trailing]

/-- Repeated slashes collapse (`/a//b` ≡ `/a/b`), for any non-empty prefix. -/
theorem splitPath_dslash (a b : Str) (ha : a ≠ []) :
    splitPath (a ++ '/' :: '/' :: b) = splitPath (a ++ '/' :: b) := by
  cases a with
  | nil => exact absurd rfl ha
  | cons c cs =>
    by_cases hc : c = '/'
    · subst hc; simp [splitPath, splitLoop_dslash]
    · have e1 : splitPath (c :: cs ++ '/' :: '/' :: b) = splitLoop (c :: cs ++ '/' :: '/' :: b) [] := by
        simp [splitPath, hc]
      have e2 : splitPath (c :: cs ++ '/' :: b) = splitLoop (c :: cs ++ '/' :: b) [] := by
        simp [splitPath, hc]
      rw [e1, e2, splitLoop_dslash]

/-- The leading slash is optional (`users` ≡ `/users`). -/
theorem splitPath_leading (p : Str) (h : p.head? ≠ some '/') : splitPath ('/' :: p) = splitPath p := by
  cases p with
  | nil => simp [splitPath, splitLoop]
  | cons c cs =>
    have hc : c ≠ '/' := by intro e; subst e; simp at h
    simp [splitPath, hc]

/-! ## Query string -/

/-- `_path_only`: everything before the first `?`.
mirrors flare/http/router.mojo:921-929 @59bda50 -/
def pathOnly : Str → Str
  | [] => []
  | c :: cs => if c = '?' then [] else c :: pathOnly cs

/-- `_query_of`: everything after the first `?` (empty if none).
mirrors flare/http/router.mojo:910-918 @59bda50 -/
def queryOf : Str → Str
  | [] => []
  | c :: cs => if c = '?' then cs else queryOf cs

theorem pathOnly_noQ (u : Str) : '?' ∉ pathOnly u := by
  induction u with
  | nil => simp [pathOnly]
  | cons c cs ih =>
    unfold pathOnly; split
    · simp
    · rename_i h; simp only [List.mem_cons, not_or]; exact ⟨fun e => h e.symm, ih⟩

theorem pathOnly_of_noQ (a : Str) (h : '?' ∉ a) : pathOnly a = a := by
  induction a with
  | nil => rfl
  | cons c cs ih =>
    have hc : c ≠ '?' := fun e => h (e ▸ List.mem_cons_self)
    simp [pathOnly, hc, ih (fun e => h (List.mem_cons_of_mem _ e))]

theorem pathOnly_append_q (a q : Str) (h : '?' ∉ a) : pathOnly (a ++ '?' :: q) = a := by
  induction a with
  | nil => simp [pathOnly]
  | cons c cs ih =>
    have hc : c ≠ '?' := fun e => h (e ▸ List.mem_cons_self)
    simp [pathOnly, hc, ih (fun e => h (List.mem_cons_of_mem _ e))]

theorem queryOf_of_noQ (a : Str) (h : '?' ∉ a) : queryOf a = [] := by
  induction a with
  | nil => rfl
  | cons c cs ih =>
    have hc : c ≠ '?' := fun e => h (e ▸ List.mem_cons_self)
    simp [queryOf, hc, ih (fun e => h (List.mem_cons_of_mem _ e))]

theorem queryOf_append_q (a q : Str) (h : '?' ∉ a) : queryOf (a ++ '?' :: q) = q := by
  induction a with
  | nil => simp [queryOf]
  | cons c cs ih =>
    have hc : c ≠ '?' := fun e => h (e ▸ List.mem_cons_self)
    simp [queryOf, hc, ih (fun e => h (List.mem_cons_of_mem _ e))]

/-- The query string never influences routing: `/users?x=1` routes like
`/users`. -/
theorem route_ignores_query (a q : Str) (h : '?' ∉ a) :
    splitPath (pathOnly (a ++ '?' :: q)) = splitPath (pathOnly a) := by
  rw [pathOnly_append_q _ _ h, pathOnly_of_noQ _ h]

/-! ## Pattern compilation -/

/-- A compiled segment (`_Segment.kind` 0 / 1 / 2). -/
inductive Seg where
  | lit (t : Str)
  | param (n : Str)
  | wild
  deriving DecidableEq, Repr

/-- Per-segment classification inside `_compile_segments`: bare `*` is the
wildcard, `:` followed by at least one byte is a parameter, everything else
(including a lone `:`) is a literal.
mirrors flare/http/router.mojo:147-155 @59bda50 -/
def classify (s : Str) : Seg :=
  match s with
  | ['*'] => .wild
  | ':' :: n => if n.isEmpty then .lit s else .param n
  | _ => .lit s

/-- `_compile_segments` over the already-split raw segments. The `sn == 0`
skip is dead code after `_split_path` but is kept; `rest ≠ []` is
`i != len(raw) - 1`.
mirrors flare/http/router.mojo:136-156 @59bda50 -/
def compileRaw : List Str → Except String (List Seg)
  | [] => .ok []
  | s :: rest =>
    if s.isEmpty then compileRaw rest
    else if s = ['*'] ∧ rest ≠ [] then
      .error "wildcard '*' must be the last segment in a route"
    else
      match compileRaw rest with
      | .ok l => .ok (classify s :: l)
      | .error e => .error e

/-- mirrors flare/http/router.mojo:136-140 @59bda50 -/
def compile (p : Str) : Except String (List Seg) := compileRaw (splitPath p)

/-- Well-formed pattern: a wildcard may only be the last segment. -/
def wf : List Seg → Bool
  | [] => true
  | [.wild] => true
  | .wild :: _ :: _ => false
  | _ :: r => wf r

theorem classify_wild_iff (s : Str) : classify s = .wild ↔ s = ['*'] := by
  unfold classify
  split
  · simp
  · rename_i n
    split <;> simp
  · rename_i h1 h2
    constructor
    · intro h; cases h
    · intro h; exact absurd h h1

theorem wf_cons_of_ne (x : Seg) (r : List Seg) (hx : x ≠ .wild) : wf (x :: r) = wf r := by
  cases x with
  | wild => exact absurd rfl hx
  | lit t => cases r <;> rfl
  | param n => cases r <;> rfl

/-- Every pattern `_compile_segments` accepts is well formed. -/
theorem compileRaw_wf (raw : List Str) (segs : List Seg) (h : compileRaw raw = .ok segs) :
    wf segs = true := by
  induction raw generalizing segs with
  | nil => simp [compileRaw] at h; subst h; rfl
  | cons s rest ih =>
    unfold compileRaw at h
    split at h
    · exact ih _ h
    · split at h
      · cases h
      · rename_i hne hnw
        split at h
        · rename_i l hl
          cases h
          by_cases hw : s = ['*']
          · have : rest = [] := if hr : rest = [] then hr else absurd ⟨hw, hr⟩ hnw
            subst this
            simp [compileRaw] at hl; subst hl
            subst hw; rfl
          · have hc : classify s ≠ .wild := fun e => hw ((classify_wild_iff s).1 e)
            rw [wf_cons_of_ne _ _ hc]; exact ih _ hl
        · cases h

/-- Compilation of a split path classifies every segment. -/
theorem compileRaw_ok_map (raw : List Str) (segs : List Seg)
    (hne : ∀ s ∈ raw, s ≠ []) (h : compileRaw raw = .ok segs) : segs = raw.map classify := by
  induction raw generalizing segs with
  | nil => simp [compileRaw] at h; simp [← h]
  | cons s rest ih =>
    have hs : s ≠ [] := hne s List.mem_cons_self
    have hs' : s.isEmpty = false := by cases s <;> simp_all
    unfold compileRaw at h
    simp only [hs', Bool.false_eq_true, if_false] at h
    split at h
    · cases h
    · split at h
      · rename_i l hl; cases h
        rw [ih l (fun x hx => hne x (List.mem_cons_of_mem _ hx)) hl]; rfl
      · cases h

/-- `_compile_segments` succeeds exactly on patterns whose classified
segments are well formed. -/
theorem compileRaw_ok_iff (raw : List Str) (hne : ∀ s ∈ raw, s ≠ []) :
    (∃ segs, compileRaw raw = .ok segs) ↔ wf (raw.map classify) = true := by
  induction raw with
  | nil => simp [compileRaw, wf]
  | cons s rest ih =>
    have hs : s ≠ [] := hne s List.mem_cons_self
    have hs' : s.isEmpty = false := by cases s <;> simp_all
    have ih' := ih (fun x hx => hne x (List.mem_cons_of_mem _ hx))
    unfold compileRaw
    simp only [hs', Bool.false_eq_true, if_false, List.map_cons]
    by_cases hw : s = ['*']
    · subst hw
      cases rest with
      | nil => simp [compileRaw, classify, wf]
      | cons r rs => simp [classify, wf]
    · have hc : classify s ≠ .wild := fun e => hw ((classify_wild_iff s).1 e)
      rw [wf_cons_of_ne _ _ hc, ← ih']
      have : ¬ (s = ['*'] ∧ rest ≠ []) := fun h => hw h.1
      simp only [this, if_false]
      constructor
      · rintro ⟨segs, h⟩
        split at h
        · rename_i l hl; exact ⟨l, hl⟩
        · cases h
      · rintro ⟨l, hl⟩
        exact ⟨classify s :: l, by simp [hl]⟩

/-! ## Segment matching -/

abbrev Binds := List (Str × Str)

/-- Wildcard tail accumulation: `if tail: tail += "/"; tail += seg`.
mirrors flare/http/router.mojo:853-858 @59bda50 -/
def joinTail : Str → List Str → Str
  | tail, [] => tail
  | tail, u :: us => joinTail ((if tail.isEmpty then tail else tail ++ ['/']) ++ u) us

/-- `_match`: captured params are listed left to right (the Mojo `Dict`
keeps insertion order; on a repeated name the later value wins on lookup).
mirrors flare/http/router.mojo:838-873 @59bda50 -/
def matchSegs : List Str → List Seg → Option Binds
  | us, [] => if us.isEmpty then some [] else none
  | us, .wild :: _ => if us.isEmpty then none else some [(['*'], joinTail [] us)]
  | [], _ :: _ => none
  | u :: us, .lit t :: ps => if u = t then matchSegs us ps else none
  | u :: us, .param n :: ps => (matchSegs us ps).map ((n, u) :: ·)

/-- Spec of matching, from the module docstring (router.mojo:6-10):
literals match exactly, `:name` matches one segment and captures it, a final
`*` matches the non-empty rest of the path joined with `/`. A wildcard that is
not last matches nothing. Written independently of `_match`. -/
def specMatch : List Seg → List Str → Option Binds
  | [], [] => some []
  | [.wild], u :: us => some [(['*'], joinSlash (u :: us))]
  | .lit t :: ps, u :: us => if t = u then specMatch ps us else none
  | .param n :: ps, u :: us => (specMatch ps us).map ((n, u) :: ·)
  | _, _ => none

theorem joinTail_eq (tail : Str) (us : List Str) (ht : tail ≠ []) :
    joinTail tail us = joinSlash (tail :: us) := by
  induction us generalizing tail with
  | nil => simp [joinTail, joinSlash]
  | cons u us ih =>
    have hte : tail.isEmpty = false := by cases tail <;> simp_all
    simp only [joinTail, hte, Bool.false_eq_true, if_false]
    rw [ih _ (by simp)]
    cases us <;> simp [joinSlash]

theorem joinTail_nil (u : Str) (us : List Str) (hu : u ≠ []) :
    joinTail [] (u :: us) = joinSlash (u :: us) := by
  simp only [joinTail, List.isEmpty_nil, if_true, List.nil_append]
  exact joinTail_eq u us hu

/-- `_match` meets the matching spec on well-formed patterns and
normal-form request segments. -/
theorem matchSegs_eq_spec (ps : List Seg) (us : List Str) (hw : wf ps = true) (hn : NF us) :
    matchSegs us ps = specMatch ps us := by
  induction ps generalizing us with
  | nil => cases us <;> simp [matchSegs, specMatch]
  | cons p ps ih =>
    cases p with
    | wild =>
      cases ps with
      | cons _ _ => simp [wf] at hw
      | nil =>
        cases us with
        | nil => simp [matchSegs, specMatch]
        | cons u us =>
          simp only [matchSegs, List.isEmpty_cons, Bool.false_eq_true, if_false, specMatch]
          rw [joinTail_nil _ _ (hn u List.mem_cons_self).1]
    | lit t =>
      have hw' : wf ps = true := by rw [wf_cons_of_ne _ _ (by simp)] at hw; exact hw
      cases us with
      | nil => simp [matchSegs, specMatch]
      | cons u us =>
        have hn' : NF us := fun x hx => hn x (List.mem_cons_of_mem _ hx)
        simp only [matchSegs, specMatch, ih us hw' hn']
        by_cases h : u = t
        · subst h; simp
        · simp [h, Ne.symm h]
    | param n =>
      have hw' : wf ps = true := by rw [wf_cons_of_ne _ _ (by simp)] at hw; exact hw
      cases us with
      | nil => simp [matchSegs, specMatch]
      | cons u us =>
        have hn' : NF us := fun x hx => hn x (List.mem_cons_of_mem _ hx)
        simp only [matchSegs, specMatch, ih us hw' hn']

/-- A matched literal-only pattern consumes exactly its segments. -/
theorem specMatch_lits (ts us : List Str) :
    (specMatch (ts.map .lit) us).isSome = true ↔ us = ts := by
  induction ts generalizing us with
  | nil => cases us <;> simp [specMatch]
  | cons t ts ih =>
    cases us with
    | nil => simp [specMatch]
    | cons u us =>
      simp only [List.map_cons, specMatch]
      by_cases h : t = u
      · subst h; simp [ih]
      · simp [h, Ne.symm h]

/-! ## The router -/

/-- `_Route`: method, compiled segments, handler id.
mirrors flare/http/router.mojo:175-196 @59bda50 -/
structure Route where
  method : Str
  segs : List Seg
  hid : Nat
  deriving DecidableEq, Repr

mutual
/-- `Router`: routes in registration order, mounts in mount order, optional
fallback handler id.
mirrors flare/http/router.mojo:339-394 @59bda50 -/
inductive Router where
  | mk (routes : List Route) (mounts : Mounts) (fallback : Option Nat)
/-- `_mounts`: (literal prefix segments, mounted sub-router).
mirrors flare/http/router.mojo:199-214 @59bda50 -/
inductive Mounts where
  | nil
  | cons (pre : List Str) (sub : Router) (rest : Mounts)
end

/-- A request as the router sees it. `params` models `req._params`
(lookup = last binding wins, as `child.params_mut()[k] = v` overwrites). -/
structure Req where
  method : Str
  url : Str
  params : Binds
  deriving DecidableEq, Repr

/-- What `Router.serve` does with a request. -/
inductive Outcome where
  /-- Run handler `hid` on this child request. -/
  | handler (hid : Nat) (req : Req)
  /-- `_method_not_allowed`: 405 with `Allow: <allow joined by ", ">`. -/
  | notAllowed (allow : List Str)
  /-- Run the custom fallback handler on this child request. -/
  | fallback (hid : Nat) (req : Req)
  /-- `not_found(req.url)`: 404 with body `Not Found: <url>`. -/
  | notFound (url : Str)
  deriving DecidableEq, Repr

/-- HTTP status class of an outcome (`none` = whatever the handler returns). -/
def Outcome.status : Outcome → Option Nat
  | .handler _ _ => none
  | .notAllowed _ => some 405
  | .fallback _ _ => none
  | .notFound _ => some 404

/-- `_add_fn` / `_add_struct`: compile the pattern (raising on a bad one) and
append the route.
mirrors flare/http/router.mojo:488-498 @59bda50 -/
def Router.add : Router → Str → Str → Nat → Except String Router
  | .mk routes ms fb, method, pat, hid =>
    match compile pat with
    | .ok segs => .ok (.mk (routes ++ [⟨method, segs, hid⟩]) ms fb)
    | .error e => .error e

/-- Result of the direct-route scan. -/
inductive Scan where
  | hit (r : Route) (ps : Binds)
  | miss (allowed : List Str)

/-- The direct-route loop of `Router.serve`: first route whose pattern
matches and whose method equals the request method wins; matching routes
with another method are appended to `allowed` unless already present.
mirrors flare/http/router.mojo:684-692 @59bda50 -/
def scan (segsIn : List Str) (method : Str) : List Route → List Str → Scan
  | [], allowed => .miss allowed
  | r :: rs, allowed =>
    match matchSegs segsIn r.segs with
    | none => scan segsIn method rs allowed
    | some ps =>
      if r.method = method then .hit r ps
      else scan segsIn method rs (if allowed.contains r.method then allowed else allowed ++ [r.method])

/-- `_prefix_match`.
mirrors flare/http/router.mojo:899-907 @59bda50 -/
def prefixMatch : List Str → List Str → Bool
  | _, [] => true
  | [], _ :: _ => false
  | u :: us, p :: ps => u == p && prefixMatch us ps

/-- `_MountedRouter.serve` URL rebuild: drop the first `k` segments, keep the
query string.
mirrors flare/http/router.mojo:800-810 @59bda50 -/
def stripUrl (k : Nat) (url : Str) : Str :=
  let segs := splitPath (pathOnly url)
  let rebuilt := '/' :: joinSlash (segs.drop k)
  let q := queryOf url
  if q.isEmpty then rebuilt else rebuilt ++ '?' :: q

mutual
/-- `Router.serve`.
mirrors flare/http/router.mojo:675-776 @59bda50 -/
def serve : Router → Req → Outcome
  | .mk routes ms fb, req =>
    let segsIn := splitPath (pathOnly req.url)
    match scan segsIn req.method routes [] with
    | .hit r ps => .handler r.hid { req with params := req.params ++ ps }
    | .miss allowed => serveMounts ms fb segsIn req allowed

/-- Mount delegation and the final 405 / fallback / 404 choice;
`_MountedRouter.serve` forwards the stripped request (same params) to the
sub-router.
mirrors flare/http/router.mojo:740-776, 800-823 @59bda50 -/
def serveMounts : Mounts → Option Nat → List Str → Req → List Str → Outcome
  | .nil, fb, _, req, allowed =>
    if allowed.isEmpty then
      (match fb with
       | some h => .fallback h req
       | none => .notFound req.url)
    else .notAllowed allowed
  | .cons pre sub rest, fb, segsIn, req, allowed =>
    if prefixMatch segsIn pre then serve sub { req with url := stripUrl pre.length req.url }
    else serveMounts rest fb segsIn req allowed
end

/-! ### Spec -/

/-- Keep the first occurrence of each element, in order. -/
def uniqAux : List Str → List Str → List Str
  | [], seen => seen
  | x :: xs, seen => uniqAux xs (if x ∈ seen then seen else seen ++ [x])

def uniq (l : List Str) : List Str := uniqAux l []

/-- A route "hits" when its pattern matches and its method is the request
method. -/
def hitB (segsIn : List Str) (method : Str) (r : Route) : Bool :=
  r.method == method && (specMatch r.segs segsIn).isSome

/-- The documented `Allow` value: the methods of every route whose pattern
matches the path, each once, in registration order (RFC 9110 §10.2.1: the
set of methods the target resource supports). -/
def allowSpec (segsIn : List Str) (routes : List Route) : List Str :=
  uniq ((routes.filter (fun r => (specMatch r.segs segsIn).isSome)).map Route.method)

mutual
/-- Spec of `Router.serve`, written from the module and method docstrings
(router.mojo:1-26, 475-486, 614-632): the first registered route matching
path and method wins; otherwise the first mount whose literal prefix is a
segment-prefix of the path gets the request with that prefix removed (query
string kept); otherwise 405 with the Allow set if the path is known under
other methods; otherwise the fallback; otherwise 404. -/
def serveSpec : Router → Req → Outcome
  | .mk routes ms fb, req =>
    let segsIn := splitPath (pathOnly req.url)
    match routes.find? (hitB segsIn req.method) with
    | some r => .handler r.hid { req with params := req.params ++ (specMatch r.segs segsIn).getD [] }
    | none => mountsSpec ms fb segsIn req (allowSpec segsIn routes)

def mountsSpec : Mounts → Option Nat → List Str → Req → List Str → Outcome
  | .nil, fb, _, req, allow =>
    if allow = [] then
      (match fb with
       | some h => .fallback h req
       | none => .notFound req.url)
    else .notAllowed allow
  | .cons pre sub rest, fb, segsIn, req, allow =>
    if pre <+: segsIn then
      serveSpec sub { req with
        url := '/' :: joinSlash (segsIn.drop pre.length) ++
               (if (queryOf req.url).isEmpty then [] else '?' :: queryOf req.url) }
    else mountsSpec rest fb segsIn req allow
end

mutual
/-- Every route pattern in the tree is well formed (true for any router
built through `Router.add`, by `compileRaw_wf`). -/
def Router.WF : Router → Prop
  | .mk routes ms _ => (∀ r ∈ routes, wf r.segs = true) ∧ ms.WF
def Mounts.WF : Mounts → Prop
  | .nil => True
  | .cons _ sub rest => sub.WF ∧ rest.WF
end

/-! ### Lemmas about the scan -/

theorem uniqAux_nodup (l seen : List Str) (h : seen.Nodup) : (uniqAux l seen).Nodup := by
  induction l generalizing seen with
  | nil => exact h
  | cons x xs ih =>
    simp only [uniqAux]
    split
    · exact ih _ h
    · rename_i hx
      apply ih
      rw [List.nodup_append]
      refine ⟨h, by simp, ?_⟩
      intro a ha b hb; simp at hb; subst hb; intro e; subst e; exact hx ha

theorem mem_uniqAux (l seen : List Str) (x : Str) : x ∈ uniqAux l seen ↔ x ∈ seen ∨ x ∈ l := by
  induction l generalizing seen with
  | nil => simp [uniqAux]
  | cons y ys ih =>
    simp only [uniqAux]
    split
    · rw [ih]; simp only [List.mem_cons]
      constructor
      · rintro (h | h)
        · exact Or.inl h
        · exact Or.inr (Or.inr h)
      · rintro (h | rfl | h)
        · exact Or.inl h
        · exact Or.inl (by assumption)
        · exact Or.inr h
    · rw [ih]; simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false]
      constructor
      · rintro ((h | h) | h)
        · exact Or.inl h
        · exact Or.inr (Or.inl h)
        · exact Or.inr (Or.inr h)
      · rintro (h | h | h)
        · exact Or.inl (Or.inl h)
        · exact Or.inl (Or.inr h)
        · exact Or.inr h

theorem uniq_nodup (l : List Str) : (uniq l).Nodup := uniqAux_nodup l [] List.nodup_nil

theorem mem_uniq (l : List Str) (x : Str) : x ∈ uniq l ↔ x ∈ l := by
  simp [uniq, mem_uniqAux]

theorem contains_iff (l : List Str) (x : Str) : l.contains x = true ↔ x ∈ l := by
  simp

/-- Under well-formedness the impl matcher is the spec matcher, route by
route. -/
theorem match_route (segsIn : List Str) (r : Route) (hw : wf r.segs = true) :
    matchSegs segsIn r.segs = specMatch r.segs segsIn ∨ ¬ NF segsIn := by
  by_cases hn : NF segsIn
  · exact Or.inl (matchSegs_eq_spec _ _ hw hn)
  · exact Or.inr hn

theorem scan_spec (segsIn : List Str) (method : Str) (hn : NF segsIn) :
    ∀ (routes : List Route) (acc : List Str), (∀ r ∈ routes, wf r.segs = true) →
      scan segsIn method routes acc =
        match routes.find? (hitB segsIn method) with
        | some r => .hit r ((specMatch r.segs segsIn).getD [])
        | none => .miss (uniqAux ((routes.filter (fun r => (specMatch r.segs segsIn).isSome)).map Route.method) acc)
  | [], acc, _ => by simp [scan, uniqAux]
  | r :: rs, acc, hw => by
    have hr := matchSegs_eq_spec r.segs segsIn (hw r List.mem_cons_self) hn
    have ih := scan_spec segsIn method hn rs
    simp only [scan, hr]
    cases hm : specMatch r.segs segsIn with
    | none =>
      simp only
      rw [ih _ (fun x hx => hw x (List.mem_cons_of_mem _ hx))]
      simp [List.find?, hitB, hm, List.filter]
    | some ps =>
      simp only
      by_cases he : r.method = method
      · simp [he, List.find?, hitB, hm]
      · simp only [he, if_false]
        rw [ih _ (fun x hx => hw x (List.mem_cons_of_mem _ hx))]
        have hb : hitB segsIn method r = false := by simp [hitB, he]
        simp only [List.find?, hb, List.filter, hm, Option.isSome_some, List.map_cons, uniqAux,
          contains_iff]

theorem prefixMatch_iff (us ps : List Str) : prefixMatch us ps = true ↔ ps <+: us := by
  induction ps generalizing us with
  | nil => simp [prefixMatch]
  | cons p ps ih =>
    cases us with
    | nil => simp [prefixMatch]
    | cons u us =>
      simp only [prefixMatch, Bool.and_eq_true, beq_iff_eq, ih, List.cons_prefix_cons]
      constructor
      · rintro ⟨rfl, h⟩; exact ⟨rfl, h⟩
      · rintro ⟨rfl, h⟩; exact ⟨rfl, h⟩

theorem nf_drop (segs : List Str) (k : Nat) (h : NF segs) : NF (segs.drop k) :=
  fun s hs => h s (List.mem_of_mem_drop hs)

theorem joinSlash_noQ (segs : List Str) (h : ∀ s ∈ segs, '?' ∉ s) : '?' ∉ joinSlash segs := by
  induction segs with
  | nil => simp [joinSlash]
  | cons s t ih =>
    have hs := h s List.mem_cons_self
    have ht := ih (fun x hx => h x (List.mem_cons_of_mem _ hx))
    cases t with
    | nil => simpa [joinSlash] using hs
    | cons t1 t2 =>
      simp only [joinSlash, List.mem_append, List.mem_cons, not_or]
      refine ⟨hs, by decide, ?_⟩
      simpa [joinSlash] using ht

/-- Segments of a request path never contain `?`. -/
theorem segs_noQ (url : Str) : ∀ s ∈ splitPath (pathOnly url), '?' ∉ s :=
  fun s hs hq => pathOnly_noQ url (splitPath_sub _ s hs '?' hq)

/-- The rebuilt URL of a mounted request splits to the remaining segments. -/
theorem stripUrl_segs (k : Nat) (url : Str) :
    splitPath (pathOnly (stripUrl k url)) = (splitPath (pathOnly url)).drop k := by
  have hnq : '?' ∉ ('/' :: joinSlash ((splitPath (pathOnly url)).drop k)) := by
    simp only [List.mem_cons, not_or]
    exact ⟨by decide, joinSlash_noQ _ (fun s hs => segs_noQ url s (List.mem_of_mem_drop hs))⟩
  unfold stripUrl
  simp only
  split
  · rw [pathOnly_of_noQ _ hnq]
    exact splitPath_render _ (nf_drop _ _ (splitPath_nf _))
  · rw [pathOnly_append_q _ _ hnq]
    exact splitPath_render _ (nf_drop _ _ (splitPath_nf _))

/-- The rebuilt URL keeps the query string. -/
theorem stripUrl_query (k : Nat) (url : Str) : queryOf (stripUrl k url) = queryOf url := by
  have hnq : '?' ∉ ('/' :: joinSlash ((splitPath (pathOnly url)).drop k)) := by
    simp only [List.mem_cons, not_or]
    exact ⟨by decide, joinSlash_noQ _ (fun s hs => segs_noQ url s (List.mem_of_mem_drop hs))⟩
  unfold stripUrl
  simp only
  split
  · rename_i h; rw [queryOf_of_noQ _ hnq]; simp at h; exact h.symm
  · rw [queryOf_append_q _ _ hnq]

theorem stripUrl_eq (k : Nat) (url : Str) :
    stripUrl k url = '/' :: joinSlash ((splitPath (pathOnly url)).drop k) ++
      (if (queryOf url).isEmpty then [] else '?' :: queryOf url) := by
  unfold stripUrl; split <;> simp_all

/-- **Mount stripping composes**: stripping `k₁` then `k₂` segments is
stripping `k₁ + k₂` (query string preserved). -/
theorem stripUrl_compose (k₁ k₂ : Nat) (url : Str) :
    stripUrl k₂ (stripUrl k₁ url) = stripUrl (k₁ + k₂) url := by
  rw [stripUrl_eq k₂ (stripUrl k₁ url), stripUrl_segs, stripUrl_query, List.drop_drop,
    stripUrl_eq (k₁ + k₂)]

/-! ### Main theorems -/

mutual
/-- **Router meets its spec** (on routers built from accepted patterns). -/
theorem serve_eq_spec : ∀ (r : Router) (req : Req), r.WF → serve r req = serveSpec r req
  | .mk routes ms fb, req, hw => by
    simp only [Router.WF] at hw
    simp only [serve, serveSpec]
    rw [scan_spec _ _ (splitPath_nf _) routes [] hw.1]
    cases routes.find? (hitB (splitPath (pathOnly req.url)) req.method) with
    | some r => rfl
    | none =>
      simp only
      exact serveMounts_eq_spec ms fb _ req _ rfl hw.2
theorem serveMounts_eq_spec : ∀ (ms : Mounts) (fb : Option Nat) (segsIn : List Str) (req : Req)
    (allow : List Str), segsIn = splitPath (pathOnly req.url) → ms.WF →
    serveMounts ms fb segsIn req allow = mountsSpec ms fb segsIn req allow
  | .nil, fb, segsIn, req, allow, _, _ => by
    simp only [serveMounts, mountsSpec, List.isEmpty_iff]
  | .cons pre sub rest, fb, segsIn, req, allow, hs, hw => by
    simp only [Mounts.WF] at hw
    simp only [serveMounts, mountsSpec]
    by_cases hp : pre <+: segsIn
    · have : prefixMatch segsIn pre = true := (prefixMatch_iff _ _).2 hp
      simp only [this, if_true, hp]
      rw [serve_eq_spec sub _ hw.1, stripUrl_eq, ← hs]
    · have : prefixMatch segsIn pre = false := by
        cases h : prefixMatch segsIn pre
        · rfl
        · exact absurd ((prefixMatch_iff _ _).1 h) hp
      simp only [this, hp, if_false, Bool.false_eq_true]
      exact serveMounts_eq_spec rest fb segsIn req allow hs hw.2
end

/-- Determinism, stated for the record: `serve` is a total function of the
router and the request, so two runs on the same input agree (the Mojo code
reads no clock, no randomness and no global state on this path). -/
theorem serve_deterministic (r : Router) (req : Req) (o₁ o₂ : Outcome)
    (h₁ : serve r req = o₁) (h₂ : serve r req = o₂) : o₁ = o₂ := h₁ ▸ h₂

/-- Well-formed outcome: a 405 always carries a non-empty, duplicate-free
`Allow` list. -/
def Outcome.Valid : Outcome → Prop
  | .notAllowed L => L ≠ [] ∧ L.Nodup
  | _ => True

theorem scan_miss_nodup (segsIn : List Str) (method : Str) (routes : List Route)
    (hn : NF segsIn) (hw : ∀ r ∈ routes, wf r.segs = true) (allowed : List Str)
    (h : scan segsIn method routes [] = .miss allowed) : allowed.Nodup := by
  rw [scan_spec _ _ hn routes [] hw] at h
  split at h
  · cases h
  · cases h; exact uniqAux_nodup _ _ List.nodup_nil

mutual
/-- **Result classes**: every outcome is a handler call, a 405 with a
non-empty duplicate-free `Allow`, the fallback, or a 404 — through any depth
of mounts. -/
theorem serve_valid : ∀ (r : Router) (req : Req), r.WF → (serve r req).Valid
  | .mk routes ms fb, req, hw => by
    simp only [Router.WF] at hw
    simp only [serve]
    cases hs : scan (splitPath (pathOnly req.url)) req.method routes [] with
    | hit r ps => simp [Outcome.Valid]
    | miss allowed =>
      simp only
      exact serveMounts_valid ms fb _ req allowed hw.2
        (scan_miss_nodup _ _ routes (splitPath_nf _) hw.1 allowed hs)
theorem serveMounts_valid : ∀ (ms : Mounts) (fb : Option Nat) (segsIn : List Str) (req : Req)
    (allow : List Str), ms.WF → allow.Nodup → (serveMounts ms fb segsIn req allow).Valid
  | .nil, fb, segsIn, req, allow, _, hn => by
    simp only [serveMounts]
    split
    · split <;> simp [Outcome.Valid]
    · rename_i he
      refine ⟨?_, hn⟩
      intro e; subst e; simp at he
  | .cons pre sub rest, fb, segsIn, req, allow, hw, hn => by
    simp only [Mounts.WF] at hw
    simp only [serveMounts]
    split
    · exact serve_valid sub _ hw.1
    · exact serveMounts_valid rest fb segsIn req allow hw.2 hn
end

/-- **Allow header** (router without mounts): a 405 lists each method once,
exactly the methods of the routes whose pattern matches the path, and never
the request's own method. -/
theorem allow_exact (routes : List Route) (fb : Option Nat) (req : Req) (L : List Str)
    (hw : ∀ r ∈ routes, wf r.segs = true)
    (h : serve (.mk routes .nil fb) req = .notAllowed L) :
    L.Nodup ∧
    (∀ m, m ∈ L ↔ ∃ r ∈ routes, (specMatch r.segs (splitPath (pathOnly req.url))).isSome ∧ r.method = m) ∧
    req.method ∉ L := by
  rw [serve_eq_spec _ _ (by simpa [Router.WF, Mounts.WF] using hw)] at h
  simp only [serveSpec] at h
  split at h
  · cases h
  · rename_i hf
    simp only [mountsSpec] at h
    split at h
    · split at h <;> cases h
    · cases h
      refine ⟨uniq_nodup _, ?_, ?_⟩
      · intro m
        simp only [allowSpec, mem_uniq, List.mem_map, List.mem_filter]
        constructor
        · rintro ⟨r, ⟨hr, hm⟩, rfl⟩; exact ⟨r, hr, hm, rfl⟩
        · rintro ⟨r, hr, hm, rfl⟩; exact ⟨r, ⟨hr, hm⟩, rfl⟩
      · intro hm
        simp only [allowSpec, mem_uniq, List.mem_map, List.mem_filter] at hm
        obtain ⟨r, ⟨hr, hmt⟩, he⟩ := hm
        have := List.find?_eq_none.1 hf r hr
        simp [hitB, he, hmt] at this

/-- Registration-order shadowing: if the first route that matches path and
method is `r`, `r` handles the request whatever comes after it. -/
theorem first_route_wins (routes rest : List Route) (r : Route) (ms : Mounts) (fb : Option Nat)
    (req : Req) (hw : (∀ x ∈ routes ++ r :: rest, wf x.segs = true) ∧ ms.WF)
    (hpre : ∀ x ∈ routes, hitB (splitPath (pathOnly req.url)) req.method x = false)
    (hr : hitB (splitPath (pathOnly req.url)) req.method r = true) :
    ∃ ps, serve (.mk (routes ++ r :: rest) ms fb) req = .handler r.hid { req with params := req.params ++ ps } := by
  rw [serve_eq_spec _ _ (by simpa [Router.WF] using hw)]
  simp only [serveSpec]
  have : (routes ++ r :: rest).find? (hitB (splitPath (pathOnly req.url)) req.method) = some r := by
    rw [List.find?_append]
    have : routes.find? (hitB (splitPath (pathOnly req.url)) req.method) = none :=
      List.find?_eq_none.2 (fun x hx => by simp [hpre x hx])
    simp [this, List.find?, hr]
  rw [this]
  exact ⟨_, rfl⟩

theorem drop_of_prefix (p₁ p₂ S : List Str) (h : (p₁ ++ p₂) <+: S) : p₂ <+: S.drop p₁.length := by
  obtain ⟨t, rfl⟩ := h
  simp [List.append_assoc]

/-- **Nested mounts = concatenated prefix**: mounting `leaf` at `p₂` inside a
router mounted at `p₁` behaves exactly like mounting `leaf` at `p₁ ++ p₂`, for
every request under that prefix (and any direct routes / fallback on the
outer router). -/
theorem mount_compose (R : List Route) (fb fb' : Option Nat) (p₁ p₂ : List Str) (leaf : Router)
    (req : Req) (h : (p₁ ++ p₂) <+: splitPath (pathOnly req.url)) :
    serve (.mk R (.cons p₁ (.mk [] (.cons p₂ leaf .nil) fb') .nil) fb) req =
    serve (.mk R (.cons (p₁ ++ p₂) leaf .nil) fb) req := by
  simp only [serve]
  cases scan (splitPath (pathOnly req.url)) req.method R [] with
  | hit r ps => rfl
  | miss allowed =>
    simp only [serveMounts]
    have h1 : prefixMatch (splitPath (pathOnly req.url)) p₁ = true :=
      (prefixMatch_iff _ _).2 (List.IsPrefix.trans (List.prefix_append _ _) h)
    have h12 : prefixMatch (splitPath (pathOnly req.url)) (p₁ ++ p₂) = true :=
      (prefixMatch_iff _ _).2 h
    have h2 : prefixMatch ((splitPath (pathOnly req.url)).drop p₁.length) p₂ = true :=
      (prefixMatch_iff _ _).2 (drop_of_prefix _ _ _ h)
    simp only [h1, h12, if_true, serve, scan, stripUrl_segs, serveMounts, h2,
      stripUrl_compose, List.length_append]

/-- A mount claims its prefix before the parent's 405: with a direct
`POST /api/x` and a mount at `/api` whose sub-router has no routes,
`GET /api/x` is the sub-router's 404, not the parent's 405 (documented at
router.mojo:734-739). -/
theorem mount_beats_405 :
    serve (.mk [⟨"POST".toList, [.lit "api".toList, .lit "x".toList], 0⟩]
             (.cons ["api".toList] (.mk [] .nil none) .nil) none)
          ⟨"GET".toList, "/api/x".toList, []⟩ = .notFound "/x".toList := by
  decide

/-- Mount prefixes match whole segments: `/api` does not claim `/apix`. -/
theorem mount_boundary :
    prefixMatch (splitPath (pathOnly "/apix/y".toList)) ["api".toList] = false ∧
    prefixMatch (splitPath (pathOnly "/api/y".toList)) ["api".toList] = true := by
  decide

/-- Trailing slash and repeated slashes do not change routing. -/
theorem slash_examples :
    splitPath "/users/".toList = ["users".toList] ∧
    splitPath "users".toList = ["users".toList] ∧
    splitPath "//a///b//".toList = ["a".toList, "b".toList] ∧
    splitPath "/".toList = [] := by
  decide

/-- A wildcard must consume at least one segment (`/files/*` does not match
`/files`), and captures the rest joined by `/`. -/
theorem wild_examples :
    matchSegs ["files".toList] [.lit "files".toList, .wild] = none ∧
    matchSegs ["files".toList, "a".toList, "b".toList] [.lit "files".toList, .wild] =
      some [("*".toList, "a/b".toList)] := by
  decide

/-- `_compile_segments` rejects a non-final wildcard and treats a lone `:` as
a literal. -/
theorem compile_examples :
    (match compile "/a/*/b".toList with | .error _ => true | .ok _ => false) = true ∧
    (match compile "/a/:/:id/*".toList with
     | .ok l => l == [.lit "a".toList, .lit ":".toList, .param "id".toList, .wild]
     | .error _ => false) = true := by
  decide

/-- Inside a mount, the 404 body names the stripped path (`/x`), not the
path the client sent (`/api/x`). Observable but harmless. -/
theorem mount_404_url :
    serve (.mk [] (.cons ["api".toList] (.mk [] .nil none) .nil) none)
          ⟨"GET".toList, "/api/x?q=1".toList, []⟩ = .notFound "/x?q=1".toList := by
  decide

end Flare.L4.Router
