/-!
# CORS middleware (`flare/http/cors.mojo`)

Sans-I/O model of `_origin_allowed`, `Cors._attach_origin` and `Cors.serve`.
Header maps are association lists with flare's `HeaderMap` semantics:
`set` overwrites the first case-insensitively equal name in place (else
appends), `append` always appends, `get` returns the first match.
The inner handler is an arbitrary response `inner`.

Spec (WHATWG Fetch §3.2, "CORS protocol"):
* an origin is allowed iff it is listed explicitly, or `*` is listed and
  credentials are off (a credentialed response may not use `*`, so `*`
  cannot authorise a credentialed request); this is a set property and so
  independent of list order;
* a credentialed response carries `Access-Control-Allow-Origin` equal to the
  request origin, never `*`, plus `Access-Control-Allow-Credentials: true`;
* Fetch §3.2.5 ("CORS protocol and HTTP caches"): when the
  `Access-Control-Allow-Origin` value depends on the request's `Origin`,
  `Vary: Origin` must be on all responses, including those to requests
  without `Origin`.
-/
namespace Flare.L4.Cors

/-- Header names. flare compares names case-insensitively; the model
normalises them: the names the middleware writes are constructors, and any
other header of the inner response is `other s` (an inner header whose name
case-insensitively equals one of the constructors is represented by that
constructor, which is exactly flare's case-insensitive matching). -/
inductive HName
  | acao | acac | vary | aceh | acam | acah | acma
  | other (s : String)
  deriving DecidableEq, Repr

abbrev Headers := List (HName × String)

def nameEq (a b : HName) : Bool := a == b

/-- `HeaderMap.set`. mirrors flare/http/headers.mojo:139-156 @59bda50 -/
def setH (n : HName) (v : String) : Headers → Headers
  | [] => [(n, v)]
  | (k, w) :: hs => if nameEq k n then (n, v) :: hs else (k, w) :: setH n v hs

/-- `HeaderMap.append`. mirrors flare/http/headers.mojo:158-170 @59bda50 -/
def appendH (n : HName) (v : String) (hs : Headers) : Headers := hs ++ [(n, v)]

/-- `HeaderMap.get` (`none` for flare's `""`). mirrors flare/http/headers.mojo:172-184 @59bda50 -/
def getH (n : HName) : Headers → Option String
  | [] => none
  | (k, w) :: hs => if nameEq k n then some w else getH n hs

structure Config where
  origins : List String
  methods : List String
  allowHeaders : List String
  exposed : List String
  maxAge : Int
  creds : Bool

structure Req where
  method : String
  origin : String     -- "" when absent
  acrm : String       -- Access-Control-Request-Method, "" when absent
  acrh : String       -- Access-Control-Request-Headers, "" when absent

structure Resp where
  status : Nat
  headers : Headers

/-- `_origin_allowed`'s scan as shipped (fixed, APP-21): under credentials a
`*` entry authorises nothing but the scan continues (`continue`), so the
decision does not depend on list order.
mirrors flare/http/cors.mojo:89-104 (fixed, APP-21) -/
def originAllowedLoop (origin : String) (creds : Bool) : List String → Bool
  | [] => false
  | e :: es => if e = "*" then (if creds then originAllowedLoop origin creds es else true)
               else if e = origin then true
               else originAllowedLoop origin creds es

/-- mirrors flare/http/cors.mojo:89-104 (fixed, APP-21) -/
def originAllowed (origin : String) (cfg : Config) : Bool :=
  if origin = "" then false else originAllowedLoop origin cfg.creds cfg.origins

/-- The scan before the APP-21 fix: it returned `not allow_credentials` at the
first `*`.
mirrors flare/http/cors.mojo:89-98 @59bda50 -/
def originAllowedLoopOld (origin : String) (creds : Bool) : List String → Bool
  | [] => false
  | e :: es => if e = "*" then !creds else if e = origin then true
               else originAllowedLoopOld origin creds es

/-- mirrors flare/http/cors.mojo:89-98 @59bda50 -/
def originAllowedOld (origin : String) (cfg : Config) : Bool :=
  if origin = "" then false else originAllowedLoopOld origin cfg.creds cfg.origins

/-- mirrors flare/http/cors.mojo:101-107 @59bda50 -/
def join (parts : List String) (sep : String) : String := sep.intercalate parts

/-- The `Access-Control-Allow-Origin` value. mirrors flare/http/cors.mojo:124-143 @59bda50 -/
def allowValue (cfg : Config) (origin : String) : String :=
  if cfg.creds then origin
  else match cfg.origins with
    | [o] => if o ≠ "*" then o else "*"
    | _ => origin

/-- mirrors flare/http/cors.mojo:121-150 @59bda50 -/
def attachOrigin (cfg : Config) (r : Resp) (origin : String) : Resp :=
  let hs := if cfg.creds then setH .acac "true" r.headers
            else r.headers
  let hs := setH .acao (allowValue cfg origin) hs
  let hs := appendH .vary "Origin" hs
  let hs := if cfg.exposed ≠ [] then
      setH .aceh (join cfg.exposed ", ") hs else hs
  { r with headers := hs }

def isPreflight (req : Req) : Bool := req.method = "OPTIONS" && req.acrm ≠ ""

/-- mirrors flare/http/cors.mojo:152-197 @59bda50 -/
def serve (cfg : Config) (inner : Resp) (req : Req) : Resp :=
  if req.origin = "" then inner
  else if !originAllowed req.origin cfg then
    if isPreflight req then ⟨403, []⟩ else inner
  else if isPreflight req then
    let r := attachOrigin cfg ⟨204, []⟩ req.origin
    let hs := setH .acam (join cfg.methods ", ") r.headers
    let hv := if cfg.allowHeaders = [] then req.acrh else join cfg.allowHeaders ", "
    let hs := if hv ≠ "" then setH .acah hv hs else hs
    let hs := setH .acma (toString cfg.maxAge) hs
    ⟨204, hs⟩
  else attachOrigin cfg inner req.origin

/-! ## Spec -/

/-- Fetch: allowed iff listed explicitly, or wildcard without credentials. -/
def allowedSpec (cfg : Config) (origin : String) : Prop :=
  origin ≠ "" ∧ ((origin ∈ cfg.origins ∧ origin ≠ "*") ∨ (cfg.creds = false ∧ "*" ∈ cfg.origins))

instance (cfg : Config) (o : String) : Decidable (allowedSpec cfg o) := by
  unfold allowedSpec; infer_instance

def acao (r : Resp) : Option String := getH .acao r.headers

def hasVaryOrigin (r : Resp) : Prop := (HName.vary, "Origin") ∈ r.headers

instance (r : Resp) : Decidable (hasVaryOrigin r) := by unfold hasVaryOrigin; infer_instance

/-! ## Header-map lemmas -/

theorem nameEq_refl (n : HName) : nameEq n n = true := by simp [nameEq]

theorem getH_setH (n : HName) (v : String) (hs : Headers) : getH n (setH n v hs) = some v := by
  induction hs with
  | nil => simp [setH, getH, nameEq_refl]
  | cons h hs ih =>
    obtain ⟨k, w⟩ := h
    simp only [setH]
    by_cases hk : nameEq k n = true
    · simp [hk, getH, nameEq_refl]
    · simp [hk, getH, ih]

theorem getH_setH_ne (n m : HName) (v : String) (hs : Headers) (h : nameEq n m = false) :
    getH m (setH n v hs) = getH m hs := by
  induction hs with
  | nil =>
    simp [setH, getH, h]
  | cons x hs ih =>
    obtain ⟨k, w⟩ := x
    simp only [setH]
    by_cases hk : nameEq k n = true
    · have hkm : nameEq k m = false := by
        simp [nameEq] at hk h ⊢; rw [hk]; exact h
      simp [hk, getH, hkm, h]
    · simp [hk, getH, ih]

theorem getH_appendH_of_some (n m : HName) (v : String) (hs : Headers) (w : String)
    (h : getH m hs = some w) : getH m (appendH n v hs) = some w := by
  unfold appendH
  induction hs with
  | nil => simp [getH] at h
  | cons x hs ih =>
    obtain ⟨k, w'⟩ := x
    simp only [getH, List.cons_append] at h ⊢
    split <;> simp_all

theorem mem_setH_of_mem (n : HName) (v : String) (hs : Headers) (x : HName × String)
    (hx : x ∈ hs) (hn : nameEq x.1 n = false) : x ∈ setH n v hs := by
  induction hs with
  | nil => simp at hx
  | cons y hs ih =>
    obtain ⟨k, w⟩ := y
    simp only [setH]
    rcases List.mem_cons.1 hx with h | h
    · subst h; simp at hn; simp [hn]
    · split <;> simp [ih h, h]

/-! ## Origin allowance -/

theorem loopOld_sound (o : String) (creds : Bool) (es : List String) :
    originAllowedLoopOld o creds es = true →
      ((o ∈ es ∧ o ≠ "*") ∨ (creds = false ∧ "*" ∈ es)) := by
  induction es with
  | nil => simp [originAllowedLoopOld]
  | cons e es ih =>
    simp only [originAllowedLoopOld]
    by_cases he : e = "*"
    · subst he; cases creds <;> simp
    · by_cases heo : e = o
      · subst heo; simp [he]
      · simp only [he, heo, if_false]; intro h
        rcases ih h with h | h
        · exact Or.inl ⟨List.mem_cons_of_mem _ h.1, h.2⟩
        · exact Or.inr ⟨h.1, List.mem_cons_of_mem _ h.2⟩

/-- The pre-fix check is sound but incomplete (see `Flare.Bugs.APP_21`). -/
theorem originAllowedOld_sound (o : String) (cfg : Config) :
    originAllowedOld o cfg = true → allowedSpec cfg o := by
  unfold originAllowedOld allowedSpec
  split
  · simp
  · intro h; exact ⟨by assumption, loopOld_sound _ _ _ h⟩

theorem loop_iff (o : String) (creds : Bool) (es : List String) :
    originAllowedLoop o creds es = true ↔
      ((o ∈ es ∧ o ≠ "*") ∨ (creds = false ∧ "*" ∈ es)) := by
  induction es with
  | nil => simp [originAllowedLoop]
  | cons e es ih =>
    simp only [originAllowedLoop]
    by_cases he : e = "*"
    · subst he
      cases creds
      · simp
      · simp only [if_true, ih, List.mem_cons]
        constructor
        · rintro (⟨h1, h2⟩ | ⟨h1, _⟩)
          · exact Or.inl ⟨Or.inr h1, h2⟩
          · cases h1
        · rintro (⟨h1 | h1, h2⟩ | ⟨h1, _⟩)
          · exact absurd h1 h2
          · exact Or.inl ⟨h1, h2⟩
          · cases h1
    · by_cases heo : e = o
      · subst heo; simp [he]
      · simp only [he, heo, if_false, ih, List.mem_cons]
        constructor
        · rintro (⟨h1, h2⟩ | ⟨h1, h2⟩)
          · exact Or.inl ⟨Or.inr h1, h2⟩
          · exact Or.inr ⟨h1, Or.inr h2⟩
        · rintro (⟨h1 | h1, h2⟩ | ⟨h1, h3 | h3⟩)
          · exact absurd h1.symm heo
          · exact Or.inl ⟨h1, h2⟩
          · exact absurd h3.symm he
          · exact Or.inr ⟨h1, h3⟩

/-- The shipped check equals the spec for every configuration (general),
for credentialed and plain configs alike. -/
theorem originAllowed_iff (o : String) (cfg : Config) :
    originAllowed o cfg = true ↔ allowedSpec cfg o := by
  unfold originAllowed allowedSpec
  by_cases h : o = "" <;> simp [h, loop_iff]

/-- Soundness (general): flare never allows an origin the spec rejects —
in particular never a credentialed request through `*`. -/
theorem originAllowed_sound (o : String) (cfg : Config) :
    originAllowed o cfg = true → allowedSpec cfg o :=
  (originAllowed_iff o cfg).1

/-- Without credentials flare's check is exactly the spec (general); with the
APP-21 fix this holds with credentials too (`originAllowed_iff`). -/
theorem originAllowed_eq_spec_noCreds (o : String) (cfg : Config) (_hc : cfg.creds = false) :
    originAllowed o cfg = true ↔ allowedSpec cfg o :=
  originAllowed_iff o cfg

/-- The spec is order independent (general). -/
theorem allowedSpec_perm (cfg cfg' : Config) (o : String)
    (hp : cfg.origins.Perm cfg'.origins) (hc : cfg.creds = cfg'.creds) :
    allowedSpec cfg o ↔ allowedSpec cfg' o := by
  unfold allowedSpec; rw [hp.mem_iff, hp.mem_iff, hc]

/-- The shipped check does not depend on the order of the allowlist
(general). -/
theorem originAllowed_perm (o : String) (cfg cfg' : Config)
    (hp : cfg.origins.Perm cfg'.origins) (hc : cfg.creds = cfg'.creds) :
    originAllowed o cfg = originAllowed o cfg' := by
  have := (originAllowed_iff o cfg).trans
    ((allowedSpec_perm cfg cfg' o hp hc).trans (originAllowed_iff o cfg').symm)
  cases h1 : originAllowed o cfg <;> cases h2 : originAllowed o cfg' <;> simp_all

/-! ## Emitted headers -/

/-- The middleware's `Access-Control-Allow-Origin` value is the request
origin, or `*` only when credentials are off (general). -/
theorem allowValue_cases (cfg : Config) (o : String) (h : originAllowed o cfg = true) :
    allowValue cfg o = o ∨ (allowValue cfg o = "*" ∧ cfg.creds = false) := by
  have hs := originAllowed_sound o cfg h
  unfold allowValue
  cases hc : cfg.creds
  · simp only [Bool.false_eq_true, ↓reduceIte]
    split
    · rename_i x hx
      by_cases hx' : x = "*"
      · simp [hx']
      · simp only [hx', ne_eq, not_false_eq_true, ↓reduceIte]
        left
        unfold allowedSpec at hs; rw [hx, hc] at hs
        rcases hs.2 with ⟨h1, _⟩ | ⟨_, h2⟩
        · simp at h1; exact h1.symm
        · simp at h2; exact absurd h2.symm hx'
    · simp
  · simp

theorem acao_attach (cfg : Config) (r : Resp) (o : String) :
    acao (attachOrigin cfg r o) = some (allowValue cfg o) := by
  unfold attachOrigin acao
  simp only
  split
  · rw [getH_setH_ne _ _ _ _ (by decide)]
    exact getH_appendH_of_some _ _ _ _ _ (getH_setH _ _ _)
  · exact getH_appendH_of_some _ _ _ _ _ (getH_setH _ _ _)

/-- Any `Access-Control-Allow-Origin` on a response comes from an allowed
origin and has value `allowValue` (general; the inner handler is assumed not
to set the header itself). -/
theorem serve_acao (cfg : Config) (inner : Resp) (req : Req)
    (hinner : acao inner = none) (v : String)
    (hv : acao (serve cfg inner req) = some v) :
    originAllowed req.origin cfg = true ∧ v = allowValue cfg req.origin := by
  unfold serve at hv
  by_cases ho : req.origin = ""
  · simp [ho, hinner] at hv
  · cases ha : originAllowed req.origin cfg
    · by_cases hp : isPreflight req = true
      · simp [ho, ha, hp, acao, getH] at hv
      · simp [ho, ha, hp, hinner] at hv
    · refine ⟨rfl, ?_⟩
      by_cases hp : isPreflight req = true
      · simp only [ho, ha, hp, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at hv
        simp only [acao] at hv
        rw [getH_setH_ne _ _ _ _ (by decide)] at hv
        have hx := acao_attach cfg ⟨204, []⟩ req.origin
        unfold acao at hx
        have hy : ∀ (c : Prop) [Decidable c] (x : String) (Y : Headers),
            getH .acao (if c then setH .acah x Y else Y) = getH .acao Y := by
          intro c _ x Y; split
          · exact getH_setH_ne _ _ _ _ (by decide)
          · rfl
        rw [hy, getH_setH_ne _ _ _ _ (by decide), hx] at hv
        cases hv; rfl
      · simp only [ho, ha, hp, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at hv
        rw [acao_attach] at hv; cases hv; rfl

/-- **With credentials, `Access-Control-Allow-Origin` is never `*`**
(general): it equals the request origin, which cannot be `*` when allowed. -/
theorem acao_not_star_with_creds (cfg : Config) (inner : Resp) (req : Req)
    (hc : cfg.creds = true) (v : String)
    (hv : acao (serve cfg inner req) = some v)
    (hinner : acao inner = none) : v ≠ "*" ∧ v = req.origin := by
  obtain ⟨hal, hv⟩ := serve_acao cfg inner req hinner v hv
  have hs := originAllowed_sound _ _ hal
  unfold allowedSpec at hs; rw [hc] at hs
  have hstar : req.origin ≠ "*" := by
    rcases hs.2 with h | h
    · exact h.2
    · simp at h
  have hav : allowValue cfg req.origin = req.origin := by simp [allowValue, hc]
  rw [hv, hav]; exact ⟨hstar, rfl⟩

/-- Without credentials the value is the request origin or `*` (general). -/
theorem acao_origin_or_star (cfg : Config) (inner : Resp) (req : Req)
    (hinner : acao inner = none) (v : String)
    (hv : acao (serve cfg inner req) = some v) :
    v = req.origin ∨ (v = "*" ∧ cfg.creds = false) := by
  obtain ⟨hal, hv⟩ := serve_acao cfg inner req hinner v hv
  rw [hv]; exact allowValue_cases cfg _ hal

/-- Every response the middleware stamps with an allowed origin carries
`Vary: Origin` (general). -/
theorem attach_has_vary (cfg : Config) (r : Resp) (o : String) :
    hasVaryOrigin (attachOrigin cfg r o) := by
  unfold attachOrigin hasVaryOrigin appendH
  simp only
  split
  · apply mem_setH_of_mem _ _ _ _ (by simp) (by decide)
  · simp

/-- Preflight short-circuit (general): an allowed preflight is answered 204
without consulting the inner handler. -/
theorem preflight_ignores_inner (cfg : Config) (i1 i2 : Resp) (req : Req)
    (hp : isPreflight req = true) :
    serve cfg i1 req = serve cfg i2 req ∨ req.origin = "" ∨ originAllowed req.origin cfg = false := by
  unfold serve
  by_cases ho : req.origin = ""
  · exact Or.inr (Or.inl ho)
  · cases ha : originAllowed req.origin cfg
    · exact Or.inr (Or.inr rfl)
    · left; simp [ho, hp]

/-! ## Fixed models -/

/-- Fixed serve: also append `Vary: Origin` on the responses that bypass
the CORS headers (no `Origin`, rejected origin, rejected preflight). -/
def serveFixed (cfg : Config) (inner : Resp) (req : Req) : Resp :=
  let r := serve cfg inner req
  if hasVaryOrigin r then r else { r with headers := appendH .vary "Origin" r.headers }

theorem serveFixed_vary (cfg : Config) (inner : Resp) (req : Req) :
    hasVaryOrigin (serveFixed cfg inner req) := by
  unfold serveFixed
  simp only
  split
  · assumption
  · simp [hasVaryOrigin, appendH]

end Flare.L4.Cors
