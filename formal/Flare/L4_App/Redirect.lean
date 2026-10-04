import Flare.Core.Bytes

/-!
# Redirect policy and the client redirect loop

Models (strings are ASCII `List Char`; Mojo indexes bytes, which coincide
with characters on ASCII input):

* `parse`: `Url.parse` (flare/http/url.mojo:73-197) including userinfo
  stripping, IPv6 brackets, default ports and `_parse_port`.
* `resolveLocation`: `_resolve_location` (redirect_policy.mojo:154-185).
* `sameOrigin`: `_same_origin` (redirect_policy.mojo:188-198).
* `decideR`: `RedirectPolicy.decide` (redirect_policy.mojo:271-354).
* `sendLoop`: the redirect-following loop of `HttpClient._send_once`
  (client.mojo:2196-2281), over an arbitrary server (a function from
  `(url, method)` to `(status, Location)`), tracking which credentials
  each hop carries: the effective `Authorization`, a caller-supplied
  `Cookie`, `Proxy-Authorization`, and whether a body is sent.

`none` stands for a raised `Error` throughout.

Specs (independent of the code):
* termination: at most `max_redirects` redirects are followed;
* credential confinement (requests-library / Fetch behaviour, and the
  module docstring :16-22): with `forward_auth_cross_origin = False`, a hop
  that carries `Authorization`, a caller `Cookie` or `Proxy-Authorization`
  has the same origin (RFC 6454 tuple as computed by `parse`) as the
  original request;
* monotonicity: once a credential is dropped it is never re-added, even if
  a later hop returns to the original origin (stricter than curl, which
  re-sends credentials to the original host; fail-safe);
* methods (RFC 9110 §15.4): 307/308 preserve method and body; 303 turns
  any method except HEAD into GET; 301/302 may only turn POST into GET.

Results: `decide_follow_lt_max`, `sendLoop_terminates` (general),
`sendLoop_auth_confined`, `sendLoop_cookie_confined`,
`sendLoop_proxy_confined`, `sendLoop_auth_monotone` (general, every server),
`decide_method_rfc` (general) and `decide_301_delete_is_get` (a documented
deviation: the `RedirectDecision` docstring says "POST/PUT/PATCH -> GET on
301/302/303"). Resolution and origin bugs: `Flare.Bugs.APP_43..45`.
-/
namespace Flare.L4.Redirect

abbrev Str := List Char

/-! ## String helpers (mirror `_find` / `_rfind`, url.mojo:218-261) -/

/-- First index of `sub` in `s` (`_find`). -/
def findSub (s sub : Str) : Option Nat :=
  if sub = [] then some 0 else go s 0
where
  go : Str → Nat → Option Nat
    | [], _ => none
    | c :: cs, i => if sub.isPrefixOf (c :: cs) then some i else go cs (i + 1)

/-- Last index of character `c` in `s` (`_rfind` with a 1-byte needle). -/
def rfindChar (s : Str) (c : Char) : Option Nat :=
  (s.reverse.idxOf? c).map fun j => s.length - 1 - j

def findChar (s : Str) (c : Char) : Option Nat := s.idxOf? c

def digitsAux : Nat → Nat → Str
  | 0, _ => []
  | f + 1, n => if n < 10 then [Char.ofNat (48 + n)] else digitsAux f (n / 10) ++ [Char.ofNat (48 + n % 10)]

/-- Decimal digits of `n` (`String(Int(port))`). -/
def digitsOf (n : Nat) : Str := digitsAux (n + 1) n

/-! ## `Url.parse` -/

structure Url where
  scheme : Str
  host : Str
  port : Nat
  path : Str
  query : Str
  fragment : Str
  deriving DecidableEq, Repr

/-- mirrors flare/http/url.mojo:264-269 @59bda50 -/
def defaultPort (scheme : Str) : Nat := if scheme = "https".toList then 443 else 80

/-- mirrors flare/http/url.mojo:272-299 @59bda50 -/
def parsePort (s : Str) : Option Nat :=
  if s = [] then none
  else if s.length > 5 then none
  else if s.all (fun c => '0' ≤ c ∧ c ≤ '9') then
    let v := s.foldl (fun acc c => acc * 10 + (c.toNat - 48)) 0
    if v < 1 ∨ v > 65535 then none else some v
  else none

/-- mirrors flare/http/url.mojo:73-197 @59bda50 -/
def parse (raw : Str) : Option Url := do
  let se ← findSub raw "://".toList
  let scheme := raw.take se
  if ¬ (scheme = "http".toList ∨ scheme = "https".toList) then none
  let s := raw.drop (se + 3)
  let (s, fragment) := match rfindChar s '#' with
    | some fp => (s.take fp, s.drop (fp + 1))
    | none => (s, [])
  let (authority, pq) := match findChar s '/' with
    | some ps => (s.take ps, s.drop ps)
    | none => (s, ['/'])
  let (path, query) := match findChar pq '?' with
    | some qp => (pq.take qp, pq.drop (qp + 1))
    | none => (pq, [])
  let path := if path = [] then ['/'] else path
  let authority := match findChar authority '@' with
    | some ap => authority.drop (ap + 1)
    | none => authority
  let (host, port) ← match authority with
    | '[' :: _ => do
      let be ← findChar authority ']'
      let host := (authority.take be).drop 1
      let after := authority.drop (be + 1)
      match after with
      | ':' :: ps => do let p ← parsePort ps; pure (host, p)
      | _ => pure (host, defaultPort scheme)
    | _ => match rfindChar authority ':' with
      | some cp => do
        let p ← parsePort (authority.drop (cp + 1))
        pure (authority.take cp, p)
      | none => pure (authority, defaultPort scheme)
  if host = [] then none
  pure ⟨scheme, host, port, path, query, fragment⟩

/-- mirrors flare/http/url.mojo:199-207 @59bda50 -/
def Url.requestTarget (u : Url) : Str := if u.query = [] then u.path else u.path ++ '?' :: u.query

/-! ## `_resolve_location` and `_same_origin` -/

def originStr (u : Url) : Str := u.scheme ++ "://".toList ++ u.host ++ [':'] ++ digitsOf u.port

/-- Directory part of the request target: up to and including the last
`/` (whole target when there is none).
mirrors flare/http/redirect_policy.mojo:175-184 @59bda50 -/
def dirOf (target : Str) : Str :=
  match rfindChar target '/' with
  | some i => target.take (i + 1)
  | none => target

/-- mirrors flare/http/redirect_policy.mojo:154-185 @59bda50 -/
def resolveLocation (base loc : Str) : Option Str := do
  if loc = [] then none
  if "http://".toList.isPrefixOf loc ∨ "https://".toList.isPrefixOf loc then return loc
  let b ← parse base
  let origin := originStr b
  match loc with
  | '/' :: _ => return origin ++ loc
  | _ => return origin ++ dirOf b.requestTarget ++ loc

/-- The origin tuple flare compares (scheme, host, port). -/
def originOf (u : Str) : Option (Str × Str × Nat) :=
  (parse u).map fun v => (v.scheme, v.host, v.port)

/-- mirrors flare/http/redirect_policy.mojo:188-198 @59bda50 -/
def sameOrigin (a b : Str) : Option Bool := do
  let u ← parse a
  let v ← parse b
  return (u.scheme = v.scheme ∧ u.host = v.host ∧ u.port = v.port : Bool)

theorem sameOrigin_true {a b : Str} (h : sameOrigin a b = some true) :
    ∃ o, originOf a = some o ∧ originOf b = some o := by
  unfold sameOrigin at h
  unfold originOf
  cases ha : parse a with
  | none => simp [ha] at h
  | some u =>
    cases hb : parse b with
    | none => simp [ha, hb] at h
    | some v =>
      simp [ha, hb] at h
      obtain ⟨h1, h2, h3⟩ := h
      exact ⟨(u.scheme, u.host, u.port), rfl, by simp [h1, h2, h3]⟩

/-! ## `RedirectPolicy.decide` -/

inductive Action | follow | stop | reject
  deriving DecidableEq, Repr

structure Policy where
  maxRedirects : Int
  mode : Nat            -- 0 FOLLOW_ALL, 1 SAME_ORIGIN_ONLY, 2 DENY
  fwdAuthCrossOrigin : Bool
  deriving DecidableEq, Repr

structure Decision where
  action : Action
  nextMethod : Str
  nextUrl : Str
  bodyDropped : Bool
  fwdAuth : Bool
  deriving DecidableEq, Repr

/-- mirrors flare/http/redirect_policy.mojo:271-354 @59bda50 -/
def decideR (p : Policy) (cur method : Str) (status : Int) (loc : Str) (hops : Int) :
    Option Decision := do
  if loc = [] then return ⟨.stop, [], [], false, true⟩
  if p.mode = 2 then return ⟨.stop, [], [], false, true⟩
  if hops ≥ p.maxRedirects then return ⟨.stop, [], [], false, true⟩
  let next ← resolveLocation cur loc
  let same ← sameOrigin cur next
  if p.mode = 1 ∧ ¬ same then return ⟨.reject, [], [], false, false⟩
  let isSafe := method = "GET".toList ∨ method = "HEAD".toList
  let rewrite := ¬ isSafe ∧ (status = 301 ∨ status = 302 ∨ status = 303)
  let nm := if rewrite then "GET".toList else method
  return ⟨.follow, nm, next, rewrite, same || p.fwdAuthCrossOrigin⟩

theorem decide_follow (p : Policy) (cur m : Str) (st : Int) (loc : Str) (hops : Int) (d : Decision)
    (h : decideR p cur m st loc hops = some d) (hf : d.action = .follow) :
    hops < p.maxRedirects ∧ ∃ same, sameOrigin cur d.nextUrl = some same ∧
      d.fwdAuth = (same || p.fwdAuthCrossOrigin) ∧
      d.bodyDropped = decide (¬ (m = "GET".toList ∨ m = "HEAD".toList) ∧ (st = 301 ∨ st = 302 ∨ st = 303)) ∧
      d.nextMethod = (if ¬ (m = "GET".toList ∨ m = "HEAD".toList) ∧ (st = 301 ∨ st = 302 ∨ st = 303)
                      then "GET".toList else m) := by
  unfold decideR at h
  by_cases h1 : loc = []
  · simp [h1] at h; subst h; simp at hf
  by_cases h2 : p.mode = 2
  · simp [h1, h2] at h; subst h; simp at hf
  by_cases h3 : hops ≥ p.maxRedirects
  · simp [h1, h2, h3] at h; subst h; simp at hf
  simp only [h1, h2, h3, if_false] at h
  cases hr : resolveLocation cur loc with
  | none => simp [hr] at h
  | some next =>
    cases hs : sameOrigin cur next with
    | none => simp [hr, hs] at h
    | some same =>
      simp only [hr, hs, Option.bind_eq_bind, Option.bind_some] at h
      by_cases h4 : p.mode = 1 ∧ ¬ same = true
      · simp only [h4] at h
        simp at h; subst h; simp at hf
      · rw [if_neg h4] at h
        simp at h; subst h
        refine ⟨by omega, same, hs, rfl, by simp, by simp⟩

/-- Termination clause: a redirect is followed only while
`hops < max_redirects`. -/
theorem decide_follow_lt_max (p : Policy) (cur m : Str) (st : Int) (loc : Str) (hops : Int)
    (d : Decision) (h : decideR p cur m st loc hops = some d) (hf : d.action = .follow) :
    hops < p.maxRedirects := (decide_follow p cur m st loc hops d h hf).1

/-- RFC 9110 §15.4 method rule for the next request. -/
def MethodOK (status : Int) (m next : Str) (dropped : Bool) : Prop :=
  if status = 307 ∨ status = 308 then next = m ∧ dropped = false
  else if status = 303 then
    (if m = "HEAD".toList then next = m else next = "GET".toList) ∧ (dropped = true ↔ next ≠ m)
  else if status = 301 ∨ status = 302 then
    (next = m ∨ (m = "POST".toList ∧ next = "GET".toList)) ∧ (dropped = true ↔ next ≠ m)
  else next = m ∧ dropped = false

/-- `decide` meets RFC 9110 §15.4 for 303, 307, 308, every other non-301/302
status, and for 301/302 whenever the method is GET, HEAD or POST. -/
theorem decide_method_rfc (p : Policy) (cur m : Str) (st : Int) (loc : Str) (hops : Int)
    (d : Decision) (h : decideR p cur m st loc hops = some d) (hf : d.action = .follow)
    (hm : ¬ (st = 301 ∨ st = 302) ∨ m = "GET".toList ∨ m = "HEAD".toList ∨ m = "POST".toList) :
    MethodOK st m d.nextMethod d.bodyDropped := by
  obtain ⟨_, _, _, _, hb, hn⟩ := decide_follow p cur m st loc hops d h hf
  rw [hb, hn]
  unfold MethodOK
  by_cases hs : st = 307 ∨ st = 308
  · simp only [hs, if_true]; constructor
    · rw [if_neg (by omega)]
    · simp; omega
  · rw [if_neg hs]
    by_cases h303 : st = 303
    · subst h303; simp only [if_true]
      by_cases hh : m = "HEAD".toList
      · subst hh; simp
      · by_cases hg : m = "GET".toList
        · subst hg; simp
        · simp at hh hg; simp [hh, hg]; exact fun e => hg e.symm
    · rw [if_neg h303]
      by_cases h12 : st = 301 ∨ st = 302
      · rw [if_pos h12]
        rcases hm with hm | hm | hm | hm
        · exact absurd h12 hm
        · subst hm; simp
        · subst hm; simp
        · subst hm; simp; omega
      · rw [if_neg h12]
        simp only [show ¬ (st = 301 ∨ st = 302 ∨ st = 303) by omega, and_false, if_false,
          decide_false]
        exact ⟨trivial, trivial⟩

/-- Documented deviation (RedirectDecision docstring, redirect_policy.mojo:134-137):
a DELETE answered by 301 is re-issued as a body-less GET; RFC 9110 §15.4.2
only permits rewriting POST. -/
theorem decide_301_delete_is_get :
    decideR ⟨10, 0, false⟩ "http://h/a".toList "DELETE".toList 301 "/b".toList 0
      = some ⟨.follow, "GET".toList, "http://h:80/b".toList, true, true⟩ := by decide

/-! ## The client redirect loop -/

/-- What one hop puts on the wire (credential-relevant parts only). -/
structure Hop where
  url : Str
  method : Str
  auth : Bool
  cookie : Bool
  proxyAuth : Bool
  body : Bool
  deriving DecidableEq, Repr

inductive Out
  | done (trace : List Hop)
  | raised (trace : List Hop)
  | fuelOut
  deriving DecidableEq, Repr

def Out.trace : Out → List Hop
  | .done t => t
  | .raised t => t
  | .fuelOut => []

/-- `srv url method = (status, Location)`. `_resolve_url` is the identity
on absolute URLs, which every hop URL is (the request URL is resolved by
the caller and `decide` returns absolute URLs).
mirrors flare/http/client.mojo:2196-2281 @59bda50 -/
def sendLoop (p : Policy) (srv : Str → Str → Int × Str) :
    Nat → Str → Str → Bool → Bool → Bool → Bool → Int → Out
  | 0, _, _, _, _, _, _, _ => .fuelOut
  | fuel + 1, cur, m, auth, ck, pa, body, hops =>
    let hop : Hop := ⟨cur, m, auth, ck, pa, body⟩
    let (st, loc) := srv cur m
    if ¬ (300 ≤ st ∧ st < 400) then .done [hop]
    else match decideR p cur m st loc hops with
      | none => .raised [hop]
      | some d =>
        match d.action with
        | .follow =>
          match sameOrigin cur d.nextUrl with
          | none => .raised [hop]
          | some so =>
            match sendLoop p srv fuel d.nextUrl d.nextMethod (auth && d.fwdAuth) (ck && so)
                (pa && so) (body && !d.bodyDropped) (hops + 1) with
            | .done t => .done (hop :: t)
            | .raised t => .raised (hop :: t)
            | .fuelOut => .fuelOut
        | .reject => .raised [hop]
        | .stop => if loc = [] ∨ p.mode = 2 then .done [hop] else .raised [hop]

/-- `HttpClient._send_once` entry: hop counter 0. -/
def sendOnce (p : Policy) (srv : Str → Str → Int × Str) (fuel : Nat) (url m : Str)
    (auth ck pa body : Bool) : Out :=
  sendLoop p srv fuel url m auth ck pa body 0

theorem sendLoop_terminates_aux (p : Policy) (srv : Str → Str → Int × Str) :
    ∀ (fuel : Nat) cur m a c x b (hops : Int), 1 ≤ fuel → p.maxRedirects < hops + fuel →
      sendLoop p srv fuel cur m a c x b hops ≠ .fuelOut ∧
      (sendLoop p srv fuel cur m a c x b hops).trace.length ≤ fuel
  | 0, _, _, _, _, _, _, _, h1, _ => by omega
  | fuel + 1, cur, m, a, c, x, b, hops, _, h => by
    simp only [sendLoop]
    split
    · simp [Out.trace]
    · split
      · simp [Out.trace]
      · next d hd =>
          split
          · next hf =>
            have hlt := decide_follow_lt_max p cur m _ _ hops d hd hf
            split
            · simp [Out.trace]
            · next so _ =>
              have ih := sendLoop_terminates_aux p srv fuel d.nextUrl d.nextMethod (a && d.fwdAuth)
                (c && so) (x && so) (b && !d.bodyDropped) (hops + 1) (by omega) (by omega)
              split
              · next t ht => rw [ht] at ih; simp [Out.trace] at ih ⊢; omega
              · next t ht => rw [ht] at ih; simp [Out.trace] at ih ⊢; omega
              · next ht => rw [ht] at ih; simp at ih
          · simp [Out.trace]
          · split <;> simp [Out.trace]

/-- Termination: with fuel `max_redirects + 1` the loop always finishes
(returns or raises) and sends at most `max_redirects + 1` requests, i.e.
follows at most `max_redirects` redirects, for every server. -/
theorem sendLoop_terminates (p : Policy) (srv : Str → Str → Int × Str) (url m : Str)
    (a c x b : Bool) :
    sendOnce p srv (p.maxRedirects.toNat + 1) url m a c x b ≠ .fuelOut ∧
    (sendOnce p srv (p.maxRedirects.toNat + 1) url m a c x b).trace.length
      ≤ p.maxRedirects.toNat + 1 :=
  sendLoop_terminates_aux p srv _ url m a c x b 0 (by omega) (by omega)

/-- Generic hop invariant: a predicate on (url, auth, cookie, proxy-auth)
preserved by every followed redirect holds at every hop. -/
theorem sendLoop_inv (p : Policy) (srv : Str → Str → Int × Str)
    (I : Str → Bool → Bool → Bool → Prop)
    (hI : ∀ cur m st loc hops d so a c x, decideR p cur m st loc hops = some d →
      d.action = .follow → sameOrigin cur d.nextUrl = some so → I cur a c x →
      I d.nextUrl (a && d.fwdAuth) (c && so) (x && so)) :
    ∀ (fuel : Nat) cur m a c x b (hops : Int), I cur a c x →
      ∀ h ∈ (sendLoop p srv fuel cur m a c x b hops).trace, I h.url h.auth h.cookie h.proxyAuth
  | 0, _, _, _, _, _, _, _, _ => by simp [sendLoop, Out.trace]
  | fuel + 1, cur, m, a, c, x, b, hops, hi => by
    simp only [sendLoop]
    split
    · simp [Out.trace]; exact hi
    · split
      · simp [Out.trace]; exact hi
      · next d hd =>
          split
          · next hf =>
            split
            · simp [Out.trace]; exact hi
            · next so hso =>
              have ih := sendLoop_inv p srv I hI fuel d.nextUrl d.nextMethod (a && d.fwdAuth)
                (c && so) (x && so) (b && !d.bodyDropped) (hops + 1)
                (hI cur m _ _ hops d so a c x hd hf hso hi)
              split
              · next t ht =>
                rw [ht] at ih; simp only [Out.trace, List.mem_cons] at ih ⊢
                intro h hh; rcases hh with hh | hh
                · subst hh; exact hi
                · exact ih h hh
              · next t ht =>
                rw [ht] at ih; simp only [Out.trace, List.mem_cons] at ih ⊢
                intro h hh; rcases hh with hh | hh
                · subst hh; exact hi
                · exact ih h hh
              · simp [Out.trace]
          · simp [Out.trace]; exact hi
          · split <;> (simp [Out.trace]; exact hi)

/-- Confinement predicate: every credential present on a hop is for the
original origin `o0`. -/
def Confined (o0 : Str × Str × Nat) (u : Str) (a c x : Bool) : Prop :=
  (a = true → originOf u = some o0) ∧ (c = true → originOf u = some o0) ∧
  (x = true → originOf u = some o0)

theorem confined_step (p : Policy) (hp : p.fwdAuthCrossOrigin = false) (o0 : Str × Str × Nat) :
    ∀ cur m st loc hops d so a c x, decideR p cur m st loc hops = some d →
      d.action = .follow → sameOrigin cur d.nextUrl = some so → Confined o0 cur a c x →
      Confined o0 d.nextUrl (a && d.fwdAuth) (c && so) (x && so) := by
  intro cur m st loc hops d so a c x hd hf hso ⟨ha, hc, hx⟩
  obtain ⟨_, same, hs, hfa, _⟩ := decide_follow p cur m st loc hops d hd hf
  rw [hs] at hso; injection hso with hso; subst hso
  rw [hp, Bool.or_false] at hfa
  refine ⟨fun h => ?_, fun h => ?_, fun h => ?_⟩
  · simp only [Bool.and_eq_true] at h
    rw [hfa] at h
    obtain ⟨o, h1, h2⟩ := sameOrigin_true (h.2 ▸ hs)
    rw [h2, ← h1]; exact ha h.1
  · simp only [Bool.and_eq_true] at h
    obtain ⟨o, h1, h2⟩ := sameOrigin_true (h.2 ▸ hs)
    rw [h2, ← h1]; exact hc h.1
  · simp only [Bool.and_eq_true] at h
    obtain ⟨o, h1, h2⟩ := sameOrigin_true (h.2 ▸ hs)
    rw [h2, ← h1]; exact hx h.1

/-- Credential confinement: with `forward_auth_cross_origin = False`, any
hop that carries `Authorization`, a caller `Cookie` or
`Proxy-Authorization` targets the original request's origin, for every
server behaviour and every redirect chain (including chains that leave
the origin and later come back). -/
theorem sendLoop_confined (p : Policy) (hp : p.fwdAuthCrossOrigin = false)
    (srv : Str → Str → Int × Str) (fuel : Nat) (url m : Str) (a c x b : Bool)
    (o0 : Str × Str × Nat) (h0 : originOf url = some o0) :
    ∀ h ∈ (sendOnce p srv fuel url m a c x b).trace,
      (h.auth = true → originOf h.url = some o0) ∧
      (h.cookie = true → originOf h.url = some o0) ∧
      (h.proxyAuth = true → originOf h.url = some o0) :=
  sendLoop_inv p srv (Confined o0) (confined_step p hp o0) fuel url m a c x b 0
    ⟨fun _ => h0, fun _ => h0, fun _ => h0⟩

/-- Monotonicity: once Authorization has been dropped it is never
re-added on a later hop. -/
theorem sendLoop_auth_monotone (p : Policy) (srv : Str → Str → Int × Str) (fuel : Nat)
    (cur m : Str) (c x b : Bool) (hops : Int) :
    ∀ h ∈ (sendLoop p srv fuel cur m false c x b hops).trace, h.auth = false :=
  sendLoop_inv p srv (fun _ a _ _ => a = false)
    (by intro _ _ _ _ _ _ _ a _ _ _ _ _ ha; subst ha; rfl) fuel cur m false c x b hops rfl

/-- Same for a caller-supplied Cookie and Proxy-Authorization. -/
theorem sendLoop_cookie_proxy_monotone (p : Policy) (srv : Str → Str → Int × Str) (fuel : Nat)
    (cur m : Str) (a b : Bool) (hops : Int) :
    ∀ h ∈ (sendLoop p srv fuel cur m a false false b hops).trace,
      h.cookie = false ∧ h.proxyAuth = false :=
  sendLoop_inv p srv (fun _ _ c x => c = false ∧ x = false)
    (by intro _ _ _ _ _ _ _ _ c x _ _ _ ⟨hc, hx⟩; subst hc; subst hx; exact ⟨rfl, rfl⟩)
    fuel cur m a false false b hops ⟨rfl, rfl⟩

end Flare.L4.Redirect
