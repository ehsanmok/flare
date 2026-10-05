import Flare.Core

/-!
# Generic middleware: Logger, RequestId, CatchPanic, Compress

Model of flare/http/middleware.mojo. A handler is a function from a request
to `Except String Resp` (a Mojo `raise` is `.error`). Header maps mirror
`HeaderMap` (flare/http/headers.mojo:104-213): an ordered list of
`(name, value)` pairs with case-insensitive names; `set` replaces the first
match or appends, `append` always appends, `get` returns the first match or
`""`.

Side effects that do not change the response (Logger's `print`, the clock
read behind RequestId's generated id) are abstracted: the generated id is a
parameter. Compress takes the negotiated pick and the encoder as
parameters (negotiation itself is modelled in `Negotiate`).

Results:
* `logger_transparent`: Logger does not change the result, including the
  error message it re-raises.
* `catchPanic_total`, `catchPanic_ok`, `catchPanic_idem`,
  `catchPanic_logger`: CatchPanic never raises, passes successful
  responses through, is idempotent, and absorbs Logger.
* `requestId_sets`, `requestId_echo`: RequestId puts the inbound id (or the
  generated one) on every successful response.
* Ordering law: `requestId_outside_catchPanic` (the id is on every
  response) versus `catchPanic_outside_requestId_error` (when the handler
  raises, the 500 carries no id). The order of the stack matters.
* Compress: `compress_skips_encoded` (no double encoding),
  `compress_content_length` (Content-Length matches the encoded body),
  `compress_vary_when_encoded`. Two findings: it re-encodes 206 partial
  responses (APP-26) and omits `Vary: Accept-Encoding` on the identity
  responses it negotiated (APP-27); the shipped `compress` meets both specs
  (`compress_partial`, `compress_vary`).
-/
namespace Flare.L4.Middleware

abbrev Hdrs := List (String × String)

def ieq (a b : String) : Bool := a.toLower == b.toLower

theorem ieq_self (a : String) : ieq a a = true := by simp [ieq]

/-- `HeaderMap.set`.
mirrors flare/http/headers.mojo:139-156 @59bda50 -/
def setH : Hdrs → String → String → Hdrs
  | [], k, v => [(k, v)]
  | (k', v') :: t, k, v => if ieq k' k then (k, v) :: t else (k', v') :: setH t k v

/-- `HeaderMap.append`.
mirrors flare/http/headers.mojo:158-170 @59bda50 -/
def appendH (h : Hdrs) (k v : String) : Hdrs := h ++ [(k, v)]

/-- `HeaderMap.get`.
mirrors flare/http/headers.mojo:172-184 @59bda50 -/
def getH : Hdrs → String → String
  | [], _ => ""
  | (k', v') :: t, k => if ieq k' k then v' else getH t k

/-- `HeaderMap.contains`.
mirrors flare/http/headers.mojo:201-213 @59bda50 -/
def hasH (h : Hdrs) (k : String) : Bool := h.any (fun p => ieq p.1 k)

theorem getH_setH_self (h : Hdrs) (k v : String) : getH (setH h k v) k = v := by
  induction h with
  | nil => simp [setH, getH, ieq_self]
  | cons p t ih =>
    obtain ⟨k', v'⟩ := p
    simp only [setH]
    split
    · simp [getH, ieq_self]
    · rename_i hk; simp [getH, hk, ih]

theorem getH_append_of_has (h : Hdrs) (k k2 v2 : String) (hh : hasH h k = true) :
    getH (appendH h k2 v2) k = getH h k := by
  induction h with
  | nil => simp [hasH] at hh
  | cons p t ih =>
    obtain ⟨k', v'⟩ := p
    simp only [appendH, List.cons_append, getH] at ih ⊢
    split
    · rfl
    · rename_i hk
      have : hasH t k = true := by simpa [hasH, hk] using hh
      exact ih this

theorem hasH_setH_self (h : Hdrs) (k v : String) : hasH (setH h k v) k = true := by
  induction h with
  | nil => simp [setH, hasH, ieq_self]
  | cons p t ih =>
    obtain ⟨k', v'⟩ := p
    simp only [setH]
    split
    · simp [hasH, ieq_self]
    · simp only [hasH, List.any_cons] at ih ⊢; simp [ih]

structure Req where
  hdrs : Hdrs

structure Resp where
  status : Nat
  hdrs : Hdrs
  body : List UInt8
deriving DecidableEq

abbrev Handler := Req → Except String Resp

/-! ## Logger, CatchPanic, RequestId -/

/-- `Logger.serve`: log and pass through; on `raise`, log and re-raise the
same message.
mirrors flare/http/middleware.mojo:61-86 @59bda50 -/
def logger (h : Handler) : Handler := fun r =>
  match h r with
  | .ok x => .ok x
  | .error m => .error m

/-- The 500 that CatchPanic substitutes. -/
def panic500 (body : List UInt8) : Resp :=
  ⟨500, [("Content-Type", "text/plain; charset=utf-8")], body⟩

/-- `CatchPanic.serve`.
mirrors flare/http/middleware.mojo:397-404 @59bda50 -/
def catchPanic (body : List UInt8) (h : Handler) : Handler := fun r =>
  match h r with
  | .ok x => .ok x
  | .error _ => .ok (panic500 body)

/-- The id RequestId uses: the inbound `x-request-id`, or the generated one
(`"req-" + perf_counter_ns()`, abstracted as `gen`). -/
def ridOf (gen : String) (r : Req) : String :=
  if (getH r.hdrs "x-request-id").isEmpty then gen else getH r.hdrs "x-request-id"

/-- `RequestId.serve`.
mirrors flare/http/middleware.mojo:105-111 @59bda50 -/
def requestId (gen : String) (h : Handler) : Handler := fun r =>
  match h r with
  | .ok x => .ok { x with hdrs := setH x.hdrs "X-Request-Id" (ridOf gen r) }
  | .error m => .error m

theorem logger_transparent (h : Handler) : logger h = h := by
  funext r; unfold logger; split <;> rename_i heq <;> rw [heq]

theorem catchPanic_total (b : List UInt8) (h : Handler) (r : Req) :
    ∃ x, catchPanic b h r = .ok x := by
  unfold catchPanic; split
  · exact ⟨_, rfl⟩
  · exact ⟨_, rfl⟩

theorem catchPanic_ok (b : List UInt8) (h : Handler) (r : Req) (x : Resp) (hx : h r = .ok x) :
    catchPanic b h r = .ok x := by
  simp [catchPanic, hx]

theorem catchPanic_idem (b b' : List UInt8) (h : Handler) :
    catchPanic b (catchPanic b' h) = catchPanic b' h := by
  funext r
  obtain ⟨x, hx⟩ := catchPanic_total b' h r
  rw [catchPanic_ok b _ r x hx, hx]

theorem catchPanic_logger (b : List UInt8) (h : Handler) :
    catchPanic b (logger h) = catchPanic b h := by
  rw [logger_transparent]

theorem requestId_sets (gen : String) (h : Handler) (r : Req) (x : Resp)
    (hx : requestId gen h r = .ok x) : getH x.hdrs "X-Request-Id" = ridOf gen r := by
  unfold requestId at hx
  split at hx
  · cases hx; exact getH_setH_self _ _ _
  · cases hx

/-- An inbound non-empty `x-request-id` is echoed. -/
theorem requestId_echo (gen : String) (h : Handler) (r : Req) (x : Resp)
    (hin : (getH r.hdrs "x-request-id").isEmpty = false)
    (hx : requestId gen h r = .ok x) : getH x.hdrs "X-Request-Id" = getH r.hdrs "x-request-id" := by
  rw [requestId_sets gen h r x hx]; simp [ridOf, hin]

/-- **Ordering law, RequestId outermost.** Every request gets a response
carrying the request id, even when the inner handler raises. -/
theorem requestId_outside_catchPanic (gen : String) (b : List UInt8) (h : Handler) (r : Req) :
    ∃ x, requestId gen (catchPanic b h) r = .ok x ∧ getH x.hdrs "X-Request-Id" = ridOf gen r := by
  obtain ⟨y, hy⟩ := catchPanic_total b h r
  refine ⟨{ y with hdrs := setH y.hdrs "X-Request-Id" (ridOf gen r) }, ?_, getH_setH_self _ _ _⟩
  simp [requestId, hy]

/-- **Ordering law, CatchPanic outermost.** When the handler raises, the
response is CatchPanic's fixed 500, whose only header is Content-Type: the
request id is lost. -/
theorem catchPanic_outside_requestId_error (gen : String) (b : List UInt8) (h : Handler)
    (r : Req) (m : String) (he : h r = .error m) :
    catchPanic b (requestId gen h) r = .ok (panic500 b) := by
  simp [catchPanic, requestId, he]

/-! ## Compress -/

inductive Enc
  | br | gzip | identity
deriving DecidableEq

def Enc.name : Enc → String
  | .br => "br" | .gzip => "gzip" | .identity => "identity"

/-- `_AcceptEncodingPick`: the encoding and its quality out of 1000. -/
structure Pick where
  enc : Enc
  q : Nat

/-- Compress parameters: the pick for this request, whether brotli is
linkable, the encoder, and `min_size_bytes`. -/
structure CCfg where
  pick : Pick
  brotliOk : Bool
  encode : Enc → List UInt8 → List UInt8
  minSize : Nat

/-- The encoding branch: replace the body, set Content-Encoding and
Content-Length, append `Vary: Accept-Encoding`.
mirrors flare/http/middleware.mojo:360-376 @59bda50 -/
def encodeAs (c : CCfg) (e : Enc) (x : Resp) : Resp :=
  let b := c.encode e x.body
  { x with body := b,
           hdrs := appendH (setH (setH x.hdrs "Content-Encoding" e.name) "Content-Length"
                     (toString b.length)) "Vary" "Accept-Encoding" }

/-- A 206 (or a response with Content-Range) has its byte offsets fixed
relative to the identity bytes. -/
def isPartial (x : Resp) : Bool := x.status == 206 || hasH x.hdrs "content-range"

/-- `Compress.serve` before the APP-26 fix: no check for partial content.
mirrors flare/http/middleware.mojo:345-376 @59bda50 -/
def compressOld (c : CCfg) (x : Resp) : Resp :=
  if c.pick.q == 0 then x
  else if x.body.length < c.minSize then x
  else if hasH x.hdrs "content-encoding" then x
  else match c.pick.enc with
    | .br => if c.brotliOk then encodeAs c .br x else x
    | .gzip => encodeAs c .gzip x
    | .identity => x

/-- `Compress.serve` after the APP-26 fix but before the APP-27 one: partial
responses pass through, the identity branches still lack `Vary`.
mirrors flare/http/middleware.mojo:345-382 (APP-26 fixed, APP-27 not) -/
def compressNoVary (c : CCfg) (x : Resp) : Resp :=
  if c.pick.q == 0 then x
  else if x.body.length < c.minSize then x
  else if hasH x.hdrs "content-encoding" then x
  else if isPartial x then x
  else match c.pick.enc with
    | .br => if c.brotliOk then encodeAs c .br x else x
    | .gzip => encodeAs c .gzip x
    | .identity => x

def vary (x : Resp) : Resp := { x with hdrs := appendH x.hdrs "Vary" "Accept-Encoding" }

/-- `Compress.serve` as shipped (fixed, APP-26 and APP-27): responses that are
too small, already encoded or partial pass through untouched; every other
response carries `Vary: Accept-Encoding`, whether it is encoded or left as
identity (no usable `Accept-Encoding`, identity preferred, every coding
refused, brotli unavailable).
mirrors flare/http/middleware.mojo:345-390 (fixed, APP-26, APP-27) -/
def compress (c : CCfg) (x : Resp) : Resp :=
  if x.body.length < c.minSize then x
  else if hasH x.hdrs "content-encoding" then x
  else if isPartial x then x
  else if c.pick.q == 0 then vary x
  else match c.pick.enc with
    | .br => if c.brotliOk then encodeAs c .br x else vary x
    | .gzip => encodeAs c .gzip x
    | .identity => vary x

def compressMW (cfgOf : Req → CCfg) (h : Handler) : Handler := fun r =>
  (h r).map (compress (cfgOf r))

theorem compress_skips_encoded (c : CCfg) (x : Resp) (h : hasH x.hdrs "content-encoding" = true) :
    compress c x = x := by
  unfold compress
  split; · rfl
  simp

/-- Whatever Compress emits is the inner response, the inner response with
`Vary` added, or the response encoded by `encodeAs` with a supported
encoding. -/
theorem compress_cases (c : CCfg) (x : Resp) :
    compress c x = x ∨ compress c x = vary x ∨
      ∃ e, e ≠ .identity ∧ compress c x = encodeAs c e x := by
  unfold compress
  split; · exact .inl rfl
  split; · exact .inl rfl
  split; · exact .inl rfl
  split; · exact .inr (.inl rfl)
  split
  · split
    · exact .inr (.inr ⟨.br, by decide, rfl⟩)
    · exact .inr (.inl rfl)
  · exact .inr (.inr ⟨.gzip, by decide, rfl⟩)
  · exact .inr (.inl rfl)

theorem encodeAs_content_length (c : CCfg) (e : Enc) (x : Resp) :
    getH (encodeAs c e x).hdrs "Content-Length" = toString (encodeAs c e x).body.length := by
  simp only [encodeAs]
  rw [getH_append_of_has _ _ _ _ (hasH_setH_self _ _ _), getH_setH_self]

theorem encodeAs_vary (c : CCfg) (e : Enc) (x : Resp) :
    ("Vary", "Accept-Encoding") ∈ (encodeAs c e x).hdrs := by
  simp [encodeAs, appendH]

theorem vary_mem (x : Resp) : ("Vary", "Accept-Encoding") ∈ (vary x).hdrs := by
  simp [vary, appendH]

/-- When Compress changes the body, Content-Length matches the encoded
body. -/
theorem compress_content_length (c : CCfg) (x : Resp) (hne : (compress c x).body ≠ x.body) :
    getH (compress c x).hdrs "Content-Length" = toString (compress c x).body.length := by
  rcases compress_cases c x with h | h | ⟨e, -, h⟩
  · exact absurd (by rw [h]) hne
  · exact absurd (by rw [h]; rfl) hne
  · rw [h]; exact encodeAs_content_length c e x

theorem compress_vary_when_encoded (c : CCfg) (x : Resp) (hne : compress c x ≠ x) :
    ("Vary", "Accept-Encoding") ∈ (compress c x).hdrs := by
  rcases compress_cases c x with h | h | ⟨e, -, h⟩
  · exact absurd h hne
  · rw [h]; exact vary_mem x
  · rw [h]; exact encodeAs_vary c e x

/-- Spec for APP-26 (RFC 9110 §14.4): a partial response passes through
unchanged. -/
def PartialSpec (f : Resp → Resp) : Prop := ∀ x, isPartial x = true → f x = x

/-- The shipped `compress` meets the APP-26 spec for every configuration. -/
theorem compress_partial (c : CCfg) : PartialSpec (compress c) := by
  intro x hp
  unfold compress
  split; · rfl
  split; · rfl
  simp

/-- The response's selected representation depends on Accept-Encoding:
the body is large enough to compress, not already encoded, not partial. -/
def negotiated (c : CCfg) (x : Resp) : Prop :=
  c.minSize ≤ x.body.length ∧ hasH x.hdrs "content-encoding" = false ∧ isPartial x = false

/-- Spec for APP-27 (RFC 9110 §12.5.5): every negotiated response carries
`Vary: Accept-Encoding`. -/
def VarySpec (f : CCfg → Resp → Resp) : Prop :=
  ∀ c x, negotiated c x → ("Vary", "Accept-Encoding") ∈ (f c x).hdrs

/-- The shipped `compress` meets the APP-27 spec for every configuration and
response. -/
theorem compress_vary : VarySpec compress := by
  intro c x ⟨hmin, hce, hp⟩
  have hlt : ¬ x.body.length < c.minSize := by omega
  unfold compress
  simp only [hlt, if_false, hce, Bool.false_eq_true, hp]
  split
  · exact vary_mem x
  · split
    · split
      · exact encodeAs_vary c _ x
      · exact vary_mem x
    · exact encodeAs_vary c _ x
    · exact vary_mem x

/-- Whenever the pre-APP-27 Compress changes a response, the shipped one gives
the same result: the fix only adds `Vary` to responses that were left alone. -/
theorem compress_agrees (c : CCfg) (x : Resp) (hne : compressNoVary c x ≠ x) :
    compress c x = compressNoVary c x := by
  have hq : (c.pick.q == 0) = false := by
    cases h : c.pick.q == 0
    · rfl
    · exact absurd (by simp [compressNoVary, h]) hne
  have hm : ¬ x.body.length < c.minSize := by
    intro hl; exact hne (by simp [compressNoVary, hq, hl])
  have he : hasH x.hdrs "content-encoding" = false := by
    cases h : hasH x.hdrs "content-encoding"
    · rfl
    · exact absurd (by simp [compressNoVary, h]) hne
  have hp : isPartial x = false := by
    cases h : isPartial x
    · rfl
    · exact absurd (by simp [compressNoVary, hq, hm, he, h]) hne
  unfold compressNoVary compress at *
  simp only [hq, hm, he, hp, Bool.false_eq_true, if_false] at hne ⊢
  split <;> rename_i henc
  · split <;> rename_i hb
    · rfl
    · exact absurd (by simp [henc, hb]) hne
  · rfl
  · exact absurd (by simp [henc]) hne

end Flare.L4.Middleware
