import Flare.Core

/-!
# Documented policies: error logging, entry points, session expiry, TLS resumption

Small models of what five documented promises reduce to (DOC-04 to DOC-08
of the 0.12 audit). Each section abstracts one code path to the values the
promise talks about and proves the promise for the shipped code.
-/
namespace Flare.L4.Policies

/-! ## Error paths log the message with the request id (DOC-04) -/

namespace ErrorLog

/-- One log line: the request id it names (if any) and the message. -/
structure Line where
  rid : Option String
  msg : String
  deriving DecidableEq, Repr

/-- What an error path produces for one request. -/
structure Out where
  status : Nat
  body : String
  log : List Line
  deriving DecidableEq, Repr

/-- The documented policy for one error path: fixed status and body, and a
log line carrying both the full message and the request id. -/
def Policy (status : Nat) (body : String) (path : String → String → Out) : Prop :=
  ∀ rid msg, (path rid msg).status = status ∧ (path rid msg).body = body ∧
    Line.mk (some rid) msg ∈ (path rid msg).log

/-- Handler error: `log_handler_error(request_id, msg)` before
`map_handler_error`.
mirrors flare/errors.mojo#log_handler_error sha=2dc258b21eb0 at=ea1b9282 (fixed, DOC-04) -/
def handlerError (rid msg : String) : Out :=
  { status := 500, body := "Internal Server Error", log := [⟨some rid, msg⟩] }

/-- Extractor error: `Extracted.serve` passes the request's `x-request-id`
to `_bad_request_from_error`, which logs it with the message.
mirrors flare/http/extract.mojo#Extracted.serve+_bad_request_from_error sha=6657a3f2b4ea at=ea1b9282 (fixed, DOC-04) -/
def extractorError (rid msg : String) : Out :=
  { status := 400, body := "Bad Request", log := [⟨some rid, msg⟩] }

theorem policy :
    Policy 500 "Internal Server Error" handlerError ∧
    Policy 400 "Bad Request" extractorError := by
  refine ⟨fun rid msg => ?_, fun rid msg => ?_⟩ <;>
    simp [handlerError, extractorError]

end ErrorLog

/-! ## Single-listener entry points reject extra listeners (DOC-05) -/

namespace EntryPoints

/-- What the entry points look at: a TLS context, and how many extra
listeners `bind` left in `_extra_listener_fds`. -/
structure Server where
  tls : Bool
  extras : Nat
  deriving DecidableEq, Repr

/-- `raises`, or runs a loop that accepts on the listed listeners (0 is the
primary, `i + 1` the `i`-th extra). -/
inductive Outcome
  | raises
  | runs (accepts : List Nat)
  deriving DecidableEq, Repr

/-- The doc's promise: raise when a TLS context or extra listeners are bound. -/
def Spec (e : Server → Outcome) : Prop :=
  ∀ s, (s.tls = true ∨ s.extras > 0) → e s = .raises

/-- What "silently ignoring" rules out: a loop that runs accepts on every
bound listener. -/
def NoSilentIgnore (e : Server → Outcome) : Prop :=
  ∀ s l, e s = .runs l → ∀ i, i ≤ s.extras → i ∈ l

/-- A TLS context (the inline check) or extra listeners
(`_reject_extra_listeners`) raise.
mirrors flare/http/server.mojo#HttpServer._reject_extra_listeners sha=4590d05e822d at=ea1b9282 (fixed, DOC-05) -/
def entry (s : Server) : Outcome :=
  if s.tls || decide (s.extras > 0) then .raises else .runs [0]

theorem entry_spec : Spec entry ∧ NoSilentIgnore entry := by
  refine ⟨fun s h => ?_, fun s l h i hi => ?_⟩
  · rcases h with h | h <;> simp [entry, h]
  · unfold entry at h
    split at h
    · cases h
    · rename_i hc
      cases h
      have : s.extras = 0 := by simp at hc; omega
      simp; omega

end EntryPoints

/-! ## Sessions expire server-side (DOC-06) -/

namespace Session

/-- A verified signed-cookie payload: the session value and the absolute
expiry it was signed with. -/
structure Payload where
  exp : Option Nat
  value : String
  deriving DecidableEq, Repr

/-- `DEFAULT_SESSION_TTL_S`. -/
def lifetime : Nat := 86400

/-- `MemorySessionBackend.set`: `ttl_s <= 0` means no expiry (stored as 0). -/
def expiry (now ttl : Nat) : Nat := if ttl = 0 then 0 else now + ttl

/-- `MemorySessionBackend.get`: live unless an expiry is set and reached. -/
def live (exp now : Nat) : Bool := exp == 0 || decide (now < exp)

/-- `BackedSessionStore.save` at `i`, then `load` at `t`. -/
def bsAccepts (ttl i t : Nat) : Bool := live (expiry i ttl) t

/-- Server-side expiry: a session issued at `i` is refused from `i + L` on,
for some lifetime `L`. `accepts i t`: issued at `i`, presented at `t`. -/
def Expires (accepts : Nat → Nat → Bool) : Prop :=
  ∃ L, ∀ i t, i + L ≤ t → accepts i t = false

/-- `encode_at` signs `"<now + ttl_s>|<value>"`; `load_at` refuses a
payload with no expiry or a past one.
mirrors flare/http/session.mojo#CookieSessionStore.encode_at+CookieSessionStore.load_at sha=f0b87fbcec86 at=ea1b9282 (fixed, DOC-06) -/
def csEncode (now : Nat) (v : String) : Payload := ⟨some (now + lifetime), v⟩

/-- mirrors flare/http/session.mojo#CookieSessionStore.encode_at+CookieSessionStore.load_at sha=f0b87fbcec86 at=ea1b9282 (fixed, DOC-06) -/
def csLoad (now : Nat) (p : Payload) : Option String :=
  match p.exp with
  | some e => if now < e then some p.value else none
  | none => none

def csAccepts (v : String) (i t : Nat) : Bool := (csLoad t (csEncode i v)).isSome

/-- `BackedSessionStore.__init__`: `ttl_s` defaults to `DEFAULT_SESSION_TTL_S`.
mirrors flare/http/session.mojo#BackedSessionStore.__init__+DEFAULT_SESSION_TTL_S sha=ee85d229796f at=ea1b9282 (fixed, DOC-06) -/
def backedDefaultTtl : Nat := lifetime

theorem expires (v : String) :
    Expires (csAccepts v) ∧ Expires (bsAccepts backedDefaultTtl) := by
  refine ⟨⟨lifetime, fun i t h => ?_⟩, ⟨lifetime, fun i t h => ?_⟩⟩
  · have : ¬ t < i + lifetime := by omega
    simp [csAccepts, csLoad, csEncode, this]
  · have : ¬ t < i + lifetime := by omega
    simp [bsAccepts, live, expiry, backedDefaultTtl, lifetime] at this ⊢
    omega

/-- A payload signed without an expiry is refused. -/
theorem csLoad_rejects_bare (t : Nat) (v : String) : csLoad t ⟨none, v⟩ = none := rfl

/-- A fresh session is accepted. -/
theorem csLoad_fresh (i : Nat) (v : String) : csLoad i (csEncode i v) = some v := by
  simp [csLoad, csEncode, lifetime]

end Session

/-! ## TLS reload rotates resumption state (DOC-07) -/

namespace TlsReload

/-- The parts of an `SSL_CTX` that matter here. -/
structure Ctx where
  cert : Nat
  ticketKey : Nat
  cache : List Nat
  deriving DecidableEq, Repr

/-- A resumption attempt: the key its ticket was sealed under, or a cached
session id. -/
inductive Offer
  | ticket (key : Nat)
  | sessionId (id : Nat)
  deriving DecidableEq, Repr

def resumes (c : Ctx) : Offer → Bool
  | .ticket k => k == c.ticketKey
  | .sessionId i => c.cache.contains i

/-- `TlsAcceptor.reload`: a fresh `SSL_CTX` (new ticket key, empty cache).
mirrors flare/tls/acceptor.mojo#TlsAcceptor.reload sha=74b6a208f52c at=ea1b9282 (fixed, DOC-07) -/
def reload (_c : Ctx) (newCert fresh : Nat) : Ctx :=
  { cert := newCert, ticketKey := fresh, cache := [] }

/-- The doc's promise: after `reload`, nothing issued before it resumes. -/
def Rotates (r : Ctx → Nat → Nat → Ctx) : Prop :=
  ∀ c cert fresh o, fresh ≠ c.ticketKey → resumes c o = true → resumes (r c cert fresh) o = false

theorem rotates : Rotates reload := by
  intro c cert fresh o hfresh hres
  cases o with
  | ticket k =>
    simp [resumes] at hres
    subst hres
    simp [resumes, reload]
    omega
  | sessionId i => simp [resumes, reload]

/-- Sessions issued after the reload still resume. -/
theorem reload_new_ticket (c : Ctx) (cert fresh : Nat) :
    resumes (reload c cert fresh) (.ticket fresh) = true := by
  simp [resumes, reload]

end TlsReload

/-! ## Session tickets are opt-in (DOC-08) -/

namespace Tickets

/-- What a server `SSL_CTX` does about resumption. -/
structure Ctx where
  issues : Bool
  resumes : Bool
  deriving DecidableEq, Repr

/-- After `flare_ssl_ctx_enable_session_tickets`. -/
def ticketsOn : Ctx := { issues := true, resumes := true }
/-- After `flare_ssl_ctx_disable_session_tickets`. -/
def ticketsOff : Ctx := { issues := false, resumes := false }

/-- `TlsServerConfig.enable_session_tickets` defaults to `False`;
`TlsAcceptor.__init__` enables, or calls
`flare_ssl_ctx_disable_session_tickets`.
mirrors flare/tls/acceptor.mojo#TlsServerConfig.__init__+TlsAcceptor.__init__ sha=397845a14f0a at=ea1b9282 (fixed, DOC-08) -/
def defaultTickets : Bool := false

/-- mirrors flare/tls/acceptor.mojo#TlsServerConfig.__init__+TlsAcceptor.__init__ sha=397845a14f0a at=ea1b9282 (fixed, DOC-08) -/
def build (enable : Bool) : Ctx := if enable then ticketsOn else ticketsOff

/-- The doc's promise: off unless asked for, and off really means off. -/
def OptIn (dflt : Bool) (b : Bool → Ctx) : Prop :=
  dflt = false ∧ (b false).issues = false ∧ (b false).resumes = false

theorem opt_in : OptIn defaultTickets build := by
  unfold OptIn; decide

/-- Callers who ask for resumption get it. -/
theorem build_on : build true = ticketsOn := by decide

end Tickets

end Flare.L4.Policies
