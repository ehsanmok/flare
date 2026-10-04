/-!
# DOC-07: `TlsAcceptor.reload()` does not rotate the session-ticket key

* flare file: `flare/tls/acceptor.mojo:369-376` @59bda50 (`reload` calls
  `ServerCtx.reload`, `flare/tls/_server_ffi.mojo:272-276`, which calls
  `flare_ssl_ctx_reload`, `flare/tls/ffi/openssl_wrapper.cpp:559+`: a new
  chain and key are installed on the same `SSL_CTX`). Tickets are on by
  default (`acceptor.mojo:206`, `openssl_wrapper.cpp:489-516`); nothing sets
  new ticket keys or flushes the server session cache.
* Doc clause: `docs/threat-model.md:59` (TLS session-ticket replay) "the
  OpenSSL rotation key is part of the TlsAcceptor and rotates with `reload`".
* What goes wrong: a ticket (or cached session) issued before `reload()`
  still resumes after it, so `reload` gives no ticket-key rotation: whoever
  holds an old ticket, or the old key, keeps resuming.
* Fix (`reloadFixed`): build a fresh context on reload (new ticket key, empty
  session cache), as `TlsAcceptor.__init__` does.

OpenSSL itself is not modelled: a ticket is the key it was sealed under, and
a resumption succeeds when that key is the context's current key or the
session id is in the server cache. A fresh key differs from the old one (the
hypothesis `hfresh`; OpenSSL draws 80 random bytes).
-/
namespace Flare.Bugs.DOC_07

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

/-- mirrors flare/tls/acceptor.mojo:369-376 @59bda50 and
flare/tls/ffi/openssl_wrapper.cpp:559-620 @59bda50 -/
def reload (c : Ctx) (newCert _fresh : Nat) : Ctx := { c with cert := newCert }

def reloadFixed (_c : Ctx) (newCert fresh : Nat) : Ctx :=
  { cert := newCert, ticketKey := fresh, cache := [] }

/-- The doc's promise: after `reload`, nothing issued before it resumes. -/
def Rotates (r : Ctx → Nat → Nat → Ctx) : Prop :=
  ∀ c cert fresh o, fresh ≠ c.ticketKey → resumes c o = true → resumes (r c cert fresh) o = false

/-- The repro: a ticket sealed before the reload (same cert files) resumes
after it. -/
def ctx0 : Ctx := { cert := 1, ticketKey := 42, cache := [] }

theorem bug : resumes (reload ctx0 1 43) (.ticket 42) = true := by decide

theorem counterexample : ¬ Rotates reload := by
  intro h
  have := h ctx0 1 43 (.ticket 42) (by decide) (by decide)
  rw [bug] at this
  cases this

theorem fixed : Rotates reloadFixed := by
  intro c cert fresh o hfresh hres
  cases o with
  | ticket k =>
    simp [resumes] at hres
    subst hres
    simp [resumes, reloadFixed]
    omega
  | sessionId i => simp [resumes, reloadFixed]

/-- The fix still resumes sessions issued after the reload. -/
theorem fixed_new_ticket (c : Ctx) (cert fresh : Nat) :
    resumes (reloadFixed c cert fresh) (.ticket fresh) = true := by
  simp [resumes, reloadFixed]

end Flare.Bugs.DOC_07
