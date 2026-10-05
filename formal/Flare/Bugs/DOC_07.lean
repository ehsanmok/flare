/-!
# DOC-07: `TlsAcceptor.reload()` does not rotate the session-ticket key

Status: resolved. `TlsAcceptor.reload` builds a new `TlsAcceptor` from `config`
and replaces `self` (`flare/tls/acceptor.mojo`), so the new `SSL_CTX` has fresh
ticket keys and an empty session cache; a failed reload raises before anything
is replaced. Regression test `tests/tls/test_tls_ticket_rotation.mojo::
test_reload_rotates_the_ticket_key`. `reload` below is the shipped model;
`reloadOld` is the pre-fix behaviour.

* flare file (pre-fix): `flare/tls/acceptor.mojo:369-376` @59bda50 (`reload` calls
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
* Fix (`reload`): build a fresh context on reload (new ticket key, empty
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

/-- Pre-fix.
mirrors flare/tls/acceptor.mojo:369-376 @59bda50 and
flare/tls/ffi/openssl_wrapper.cpp:559-620 @59bda50 -/
def reloadOld (c : Ctx) (newCert _fresh : Nat) : Ctx := { c with cert := newCert }

/-- `TlsAcceptor.reload`: a fresh `SSL_CTX` (new ticket key, empty cache).
mirrors flare/tls/acceptor.mojo:369-387 (fixed, DOC-07) -/
def reload (_c : Ctx) (newCert fresh : Nat) : Ctx :=
  { cert := newCert, ticketKey := fresh, cache := [] }

/-- The doc's promise: after `reload`, nothing issued before it resumes. -/
def Rotates (r : Ctx → Nat → Nat → Ctx) : Prop :=
  ∀ c cert fresh o, fresh ≠ c.ticketKey → resumes c o = true → resumes (r c cert fresh) o = false

/-- The repro: a ticket sealed before the reload (same cert files) resumes
after it. -/
def ctx0 : Ctx := { cert := 1, ticketKey := 42, cache := [] }

theorem bug : resumes (reloadOld ctx0 1 43) (.ticket 42) = true := by decide

theorem counterexample : ¬ Rotates reloadOld := by
  intro h
  have := h ctx0 1 43 (.ticket 42) (by decide) (by decide)
  rw [bug] at this
  cases this

theorem fixed : Rotates reload := by
  intro c cert fresh o hfresh hres
  cases o with
  | ticket k =>
    simp [resumes] at hres
    subst hres
    simp [resumes, reload]
    omega
  | sessionId i => simp [resumes, reload]

/-- The fix still resumes sessions issued after the reload. -/
theorem fixed_new_ticket (c : Ctx) (cert fresh : Nat) :
    resumes (reload c cert fresh) (.ticket fresh) = true := by
  simp [resumes, reload]

end Flare.Bugs.DOC_07
