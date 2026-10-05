/-!
# DOC-08: server session tickets are not opt-in, and the off switch does not work

Status: resolved. `TlsServerConfig.enable_session_tickets` defaults to `False`
and `TlsAcceptor` now calls the new `ServerCtx.disable_session_tickets`
(`flare_ssl_ctx_disable_session_tickets`: `SSL_OP_NO_TICKET`,
`SSL_CTX_set_num_tickets(ctx, 0)`, `SSL_SESS_CACHE_OFF`) when it is `False`.
Regression tests `tests/tls/test_tls_ticket_rotation.mojo`
(`test_session_tickets_are_opt_in_by_default`, `test_tickets_off_issues_no_session`,
`test_default_config_issues_no_session`; control
`test_explicit_tickets_issue_a_resumable_session`). The unprimed definitions
below (`defaultTickets`, `build`) are the shipped model; the `Old` ones are the
pre-fix behaviour.

* flare file (pre-fix): `flare/tls/acceptor.mojo:206` @59bda50
  (`enable_session_tickets: Bool = True`) and `acceptor.mojo:364-365` (the
  flag only decides whether `flare_ssl_ctx_enable_session_tickets` is called).
  With `False` the context keeps what `flare_ssl_ctx_new_server`
  (`flare/tls/ffi/openssl_wrapper.cpp:526-557`) left it with: OpenSSL's
  defaults, under which a TLS 1.3 server sends two NewSessionTicket messages
  and keeps a server session cache.
* Doc clause: `docs/features.md:572` "server-side ticket cache (opt-in via
  `TlsServerConfig.enable_session_tickets`)".
* What goes wrong: a default `TlsServerConfig` issues resumable tickets, and
  one built with `enable_session_tickets=False` still issues them and resumes
  them. There is no way to turn resumption off.
* Fix (`build`, `defaultTickets`): default the flag to `False`, and
  when it is `False` set `SSL_OP_NO_TICKET`, `SSL_CTX_set_num_tickets(ctx, 0)`
  and `SSL_SESS_CACHE_OFF`.

OpenSSL is modelled by what a context does with a returning client: whether
it issues a ticket, and whether it resumes one. `opensslDefault` is the
context `SSL_CTX_new(TLS_server_method())` gives.
-/
namespace Flare.Bugs.DOC_08

/-- What a server `SSL_CTX` does about resumption. -/
structure Ctx where
  issues : Bool
  resumes : Bool
  deriving DecidableEq, Repr

/-- OpenSSL's defaults for a fresh server context. -/
def opensslDefault : Ctx := { issues := true, resumes := true }

/-- After `flare_ssl_ctx_enable_session_tickets`. -/
def ticketsOn : Ctx := { issues := true, resumes := true }

def ticketsOff : Ctx := { issues := false, resumes := false }

/-- Pre-fix.
mirrors flare/tls/acceptor.mojo:206 @59bda50 -/
def defaultTicketsOld : Bool := true

/-- Pre-fix.
mirrors flare/tls/acceptor.mojo:364-365 @59bda50 and
flare/tls/ffi/openssl_wrapper.cpp:526-557 @59bda50 -/
def buildOld (enable : Bool) : Ctx := if enable then ticketsOn else opensslDefault

/-- `TlsServerConfig.enable_session_tickets` default.
mirrors flare/tls/acceptor.mojo:208 (fixed, DOC-08) -/
def defaultTickets : Bool := false

/-- `TlsAcceptor.__init__`: enable, or `flare_ssl_ctx_disable_session_tickets`.
mirrors flare/tls/acceptor.mojo:365-368 and
flare/tls/ffi/openssl_wrapper.cpp:518-533 (fixed, DOC-08) -/
def build (enable : Bool) : Ctx := if enable then ticketsOn else ticketsOff

/-- The doc's promise: off unless asked for, and off really means off. -/
def OptIn (dflt : Bool) (b : Bool → Ctx) : Prop :=
  dflt = false ∧ (b false).issues = false ∧ (b false).resumes = false

/-- The repro: the default is on, and `False` still issues and resumes. -/
theorem bug : defaultTicketsOld = true ∧ (buildOld false).issues = true ∧ (buildOld false).resumes = true := by
  decide

theorem counterexample : ¬ OptIn defaultTicketsOld buildOld := by
  intro h
  exact absurd h.1 (by decide)

theorem counterexample_switch : (buildOld false).resumes = true := by decide

theorem fixed : OptIn defaultTickets build := by
  unfold OptIn; decide

/-- The fix keeps resumption for callers who ask for it. -/
theorem fixed_on : build true = ticketsOn := by decide

end Flare.Bugs.DOC_08
