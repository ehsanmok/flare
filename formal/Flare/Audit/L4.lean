import Flare.L4_App
/-! L4 application layer: axiom footprint of the headline theorems. Expected:
`propext`, `Quot.sound`, `Classical.choice`. -/

-- ConnSM (HTTP/1.1 connection state machine)
#print axioms Flare.L4.ConnSM.inv_inductive
#print axioms Flare.L4.ConnSM.responses_fifo
#print axioms Flare.L4.ConnSM.wire_is_responses
#print axioms Flare.L4.ConnSM.writable_resumes
#print axioms Flare.L4.ConnSM.timeout_closes
#print axioms Flare.L4.ConnSM.run_segs_frozen
#print axioms Flare.L4.ConnSM.ka_bound
#print axioms Flare.L4.ConnSM.closeHonoured_step
#print axioms Flare.L4.ConnSM.no_request_after_close_header
#print axioms Flare.L4.ConnSM.Framing.serialize_spec
#print axioms Flare.L4.ConnSM.Framing.headFlag_spec
#print axioms Flare.L4.ConnSM.Framing.staticBytes_spec
-- KeepAlive (Connection header)
#print axioms Flare.L4.KeepAlive.computeCloseAfter_eq_spec
#print axioms Flare.L4.KeepAlive.wantsClose_spec
#print axioms Flare.L4.KeepAlive.wantsClose_sound_close
-- ServerConfig
#print axioms Flare.L4.ServerConfig.default_check
#print axioms Flare.L4.ServerConfig.body_timer_le_request
#print axioms Flare.L4.ServerConfig.head_timer_unordered
#print axioms Flare.L4.ServerConfig.overCapImpl_eq_spec
-- Router / ComptimeRouter
#print axioms Flare.L4.Router.serve_eq_spec
#print axioms Flare.L4.Router.serve_deterministic
#print axioms Flare.L4.Router.serve_valid
#print axioms Flare.L4.Router.allow_exact
#print axioms Flare.L4.Router.first_route_wins
#print axioms Flare.L4.Router.mount_compose
#print axioms Flare.L4.Router.mount_boundary
#print axioms Flare.L4.Router.splitPath_idem
#print axioms Flare.L4.ComptimeRouter.router_equiv_comptime
#print axioms Flare.L4.ComptimeRouter.serveCT_eq_serve
#print axioms Flare.L4.ComptimeRouter.matchOne_eq_spec
#print axioms Flare.L4.ComptimeRouter.matchOne_nonfinal_wild
-- Middleware
#print axioms Flare.L4.Middleware.logger_transparent
#print axioms Flare.L4.Middleware.catchPanic_total
#print axioms Flare.L4.Middleware.catchPanic_idem
#print axioms Flare.L4.Middleware.requestId_echo
#print axioms Flare.L4.Middleware.requestId_outside_catchPanic
#print axioms Flare.L4.Middleware.catchPanic_outside_requestId_error
#print axioms Flare.L4.Middleware.compress_skips_encoded
#print axioms Flare.L4.Middleware.compress_content_length
#print axioms Flare.L4.Middleware.compress_partial
#print axioms Flare.L4.Middleware.compress_vary_when_encoded
#print axioms Flare.L4.Middleware.compress_vary
#print axioms Flare.L4.Middleware.compress_agrees
-- Negotiate / Cors / Cookie / Form / Url
#print axioms Flare.L4.Negotiate.decide'_eq_spec
#print axioms Flare.L4.Negotiate.negotiate_eq_spec
#print axioms Flare.L4.Negotiate.decide'_perm
#print axioms Flare.L4.Negotiate.decide'_refused_identity
#print axioms Flare.L4.Negotiate.specPick_perm
#print axioms Flare.L4.Cors.originAllowed_sound
#print axioms Flare.L4.Cors.originAllowed_iff
#print axioms Flare.L4.Cors.originAllowed_perm
#print axioms Flare.L4.Cors.acao_not_star_with_creds
#print axioms Flare.L4.Cors.attach_has_vary
#print axioms Flare.L4.Cors.serve_vary
#print axioms Flare.L4.Cookie.toSetCookie_noCRLF
#print axioms Flare.L4.Cookie.toSetCookie_none_secure
#print axioms Flare.L4.Cookie.parseMaxAge_sound
#print axioms Flare.L4.Cookie.parseMaxAge_complete
#print axioms Flare.L4.Form.urldecodeBytes_urlencode
#print axioms Flare.L4.Form.urldecode_urlencode
#print axioms Flare.L4.Form.parseForm_toUrlencoded
#print axioms Flare.L4.Form.urldecode_valid
#print axioms Flare.L4.Url.parsePort_iff
#print axioms Flare.L4.Url.parse_port
#print axioms Flare.L4.Url.parse_spec
-- Reliability: RateLimit / CircuitBreaker / Retry
#print axioms Flare.L4.RateLimit.step_eq_spec
#print axioms Flare.L4.RateLimit.step_inv
#print axioms Flare.L4.RateLimit.step_last_ok
#print axioms Flare.L4.RateLimit.stepUnclamped_eq_spec
#print axioms Flare.L4.RateLimit.stepUnclamped_inv
#print axioms Flare.L4.RateLimit.overflow_iff
#print axioms Flare.L4.CircuitBreaker.counts_inductive
#print axioms Flare.L4.CircuitBreaker.step_counts_inv
#print axioms Flare.L4.CircuitBreaker.step_open_rejects
#print axioms Flare.L4.CircuitBreaker.cooldown_respected
#print axioms Flare.L4.CircuitBreaker.single_probe
#print axioms Flare.L4.Retry.budget_le_max
#print axioms Flare.L4.Retry.sleep_bounds
#print axioms Flare.L4.Retry.serve_calls_bounded
#print axioms Flare.L4.Retry.uncapped_wraps
-- Client: Redirect / ClientPool
#print axioms Flare.L4.Redirect.decide_follow_lt_max
#print axioms Flare.L4.Redirect.sendLoop_terminates
#print axioms Flare.L4.Redirect.rdsAux_no_dots
#print axioms Flare.L4.Redirect.sendLoop_confined
#print axioms Flare.L4.Redirect.sendLoop_auth_monotone
#print axioms Flare.L4.Redirect.sendLoop_cookie_proxy_monotone
#print axioms Flare.L4.Redirect.decide_method_rfc
#print axioms Flare.L4.ClientPool.inv_inductive
#print axioms Flare.L4.ClientPool.caps
#print axioms Flare.L4.ClientPool.acquire_same_origin
-- Drain (single worker)
-- Fixed findings

-- Drain timeout, client pool leases, h2c hand-off, WebSocket over TLS
#print axioms Flare.L4.Drain.graceful
#print axioms Flare.L4.ClientLease.dispose_first
#print axioms Flare.L4.ClientLease.dispose_second
#print axioms Flare.L4.ClientLease.release_once
#print axioms Flare.L4.ClientLease.inv_reachable
#print axioms Flare.L4.ClientLease.acquire_not_held
#print axioms Flare.L4.ClientLease.pool_fd_once
#print axioms Flare.L4.ConnExt.H2c.run_spec
#print axioms Flare.L4.ConnExt.Ws.spec

-- Liveness under fair events, streaming bodies, TLS cross-interest, Negotiate splitter
#print axioms Flare.L4.ConnLive.eventually_served
#print axioms Flare.L4.ConnLive.done_reason
#print axioms Flare.L4.ConnLive.trace_done_sc
#print axioms Flare.L4.ConnStream.Stream.inv_onWritable
#print axioms Flare.L4.ConnStream.Stream.wire_exact_at_end
#print axioms Flare.L4.ConnStream.Stream.wire_prefix
#print axioms Flare.L4.ConnStream.Stream.interest
#print axioms Flare.L4.ConnStream.Tls.blocked_interest
#print axioms Flare.L4.ConnStream.Tls.retry_read
#print axioms Flare.L4.ConnStream.Tls.retry_write
#print axioms Flare.L4.ConnStream.Tls.read_fifo
#print axioms Flare.L4.ConnStream.Tls.inv_route
#print axioms Flare.L4.ConnStream.Tls.interest_nonempty
#print axioms Flare.L4.Negotiate.parseHeaderMojo_eq
-- Interim 100 Continue that the socket does not take whole (APP-49)
#print axioms Flare.L4.Continue.Plain.run_spec
#print axioms Flare.L4.Continue.Tls.run_spec
-- Documented policies (DOC-04 to DOC-08)
#print axioms Flare.L4.Policies.ErrorLog.policy
#print axioms Flare.L4.Policies.EntryPoints.entry_spec
#print axioms Flare.L4.Policies.Session.expires
#print axioms Flare.L4.Policies.TlsReload.rotates
#print axioms Flare.L4.Policies.Tickets.opt_in
