import Flare.L4_App
/-! L4 application layer: axiom footprint of the headline theorems. Expected
outside `Flare.Bugs`: `propext`, `Quot.sound`, `Classical.choice`. Concrete
counterexamples in `Flare.Bugs.APP_*` that use `native_decide` additionally
report a per-theorem auxiliary axiom `<thm>._native.native_decide.ax_*`. -/

-- ConnSM (HTTP/1.1 connection state machine)
#print axioms Flare.L4.ConnSM.inv_inductive
#print axioms Flare.L4.ConnSM.responses_fifo
#print axioms Flare.L4.ConnSM.wire_is_responses
#print axioms Flare.L4.ConnSM.writable_resumes
#print axioms Flare.L4.ConnSM.timeout_closes
#print axioms Flare.L4.ConnSM.run_segs_frozen
#print axioms Flare.L4.ConnSM.ka_bound
#print axioms Flare.L4.ConnSM.closeHonoured_step
#print axioms Flare.L4.ConnSM.fixed_no_request_after_close_header
#print axioms Flare.L4.ConnSM.Framing.serialize_spec
#print axioms Flare.L4.ConnSM.Framing.headFlagFixed_spec
#print axioms Flare.L4.ConnSM.Framing.staticBytes_spec
-- KeepAlive (Connection header)
#print axioms Flare.L4.KeepAlive.computeCloseAfterFixed_eq_spec
#print axioms Flare.L4.KeepAlive.wantsCloseFixed_spec
#print axioms Flare.L4.KeepAlive.wantsClose_sound_close
-- ServerConfig
#print axioms Flare.L4.ServerConfig.default_check
#print axioms Flare.L4.ServerConfig.body_timer_le_request
#print axioms Flare.L4.ServerConfig.head_timer_unordered
#print axioms Flare.L4.ServerConfig.overCapFixed_eq_spec
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
#print axioms Flare.L4.ComptimeRouter.matchOne_spec
-- Middleware
#print axioms Flare.L4.Middleware.logger_transparent
#print axioms Flare.L4.Middleware.catchPanic_total
#print axioms Flare.L4.Middleware.catchPanic_idem
#print axioms Flare.L4.Middleware.requestId_echo
#print axioms Flare.L4.Middleware.requestId_outside_catchPanic
#print axioms Flare.L4.Middleware.catchPanic_outside_requestId_error
#print axioms Flare.L4.Middleware.compress_skips_encoded
#print axioms Flare.L4.Middleware.compress_content_length
#print axioms Flare.L4.Middleware.compressFixed_partial
#print axioms Flare.L4.Middleware.compressFixed_vary
#print axioms Flare.L4.Middleware.compressFixed_agrees
-- Negotiate / Cors / Cookie / Form / Url
#print axioms Flare.L4.Negotiate.decide_eq_spec_of_noStar
#print axioms Flare.L4.Negotiate.decideFixed_eq_spec
#print axioms Flare.L4.Negotiate.specPick_perm
#print axioms Flare.L4.Cors.originAllowed_sound
#print axioms Flare.L4.Cors.acao_not_star_with_creds
#print axioms Flare.L4.Cors.attach_has_vary
#print axioms Flare.L4.Cors.serveFixed_vary
#print axioms Flare.L4.Cookie.toSetCookie_noCRLF
#print axioms Flare.L4.Cookie.toSetCookie_none_secure
#print axioms Flare.L4.Cookie.parseMaxAge_sound
#print axioms Flare.L4.Cookie.parseMaxAge_complete
#print axioms Flare.L4.Form.urldecodeBytes_urlencode
#print axioms Flare.L4.Form.urldecode_urlencode
#print axioms Flare.L4.Form.parseFormOld_toUrlencoded
#print axioms Flare.L4.Form.parseForm_toUrlencoded
#print axioms Flare.L4.Form.urldecode_valid
#print axioms Flare.L4.Url.parsePort_iff
#print axioms Flare.L4.Url.parse_port
#print axioms Flare.L4.Url.parseFixed_spec
#print axioms Flare.L4.Url.parseOld_eq_parseFixed_of_clean
-- Reliability: RateLimit / CircuitBreaker / Retry
#print axioms Flare.L4.RateLimit.step_eq_spec
#print axioms Flare.L4.RateLimit.step_inv
#print axioms Flare.L4.RateLimit.overflow_iff
#print axioms Flare.L4.CircuitBreaker.counts_inductive
#print axioms Flare.L4.CircuitBreaker.step_open_rejects
#print axioms Flare.L4.Retry.budget_le_max
#print axioms Flare.L4.Retry.sleep_bounds
#print axioms Flare.L4.Retry.serve_calls_bounded
#print axioms Flare.L4.Retry.uncapped_wraps
-- Client: Redirect / ClientPool
#print axioms Flare.L4.Redirect.decide_follow_lt_max
#print axioms Flare.L4.Redirect.sendLoop_terminates
#print axioms Flare.L4.Redirect.sendLoop_confined
#print axioms Flare.L4.Redirect.sendLoop_auth_monotone
#print axioms Flare.L4.Redirect.sendLoop_cookie_proxy_monotone
#print axioms Flare.L4.Redirect.decide_method_rfc
#print axioms Flare.L4.ClientPool.inv_inductive
#print axioms Flare.L4.ClientPool.caps
#print axioms Flare.L4.ClientPool.acquire_same_origin
-- Drain (single worker)
#print axioms Flare.L4.Drain.drain_ignores_timeout
#print axioms Flare.L4.Drain.drain_report_zero

-- Findings: counterexample and fix-meets-spec per issue
#print axioms Flare.Bugs.APP_01.violates_spec
#print axioms Flare.Bugs.APP_01.fixed_close_header_implies_close
#print axioms Flare.Bugs.APP_02.violates_spec
#print axioms Flare.Bugs.APP_02.wantsCloseFixed_meets_spec
#print axioms Flare.Bugs.APP_03.violates_spec
#print axioms Flare.Bugs.APP_03.computeCloseAfterFixed_meets_spec
#print axioms Flare.Bugs.APP_04.static_head_emits_body
#print axioms Flare.Bugs.APP_04.staticFixed_head_no_body
#print axioms Flare.Bugs.APP_05.handler_error_head_emits_body
#print axioms Flare.Bugs.APP_05.errorFixed_head_no_body
#print axioms Flare.Bugs.APP_06.violates_spec
#print axioms Flare.Bugs.APP_06.capFixed_spec
#print axioms Flare.Bugs.APP_10.matchOne_violates_spec
#print axioms Flare.Bugs.APP_10.fixed_meets_spec
#print axioms Flare.Bugs.APP_20.negotiate_violates_spec
#print axioms Flare.Bugs.APP_20.fixed_meets_spec
#print axioms Flare.Bugs.APP_21.violates_spec
#print axioms Flare.Bugs.APP_21.fixed_meets_spec
#print axioms Flare.Bugs.APP_22.violates_spec
#print axioms Flare.Bugs.APP_22.fixed_meets_spec
#print axioms Flare.Bugs.APP_23.host_confusion
#print axioms Flare.Bugs.APP_23.implFixed_meets_spec
#print axioms Flare.Bugs.APP_24.urldecode_violates_spec
#print axioms Flare.Bugs.APP_24.urldecodeFixed_meets_spec
#print axioms Flare.Bugs.APP_24.parseForm_rejects_F0
#print axioms Flare.Bugs.APP_25.host_has_at
#print axioms Flare.Bugs.APP_25.implFixed_meets_spec
#print axioms Flare.Bugs.APP_26.violates_spec
#print axioms Flare.Bugs.APP_26.fixed_meets_spec
#print axioms Flare.Bugs.APP_27.violates_spec
#print axioms Flare.Bugs.APP_27.fixed_meets_spec
#print axioms Flare.Bugs.APP_40.full_bucket_rejected_after_idle
#print axioms Flare.Bugs.APP_40.implFixed_refines_spec
#print axioms Flare.Bugs.APP_41.slow_failure_skips_cooldown
#print axioms Flare.Bugs.APP_41.fixed_cooldown_respected
#print axioms Flare.Bugs.APP_42.halfopen_admits_two
#print axioms Flare.Bugs.APP_42.fixed_halfopen_one_probe
#print axioms Flare.Bugs.APP_43.violates_spec
#print axioms Flare.Bugs.APP_43.resolveFixed_network_path
#print axioms Flare.Bugs.APP_44.host_case_not_same_origin
#print axioms Flare.Bugs.APP_44.sameOriginFixed_case
#print axioms Flare.Bugs.APP_45.query_only_reference_wrong
#print axioms Flare.Bugs.APP_45.resolveFixed_query_only

-- Drain timeout, client pool leases, h2c hand-off, WebSocket over TLS
#print axioms Flare.L4.Drain.drain_ignores_timeout
#print axioms Flare.L4.Drain.fixed_graceful
#print axioms Flare.L4.ClientLease.dispose_first
#print axioms Flare.L4.ClientLease.dispose_second
#print axioms Flare.L4.ClientLease.release_once
#print axioms Flare.L4.ClientLease.inv_reachable
#print axioms Flare.L4.ClientLease.acquire_not_held
#print axioms Flare.L4.ClientLease.pool_fd_once
#print axioms Flare.L4.ConnExt.H2c.impl_spins
#print axioms Flare.L4.ConnExt.H2c.fixed_spec
#print axioms Flare.L4.ConnExt.Ws.old_violates
#print axioms Flare.L4.ConnExt.Ws.spec
#print axioms Flare.Bugs.APP_46.violates_spec
#print axioms Flare.Bugs.APP_46.fixed_meets_spec
#print axioms Flare.Bugs.APP_47.violates_spec
#print axioms Flare.Bugs.APP_47.fixed_meets_spec
#print axioms Flare.Bugs.APP_48.violates_spec
#print axioms Flare.Bugs.APP_48.fixed_meets_spec

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
#print axioms Flare.L4.Negotiate.negotiateMojo_eq

-- Interim 100 Continue that the socket does not take whole (APP-49)
#print axioms Flare.L4.Continue.Plain.violates
#print axioms Flare.L4.Continue.Plain.fixed_spec
#print axioms Flare.L4.Continue.Tls.violates
#print axioms Flare.L4.Continue.Tls.fixed_spec
#print axioms Flare.Bugs.APP_49.violates_spec
#print axioms Flare.Bugs.APP_49.tls_response_lost
#print axioms Flare.Bugs.APP_49.fixed_meets_spec
