-- 1MB POST upload (v0.5.0 Step 2 / Track 6.2). Headline target
-- for the RequestView zero-copy gate: ≥ 4x throughput vs the
-- v0.4.x copy path once the reactor adopts ``parse_request_view``.
local body = string.rep("x", 1024 * 1024)
wrk.method = "POST"
wrk.body = body
wrk.headers["Content-Type"] = "application/octet-stream"
