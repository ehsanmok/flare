-- 16MB POST upload (v0.5.0 Step 2 / Track 6.2). Larger headline
-- target for the RequestView zero-copy gate.
local body = string.rep("x", 16 * 1024 * 1024)
wrk.method = "POST"
wrk.body = body
wrk.headers["Content-Type"] = "application/octet-stream"
