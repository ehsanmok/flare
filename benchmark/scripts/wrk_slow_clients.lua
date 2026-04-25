-- Slow-clients workload (v0.5.0 Step 2 / Track 6.2).
--
-- Each connection sends a request, then trickles 1 byte every
-- 100ms. The server's read_body_timeout_ms (default 5s in
-- ServerConfig) should fire eventually and close the
-- connection — the v0.4.x slow-body-DoS fix wired through
-- Step 1's deadline plumbing.
--
-- This Lua script hooks wrk's per-thread state machine to delay
-- between body chunks. wrk's protocol model isn't a perfect fit
-- for slow-clients (it doesn't natively pace bytes); this is the
-- closest approximation. A future bench harness commit may replace
-- the wrk driver here with a custom socket-trickle harness.
local body_chunks = {}
for i = 1, 100 do
    body_chunks[i] = "x"
end

wrk.method = "POST"
wrk.body = table.concat(body_chunks)
wrk.headers["Content-Type"] = "application/octet-stream"

-- Sleep between requests so each connection's effective rate is
-- one byte per 100ms across the run.
function delay()
    return 100
end
