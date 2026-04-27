-- benchmark/scripts/wrk_soak_slow_clients.lua
--
-- v0.5.0 / S3.7 — slow-client soak workload (see docs/soak.md).
--
-- Models the design-v0.5 §6.5 slow-client gate:
-- "256 connections, 1 byte / 100 ms, watch RSS. Expect: flat memory
-- after 1 hour."
--
-- wrk's protocol model isn't a perfect fit for byte-level pacing
-- inside a single request body; the closest approximation we can
-- drive from a lua script is to make every connection issue a
-- short POST and then sleep 100 ms before its next request. The
-- effective per-connection rate is ~10 req/s carrying ~100 B each,
-- which exercises:
--
--   * accept-loop holding many concurrent connections,
--   * read-body deadline arming/cancelling per request,
--   * keep-alive bookkeeping under low per-connection throughput.
--
-- It does NOT exercise flare's read-body-timeout-fires path the
-- way a true byte-trickle harness would. That gap is captured at
-- the top of docs/soak.md and is the reason the 24 h gate runs
-- on EPYC, not on this Lua approximation.
local body_chunks = {}
for i = 1, 100 do
    body_chunks[i] = "x"
end

wrk.method = "POST"
wrk.path = "/plaintext"
wrk.body = table.concat(body_chunks)
wrk.headers["Content-Type"] = "application/octet-stream"

function delay()
    return 100
end
