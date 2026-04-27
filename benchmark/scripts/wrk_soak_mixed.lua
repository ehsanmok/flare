-- benchmark/scripts/wrk_soak_mixed.lua
--
-- v0.5.0 / S3.7 — mixed-load soak workload (see docs/soak.md).
--
-- Models the design-v0.5 §6.5 mixed-load gate:
-- "20% slow, 80% normal. Expect: zero failed requests, zero
-- crashes, RSS within 2x of cold-start."
--
-- The "slow" share here is approximated by tagging every 5th
-- request with ``Connection: close`` (forces the server to close
-- the connection after the response, the way a slow client would
-- if it hung up). The remaining 80% are standard HTTP/1.1
-- keep-alive requests. This is the same approximation
-- ``wrk_mixed_keepalive.lua`` uses for the bench-vs-baseline
-- ``mixed_keepalive`` config; the soak variant reuses the shape
-- and pins the path to ``/plaintext`` for the soak harness.
local counter = 0

request = function()
    counter = counter + 1
    local headers = {}
    if counter % 5 == 0 then
        headers["Connection"] = "close"
    end
    return wrk.format("GET", "/plaintext", headers)
end
