-- benchmark/scripts/wrk_mixed_keepalive.lua
--
-- v0.5.0 Step 1 — drives the ``mixed_keepalive`` workload.
--
-- Sends ``Connection: close`` on roughly 20% of requests (every
-- 5th) and keeps the rest as standard HTTP/1.1 keep-alive. Catches
-- regressions in flare's connection-disposition path that a pure
-- keep-alive load doesn't exercise.

-- Keep the wrk default (no path argument) for easy harness swap-in.
local counter = 0

request = function()
    counter = counter + 1
    local headers = {}
    if counter % 5 == 0 then
        headers["Connection"] = "close"
    end
    return wrk.format(nil, nil, headers)
end
