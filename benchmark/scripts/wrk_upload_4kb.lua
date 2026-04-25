-- 4KB POST upload (v0.5.0 Step 2 / Track 6.2).
local body = string.rep("x", 4 * 1024)
wrk.method = "POST"
wrk.body = body
wrk.headers["Content-Type"] = "application/octet-stream"
