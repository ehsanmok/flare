-- 4KB GET download (v0.5.0 Step 2 / Track 6.2). Server is
-- expected to expose a /4kb route returning a 4KB response body.
wrk.method = "GET"
wrk.path = "/4kb"
