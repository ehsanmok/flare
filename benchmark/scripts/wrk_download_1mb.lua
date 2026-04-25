-- 1MB GET download (v0.5.0 Step 2 / Track 6.2). Headline target
-- for the streaming-body reactor adoption: response should not
-- allocate 1MB per concurrent client once the chunked-write
-- loop lands.
wrk.method = "GET"
wrk.path = "/1mb"
