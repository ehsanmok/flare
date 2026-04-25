-- Churn workload (v0.5.0 Step 2 / Track 6.2).
--
-- Every request sets ``Connection: close`` so the server closes
-- after the response. wrk reopens for the next request. The
-- effective rate is bounded by ephemeral-port turnover and
-- accept() throughput.
wrk.method = "GET"
wrk.path = "/"
wrk.headers["Connection"] = "close"
