-- TLS handshake-per-request workload (v0.5.0 Step 3 /
-- Track 6.4).
--
-- Sets ``Connection: close`` so the server drops the TCP
-- connection after the response, and wrk reopens for the next
-- request. Combined with TLS, this means every request pays
-- the full handshake cost — the worst-case TLS scenario for
-- chatty REST APIs that don't reuse connections.
wrk.method = "GET"
wrk.path = "/plaintext"
wrk.headers["Connection"] = "close"
