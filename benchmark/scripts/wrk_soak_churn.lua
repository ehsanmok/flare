-- benchmark/scripts/wrk_soak_churn.lua
--
-- v0.5.0 / S3.7 — churn soak workload (see docs/soak.md).
--
-- Every request sets ``Connection: close`` so the server closes
-- after the response. wrk reopens for the next request. The
-- effective rate is bounded by ephemeral-port turnover and the
-- accept() throughput on the dev / EPYC box.
--
-- Models the design-v0.5 §6.5 churn gate:
-- "10K conn/s open-close. Expect: zero leaked fds."
--
-- Path is ``/plaintext`` to match the bench-vs-baseline harness so
-- soak runs use the identical server entry point.
wrk.method = "GET"
wrk.path = "/plaintext"
wrk.headers["Connection"] = "close"
