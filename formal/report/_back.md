### Outside the model throughout

- Cryptography and TLS. OpenSSL is a black box: the handshake, certificate
  verification, ciphers, session tickets and the QUIC packet protection keys
  are not modelled. The models start from decrypted bytes and from what the
  TLS layer reports (handshake done, ALPN result, close_notify or not).
- The Mojo compiler and runtime, libc, and the kernel. Their behaviour enters
  only through the stated hypotheses; the proofs say nothing about a libc
  that breaks them.
- Performance and timing. No theorem bounds latency, throughput or memory use
  beyond the explicit caps in the code, and nothing is said about timing side
  channels. The exceptions are the QUIC idle and closing timers and the
  shutdown bound in `Flare.L5.Timed`, both over an abstract clock.
- Compression internals (zlib, brotli, the permessage-deflate LZ77 state).
  Only the size caps and the decisions around them are modelled.
- Fairness. The concurrency and machine models assume no fair scheduler, so
  what they prove is safety. The liveness results either take fairness as an
  explicit hypothesis (`Flare.L4.ConnLive.eventually_served`,
  `Flare.L5.Timed.teardown_done_by`), are bounded,
  or are argued in prose, and each section says which.

### Next steps

- Run `formal-check` and `difftest` in CI. Neither is wired into `.github`
  yet; the pre-commit hook runs the fast gates and the affected difftests.
- Work down the tracked-tier anchor backlog (`pixi run -e formal
  formal-status`), so more models are checked against the current code.
- Extend the difftest to the client role of HTTP/2 and to QUIC, the largest
  models it does not reach yet.
