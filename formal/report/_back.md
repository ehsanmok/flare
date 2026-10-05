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

- Run `formal-check` and `formal-repros` in CI. Neither is wired into
  `.github` yet. A clean Lean build took about two and a half minutes on an
  Apple Silicon Mac, and one pass over all repros about six and a half;
  the io_uring repros need a Linux runner.
- Keep the models in sync with the code. Each implementation model names the
  Mojo lines it mirrors, so a CI step could fail when one of
  those line ranges changes and the matching Lean file does not.
- Test the models against the code. Running the Lean implementation models
  with `#eval` on the inputs in the existing fuzz corpora and comparing their
  output with flare's would catch drift between the transliteration and the
  source that the fidelity comments cannot.
- Keep the repros as regression checks. All 138 findings are fixed and every
  repro carries a `# RESOLVED:` header; `formal-repros` reports a resolved
  repro that starts failing again as an error.
