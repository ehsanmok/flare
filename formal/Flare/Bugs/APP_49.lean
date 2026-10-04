import Flare.L4_App.Continue

/-!
# APP-49: an interim `100 Continue` the socket does not take whole is never completed

flare/http/_reactor/conn_handle.mojo:544-576 @59bda50 (`_maybe_send_continue`)
writes the interim line once with a non-blocking `_send` (cleartext) or
`SSL_write` (TLS) and ignores the result; the final response is then
serialised into a cleared `write_buf` and sent from offset 0.

Spec clause: RFC 9112 §2.1 and §4, RFC 9110 §15.2: the server sends
complete messages (an interim response is a whole status line and header
section), and the request is answered.

Counterexamples, both observed on Linux:
* cleartext: the kernel takes 24 of the 25 bytes; the client reads
  `HTTP/1.1 100 Continue\r\n\r` followed directly by `HTTP/1.1 200 OK`;
* TLS: the record does not go out whole; OpenSSL keeps it pending, the
  response's `SSL_write` from `write_buf` fails (`SSL_R_BAD_WRITE_RETRY`)
  and the connection closes with the response unsent.

Repro: formal/repro/APP-49_continue_partial_send_corrupts_stream.mojo.
-/
namespace Flare.Bugs.APP_49
open Flare.L4.Continue

/-- `HTTP/1.1 100 Continue\r\n\r\n` -/
def interim : Bytes :=
  [72, 84, 84, 80, 47, 49, 46, 49, 32, 49, 48, 48, 32,
   67, 111, 110, 116, 105, 110, 117, 101, 13, 10, 13, 10]

/-- `HTTP/1.1 200 OK\r\n` (the start of the final response) -/
def final : Bytes :=
  [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10]

/-- The observed cleartext case: 24 of 25 bytes taken. -/
theorem observed_wire :
    Plain.run [] interim final 24 = interim.take 24 ++ final := by
  rw [Plain.run_eq]; rfl

/-- **Counterexample (cleartext)**: every short send breaks the spec; in
particular the observed one. -/
theorem violates_spec :
    (∀ pre I R k, 0 < k → k < I.length → ¬ Spec pre I R (Plain.run pre I R k) false) ∧
      ¬ Spec [] interim final (Plain.run [] interim final 24) false :=
  ⟨Plain.violates, Plain.violates [] interim final 24 (by decide) (by decide)⟩

/-- **Counterexample (TLS)**: when the interim record does not go out
whole, the response is lost and the connection closes. -/
theorem tls_response_lost (pre I R : Bytes) :
    (Tls.run pre I R false).closed = true ∧ (Tls.run pre I R false).wire = pre ∧
      ¬ Spec pre I R (Tls.run pre I R false).wire (Tls.run pre I R false).closed :=
  Tls.violates pre I R

/-- **Fix meets spec**: keep what the socket did not take and send it
before the response (cleartext: prepend the tail to `write_buf`; TLS:
retry from the connection's own copy), for every kernel and TLS outcome. -/
theorem fixed_meets_spec :
    (∀ pre I R k, Spec pre I R (Plain.runFixed pre I R k) false) ∧
      (∀ pre I R ok, Spec pre I R (Tls.runFixed pre I R ok).wire (Tls.runFixed pre I R ok).closed) :=
  ⟨Plain.fixed_spec, Tls.fixed_spec⟩

end Flare.Bugs.APP_49
