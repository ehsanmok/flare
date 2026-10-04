import Flare.L3_Protocol.H1.ClientResponse

/-!
# H1-11: a streamed TLS download ending without close_notify is complete

* flare file: `flare/http/_client/download.mojo:215-220` (close-delimited
  bodies read to `n == 0`) over `flare/http/_client/h2_transport.mojo`
  (`read` returns 0 on an unclean TLS EOF) @59bda50. The buffered readers
  have the guard (`flare/http/_client/parse.mojo:665-683`).
* Spec clause: RFC 8446 §6.1 (a close without close_notify is a
  truncation) with RFC 9112 §8 (a close-delimited body ends at a clean
  close).
* What goes wrong: an attacker who can reset the TCP connection cuts the
  body at any point and the download reports success.
* Fix (`dlCloseFixed`, the buffered guard): `bufferedClose_safe`.
-/
namespace Flare.Bugs.H1_11
open Flare Flare.L3.H1.ClientResponse

def part : List Bytes := [[112, 97, 114, 116, 105, 97, 108]]

theorem shipped_accepts : dlClose part true = .ok [112, 97, 114, 116, 105, 97, 108] := rfl

theorem counterexample : ¬ TruncSafe dlClose := fun h => h _ _ shipped_accepts

theorem fixed_safe : TruncSafe dlCloseFixed := bufferedClose_safe

end Flare.Bugs.H1_11
