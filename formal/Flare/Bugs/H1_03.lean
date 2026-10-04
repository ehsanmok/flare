import Flare.L3_Protocol.H1.Framing

/-!
# H1-03: `Transfer-Encoding : chunked` desyncs reactor and parser under `allow_ows_around_colon`

* flare file: `flare/http/proto/chunked.mojo:139-141` (`buf[p] == ':'` right
  after the 17-byte name) vs `flare/http/_server/parse.mojo:247-256`
  (`allow_ows_around_colon` strips SP/HTAB before the colon) @59bda50.
* Spec clause: RFC 9112 §6.3 (the framing every recipient derives must
  agree) and §5.1 (whitespace before the colon is invalid; a server that
  accepts it must not let it change the framing).
* What goes wrong: the reactor does not see the TE line, frames the request
  by Content-Length (absent, so 0), and hands the parser only the head. The
  parser recognises `Transfer-Encoding: chunked` and accepts. The chunked
  body is then parsed as the next request on the connection.
* Fix: in `request_te_framing`, skip SP/HTAB between the name and the colon
  (`scanField true`), which `framing_agrees` proves agrees with the
  OWS-lenient parser whenever it accepts.
-/
namespace Flare.Bugs.H1_03
open Flare Flare.L3.H1.Framing

/-- Field lines of the repro's request head. -/
def lines : List Bytes := [Bytes.ofString "Host: a", Bytes.ofString "Transfer-Encoding : chunked"]

theorem reactor_frames_by_length : reactorFraming false false (2 ^ 20) lines = .length 0 := by
  native_decide

theorem parser_sees_chunked : parserFraming true false (2 ^ 20) lines = .chunked := by
  native_decide

theorem counterexample :
    parserFraming true false (2 ^ 20) lines ≠ .reject ∧
    reactorFraming false false (2 ^ 20) lines ≠ parserFraming true false (2 ^ 20) lines := by
  rw [reactor_frames_by_length, parser_sees_chunked]
  exact ⟨by decide, by decide⟩

/-- With the fix the reactor sees the TE line. -/
theorem fixed_frames_chunked : reactorFraming true false (2 ^ 20) lines = .chunked := by
  native_decide

/-- The fixed reactor agrees with the OWS-lenient parser on every accepted head. -/
theorem fixed_agrees (allowCL : Bool) (maxBody : Nat) (ls : List Bytes)
    (h : parserFraming true allowCL maxBody ls ≠ .reject) :
    reactorFraming true allowCL maxBody ls = parserFraming true allowCL maxBody ls :=
  framing_agrees true allowCL maxBody ls h

end Flare.Bugs.H1_03
