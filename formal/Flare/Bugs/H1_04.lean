import Flare.L3_Protocol.H1.Framing

/-!
# H1-04: a bare-LF header line hides `Transfer-Encoding` from the reactor under `allow_lf_only_line_endings`

Status: resolved. `request_te_framing` now ends header lines (and the request
line) at LF, dropping a preceding CR (`reactorLines`). Regression tests:
`tests/http/test_h1_smuggling.mojo::test_te_framing_ends_header_lines_at_a_bare_lf`,
`test_bare_lf_reactor_and_parser_agree`.

* flare file: `flare/http/proto/chunked.mojo:143-178` (fixed, H1-04); before
  the fix `:133-137` (header lines split on CRLF only) vs
  `flare/http/_server/parse_util.mojo` `_read_line_buf_lenient` (splits on LF
  when `allow_lf_only_line_endings`) @59bda50.
* Spec clause: RFC 9112 §2.2 (a recipient MAY accept bare LF as a line
  terminator) together with §6.3 (framing must agree).
* What goes wrong: `Host: a\nTransfer-Encoding: chunked` is one line to the
  reactor, which therefore frames by Content-Length 0, and two lines to the
  parser, which accepts `Transfer-Encoding: chunked`. The chunked body is
  parsed as the next request.
* Fix: split the reactor's header lines on LF and drop one trailing CR,
  exactly as the LF-lenient parser does (`reactorLines`, `lf_fixed_agrees`).
  The head terminator search (CRLFCRLF) is unchanged and lies outside this
  line-level model. The counterexample is kept about `linesCRLFOld`, the
  pre-fix split.
-/
namespace Flare.Bugs.H1_04
open Flare Flare.L3.H1.Framing

/-- The repro's header block (between the request line and the final CRLF). -/
def blk : Bytes := Bytes.ofString "Host: a\nTransfer-Encoding: chunked"

theorem reactor_lines : linesCRLFOld blk = [blk] := by native_decide

theorem reactor_frames_by_length : reactorFraming false (2 ^ 20) (linesCRLFOld blk) = .length 0 := by
  native_decide

theorem parser_sees_chunked : parserFraming false false (2 ^ 20) (linesLF blk) = .chunked := by
  native_decide

theorem counterexample :
    parserFraming false false (2 ^ 20) (linesLF blk) ≠ .reject ∧
    reactorFraming false (2 ^ 20) (linesCRLFOld blk) ≠
      parserFraming false false (2 ^ 20) (linesLF blk) := by
  rw [reactor_frames_by_length, parser_sees_chunked]
  exact ⟨by decide, by decide⟩

/-- The shipped reactor sees the TE line. -/
theorem fixed_frames_chunked : reactorFraming false (2 ^ 20) (reactorLines blk) = .chunked := by
  native_decide

/-- The shipped reactor agrees with the LF-lenient parser on every accepted block. -/
theorem fixed_agrees (allowCL : Bool) (maxBody : Nat) (b : Bytes)
    (h : parserFraming false allowCL maxBody (linesLF b) ≠ .reject) :
    reactorFraming allowCL maxBody (reactorLines b) = parserFraming false allowCL maxBody (linesLF b) :=
  lf_fixed_agrees allowCL maxBody b h

end Flare.Bugs.H1_04
