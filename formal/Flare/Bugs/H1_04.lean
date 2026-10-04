import Flare.L3_Protocol.H1.Framing

/-!
# H1-04: a bare-LF header line hides `Transfer-Encoding` from the reactor under `allow_lf_only_line_endings`

* flare file: `flare/http/proto/chunked.mojo:133-137` (header lines split on
  CRLF only) vs `flare/http/_server/parse_util.mojo` `_read_line_buf_lenient`
  (splits on LF when `allow_lf_only_line_endings`) @59bda50.
* Spec clause: RFC 9112 §2.2 (a recipient MAY accept bare LF as a line
  terminator) together with §6.3 (framing must agree).
* What goes wrong: `Host: a\nTransfer-Encoding: chunked` is one line to the
  reactor, which therefore frames by Content-Length 0, and two lines to the
  parser, which accepts `Transfer-Encoding: chunked`. The chunked body is
  parsed as the next request.
* Fix: split the reactor's header lines on LF and drop one trailing CR,
  exactly as the LF-lenient parser does (`lf_fixed_agrees`). The head
  terminator search must then also accept LF LF; that part lies outside this
  line-level model.
-/
namespace Flare.Bugs.H1_04
open Flare Flare.L3.H1.Framing

/-- The repro's header block (between the request line and the final CRLF). -/
def blk : Bytes := Bytes.ofString "Host: a\nTransfer-Encoding: chunked"

theorem reactor_lines : linesCRLF blk = [blk] := by native_decide

theorem reactor_frames_by_length : reactorFraming false false (2 ^ 20) (linesCRLF blk) = .length 0 := by
  native_decide

theorem parser_sees_chunked : parserFraming false false (2 ^ 20) (linesLF blk) = .chunked := by
  native_decide

theorem counterexample :
    parserFraming false false (2 ^ 20) (linesLF blk) ≠ .reject ∧
    reactorFraming false false (2 ^ 20) (linesCRLF blk) ≠
      parserFraming false false (2 ^ 20) (linesLF blk) := by
  rw [reactor_frames_by_length, parser_sees_chunked]
  exact ⟨by decide, by decide⟩

theorem fixed_frames_chunked : reactorFraming false false (2 ^ 20) (linesLF blk) = .chunked := by
  native_decide

theorem fixed_agrees (allowCL : Bool) (maxBody : Nat) (b : Bytes)
    (h : parserFraming false allowCL maxBody (linesLF b) ≠ .reject) :
    reactorFraming false allowCL maxBody (linesLF b) = parserFraming false allowCL maxBody (linesLF b) :=
  lf_fixed_agrees allowCL maxBody b h

end Flare.Bugs.H1_04
