import Flare.L3_Protocol.H1.ChunkedSpec

/-!
# H1-02: bare LF inside a chunk extension or trailer line is accepted

Status: resolved. `scan_chunked_resume` now treats a size line or trailer
line that contains an LF as MALFORMED (`implP` has `rejectLF = true`).
Regression test: `tests/http/test_chunked_request.mojo::test_scan_rejects_bare_lf_in_chunk_lines`.

* flare file: `flare/http/proto/chunked.mojo:253-325` (fixed, H1-02); before the
  fix `:239-266` (size line, extension skipped after `;`) and `:270-290`
  (trailer lines) @59bda50.
* Spec clause: RFC 9112 §7.1.1 (chunk-ext is tokens / quoted-strings, no LF)
  together with RFC 9112 §2.2 (a recipient MAY treat a bare LF as a line
  terminator). Every body flare accepts must be framed identically by an
  LF-tolerant recipient (`LfSafe`), else the two disagree on where the body
  ends (request smuggling).
* What went wrong: only CRLF ended a line; bytes after `;` and whole trailer
  lines were never inspected, so `0;\n\r\nX: y\r\n\r\n` was accepted with end
  13, while an LF-tolerant recipient ends the same body at 5.
* Fix (`implP`): a size or trailer line containing LF is MALFORMED. The
  counterexample is kept about the explicitly named pre-fix scanner `oldP`.
-/
namespace Flare.Bugs.H1_02
open Flare Flare.L3.H1.Chunked

/-- Every accepted body is framed the same by an LF-tolerant recipient. -/
def LfSafe (P : Policy) : Prop :=
  ∀ (buf : Bytes) (start mb e : Nat), scanEnd P buf start mb = .done e →
    ∃ out, decodeBody buf start = .ok (out, e) ∧
      (lfScan (buf.drop start)).map (fun r => (r.1, r.2 + start)) = some (out, e)

def body : Bytes := Bytes.ofString "0;\n\r\nX: y\r\n\r\n"

/-- The pre-fix scanner accepts the witness, ending at 13. -/
theorem old_accepts : scanOld body 0 (2 ^ 20) = .done 13 := by native_decide
theorem lf_recipient_ends_at_5 : lfScan body = some ([], 5) := by native_decide

/-- The pre-fix scanner (`oldP`) is not `LfSafe`. -/
theorem counterexample : ¬ LfSafe oldP := by
  intro h
  obtain ⟨out, -, hl⟩ := h body 0 (2 ^ 20) 13 old_accepts
  rw [List.drop_zero, lf_recipient_ends_at_5] at hl
  simp at hl

/-- The shipped scanner is `LfSafe`. -/
theorem fixed_agrees_lfTolerant : LfSafe implP :=
  fun buf start mb e h => Flare.L3.H1.Chunked.impl_agrees_lfTolerant buf start mb e h

/-- The shipped scanner rejects the witness. -/
theorem fixed_rejects : scanImpl body 0 (2 ^ 20) = .malformed := by native_decide

end Flare.Bugs.H1_02
