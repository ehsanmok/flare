import Flare.L3_Protocol.H1.ChunkedSpec

/-!
# H1-02: bare LF inside a chunk extension or trailer line is accepted

* flare file: `flare/http/proto/chunked.mojo:239-266` (size line, extension
  skipped after `;`) and `:270-290` (trailer lines) @59bda50.
* Spec clause: RFC 9112 §7.1.1 (chunk-ext is tokens / quoted-strings, no LF)
  together with RFC 9112 §2.2 (a recipient MAY treat a bare LF as a line
  terminator). Every body flare accepts must be framed identically by an
  LF-tolerant recipient (`LfSafe`), else the two disagree on where the body
  ends (request smuggling).
* What goes wrong: only CRLF ends a line; bytes after `;` and whole trailer
  lines are never inspected, so `0;\n\r\nX: y\r\n\r\n` is accepted with end
  13, while an LF-tolerant recipient ends the same body at 5.
* Fix (`fixedLFP`): a size or trailer line containing LF is MALFORMED.
-/
namespace Flare.Bugs.H1_02
open Flare Flare.L3.H1.Chunked

/-- Every accepted body is framed the same by an LF-tolerant recipient. -/
def LfSafe (P : Policy) : Prop :=
  ∀ (buf : Bytes) (start mb e : Nat), scanEnd P buf start mb = .done e →
    ∃ out, decodeBody buf start = .ok (out, e) ∧
      (lfScan (buf.drop start)).map (fun r => (r.1, r.2 + start)) = some (out, e)

def body : Bytes := Bytes.ofString "0;\n\r\nX: y\r\n\r\n"

theorem impl_accepts : scanImpl body 0 (2 ^ 20) = .done 13 := by native_decide
theorem lf_recipient_ends_at_5 : lfScan body = some ([], 5) := by native_decide

theorem counterexample : ¬ LfSafe implP := by
  intro h
  obtain ⟨out, -, hl⟩ := h body 0 (2 ^ 20) 13 impl_accepts
  rw [List.drop_zero, lf_recipient_ends_at_5] at hl
  simp at hl

theorem fixed_agrees_lfTolerant : LfSafe fixedLFP :=
  fun buf start mb e h => Flare.L3.H1.Chunked.fixedLF_agrees_lfTolerant buf start mb e h

theorem fixed_rejects : scanFixedLF body 0 (2 ^ 20) = .malformed := by native_decide

end Flare.Bugs.H1_02
