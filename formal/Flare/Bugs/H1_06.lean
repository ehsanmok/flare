import Flare.L3_Protocol.H1.ClientChunked

/-!
# H1-06: the client returns a truncated chunked body as complete

* flare file: `flare/http/_client/parse.mojo:523-604` (`_decode_chunked`:
  a missing CRLF ends the loop with what was read) and the chunked
  branches of `_parse_http_response` / `_extract_body_and_trailers`, which
  never checked that the terminating chunk arrived (@59bda50).
* Spec clause: RFC 9112 §7.1: a chunked body ends with the last-chunk and
  the trailer section; §8: a message that ends before that is incomplete.
* What goes wrong: `5\r\nhel` (connection closed mid-chunk, or a TLS peer
  that skips close_notify) decodes to `hel`, returned as the whole body.
* Fix (`cRead`): run flare's own scanner (`scan_chunked_end`) first
  (`_require_complete_chunked`) and refuse anything it does not report
  `done`. `cRead_complete` proves a returned body is always a complete,
  framed body.

Status: resolved. The counterexample is about the pre-fix path `cReadOld`;
`fixed_complete` and `fixed_rejects` are about the shipped `cRead`.
-/
namespace Flare.Bugs.H1_06
open Flare Flare.L3.H1.Chunked Flare.L3.H1.ClientChunked

def okEq {α : Type} [BEq α] (r : Except String α) (v : α) : Bool :=
  match r with
  | .ok w => w == v
  | .error _ => false

def errEq {α : Type} (r : Except String α) (e : String) : Bool :=
  match r with
  | .ok _ => false
  | .error f => f == e

theorem okEq_eq {α : Type} [BEq α] [LawfulBEq α] {r : Except String α} {v : α}
    (h : okEq r v = true) : r = .ok v := by
  cases r <;> simp_all [okEq]

theorem errEq_eq {α : Type} {r : Except String α} {e : String} (h : errEq r e = true) :
    r = .error e := by
  cases r <;> simp_all [errEq]

/-- "5\r\nhel" -/
def trunc : Bytes := [53, 13, 10, 104, 101, 108]

/-- A body is returned only if the chunked framing reached its end. -/
def Complete (mb : Nat) (dec : Bytes → Except String Bytes) : Prop :=
  ∀ l out, dec l = .ok out → ∃ e, scanEnd implP l 0 mb = .done e

theorem old_accepts : cReadOld trunc = .ok [104, 101, 108] :=
  okEq_eq (by native_decide)

theorem scanner_incomplete : scanEnd implP trunc 0 (2 ^ 20) = .incomplete := by native_decide

theorem counterexample : ¬ Complete (2 ^ 20) cReadOld := by
  intro h
  obtain ⟨e, he⟩ := h _ _ old_accepts
  rw [scanner_incomplete] at he
  cases he

theorem fixed_complete (mb : Nat) : Complete mb (cRead mb) := by
  intro l out h
  obtain ⟨e, he, -⟩ := cRead_complete mb l out h
  exact ⟨e, he⟩

theorem fixed_rejects : cRead (2 ^ 20) trunc =
    .error "HTTP response: incomplete chunked body" := errEq_eq (by native_decide)

end Flare.Bugs.H1_06
