import Flare.L3_Protocol.H1.ClientResponse

/-!
# H1-07: bare-LF response heads skip the empty line that ends them

* flare file: `flare/http/_client/parse.mojo:283-306` (`_split_lines`
  ends a line at a bare LF) and 89-125 (`_parse_response_head` skips empty
  lines and reads to the first CRLFCRLF) @59bda50.
* Spec clause: RFC 9112 §2.2: a recipient MAY treat a bare LF as a line
  terminator; then the first empty line ends the head (§2.1).
* What goes wrong: in `HTTP/1.1 200 OK\nX: a\n\nS: e\r\n\r\nb` an
  LF-recognising peer (cache, proxy) ends the head at `\n\n` and sees the
  body `S: e\r\n\r\nb`; flare reads `S: e` as a header field and the body
  as `b`.
* Fix (`headImpl`): refuse a head with a bare LF or an empty line.
  `headImpl_agrees` proves the fixed head and body start are the
  LF-recognising recipient's.

Status: resolved. The counterexample is about the pre-fix parser `headOld`;
`fixed_agrees` and `fixed_rejects` are about the shipped `headImpl`.
-/
namespace Flare.Bugs.H1_07
open Flare Flare.L3.H1.ClientResponse

def m : Bytes := Bytes.ofString "HTTP/1.1 200 OK\nX: a\n\nS: e\r\n\r\nb"

def statusL : Bytes := [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75]

theorem old_head : headOld m =
    some ([statusL, [88, 58, 32, 97], [83, 58, 32, 101]], [98]) := by native_decide

theorem lf_head : lfHead m = some ([statusL, [88, 58, 32, 97]],
    [83, 58, 32, 101, 13, 10, 13, 10, 98]) := by native_decide

theorem counterexample : ¬ HeadAgrees headOld := by
  intro h
  obtain ⟨ls0, h1, -⟩ := h _ _ _ old_head
  rw [lf_head] at h1
  simp at h1

theorem fixed_agrees : HeadAgrees headImpl := headImpl_agrees

theorem fixed_rejects : headImpl m = none := by native_decide

end Flare.Bugs.H1_07
