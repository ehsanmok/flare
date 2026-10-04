import Flare.L3_Protocol.H1.ClientResponse

/-!
# H1-08: the client reads the first three digits of a longer status code

* flare file: `flare/http/_client/parse.mojo:318-352` (`_parse_status_code`
  takes three digits after the first SP and ignores what follows) @59bda50.
* Spec clause: RFC 9112 §4: `status-code = 3DIGIT`, followed by SP.
* What goes wrong: `HTTP/1.1 2041 OK` is read as 204, a bodyless status,
  so the bytes after the head are taken as the next response on a pooled
  connection.
* Fix (`parseStatusFixed`): require SP or end of line after the three
  digits. `parseStatusFixed_delimited` proves every fixed result is a
  delimited three-digit code (`CodeDelimited`).
-/
namespace Flare.Bugs.H1_08
open Flare Flare.L3.H1.ClientResponse

def line : Bytes := Bytes.ofString "HTTP/1.1 2041 OK"

def ok3 (d : Bytes) : Bool :=
  match d with
  | a :: b :: c :: r =>
    isDig a && isDig b && isDig c && (r.head? == none || r.head? == some 32) &&
      (a.toNat - 48) * 100 + (b.toNat - 48) * 10 + (c.toNat - 48) == 204
  | _ => false

theorem no_window : ∀ n, n < 16 → ok3 (line.drop n) = false := by native_decide

theorem not_delimited : ¬ CodeDelimited line 204 := by
  rintro ⟨pre, ws, a, b, c, r, hL, ha, hb, hc, hr, hcode⟩
  have hlen : line.length = 16 := by native_decide
  have hd : line.drop (pre ++ [32] ++ ws).length = a :: b :: c :: r := by
    rw [hL]; simp
  have hn : (pre ++ [32] ++ ws).length < 16 := by
    have := congrArg List.length hL
    simp only [List.length_append, List.length_cons, List.length_nil] at this
    simp only [List.length_append, List.length_cons, List.length_nil]
    omega
  have := no_window _ hn
  rw [hd] at this
  simp only [ok3, ha, hb, hc, Bool.true_and, ← hcode] at this
  rcases hr with hr | hr
  · subst hr; simp at this
  · simp [hr] at this

theorem shipped_parses : parseStatus line = some 204 := by native_decide

theorem counterexample : ¬ ∀ l c, parseStatus l = some c → CodeDelimited l c :=
  fun h => not_delimited (h _ _ shipped_parses)

theorem fixed_delimited (l : Bytes) (c : Nat) (h : parseStatusFixed l = some c) :
    CodeDelimited l c := parseStatusFixed_delimited l c h

theorem fixed_rejects : parseStatusFixed line = none := by native_decide

end Flare.Bugs.H1_08
