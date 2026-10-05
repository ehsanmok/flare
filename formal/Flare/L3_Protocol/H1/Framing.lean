import Flare.L3_Protocol.H1.HeaderText

/-!
# HTTP/1.1 request framing: reactor scan vs full parser (RFC 9112 §6.3)

Two components decide how a request body is framed:

* the reactor's raw-byte scan, `request_te_framing`
  (`flare/http/proto/chunked.mojo:97-178`) plus `scan_content_length`
  (`flare/http/_scan.mojo:189-266`), used by
  `flare/http/_reactor/conn_handle.mojo:606-654` to decide when the request
  is complete and how many bytes to hand to the parser;
* the full parser `_parse_http_request_bytes`
  (`flare/http/_server/parse.mojo:39-353`), which re-derives the framing from
  the header lines it accepts.

If they disagree on a request the parser accepts, bytes one side counts as
body are parsed by the other as the next request: request smuggling.

Both sides are modelled over the header block as a list of field lines (the
bytes between consecutive line terminators, terminators excluded; request
line and final empty line removed). The reactor splits lines on CRLF. The
strict parser splits on CRLF too and raises on a bare LF, so in strict mode
the line lists coincide. The parser with `allow_lf_only_line_endings`
splits on LF instead; `H1-04` is that mismatch.

`scanField skip` is the reactor's per-line test. The shipped reactor skips
SP/HTAB between name and colon (`skip = true`, the `H1-03` fix); `skip = false`
is the pre-fix test, where the colon had to follow the field name immediately.
`framing_agrees` proves that whenever the parser accepts, the shipped reactor
reaches the same verdict, for both the strict and the OWS-lenient parser.

The parser model accepts a superset of what the real parser accepts. It
omits value-byte validation, the Host-duplicate check, the header size cap,
and the strict rejection of equal duplicate Content-Length values; each of
these only adds rejections. "Parser accepts ⇒ same verdict" therefore
transfers to the real parser.
-/
namespace Flare.L3.H1.Framing
open Flare Flare.L3.H1.Text

/-- The framing verdict. `chunked` frames by the terminating chunk;
`length n` by Content-Length `n`; `reject` is a 4xx/5xx (no dispatch). -/
inductive Framing where
  | chunked
  | length (n : Nat)
  | reject
  deriving DecidableEq, Repr

/-! ## The reactor's raw-byte scan -/

/-- Per-line field test of `request_te_framing` / `_match_content_length_prefix`:
case-insensitive `needle` at the start of the line, then (`skip` only) SP/HTAB,
then `:`. Returns the raw bytes after the colon. The shipped reactor always
skips (`skip = true`, H1-03 fix); `skip = false` is the pre-fix test.
mirrors flare/http/proto/chunked.mojo:97-178 and flare/http/_scan.mojo:143-186
(fixed, H1-03) -/
def scanField (skip : Bool) (needle L : Bytes) : Option Bytes :=
  if ieqPrefix needle L = true then
    match (if skip then (L.drop needle.length).dropWhile isWS else L.drop needle.length) with
    | 58 :: r => some r
    | _ => none
  else none

/-- `joined` in `request_te_framing`: a comma only when `joined` is nonempty.
mirrors flare/http/proto/chunked.mojo:142-148 @59bda50 -/
def joinR (vs : List Bytes) : Bytes :=
  vs.foldl (fun j v => (if j.isEmpty then j else j ++ [44]) ++ v) []

/-- The reactor's framing decision, parameterised by the colon test: TE scan,
then Content-Length scan (first `content-length` field at a line start), 400
for a negative value and 413 above `max_body_size`. `skip = false` is the
reactor as it was at 59bda50 (kept for `Bugs.H1_03.counterexample`).
mirrors flare/http/proto/chunked.mojo:120-158, flare/http/_scan.mojo:173-247,
flare/http/_reactor/conn_handle.mojo:622-654 @59bda50 -/
def reactorFramingWith (skip allowCL : Bool) (maxBody : Nat) (lines : List Bytes) : Framing :=
  let S := lines.filterMap (scanField skip TEn)
  let C := lines.filterMap (scanField skip CLn)
  if S = [] then
    match C with
    | [] => .length 0
    | v :: _ => if parseCL v < 0 ∨ parseCL v > maxBody then .reject else .length (parseCL v).toNat
  else if C ≠ [] ∧ allowCL = false then .reject
  else if classify (joinR S) = 1 then .chunked else .reject

/-- The shipped reactor: SP/HTAB between the field name and the colon are
skipped (H1-03 fix).
mirrors flare/http/proto/chunked.mojo:97-178, flare/http/_scan.mojo:143-266,
flare/http/_reactor/conn_handle.mojo:622-654 (fixed, H1-03) -/
def reactorFraming (allowCL : Bool) (maxBody : Nat) (lines : List Bytes) : Framing :=
  reactorFramingWith true allowCL maxBody lines

/-! ## The full parser -/

/-- Field-name slice: `line[:colon]`, with trailing SP/HTAB removed under
`allow_ows_around_colon`.
mirrors flare/http/_server/parse.mojo:247-256 @59bda50 -/
def nameOf (ows : Bool) (t : Bytes) : Bytes :=
  if ows then (t.reverse.dropWhile isWS).reverse else t

/-- The line is a field line the parser accepts: a colon, and a nonempty
all-tchar name.
mirrors flare/http/_server/parse.mojo:234-266 @59bda50 -/
def wfB (ows : Bool) (L : Bytes) : Bool :=
  match findB 58 L with
  | none => false
  | some k => let nm := nameOf ows (L.take k); !nm.isEmpty && nm.all isTchar

/-- `(k, v)`: the name, and the stripped bytes after the first colon.
mirrors flare/http/_server/parse.mojo:267-268 @59bda50 -/
def field (ows : Bool) (L : Bytes) : Bytes × Bytes :=
  match findB 58 L with
  | none => ([], [])
  | some k => (nameOf ows (L.take k), strip (L.drop (k + 1)))

/-- The value when the name equals `lit` (ASCII case-insensitive).
mirrors flare/http/_server/parse.mojo:291,306 @59bda50 -/
def parserField (ows : Bool) (lit L : Bytes) : Option Bytes :=
  if ieq (field ows L).1 lit = true then some (field ows L).2 else none

/-- `te_joined`: a comma before every value but the first.
mirrors flare/http/_server/parse.mojo:306-310 @59bda50 -/
def joinP : List Bytes → Bytes
  | [] => []
  | v :: vs => vs.foldl (fun j w => j ++ 44 :: w) v

/-- The parser's framing decision.
mirrors flare/http/_server/parse.mojo:291-353 @59bda50 -/
def parserFraming (ows allowCL : Bool) (maxBody : Nat) (lines : List Bytes) : Framing :=
  if lines.all (wfB ows) = false then .reject else
  let S := lines.filterMap (parserField ows TEn)
  let cls := (lines.filterMap (parserField ows CLn)).map parseCL
  if cls.any (· < 0) = true then .reject else
  if cls.all (· = cls.headD 0) = false then .reject else
  if S = [] then
    match cls with
    | [] => .length 0
    | v :: _ => if v > maxBody then .reject else .length v.toNat
  else if classify (joinP S) = 1 then
    (if cls ≠ [] ∧ allowCL = false then .reject else .chunked)
  else .reject

/-! ## Per-line agreement -/

theorem lower_ws {c : UInt8} (h : isWS c = true) : lower c = c := by
  have : c = 32 ∨ c = 9 := by simpa [isWS] using h
  rcases this with rfl | rfl <;> decide

theorem lower_colon : lower 58 = 58 := by decide

theorem dropWhile_ws_nonws {x : UInt8} (hx : isWS x = false) (r : Bytes) :
    (x :: r).dropWhile isWS = x :: r := by
  simp [List.dropWhile_cons, hx]

/-- Shape of an accepted field line. -/
structure Shape (ows : Bool) (L name w rest : Bytes) : Prop where
  eq : L = name ++ w ++ 58 :: rest
  ne : name ≠ []
  tchar : ∀ x ∈ name, isTchar x = true
  ws : ∀ x ∈ w, isWS x = true
  strict : ows = false → w = []
  field : field ows L = (name, strip rest)

theorem reverse_dropWhile_split (t : Bytes) :
    t = (t.reverse.dropWhile isWS).reverse ++ (t.reverse.takeWhile isWS).reverse := by
  rw [← List.reverse_append, List.takeWhile_append_dropWhile, List.reverse_reverse]

theorem shape_of_wf {ows : Bool} {L : Bytes} (h : wfB ows L = true) :
    ∃ name w rest, Shape ows L name w rest := by
  unfold wfB at h
  split at h
  · simp at h
  · rename_i k hk
    obtain ⟨hlt, hget, hnot⟩ := findB_spec hk
    simp only [Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff, List.all_eq_true] at h
    obtain ⟨hne, hall⟩ := h
    have hL : L = L.take k ++ 58 :: L.drop (k + 1) := by
      have : L.drop k = 58 :: L.drop (k + 1) := by
        rw [List.drop_eq_getElem_cons hlt]
        congr
        simpa [Bytes.getD, hlt] using hget
      rw [← this, List.take_append_drop]
    cases ows with
    | false =>
      have e1 : L = L.take k ++ [] ++ 58 :: L.drop (k + 1) := by simpa using hL
      have e2 : L.take k ≠ [] := by simpa [nameOf] using hne
      have e3 : ∀ x ∈ L.take k, isTchar x = true := by simpa [nameOf] using hall
      have e6 : field false L = (L.take k, strip (L.drop (k + 1))) := by simp [field, hk, nameOf]
      exact ⟨L.take k, [], L.drop (k + 1), e1, e2, e3, by simp, fun _ => rfl, e6⟩
    | true =>
      refine ⟨nameOf true (L.take k), ((L.take k).reverse.takeWhile isWS).reverse, L.drop (k + 1),
        ⟨?_, hne, hall, ?_, (fun h => by cases h), ?_⟩⟩
      · conv => lhs; rw [hL, reverse_dropWhile_split (L.take k)]
        simp [nameOf]
      · intro x hx
        exact mem_takeWhile (List.mem_reverse.mp hx)
      · simp [field, hk]

theorem field_of_shape {ows : Bool} {L name w rest : Bytes} (s : Shape ows L name w rest) (lit : Bytes) :
    parserField ows lit L = if ieq name lit = true then some (strip rest) else none := by
  simp [parserField, s.field]

/-- The shipped reactor's per-line test on an accepted line: it fires exactly
when the parsed name equals the needle, and returns the unstripped value. The
needle must contain no colon and no SP/HTAB. It holds for strict and
OWS-lenient lines alike, because a strict line has no whitespace before the
colon. -/
theorem scan_of_shape {ows : Bool} {L name w rest : Bytes} (s : Shape ows L name w rest)
    {N : Bytes} (hN58 : (58 : UInt8) ∉ N) (hNws : ∀ x ∈ N, isWS x = false) :
    scanField true N L = if ieq name N = true then some rest else none := by
  -- `ieqPrefix N L = ieqPrefix N name`: the byte after `name` stops the match.
  have hpre : ieqPrefix N L = ieqPrefix N name := by
    rw [s.eq]
    cases hw : w with
    | nil =>
      simp only [List.append_nil]
      exact ieqPrefix_append_stop N name rest 58 hN58 lower_colon
    | cons c w' =>
      have hc : isWS c = true := s.ws c (by simp [hw])
      have hcN : c ∉ N := fun hm => by simp [hNws c hm] at hc
      simp only [List.cons_append, List.append_assoc]
      exact ieqPrefix_append_stop N name _ c hcN (lower_ws hc)
  unfold scanField
  rw [hpre]
  by_cases hq : ieq name N = true
  · simp only [ieq, Bool.and_eq_true, beq_iff_eq] at hq
    obtain ⟨hlen, hp⟩ := hq
    have hdrop : L.drop N.length = w ++ 58 :: rest := by
      rw [s.eq, ← hlen, List.append_assoc, List.drop_left]
    simp only [hp, if_true, hdrop, ieq, hlen, beq_self_eq_true, Bool.true_and]
    rw [dropWhile_ws_prefix w (58 :: rest) s.ws]
    rfl
  · rw [if_neg hq]
    cases hp : ieqPrefix N name with
    | false => rfl
    | true =>
      simp only [if_true]
      have hle := ieqPrefix_length N name hp
      have hne : N.length ≠ name.length := by
        intro e; apply hq; simp [ieq, e, hp]
      have hlt : N.length < name.length := by omega
      have hdrop : L.drop N.length = name[N.length] :: (name.drop (N.length + 1) ++ w ++ 58 :: rest) := by
        have e := List.drop_eq_getElem_cons hlt
        rw [s.eq, List.append_assoc, List.drop_append_of_le_length (by omega), e, List.cons_append]
        simp
      have ht : isTchar name[N.length] = true := s.tchar _ (List.getElem_mem hlt)
      have hcol : name[N.length] ≠ 58 := fun e => by rw [e] at ht; exact absurd ht (by decide)
      rw [hdrop]
      rw [dropWhile_ws_nonws (isTchar_ws ht)]
      split
      · rename_i r heq; exact absurd (List.cons.inj heq).1 hcol
      · rfl

theorem TEn_no_colon : (58 : UInt8) ∉ TEn := by decide
theorem TEn_no_ws : ∀ x ∈ TEn, isWS x = false := by decide
theorem CLn_no_colon : (58 : UInt8) ∉ CLn := by decide
theorem CLn_no_ws : ∀ x ∈ CLn, isWS x = false := by decide

/-- On an accepted line the reactor's value, stripped, is the parser's. -/
theorem scan_map_strip {ows : Bool} {L : Bytes} (h : wfB ows L = true) {N : Bytes}
    (hN58 : (58 : UInt8) ∉ N) (hNws : ∀ x ∈ N, isWS x = false) :
    (scanField true N L).map strip = parserField ows N L := by
  obtain ⟨name, w, rest, s⟩ := shape_of_wf h
  rw [scan_of_shape s hN58 hNws, field_of_shape s]
  split <;> rfl

theorem filterMap_scan_strip {ows : Bool} {N : Bytes}
    (hN58 : (58 : UInt8) ∉ N) (hNws : ∀ x ∈ N, isWS x = false) :
    ∀ lines : List Bytes, lines.all (wfB ows) = true →
      (lines.filterMap (scanField true N)).map strip = lines.filterMap (parserField ows N)
  | [], _ => rfl
  | L :: ls, h => by
    simp only [List.all_cons, Bool.and_eq_true] at h
    have ih := filterMap_scan_strip hN58 hNws ls h.2
    have hl := scan_map_strip h.1 hN58 hNws
    simp only [List.filterMap_cons]
    cases hs : scanField true N L with
    | none => rw [hs] at hl; simp only [Option.map_none] at hl; rw [← hl]; exact ih
    | some v => rw [hs] at hl; simp only [Option.map_some] at hl; rw [← hl]; simp [ih]

/-! ## Tokens of the joined values -/

theorem tokens_foldlR : ∀ (vs : List Bytes) (j : Bytes),
    tokens (vs.foldl (fun j v => (if j.isEmpty then j else j ++ [44]) ++ v) j) =
      tokens j ++ vs.flatMap tokens
  | [], j => by simp
  | v :: vs, j => by
    rw [List.foldl_cons, tokens_foldlR vs]
    cases j with
    | nil => simp [tokens_nil]
    | cons c cs =>
      simp only [List.isEmpty_cons, Bool.false_eq_true, if_false, List.append_assoc,
        List.singleton_append, tokens_append_comma, List.flatMap_cons]

theorem tokens_joinR (vs : List Bytes) : tokens (joinR vs) = vs.flatMap tokens := by
  unfold joinR; rw [tokens_foldlR, tokens_nil]; rfl

theorem tokens_foldlP : ∀ (vs : List Bytes) (j : Bytes),
    tokens (vs.foldl (fun j w => j ++ 44 :: w) j) = tokens j ++ vs.flatMap tokens
  | [], j => by simp
  | v :: vs, j => by
    rw [List.foldl_cons, tokens_foldlP vs, tokens_append_comma]
    simp

theorem tokens_joinP : ∀ vs : List Bytes, tokens (joinP vs) = vs.flatMap tokens
  | [] => tokens_nil
  | v :: vs => by unfold joinP; rw [tokens_foldlP]; rfl

theorem flatMap_tokens_strip (vs : List Bytes) : (vs.map strip).flatMap tokens = vs.flatMap tokens := by
  induction vs with
  | nil => rfl
  | cons v vs ih => simp [tokens_strip, ih]

theorem classify_join (S : List Bytes) : classify (joinP (S.map strip)) = classify (joinR S) := by
  simp only [classify, tokens_joinP, tokens_joinR, flatMap_tokens_strip]

theorem parseCL_map_strip (C : List Bytes) : (C.map strip).map parseCL = C.map parseCL := by
  simp [parseCL_strip]

/-! ## No smuggling -/

/-- **Framing agreement.** If the parser accepts a header block, the shipped
reactor frames it identically: same chunked/length decision, same length.
`ows = false` is the strict parser, `ows = true` the OWS-lenient one. -/
theorem framing_agrees (ows allowCL : Bool) (maxBody : Nat) (lines : List Bytes)
    (hacc : parserFraming ows allowCL maxBody lines ≠ .reject) :
    reactorFraming allowCL maxBody lines = parserFraming ows allowCL maxBody lines := by
  have hwf : lines.all (wfB ows) = true := by
    cases h : lines.all (wfB ows)
    · exact absurd (by simp [parserFraming, h]) hacc
    · rfl
  have hS := filterMap_scan_strip TEn_no_colon TEn_no_ws lines hwf
  have hC := filterMap_scan_strip CLn_no_colon CLn_no_ws lines hwf
  unfold parserFraming at hacc ⊢
  unfold reactorFraming reactorFramingWith
  dsimp only at hacc ⊢
  rw [← hS, ← hC, parseCL_map_strip] at hacc ⊢
  rw [classify_join] at hacc ⊢
  simp only [hwf, Bool.true_eq_false, if_false] at hacc ⊢
  generalize lines.filterMap (scanField true TEn) = S at hacc ⊢
  generalize lines.filterMap (scanField true CLn) = C at hacc ⊢
  have hSe : (S.map strip = []) ↔ S = [] := List.map_eq_nil_iff
  have hCe : (C.map parseCL ≠ []) ↔ C ≠ [] := by simp
  simp only [hSe, hCe] at hacc ⊢
  by_cases hneg : (C.map parseCL).any (· < 0) = true
  · rw [if_pos hneg] at hacc; exact absurd rfl hacc
  rw [if_neg hneg] at hacc ⊢
  by_cases heq : (C.map parseCL).all (· = (C.map parseCL).headD 0) = false
  · rw [if_pos heq] at hacc; exact absurd rfl hacc
  rw [if_neg heq] at hacc ⊢
  by_cases hS0 : S = []
  · simp only [hS0, if_true] at hacc ⊢
    cases C with
    | nil => rfl
    | cons v vs =>
      have hv : ¬ parseCL v < 0 := by
        intro h; apply hneg; simp [h]
      simp only [List.map_cons] at hacc ⊢
      by_cases hm : parseCL v > maxBody
      · simp [hm] at hacc
      · simp [hv, hm]
  · simp only [hS0, if_false] at hacc ⊢
    by_cases hk : classify (joinR S) = 1
    · simp only [hk, if_true]
    · simp [hk] at hacc

/-- **No smuggling in strict mode.** With every leniency flag off, whenever
`_parse_http_request_bytes` accepts a request, the reactor's framing decision
(`request_te_framing` + `scan_content_length`) is the same. -/
theorem no_smuggling_strict (allowCL : Bool) (maxBody : Nat) (lines : List Bytes)
    (hacc : parserFraming false allowCL maxBody lines ≠ .reject) :
    reactorFraming allowCL maxBody lines = parserFraming false allowCL maxBody lines :=
  framing_agrees false allowCL maxBody lines hacc

/-! ## Line splitting (for `H1-04`) -/

/-- Split on a byte (the line loop of `_read_line_buf_lenient`).
mirrors flare/http/_server/parse_util.mojo:179-199 @59bda50 -/
def splitOn (c : UInt8) : Bytes → List Bytes
  | [] => [[]]
  | x :: xs =>
    if x = c then [] :: splitOn c xs
    else match splitOn c xs with
      | [] => [[x]]
      | y :: ys => (x :: y) :: ys

/-- Drop one trailing CR.
mirrors flare/http/_server/parse_util.mojo:201-203 @59bda50 -/
def dropCR (l : Bytes) : Bytes :=
  match l.getLast? with
  | some 13 => l.dropLast
  | _ => l

/-- The reactor's line split of a header block (`buf` between the request
line's CRLF and the final CRLF): on CRLF.
mirrors flare/http/proto/chunked.mojo:133-153 @59bda50 -/
def linesCRLF : Bytes → List Bytes
  | [] => [[]]
  | 13 :: 10 :: xs => [] :: linesCRLF xs
  | x :: xs => match linesCRLF xs with
    | [] => [[x]]
    | y :: ys => (x :: y) :: ys

/-- `_read_line_buf_lenient` with `allow_lf_only_line_endings`: split on LF,
drop a trailing CR.
mirrors flare/http/_server/parse_util.mojo:165-208 @59bda50 -/
def linesLF (b : Bytes) : List Bytes := (splitOn 10 b).map dropCR

/-- **`H1-04` fix.** A reactor that splits header lines the way the
LF-lenient parser does agrees with it whenever the parser accepts. -/
theorem lf_fixed_agrees (allowCL : Bool) (maxBody : Nat) (blk : Bytes)
    (hacc : parserFraming false allowCL maxBody (linesLF blk) ≠ .reject) :
    reactorFraming allowCL maxBody (linesLF blk) =
      parserFraming false allowCL maxBody (linesLF blk) :=
  framing_agrees false allowCL maxBody _ hacc

end Flare.L3.H1.Framing
