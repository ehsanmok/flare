import Flare.L3_Protocol.H1.Chunked
import Flare.L3_Protocol.H1.HeaderText

/-!
# The client's chunked decoder `_decode_chunked`

`flare/http/_client/parse.mojo:497-578` decodes a chunked response body in
two places:

* the pooled framed reader (`_read_http_response_framed`, parse.mojo:853-869)
  first walks the body with `scan_chunked_resume`, truncates the buffer at the
  scanner's end and then calls `_parse_http_response`, which decodes with
  `_decode_chunked`;
* the read-to-EOF readers (`_read_http_response_tcp` / `_tls`,
  parse.mojo:645-703) call `_parse_http_response` on whatever arrived before
  EOF, with no scan.

`cDec` mirrors the decoder. `cDec_agree` proves the first path right: on any
buffer the scanner accepts, `_decode_chunked` either raises or yields exactly
the bytes of `decode_chunked_body` (`decL`), reading nothing past the
scanner's end. The second path is finding H1-06 (`Bugs/H1_06.lean`).

Mojo's `String.strip()` on the byte-per-`chr` string removes the bytes
9-13, 28-30 and 32 (observed with `pixi run mojo`, byte by byte); `isSWS`
is that set.
-/
namespace Flare.L3.H1.ClientChunked
open Flare Flare.L3.H1.Chunked

/-- Bytes `String.strip()` removes from a byte-per-`chr` string. -/
def isSWS (c : UInt8) : Bool := (9 ≤ c && c ≤ 13) || (28 ≤ c && c ≤ 30) || c == 32

/-- `String.strip()`. -/
def pyStrip (l : Bytes) : Bytes := ((l.dropWhile isSWS).reverse.dropWhile isSWS).reverse

/-- The size field before the first `;` (parse.mojo:530-534). -/
def beforeSemi (l : Bytes) : Bytes := l.takeWhile (· ≠ 59)

/-- The digit loop of `_parse_hex`. -/
def hexAcc : Bytes → Nat → Option Nat
  | [], a => some a
  | c :: cs, a => match hexVal c with
    | none => none
    | some v => hexAcc cs (a * 16 + v)

/-- `_parse_hex`: empty or more than 15 digits raises.
mirrors flare/http/_client/parse.mojo:609-642 @59bda50 -/
def cHex (s : Bytes) : Option Nat :=
  if s = [] then none else if s.length > 15 then none else hexAcc s 0

/-- The trailer names `_is_forbidden_trailer` refuses.
mirrors flare/http/_client/parse.mojo:461-494 @59bda50 -/
def forbiddenNames : List Bytes :=
  ["transfer-encoding", "content-length", "host", "trailer", "authorization",
    "set-cookie", "cookie"].map Bytes.ofString

def lowerB (l : Bytes) : Bytes := l.map Flare.L3.H1.Text.lower

/-- One trailer line: a colon is required, a forbidden name raises, and
`HeaderMap.append` raises on CR/LF in the name or value.
mirrors flare/http/_client/parse.mojo:546-570 @59bda50 -/
def trailerOk (line : Bytes) : Bool :=
  match line.findIdx? (· == 58) with
  | none => false
  | some c =>
    let k := pyStrip (line.take c)
    let v := pyStrip (line.drop (c + 1))
    !(forbiddenNames.contains (lowerB k)) && !(k.contains 13 || k.contains 10 ||
      v.contains 13 || v.contains 10)

/-- The trailer loop after the zero chunk.
mirrors flare/http/_client/parse.mojo:540-571 @59bda50 -/
def cTr (l : Bytes) : Except String Unit :=
  match l with
  | [] => .ok ()
  | a :: t =>
    match h : findCRLF (a :: t) with
    | none => .ok ()
    | some 0 => .ok ()
    | some (k + 1) =>
      if trailerOk ((a :: t).take (k + 1)) then cTr ((a :: t).drop (k + 1 + 2))
      else .error "trailer"
termination_by l.length
decreasing_by simp only [List.length_drop, List.length_cons]; omega

theorem findCRLF_pos {l : Bytes} {k : Nat} (h : findCRLF l = some k) : 0 < l.length := by
  have := findCRLF_lt h; omega

/-- `_decode_chunked(raw, pos)` over the suffix `l = raw[pos:]`.
mirrors flare/http/_client/parse.mojo:497-578 @59bda50 -/
def cDec (l : Bytes) : Except String Bytes :=
  match l with
  | [] => .ok []
  | a :: t =>
    match hf : findCRLF (a :: t) with
    | none => .ok []
    | some k =>
      match cHex (pyStrip (beforeSemi ((a :: t).take k))) with
      | none => .error "chunk-size"
      | some size =>
        if size = 0 then (cTr ((a :: t).drop (k + 2))).map fun _ => []
        else (cDec (((a :: t).drop (k + 2)).drop (size + 2))).map
          fun r => ((a :: t).drop (k + 2)).take size ++ r
termination_by l.length
decreasing_by have := findCRLF_lt hf; simp only [List.length_drop, List.length_cons] at *; omega

/-! ## Agreement with the scanner and `decode_chunked_body` -/

theorem findCRLF_take : ∀ {l : Bytes} {k : Nat}, findCRLF l = some k → findCRLF (l.take (k + 2)) = some k
  | [], _, h => by simp [findCRLF] at h
  | [_], _, h => by simp [findCRLF] at h
  | a :: b :: t, k, h => by
    simp only [findCRLF] at h
    split at h
    · rename_i hab; simp at h; subst h; simp [findCRLF, hab]
    · rename_i hab
      cases h' : findCRLF (b :: t) with
      | none => simp [h'] at h
      | some j =>
        simp [h'] at h; subst h
        have ih := findCRLF_take h'
        have hl := findCRLF_lt h'
        have e1 : (a :: b :: t).take (j + 1 + 2) = a :: (b :: t).take (j + 2) := by
          simp [List.take_succ_cons]
        rw [e1]
        obtain ⟨x, xs, hx⟩ : ∃ x xs, (b :: t).take (j + 2) = x :: xs := by
          cases hh : (b :: t).take (j + 2) with
          | nil => simp at hh
          | cons x xs => exact ⟨x, xs, rfl⟩
        have hxb : x = b := by
          have := congrArg List.head? hx; simp at this; exact this.symm
        subst hxb
        rw [hx] at ih ⊢
        simp only [findCRLF, if_neg hab, ih]; rfl

theorem findCRLF_prefix {l l' : Bytes} {k : Nat} (h : findCRLF l = some k)
    (ht : l'.take (k + 2) = l.take (k + 2)) : findCRLF l' = some k := by
  have h1 := findCRLF_take h
  rw [← ht] at h1
  have := findCRLF_append (l'.drop (k + 2)) h1
  rwa [List.take_append_drop] at this

theorem take_agree {l l' : Bytes} {e n : Nat} (h : l'.take e = l.take e) (hn : n ≤ e) :
    l'.take n = l.take n := by
  have := congrArg (List.take n) h
  simp only [List.take_take, Nat.min_eq_left hn] at this
  exact this

theorem drop_agree {l l' : Bytes} {e j : Nat} (h : l'.take e = l.take e) :
    (l'.drop j).take (e - j) = (l.drop j).take (e - j) := by
  rw [← List.drop_take, ← List.drop_take, h]

theorem hexAcc_beforeSemi (mb : Nat) : ∀ (xs : Bytes) (s d size dg : Nat),
    parseSize mb xs s d = some (size, dg) →
    hexAcc (beforeSemi xs) s = some size ∧ ∀ c ∈ beforeSemi xs, (hexVal c).isSome
  | [], s, d, size, dg, h => by simp [parseSize] at h; simp [beforeSemi, hexAcc, h.1]
  | c :: cs, s, d, size, dg, h => by
    simp only [parseSize] at h
    split at h
    · rename_i hc; simp at h; simp [beforeSemi, hc, hexAcc, h.1]
    · rename_i hc
      cases hv : hexVal c with
      | none => simp [hv] at h
      | some v =>
        simp only [hv] at h
        split at h
        · simp at h
        · obtain ⟨h1, h2⟩ := hexAcc_beforeSemi mb cs _ _ _ _ h
          have hb : beforeSemi (c :: cs) = c :: beforeSemi cs := by
            simp [beforeSemi, List.takeWhile_cons, hc]
          rw [hb]
          refine ⟨by simp only [hexAcc, hv]; exact h1, ?_⟩
          intro x hx
          rcases List.mem_cons.mp hx with rfl | hx
          · simp [hv]
          · exact h2 x hx

theorem isSWS_of_hex {c : UInt8} (h : (hexVal c).isSome) : isSWS c = false := by
  unfold hexVal at h
  unfold isSWS
  have t : ∀ n : Nat, n < 256 → (UInt8.ofNat n) = c → True := fun _ _ _ => trivial
  clear t
  have hc := c.toNat_lt
  split at h
  · rename_i hh
    have a1 : 48 ≤ c.toNat := by simpa using UInt8.le_iff_toNat_le.mp hh.1
    simp only [Bool.or_eq_false_iff, Bool.and_eq_false_iff, decide_eq_false_iff_not,
      beq_eq_false_iff_ne, UInt8.le_iff_toNat_le, UInt8.toNat_ofNat]
    refine ⟨⟨Or.inr (by simp; omega), Or.inr (by simp; omega)⟩, fun e => by subst e; simp at a1⟩
  split at h
  · rename_i _ hh
    have a1 : 97 ≤ c.toNat := by simpa using UInt8.le_iff_toNat_le.mp hh.1
    simp only [Bool.or_eq_false_iff, Bool.and_eq_false_iff, decide_eq_false_iff_not,
      beq_eq_false_iff_ne, UInt8.le_iff_toNat_le, UInt8.toNat_ofNat]
    refine ⟨⟨Or.inr (by simp; omega), Or.inr (by simp; omega)⟩, fun e => by subst e; simp at a1⟩
  split at h
  · rename_i _ _ hh
    have a1 : 65 ≤ c.toNat := by simpa using UInt8.le_iff_toNat_le.mp hh.1
    simp only [Bool.or_eq_false_iff, Bool.and_eq_false_iff, decide_eq_false_iff_not,
      beq_eq_false_iff_ne, UInt8.le_iff_toNat_le, UInt8.toNat_ofNat]
    refine ⟨⟨Or.inr (by simp; omega), Or.inr (by simp; omega)⟩, fun e => by subst e; simp at a1⟩
  · simp at h

theorem pyStrip_of_noWS (l : Bytes) (h : ∀ c ∈ l, isSWS c = false) : pyStrip l = l := by
  have d1 : ∀ m : Bytes, (∀ c ∈ m, isSWS c = false) → m.dropWhile isSWS = m := by
    intro m hm
    cases m with
    | nil => rfl
    | cons x xs => simp [List.dropWhile_cons, hm x (by simp)]
  unfold pyStrip
  rw [d1 l h, d1 l.reverse (fun c hc => h c (List.mem_reverse.mp hc)), List.reverse_reverse]

/-- On a scanned size line the client's size parse agrees with the
scanner's (or raises, for more than 15 digits). -/
theorem cHex_of_parseSize {mb : Nat} {xs : Bytes} {size dg n : Nat}
    (h : parseSize mb xs 0 0 = some (size, dg)) (hc : cHex (pyStrip (beforeSemi xs)) = some n) :
    n = size := by
  obtain ⟨h1, h2⟩ := hexAcc_beforeSemi mb xs 0 0 size dg h
  rw [pyStrip_of_noWS _ (fun c hc => isSWS_of_hex (h2 c hc))] at hc
  unfold cHex at hc
  split at hc
  · cases hc
  split at hc
  · cases hc
  rw [h1] at hc; cases hc; rfl

theorem cDec_cons_eq {a : UInt8} {t : Bytes} {k : Nat} (hf : findCRLF (a :: t) = some k) :
    cDec (a :: t) =
      match cHex (pyStrip (beforeSemi ((a :: t).take k))) with
      | none => .error "chunk-size"
      | some size =>
        if size = 0 then (cTr ((a :: t).drop (k + 2))).map fun _ => []
        else (cDec (((a :: t).drop (k + 2)).drop (size + 2))).map
          fun r => ((a :: t).drop (k + 2)).take size ++ r := by
  rw [cDec]; split
  · simp_all
  · rename_i k2 hk2; rw [hf] at hk2; cases hk2; rfl

/-- **Scan/client-decoder agreement.** If `scan_chunked_*` accepts `l` at
`e`, then `_decode_chunked` run on any buffer that agrees with `l` on its
first `e` bytes (in particular `l` itself, or `l` truncated at `e` as the
framed reader does) either raises or returns exactly the bytes
`decode_chunked_body` returns. -/
theorem cDec_agree (P : Policy) (mb : Nat) : ∀ (l : Bytes) (tot e adv t : Nat),
    scanL P mb l tot = (.done e, adv, t) →
    ∀ (l' out : Bytes), l'.take e = l.take e → e ≤ l'.length → cDec l' = .ok out →
    decL l = .ok (out, e) := by
  intro l tot
  fun_induction scanL P mb l tot <;> intro e adv t h <;> simp only [Prod.mk.injEq] at h
  case case6 l tot k hk hcap hlf digits hd hps =>
    intro l' out hag hle hc
    obtain ⟨h1, -, -⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    obtain ⟨out0, hdec, -⟩ := decL_of_scanL P mb l tot (e' + (k + 2)) 0 tot
      (by rw [scanL_some hk]; simp only [if_neg hcap, if_neg hlf, hps, if_neg hd, if_true]; rw [h1']; rfl)
    have hk' := findCRLF_prefix hk (take_agree hag (by omega))
    cases l' with
    | nil => simp at hle
    | cons a t' =>
      rw [cDec_cons_eq hk', take_agree hag (show k ≤ e' + (k + 2) by omega)] at hc
      cases hx : cHex (pyStrip (beforeSemi (l.take k))) with
      | none => rw [hx] at hc; cases hc
      | some n =>
        have := cHex_of_parseSize hps hx; subst this
        rw [hx] at hc; simp only [if_true] at hc
        have hout : out = [] := by
          cases hcc : cTr ((a :: t').drop (k + 2)) <;> rw [hcc] at hc <;> simp [Except.map] at hc
          exact hc
        subst hout
        have : out0 = [] := by
          rw [decL_some hk, parseSize_hexD mb _ 0 0 0 digits hps] at hdec
          simp only [if_true] at hdec
          cases hh : decTr (l.drop (k + 2)) <;> rw [hh] at hdec <;> simp [Except.map] at hdec
          exact hdec.1
        subst this; exact hdec
  case case10 l tot k hk hcap hlf size digits hps hd hs hmb hl hcrlf r ih =>
    intro l' out hag hle hc
    obtain ⟨h1, -, -⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    have hk' := findCRLF_prefix hk (take_agree hag (by omega))
    cases l' with
    | nil => simp at hle
    | cons a t' =>
      rw [cDec_cons_eq hk', take_agree hag (show k ≤ e' + (k + 2 + size + 2) by omega)] at hc
      cases hx : cHex (pyStrip (beforeSemi (l.take k))) with
      | none => rw [hx] at hc; cases hc
      | some n =>
        have := cHex_of_parseSize hps hx; subst this
        rw [hx] at hc; simp only [if_neg hs] at hc
        cases hrec : cDec (((a :: t').drop (k + 2)).drop (n + 2)) with
        | error _ => rw [hrec] at hc; cases hc
        | ok rr =>
          rw [hrec] at hc; simp only [Except.map] at hc; cases hc
          have hag2 : (((a :: t').drop (k + 2 + n + 2))).take e' = (l.drop (k + 2 + n + 2)).take e' := by
            have := drop_agree (j := k + 2 + n + 2) hag
            simpa using this
          have ih' := ih e' r.2.1 r.2.2 (by rw [← h1']) _ rr hag2
            (by simp only [List.length_drop]; omega)
            (by rw [List.drop_drop] at hrec; rw [← hrec]; congr 2)
          have hdata : ((a :: t').drop (k + 2)).take n = (l.drop (k + 2)).take n :=
            take_agree (drop_agree (j := k + 2) hag) (by omega)
          rw [decL_some hk, parseSize_hexD mb _ 0 0 n digits hps]
          simp only [if_neg hs, if_neg (show ¬ l.length < k + 2 + n by omega), ih', hdata]
          rfl
  all_goals (try split at h) <;> (rcases h with ⟨h1, -, -⟩; simp at h1)

/-- The framed reader: scan from `body_start`, truncate at the scanner's end,
decode. The decoded body is `decode_chunked_body`'s. -/
theorem framed_chunked_agrees (P : Policy) (mb : Nat) (l : Bytes) (e adv t : Nat)
    (h : scanL P mb l 0 = (.done e, adv, t)) (out : Bytes) (hc : cDec (l.take e) = .ok out) :
    decL l = .ok (out, e) := by
  have hle := scanL_done_le P mb l 0 e adv t h
  exact cDec_agree P mb l 0 e adv t h (l.take e) out (by rw [List.take_take, Nat.min_self])
    (by simp; omega) hc

/-- The H1-06 fix: decode only a body the scanner accepts. -/
def cDecFixed (mb : Nat) (l : Bytes) : Except String Bytes :=
  match scanL implP mb l 0 with
  | (.done _, _, _) => cDec l
  | _ => .error "HTTP response: malformed or truncated chunked body"

theorem cDecFixed_complete (mb : Nat) (l out : Bytes) (h : cDecFixed mb l = .ok out) :
    ∃ e, scanEnd implP l 0 mb = .done e ∧ decodeBody l 0 = .ok (out, e) := by
  unfold cDecFixed at h
  rcases hs : scanL implP mb l 0 with ⟨r, adv, t⟩
  rw [hs] at h
  cases r with
  | done e =>
    simp only at h
    have hle := scanL_done_le implP mb l 0 e adv t hs
    refine ⟨e, ?_, ?_⟩
    · simp [scanEnd, scanResume, hs, SRes.shift]
    · have := cDec_agree implP mb l 0 e adv t hs l out rfl hle h
      unfold decodeBody; rw [List.drop_zero, this]; rfl
  | _ => cases h

end Flare.L3.H1.ClientChunked
