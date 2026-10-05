import Flare.Core

/-!
# HTTP/1.1 chunked transfer coding (RFC 9112 §7.1)

Model of `flare/http/proto/chunked.mojo` (fixed, H1-02): the completeness scanner
`scan_chunked_resume` / `scan_chunked_end`, the decoder
`decode_chunked_body`, and the response-side encoder in
`flare/http/streaming_serialize.mojo`.

Representation. The Mojo loops walk an index `pos` over a `Span[UInt8]`.
The model walks the suffix `buf.drop pos` instead and reports offsets
relative to it; `scanResume` re-adds the absolute cursor. Every index the
Mojo code computes is a non-negative `Int` bounded by `len(buf) + 2` plus a
chunk size bounded by `max_body`, so `Nat` is faithful as long as
`16 * max_body + 15 < 2^63` (`parseSize_fits`); `Int64` wraparound past
that bound is exhibited in `parseSize_wraps_unbounded`.

The scanner is parameterised by a `Policy` so that the shipped behaviour
(`implP`, which includes the H1-01 and H1-02 fixes; `oldP` and `preSegP` are
the pre-fix scanners kept for the counterexamples) share every lemma.
-/
namespace Flare.L3.H1.Chunked
open Flare

/-! ## Byte-level helpers -/

/-- First `CR LF` in `l`, as an index.
mirrors flare/http/proto/chunked.mojo:257-263 (fixed, H1-02) -/
def findCRLF : Bytes → Option Nat
  | [] => none
  | [_] => none
  | a :: b :: t => if a = 13 ∧ b = 10 then some 0 else (findCRLF (b :: t)).map (· + 1)

/-- mirrors flare/http/proto/chunked.mojo:171-180 @59bda50 -/
def hexVal (b : UInt8) : Option Nat :=
  if 48 ≤ b ∧ b ≤ 57 then some (b.toNat - 48)
  else if 97 ≤ b ∧ b ≤ 102 then some (b.toNat - 87)
  else if 65 ≤ b ∧ b ≤ 70 then some (b.toNat - 55)
  else none

/-- The chunk-size loop with the per-digit `max_body` guard. Returns
`none` for MALFORMED, else `(size, digits)`.
mirrors flare/http/proto/chunked.mojo:252-266 @59bda50 -/
def parseSize (maxBody : Nat) : Bytes → Nat → Nat → Option (Nat × Nat)
  | [], s, d => some (s, d)
  | c :: cs, s, d =>
    if c = 59 then some (s, d) else
    match hexVal c with
    | none => none
    | some v => if s * 16 + v > maxBody then none else parseSize maxBody cs (s * 16 + v) (d + 1)

theorem hexVal_le {c : UInt8} {v : Nat} (h : hexVal c = some v) : v ≤ 15 := by
  unfold hexVal at h
  have t1 : c ≤ 57 → c.toNat ≤ 57 := fun x => by simpa using UInt8.le_iff_toNat_le.mp x
  have t2 : c ≤ 102 → c.toNat ≤ 102 := fun x => by simpa using UInt8.le_iff_toNat_le.mp x
  have t3 : c ≤ 70 → c.toNat ≤ 70 := fun x => by simpa using UInt8.le_iff_toNat_le.mp x
  have t4 : 97 ≤ c → 97 ≤ c.toNat := fun x => by simpa using UInt8.le_iff_toNat_le.mp x
  have t5 : 65 ≤ c → 65 ≤ c.toNat := fun x => by simpa using UInt8.le_iff_toNat_le.mp x
  split at h
  · rename_i hc; cases h; have := t1 hc.2; omega
  split at h
  · rename_i hc; cases h; have := t2 hc.2; have := t4 hc.1; omega
  split at h
  · rename_i hc; cases h; have := t3 hc.2; have := t5 hc.1; omega
  · cases h

/-- The loop only recurses with `size ≤ max_body` (the per-digit guard), so
its result is at most `max_body`. -/
theorem parseSize_le (mb : Nat) : ∀ (l : Bytes) (s d : Nat), s ≤ mb →
    ∀ r, parseSize mb l s d = some r → r.1 ≤ mb
  | [], s, d, hs, r, h => by simp [parseSize] at h; rw [← h]; exact hs
  | c :: cs, s, d, hs, r, h => by
    unfold parseSize at h
    split at h
    · cases h; exact hs
    split at h
    · cases h
    · split at h
      · cases h
      · exact parseSize_le mb cs _ (d + 1) (by omega) r h

/-- Each `size * 16 + v` the loop computes starts from `size ≤ max_body`
(`parseSize_le`'s invariant) and a hex digit `v ≤ 15` (`hexVal_le`), so it
is at most `16 * max_body + 15` and the Mojo `Int` cannot wrap when that is
below `2^63`. -/
theorem parseSize_fits (mb s v : Nat) (hmb : 16 * mb + 15 < 2 ^ 63) (hs : s ≤ mb) (hv : v ≤ 15) :
    fitsI64 ((s * 16 + v : Nat) : Int) := by
  unfold fitsI64 I64_MIN I64_MAX; omega

/-- With `max_body ≥ 2^59` the accumulator can reach `2^63`, which a Mojo
`Int` holds as `-2^63`: below every `> max_body` check. -/
theorem parseSize_wraps_unbounded : (mojoInt (2 ^ 59 * 16)).toInt = -(2 ^ 63) := by decide

/-- Scanner verdict: `-1`, `-2`, or an end offset. -/
inductive SRes where
  | incomplete
  | malformed
  | done (e : Nat)
  deriving DecidableEq, Repr

def SRes.shift (k : Nat) : SRes → SRes
  | .done e => .done (e + k)
  | r => r

/-- The Mojo return value (`CHUNKED_INCOMPLETE = -1`, `CHUNKED_MALFORMED = -2`). -/
def SRes.toInt : SRes → Int
  | .incomplete => -1
  | .malformed => -2
  | .done e => e

/-- `CHUNK_LINE_MAX`. mirrors flare/http/proto/chunked.mojo:183 @59bda50 -/
def CAP : Nat := 4096

/-- `slack`: the incomplete-line test is `n - pos > CAP + slack`
(shipped: 1, since H1-01). `capTrailer`: complete trailer lines are also
capped (shipped: true, since H1-01). `rejectLF`: a chunk-size or trailer line
whose content holds a bare LF is MALFORMED (shipped: true, since H1-02). -/
structure Policy where
  slack : Nat
  capTrailer : Bool
  rejectLF : Bool

/-- The scanner as it was at 59bda50, before the H1-02 fix. Kept only so that
`Bugs.H1_02.counterexample` stays checkable. -/
def oldP : Policy := ⟨0, false, false⟩
/-- The scanner after the H1-02 fix and before the H1-01 fix (no slack, no
trailer cap). Kept only so that `Bugs.H1_01.counterexample` stays checkable. -/
def preSegP : Policy := ⟨0, false, true⟩
/-- The shipped behaviour: one byte of slack in the incomplete-line tests and a
cap on complete trailer lines (H1-01), and a size or trailer line containing LF
is MALFORMED (H1-02).
mirrors flare/http/proto/chunked.mojo:238-345 (fixed, H1-01) -/
def implP : Policy := ⟨1, true, true⟩

theorem findCRLF_lt : ∀ {l : Bytes} {k : Nat}, findCRLF l = some k → k + 2 ≤ l.length
  | [], _, h => by simp [findCRLF] at h
  | [_], _, h => by simp [findCRLF] at h
  | a :: b :: t, k, h => by
    simp only [findCRLF] at h
    split at h
    · simp at h; subst h; simp
    · cases h' : findCRLF (b :: t) with
      | none => simp [h'] at h
      | some j =>
        simp [h'] at h; subst h
        have := findCRLF_lt h'; simp at this ⊢; omega

/-- Trailer section after the last chunk: lines until an empty one.
mirrors flare/http/proto/chunked.mojo:290-314 (fixed, H1-02) -/
def scanTr (P : Policy) (l : Bytes) : SRes :=
  match l with
  | [] => .incomplete
  | [_] => .incomplete
  | a :: b :: t =>
    if a = 13 ∧ b = 10 then .done 2 else
    match h : findCRLF (a :: b :: t) with
    | none => if (a :: b :: t).length > CAP + P.slack then .malformed else .incomplete
    | some k =>
      if P.capTrailer = true ∧ k > CAP then .malformed else
      if P.rejectLF = true ∧ 10 ∈ (a :: b :: t).take k then .malformed else
      (scanTr P ((a :: b :: t).drop (k + 2))).shift (k + 2)
termination_by l.length
decreasing_by simp only [List.length_drop, List.length_cons]; omega

/-- The main scan loop over the suffix `l = buf[pos:]`. Returns the
verdict (offsets relative to `l`), how far the cursor advanced, and the
decoded total. mirrors flare/http/proto/chunked.mojo:253-325 (fixed, H1-02) -/
def scanL (P : Policy) (maxBody : Nat) (l : Bytes) (tot : Nat) : SRes × Nat × Nat :=
  match hf : findCRLF l with
  | none => (if l.length > CAP + P.slack then .malformed else .incomplete, 0, tot)
  | some k =>
    if k > CAP then (.malformed, 0, tot) else
    if P.rejectLF = true ∧ 10 ∈ l.take k then (.malformed, 0, tot) else
    match parseSize maxBody (l.take k) 0 0 with
    | none => (.malformed, 0, tot)
    | some (size, digits) =>
      if digits = 0 then (.malformed, 0, tot) else
      if size = 0 then ((scanTr P (l.drop (k + 2))).shift (k + 2), 0, tot) else
      if tot + size > maxBody then (.malformed, 0, tot) else
      if l.length < k + 2 + size + 2 then (.incomplete, 0, tot) else
      if l.getD (k + 2 + size) ≠ 13 ∨ l.getD (k + 2 + size + 1) ≠ 10 then
        (.malformed, 0, tot) else
      let r := scanL P maxBody (l.drop (k + 2 + size + 2)) (tot + size)
      (r.1.shift (k + 2 + size + 2), r.2.1 + (k + 2 + size + 2), r.2.2)
termination_by l.length
decreasing_by have := findCRLF_lt hf; simp only [List.length_drop]; omega

/-- `scan_chunked_resume(buf, cursor, decoded_total, max_body)`: verdict,
new cursor, new decoded total.
mirrors flare/http/proto/chunked.mojo:229-325 (fixed, H1-02) -/
def scanResume (P : Policy) (buf : Bytes) (cursor tot maxBody : Nat) : SRes × Nat × Nat :=
  let r := scanL P maxBody (buf.drop cursor) tot
  (r.1.shift cursor, cursor + r.2.1, r.2.2)

/-- mirrors flare/http/proto/chunked.mojo:207-226 (fixed, H1-02) -/
def scanEnd (P : Policy) (buf : Bytes) (start maxBody : Nat) : SRes :=
  (scanResume P buf start 0 maxBody).1

/-- The shipped scanner. -/
abbrev scanImpl := scanEnd implP
/-- The scanner before the H1-02 fix. -/
abbrev scanOld := scanEnd oldP
/-- The scanner before the H1-01 fix. -/
abbrev scanPreSeg := scanEnd preSegP

/-! ## Decoder -/

/-- mirrors flare/http/proto/chunked.mojo:328-338 @59bda50 (no `max_body`) -/
def parseHexD : Bytes → Nat → Option Nat
  | [], s => some s
  | c :: cs, s =>
    if c = 59 then some s else
    match hexVal c with
    | none => none
    | some v => parseHexD cs (s * 16 + v)

/-- mirrors flare/http/proto/chunked.mojo:340-355 @59bda50 -/
def decTr (l : Bytes) : Except String Nat :=
  match l with
  | [] => .error "chunked: truncated terminator"
  | [_] => .error "chunked: truncated terminator"
  | a :: b :: t =>
    if a = 13 ∧ b = 10 then .ok 2 else
    match h : findCRLF (a :: b :: t) with
    | none => .error "chunked: truncated trailer"
    | some k => (decTr ((a :: b :: t).drop (k + 2))).map (· + (k + 2))
termination_by l.length
decreasing_by simp only [List.length_drop, List.length_cons]; omega

/-- `decode_chunked_body`: decoded bytes and end offset (relative).
mirrors flare/http/proto/chunked.mojo:306-360 @59bda50 -/
def decL (l : Bytes) : Except String (Bytes × Nat) :=
  match hf : findCRLF l with
  | none => .error "chunked: truncated size line"
  | some k =>
    match parseHexD (l.take k) 0 with
    | none => .error "chunked: bad hex in size line"
    | some size =>
      if size = 0 then (decTr (l.drop (k + 2))).map fun e => ([], e + (k + 2))
      else if l.length < k + 2 + size then .error "chunked: truncated chunk data"
      else (decL (l.drop (k + 2 + size + 2))).map
        fun r => ((l.drop (k + 2)).take size ++ r.1, r.2 + (k + 2 + size + 2))
termination_by l.length
decreasing_by have := findCRLF_lt hf; simp only [List.length_drop]; omega

/-- `decode_chunked_body(buf, start)`. mirrors flare/http/proto/chunked.mojo:306-360 @59bda50 -/
def decodeBody (buf : Bytes) (start : Nat) : Except String (Bytes × Nat) :=
  (decL (buf.drop start)).map fun r => (r.1, r.2 + start)


/-! ## Basic lemmas -/

theorem findCRLF_append : ∀ {l : Bytes} {k : Nat} (m : Bytes), findCRLF l = some k → findCRLF (l ++ m) = some k
  | [], _, _, h => by simp [findCRLF] at h
  | [_], _, _, h => by simp [findCRLF] at h
  | a :: b :: t, k, m, h => by
    simp only [findCRLF] at h
    simp only [List.cons_append, findCRLF]
    split at h
    · simp_all
    · rename_i hab
      simp only [hab, if_false]
      cases h' : findCRLF (b :: t) with
      | none => simp [h'] at h
      | some j =>
        simp [h'] at h
        have := findCRLF_append m h'
        simp only [List.cons_append] at this
        rw [this]; simp [h]

theorem SRes.shift_eq_done {r : SRes} {k e : Nat} : r.shift k = .done e ↔ ∃ e', r = .done e' ∧ e = e' + k := by
  cases r <;> simp [SRes.shift]; omega

theorem SRes.shift_eq_malformed {r : SRes} {k : Nat} : r.shift k = .malformed ↔ r = .malformed := by
  cases r <;> simp [SRes.shift]

theorem SRes.shift_eq_incomplete {r : SRes} {k : Nat} : r.shift k = .incomplete ↔ r = .incomplete := by
  cases r <;> simp [SRes.shift]


theorem take_cons2_append (a b : UInt8) (t m : Bytes) {k : Nat} (h : k + 2 ≤ (a :: b :: t).length) :
    (a :: b :: (t ++ m)).take k = (a :: b :: t).take k := by
  rw [← List.cons_append, ← List.cons_append]; exact List.take_append_of_le_length (by omega)

theorem scanTr_done_append (P : Policy) (m : Bytes) : ∀ (l : Bytes) (e : Nat), scanTr P l = .done e → scanTr P (l ++ m) = .done e := by
  intro l
  fun_induction scanTr P l <;> intro e h
  case case3 a b t hab =>
    rw [List.cons_append, List.cons_append, scanTr]; simp_all
  case case8 a b t hab k hk hcap hlf ih =>
    obtain ⟨e', h1, rfl⟩ := SRes.shift_eq_done.mp h
    have hk' := findCRLF_append m hk
    have hlen := findCRLF_lt hk
    rw [List.cons_append, List.cons_append, scanTr]
    simp only [List.cons_append] at hk'
    rw [if_neg hab]
    split
    · simp_all
    · rename_i k2 hk2
      rw [hk'] at hk2; cases hk2
      rw [if_neg hcap, take_cons2_append a b t m hlen, if_neg hlf, ← List.cons_append, ← List.cons_append, List.drop_append_of_le_length hlen, ih e' h1]
      rfl
  all_goals simp at h

theorem getD_append_lt (l m : Bytes) (i : Nat) (h : i < l.length) : Bytes.getD (l ++ m) i = Bytes.getD l i := by
  simp [Bytes.getD, List.getElem?_append_left h]


theorem scanL_none {P : Policy} {mb : Nat} {l : Bytes} {tot : Nat} (h : findCRLF l = none) :
    scanL P mb l tot = (if l.length > CAP + P.slack then .malformed else .incomplete, 0, tot) := by
  rw [scanL]; split
  · rfl
  · simp_all

theorem scanL_some {P : Policy} {mb : Nat} {l : Bytes} {tot k : Nat} (h : findCRLF l = some k) :
    scanL P mb l tot =
    (if k > CAP then (.malformed, 0, tot) else
    if P.rejectLF = true ∧ 10 ∈ l.take k then (.malformed, 0, tot) else
    match parseSize mb (l.take k) 0 0 with
    | none => (.malformed, 0, tot)
    | some (size, digits) =>
      if digits = 0 then (.malformed, 0, tot) else
      if size = 0 then ((scanTr P (l.drop (k + 2))).shift (k + 2), 0, tot) else
      if tot + size > mb then (.malformed, 0, tot) else
      if l.length < k + 2 + size + 2 then (.incomplete, 0, tot) else
      if l.getD (k + 2 + size) ≠ 13 ∨ l.getD (k + 2 + size + 1) ≠ 10 then
        (.malformed, 0, tot) else
      let r := scanL P mb (l.drop (k + 2 + size + 2)) (tot + size)
      (r.1.shift (k + 2 + size + 2), r.2.1 + (k + 2 + size + 2), r.2.2)) := by
  rw [scanL]; split
  · simp_all
  · rename_i k2 hk2; rw [h] at hk2; cases hk2; rfl

theorem scanL_done_append (P : Policy) (mb : Nat) (m : Bytes) : ∀ (l : Bytes) (tot e adv t : Nat),
    scanL P mb l tot = (.done e, adv, t) → scanL P mb (l ++ m) tot = (.done e, adv, t) := by
  intro l tot
  fun_induction scanL P mb l tot <;> intro e adv t h
  case case6 l tot k hk hcap hlf digits hd hps =>
    have hlen := findCRLF_lt hk
    rw [scanL_some (findCRLF_append m hk), List.take_append_of_le_length (by omega), hps]
    simp only [if_neg hcap, if_neg hlf, if_neg hd, if_true]
    rw [List.drop_append_of_le_length hlen]
    simp only [Prod.mk.injEq] at h ⊢
    obtain ⟨h1, h2, h3⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    refine ⟨?_, h2, h3⟩
    rw [scanTr_done_append P m _ e' h1']; rfl
  case case10 l tot k hk hcap hlf size digits hps hd hs hmb hl hcrlf r ih =>
    have hlen := findCRLF_lt hk
    rw [scanL_some (findCRLF_append m hk), List.take_append_of_le_length (by omega), hps]
    simp only [if_neg hcap, if_neg hlf, if_neg hd, if_neg hs, if_neg hmb]
    have hl' : ¬ (l ++ m).length < k + 2 + size + 2 := by simp; omega
    rw [if_neg hl', getD_append_lt _ _ _ (by omega), getD_append_lt _ _ _ (by omega), if_neg hcrlf,
      List.drop_append_of_le_length (by omega)]
    simp only [Prod.mk.injEq] at h ⊢
    obtain ⟨h1, h2, h3⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    have := ih e' r.2.1 r.2.2 (by rw [← h1'])
    simp only [r] at this h2 h3 ⊢
    rw [this]; simp only [SRes.shift]; exact ⟨trivial, h2, h3⟩
  all_goals (try split at h) <;> simp at h

theorem SRes.shift_zero (r : SRes) : r.shift 0 = r := by cases r <;> rfl
theorem SRes.shift_shift (r : SRes) (a b : Nat) : (r.shift a).shift b = r.shift (a + b) := by
  cases r <;> simp [SRes.shift]; omega

/-- Resumption: when the scan stops for more input, re-running it on any
extension from the saved cursor equals re-running from the start. -/
theorem scanL_resume (P : Policy) (mb : Nat) (m : Bytes) : ∀ (l : Bytes) (tot adv t : Nat),
    scanL P mb l tot = (.incomplete, adv, t) →
    adv ≤ l.length ∧
    scanL P mb (l ++ m) tot =
      ((scanL P mb ((l ++ m).drop adv) t).1.shift adv,
       (scanL P mb ((l ++ m).drop adv) t).2.1 + adv,
       (scanL P mb ((l ++ m).drop adv) t).2.2) := by
  intro l tot
  fun_induction scanL P mb l tot <;> intro adv t h <;> simp only [Prod.mk.injEq] at h
  case case10 l tot k hk hcap hlf size digits hps hd hs hmb hl hcrlf r ih =>
    obtain ⟨h1, h2, h3⟩ := h
    have hlen := findCRLF_lt hk
    have h1' := SRes.shift_eq_incomplete.mp h1
    obtain ⟨hadv, ih'⟩ := ih r.2.1 r.2.2 (by rw [← h1'])
    refine ⟨by simp at hadv ⊢; omega, ?_⟩
    rw [scanL_some (findCRLF_append m hk), List.take_append_of_le_length (by omega), hps]
    simp only [if_neg hcap, if_neg hlf, if_neg hd, if_neg hs, if_neg hmb]
    have hl' : ¬ (l ++ m).length < k + 2 + size + 2 := by simp; omega
    rw [if_neg hl', getD_append_lt _ _ _ (by omega), getD_append_lt _ _ _ (by omega), if_neg hcrlf,
      List.drop_append_of_le_length (by omega)]
    rw [ih']
    have hd2 : (List.drop (k + 2 + size + 2) l ++ m).drop r.2.1 = (l ++ m).drop adv := by
      rw [← h2, ← List.drop_append_of_le_length (by omega), List.drop_drop]
      congr 1; omega
    rw [hd2, ← h3, SRes.shift_shift, ← h2]
    simp only [Prod.mk.injEq, true_and, and_true]
    omega
  all_goals (try split at h) <;> (rcases h with ⟨h1, rfl, rfl⟩; first | (simp at h1; done) | simp [SRes.shift_zero])

theorem findCRLF_none_append : ∀ {l : Bytes} {k : Nat} (m : Bytes),
    findCRLF l = none → findCRLF (l ++ m) = some k → l.length ≤ k + 1
  | [], _, _, _, _ => by simp
  | [_], _, _, _, _ => by simp
  | a :: b :: t, k, m, h, h2 => by
    simp only [findCRLF] at h
    simp only [List.cons_append, findCRLF] at h2
    split at h
    · simp at h
    · rename_i hab
      rw [if_neg hab] at h2
      cases h3 : findCRLF (b :: (t ++ m)) with
      | none => simp [h3] at h2
      | some j =>
        simp [h3] at h2
        have h4 : findCRLF (b :: t) = none := by
          cases h5 : findCRLF (b :: t) <;> simp_all
        have := findCRLF_none_append (l := b :: t) m h4 (by simpa using h3)
        simp at this ⊢; omega

/-- With `slack ≥ 1` and capped complete trailer lines (the H1-01 fix),
a MALFORMED trailer verdict survives any extension. -/
theorem scanTr_malformed_append (P : Policy) (hs : 1 ≤ P.slack) (hc : P.capTrailer = true)
    (m : Bytes) : ∀ (l : Bytes), scanTr P l = .malformed → scanTr P (l ++ m) = .malformed := by
  intro l
  fun_induction scanTr P l <;> intro h
  case case4 a b t hab hn hlen =>
    rw [List.cons_append, List.cons_append, scanTr, if_neg hab]
    split
    · rw [if_pos (by simp only [List.length_cons, List.length_append] at hlen ⊢; omega)]
    · rename_i k hk
      have := findCRLF_none_append m hn (by simpa using hk)
      simp only [List.length_cons] at this hlen
      rw [if_pos (by simp only [hc, true_and, CAP] at hlen ⊢; omega)]
  case case6 a b t hab k hk hcap =>
    have hk' := findCRLF_append m hk
    rw [List.cons_append, List.cons_append, scanTr, if_neg hab]
    simp only [List.cons_append] at hk'
    split
    · simp_all
    · rename_i k2 hk2; rw [hk'] at hk2; cases hk2; rw [if_pos hcap]
  case case7 a b t hab k hk hcap hlf =>
    have hk' := findCRLF_append m hk
    have hlen := findCRLF_lt hk
    rw [List.cons_append, List.cons_append, scanTr, if_neg hab]
    simp only [List.cons_append] at hk'
    split
    · simp_all
    · rename_i k2 hk2; rw [hk'] at hk2; cases hk2
      rw [if_neg hcap, take_cons2_append a b t m hlen, if_pos hlf]
  case case8 a b t hab k hk hcap hlf ih =>
    have hk' := findCRLF_append m hk
    have hlen := findCRLF_lt hk
    rw [List.cons_append, List.cons_append, scanTr, if_neg hab]
    simp only [List.cons_append] at hk'
    split
    · simp_all
    · rename_i k2 hk2
      rw [hk'] at hk2; cases hk2
      rw [if_neg hcap, take_cons2_append a b t m hlen, if_neg hlf, ← List.cons_append, ← List.cons_append,
        List.drop_append_of_le_length hlen, ih (SRes.shift_eq_malformed.mp h)]
      rfl
  all_goals simp at h

/-- With the H1-01 fix a MALFORMED verdict survives any extension. -/
theorem scanL_malformed_append (P : Policy) (hs : 1 ≤ P.slack) (hc : P.capTrailer = true)
    (mb : Nat) (m : Bytes) : ∀ (l : Bytes) (tot adv t : Nat),
    scanL P mb l tot = (.malformed, adv, t) → scanL P mb (l ++ m) tot = (.malformed, adv, t) := by
  intro l tot
  fun_induction scanL P mb l tot <;> intro adv t h <;> simp only [Prod.mk.injEq] at h
  case case1 l tot hn =>
    obtain ⟨h1, rfl, rfl⟩ := h
    split at h1
    · rename_i hlen
      cases hk : findCRLF (l ++ m) with
      | none => rw [scanL_none hk, if_pos (by simp; omega)]
      | some k =>
        have := findCRLF_none_append m hn hk
        rw [scanL_some hk, if_pos (by simp only [CAP] at hlen ⊢; omega)]
    · simp at h1
  case case2 l tot k hk hcap =>
    obtain ⟨-, rfl, rfl⟩ := h
    rw [scanL_some (findCRLF_append m hk), if_pos hcap]
  case case3 l tot k hk hcap hlf =>
    obtain ⟨-, rfl, rfl⟩ := h
    rw [scanL_some (findCRLF_append m hk), if_neg hcap,
      List.take_append_of_le_length (by have := findCRLF_lt hk; omega), if_pos hlf]
  case case4 l tot k hk hcap hlf hps =>
    obtain ⟨-, rfl, rfl⟩ := h
    rw [scanL_some (findCRLF_append m hk), if_neg hcap,
      List.take_append_of_le_length (by have := findCRLF_lt hk; omega), if_neg hlf, hps]
  case case5 l tot k hk hcap hlf size hps =>
    obtain ⟨-, rfl, rfl⟩ := h
    rw [scanL_some (findCRLF_append m hk), if_neg hcap,
      List.take_append_of_le_length (by have := findCRLF_lt hk; omega), if_neg hlf, hps]
    simp
  case case6 l tot k hk hcap hlf digits hd hps =>
    obtain ⟨h1, rfl, rfl⟩ := h
    have hlen := findCRLF_lt hk
    rw [scanL_some (findCRLF_append m hk), if_neg hcap, List.take_append_of_le_length (by omega), if_neg hlf, hps]
    simp only [if_neg hd, if_true]
    rw [List.drop_append_of_le_length hlen,
      scanTr_malformed_append P hs hc m _ (SRes.shift_eq_malformed.mp h1)]
    rfl
  case case7 l tot k hk hcap hlf size digits hps hd hs hmb =>
    obtain ⟨-, rfl, rfl⟩ := h
    rw [scanL_some (findCRLF_append m hk), if_neg hcap,
      List.take_append_of_le_length (by have := findCRLF_lt hk; omega), if_neg hlf, hps]
    simp only [if_neg hd, if_neg hs, if_pos hmb]
  case case9 l tot k hk hcap hlf size digits hps hd hs hmb hl hcrlf =>
    obtain ⟨-, rfl, rfl⟩ := h
    rw [scanL_some (findCRLF_append m hk), if_neg hcap,
      List.take_append_of_le_length (by have := findCRLF_lt hk; omega), if_neg hlf, hps]
    have hl' : ¬ (l ++ m).length < k + 2 + size + 2 := by simp; omega
    simp only [if_neg hd, if_neg hs, if_neg hmb, if_neg hl']
    rw [getD_append_lt _ _ _ (by omega), getD_append_lt _ _ _ (by omega), if_pos hcrlf]
  case case10 l tot k hk hcap hlf size digits hps hd hs hmb hl hcrlf r ih =>
    obtain ⟨h1, h2, h3⟩ := h
    have hlen := findCRLF_lt hk
    have h1' := SRes.shift_eq_malformed.mp h1
    have ih' := ih r.2.1 r.2.2 (by rw [← h1'])
    rw [scanL_some (findCRLF_append m hk), List.take_append_of_le_length (by omega), hps]
    simp only [if_neg hcap, if_neg hlf, if_neg hd, if_neg hs, if_neg hmb]
    have hl' : ¬ (l ++ m).length < k + 2 + size + 2 := by simp; omega
    rw [if_neg hl', getD_append_lt _ _ _ (by omega), getD_append_lt _ _ _ (by omega), if_neg hcrlf,
      List.drop_append_of_le_length (by omega), ih']
    simp only [SRes.shift, Prod.mk.injEq, true_and]
    exact ⟨h2, h3⟩
  all_goals (try split at h) <;> (rcases h with ⟨h1, -, -⟩; simp at h1)

theorem scanTr_done_le (P : Policy) : ∀ (l : Bytes) (e : Nat), scanTr P l = .done e → e ≤ l.length := by
  intro l
  fun_induction scanTr P l <;> intro e h
  case case3 => simp at h; subst h; simp
  case case8 a b t hab k hk hcap hlf ih =>
    obtain ⟨e', h1, rfl⟩ := SRes.shift_eq_done.mp h
    have := ih e' h1; have := findCRLF_lt hk
    simp only [List.length_drop, List.length_cons] at *; omega
  all_goals simp at h

theorem scanL_done_le (P : Policy) (mb : Nat) : ∀ (l : Bytes) (tot e adv t : Nat),
    scanL P mb l tot = (.done e, adv, t) → e ≤ l.length := by
  intro l tot
  fun_induction scanL P mb l tot <;> intro e adv t h <;> simp only [Prod.mk.injEq] at h
  case case6 l tot k hk hcap hlf digits hd hps =>
    obtain ⟨h1, -, -⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    have := scanTr_done_le P _ e' h1'; have := findCRLF_lt hk
    simp only [List.length_drop] at *; omega
  case case10 l tot k hk hcap hlf size digits hps hd hs hmb hl hcrlf r ih =>
    obtain ⟨h1, -, -⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    have := ih e' r.2.1 r.2.2 (by rw [← h1'])
    simp only [List.length_drop] at *; omega
  all_goals (try split at h) <;> (rcases h with ⟨h1, -, -⟩; simp at h1)

/-- **Result range** (Mojo `Int` view): every verdict of
`scan_chunked_end` is `-1`, `-2`, or an offset in `[start, len(buf)]`. -/
theorem scanEnd_range (P : Policy) (buf : Bytes) (start mb : Nat) :
    (scanEnd P buf start mb).toInt = -1 ∨ (scanEnd P buf start mb).toInt = -2 ∨
    ∃ e : Nat, scanEnd P buf start mb = .done e ∧ start ≤ e ∧ e ≤ buf.length := by
  unfold scanEnd scanResume
  rcases hr : scanL P mb (buf.drop start) 0 with ⟨r, adv, t⟩
  cases r with
  | incomplete => left; rfl
  | malformed => right; left; rfl
  | done e =>
    right; right
    have := scanL_done_le P mb _ 0 e adv t hr
    simp only [List.length_drop] at this
    refine ⟨e + start, rfl, by omega, ?_⟩
    have : start ≤ buf.length := by
      rcases Nat.lt_or_ge buf.length start with hc | hc
      · rw [List.drop_eq_nil_of_le (by omega)] at hr
        rw [scanL_none (by rfl)] at hr; simp at hr
      · exact hc
    omega

theorem parseSize_hexD (mb : Nat) : ∀ (xs : Bytes) (s d size dg : Nat),
    parseSize mb xs s d = some (size, dg) → parseHexD xs s = some size
  | [], s, d, size, dg, h => by simp [parseSize, parseHexD] at h ⊢; exact h.1
  | c :: cs, s, d, size, dg, h => by
    simp only [parseSize] at h
    simp only [parseHexD]
    split at h
    · simp_all
    · rename_i hc
      rw [if_neg hc]
      cases hv : hexVal c with
      | none => simp [hv] at h
      | some v =>
        simp only [hv] at h ⊢
        split at h
        · simp at h
        · exact parseSize_hexD mb cs _ _ _ _ h

theorem decTr_of_scanTr (P : Policy) : ∀ (l : Bytes) (e : Nat), scanTr P l = .done e → decTr l = .ok e := by
  intro l
  fun_induction scanTr P l <;> intro e h
  case case3 a b t hab => simp at h; subst h; rw [decTr, if_pos hab]
  case case8 a b t hab k hk hcap hlf ih =>
    obtain ⟨e', h1, rfl⟩ := SRes.shift_eq_done.mp h
    rw [decTr, if_neg hab]
    split
    · simp_all
    · rename_i k2 hk2; rw [hk] at hk2; cases hk2
      rw [ih e' h1]; rfl
  all_goals simp at h

theorem decL_some {l : Bytes} {k : Nat} (h : findCRLF l = some k) :
    decL l = match parseHexD (l.take k) 0 with
    | none => .error "chunked: bad hex in size line"
    | some size =>
      if size = 0 then (decTr (l.drop (k + 2))).map fun e => ([], e + (k + 2))
      else if l.length < k + 2 + size then .error "chunked: truncated chunk data"
      else (decL (l.drop (k + 2 + size + 2))).map
        fun r => ((l.drop (k + 2)).take size ++ r.1, r.2 + (k + 2 + size + 2)) := by
  rw [decL]; split
  · simp_all
  · rename_i k2 hk2; rw [h] at hk2; cases hk2; rfl

/-- **Scan/decode agreement**: when the scanner accepts at `e`, the decoder
succeeds, ends at the same `e`, and yields exactly the counted bytes. -/
theorem decL_of_scanL (P : Policy) (mb : Nat) : ∀ (l : Bytes) (tot e adv t : Nat),
    scanL P mb l tot = (.done e, adv, t) →
    ∃ out, decL l = .ok (out, e) ∧ tot + out.length = t := by
  intro l tot
  fun_induction scanL P mb l tot <;> intro e adv t h <;> simp only [Prod.mk.injEq] at h
  case case6 l tot k hk hcap hlf digits hd hps =>
    obtain ⟨h1, -, rfl⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    refine ⟨[], ?_, by simp⟩
    rw [decL_some hk, parseSize_hexD mb _ 0 0 0 digits hps]
    simp only [if_true]
    rw [decTr_of_scanTr P _ e' h1']; rfl
  case case10 l tot k hk hcap hlf size digits hps hd hs hmb hl hcrlf r ih =>
    obtain ⟨h1, -, h3⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    obtain ⟨out, hout, hlen⟩ := ih e' r.2.1 r.2.2 (by rw [← h1'])
    refine ⟨(l.drop (k + 2)).take size ++ out, ?_, ?_⟩
    · rw [decL_some hk, parseSize_hexD mb _ 0 0 size digits hps]
      simp only [if_neg hs, if_neg (show ¬ l.length < k + 2 + size by omega), hout]
      rfl
    · have : ((l.drop (k + 2)).take size).length = size := by simp; omega
      simp only [List.length_append, this]; omega
  all_goals (try split at h) <;> (rcases h with ⟨h1, -, -⟩; simp at h1)

/-- The decoded total never exceeds `max_body`. -/
theorem scanL_total_le (P : Policy) (mb : Nat) : ∀ (l : Bytes) (tot e adv t : Nat),
    tot ≤ mb → scanL P mb l tot = (.done e, adv, t) → t ≤ mb := by
  intro l tot
  fun_induction scanL P mb l tot <;> intro e adv t ht h <;> simp only [Prod.mk.injEq] at h
  case case6 => omega
  case case10 l tot k hk hcap hlf size digits hps hd hs hmb hl hcrlf r ih =>
    obtain ⟨h1, -, h3⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    have := ih e' r.2.1 r.2.2 (by omega) (by rw [← h1']); omega
  all_goals (try split at h) <;> (rcases h with ⟨h1, -, -⟩; simp at h1)
end Flare.L3.H1.Chunked
