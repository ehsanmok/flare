import Flare.L3_Protocol.H1.Chunked

/-!
# Chunked coding: specifications and the headline theorems

* `poll`: the reactor's polling loop over a growing buffer
  (`flare/http/_reactor/conn_handle.mojo:661-678`), and
  `poll_eq_oneShot`: under the H1-01 fix the verdict equals a one-shot scan
  of the final buffer, however the bytes were segmented.
* `lfScan`: a recipient that uses RFC 9112 §2.2's permission to treat a bare
  LF as a line terminator. `impl_agrees_lfTolerant`: since the H1-02 fix
  every body flare accepts is framed identically by such a recipient.
-/
namespace Flare.L3.H1.Chunked
open Flare

theorem drop_append_le {l : Bytes} {n : Nat} (m : Bytes) (h : n ≤ l.length) :
    (l ++ m).drop n = l.drop n ++ m := List.drop_append_of_le_length h

/-! ## Segmentation independence (H1-01) -/

theorem scanEnd_done_stable (P : Policy) (p q : Bytes) (start mb e : Nat)
    (h : scanEnd P p start mb = .done e) : scanEnd P (p ++ q) start mb = .done e := by
  unfold scanEnd scanResume at *
  rcases hr : scanL P mb (p.drop start) 0 with ⟨r, adv, t⟩
  rw [hr] at h
  obtain ⟨e', rfl, rfl⟩ := SRes.shift_eq_done.mp h
  have hst : start ≤ p.length := by
    rcases Nat.lt_or_ge p.length start with hc | hc
    · rw [List.drop_eq_nil_of_le (by omega), scanL_none (by rfl)] at hr; simp at hr
    · exact hc
  rw [drop_append_le q hst, scanL_done_append P mb q _ 0 e' adv t hr]; rfl

theorem scanEnd_malformed_stable (P : Policy) (hs : 1 ≤ P.slack) (hc : P.capTrailer = true)
    (p q : Bytes) (start mb : Nat)
    (h : scanEnd P p start mb = .malformed) : scanEnd P (p ++ q) start mb = .malformed := by
  unfold scanEnd scanResume at *
  rcases hr : scanL P mb (p.drop start) 0 with ⟨r, adv, t⟩
  rw [hr] at h
  have h' := SRes.shift_eq_malformed.mp h; subst h'
  have hst : start ≤ p.length := by
    rcases Nat.lt_or_ge p.length start with hc | hc
    · rw [List.drop_eq_nil_of_le (by omega), scanL_none (by rfl)] at hr; simp [CAP] at hr
    · exact hc
  rw [drop_append_le q hst, scanL_malformed_append P hs hc mb q _ 0 adv t hr]; rfl

/-- **Prefix stability** under the H1-01 fix: once a prefix of the stream
gets a definite verdict, every extension gets the same verdict. -/
theorem scanEnd_segmentation_independent (P : Policy) (hs : 1 ≤ P.slack)
    (hc : P.capTrailer = true) (p q : Bytes) (start mb : Nat)
    (h : scanEnd P p start mb ≠ .incomplete) :
    scanEnd P (p ++ q) start mb = scanEnd P p start mb := by
  cases hv : scanEnd P p start mb with
  | incomplete => exact absurd hv h
  | malformed => exact scanEnd_malformed_stable P hs hc p q start mb hv
  | done e => exact scanEnd_done_stable P p q start mb e hv

/-- Resuming from the saved `(cursor, decoded_total)` on an extended buffer
equals re-scanning from the original cursor (any policy). -/
theorem scanResume_resume (P : Policy) (b m : Bytes) (c0 t0 mb : Nat)
    (h : (scanResume P b c0 t0 mb).1 = .incomplete) :
    scanResume P (b ++ m) (scanResume P b c0 t0 mb).2.1 (scanResume P b c0 t0 mb).2.2 mb
      = scanResume P (b ++ m) c0 t0 mb := by
  unfold scanResume at *
  dsimp only at h ⊢
  rcases hr : scanL P mb (b.drop c0) t0 with ⟨r, adv, t⟩
  rw [hr] at h
  dsimp only at h ⊢
  have h' := SRes.shift_eq_incomplete.mp h; subst h'
  rcases Nat.lt_or_ge b.length c0 with hlt | hge
  · rw [List.drop_eq_nil_of_le (by omega), scanL_none (by rfl)] at hr
    simp only [Prod.mk.injEq] at hr; obtain ⟨-, rfl, rfl⟩ := hr
    simp
  · obtain ⟨_, hres⟩ := scanL_resume P mb m _ t0 adv t hr
    rw [drop_append_le m hge, hres]
    have : (b ++ m).drop (c0 + adv) = (b.drop c0 ++ m).drop adv := by
      rw [← drop_append_le m hge, List.drop_drop]
    rw [this, SRes.shift_shift]
    simp only [Prod.mk.injEq, and_true]
    exact ⟨by congr 1; omega, by omega⟩

/-- The reactor's polling loop: scan the buffer from the saved state; while
the verdict is INCOMPLETE and another segment arrives, append it and resume.
mirrors flare/http/_reactor/conn_handle.mojo:661-678 @59bda50 -/
def poll (P : Policy) (mb : Nat) : Bytes → Nat → Nat → List Bytes → SRes
  | buf, c, t, [] => (scanResume P buf c t mb).1
  | buf, c, t, seg :: segs =>
    let r := scanResume P buf c t mb
    if r.1 = .incomplete then poll P mb (buf ++ seg) r.2.1 r.2.2 segs else r.1

theorem poll_inv (P : Policy) (hs : 1 ≤ P.slack) (hc : P.capTrailer = true) (mb h : Nat) :
    ∀ (segs : List Bytes) (buf : Bytes) (c t : Nat),
    (∀ ext, scanResume P (buf ++ ext) c t mb = scanResume P (buf ++ ext) h 0 mb) →
    poll P mb buf c t segs = scanEnd P (buf ++ segs.flatten) h mb
  | [], buf, c, t, hinv => by
    have := hinv []; simp only [List.append_nil] at this
    simp [poll, scanEnd, this]
  | seg :: segs, buf, c, t, hinv => by
    simp only [poll]
    split
    · rename_i hinc
      rw [poll_inv P hs hc mb h segs (buf ++ seg) _ _ ?_]
      · simp [List.append_assoc]
      · intro ext
        have h1 := scanResume_resume P buf (seg ++ ext) c t mb hinc
        rw [List.append_assoc, h1, hinv]
    · rename_i hni
      have h0 := hinv []; simp only [List.append_nil] at h0
      have hv : scanEnd P buf h mb ≠ .incomplete := by
        unfold scanEnd; rw [← h0]; exact hni
      unfold scanEnd at hv ⊢
      rw [h0]
      exact (scanEnd_segmentation_independent P hs hc buf _ h mb hv).symm

/-- **Chunking independence of the reactor** (H1-01 fix): however the
request body is split into reads, the reactor's verdict equals a one-shot
scan of all the bytes it has received. -/
theorem poll_eq_oneShot (P : Policy) (hs : 1 ≤ P.slack) (hc : P.capTrailer = true)
    (mb h : Nat) (b0 : Bytes) (segs : List Bytes) :
    poll P mb b0 h 0 segs = scanEnd P (b0 ++ segs.flatten) h mb :=
  poll_inv P hs hc mb h segs b0 h 0 (fun _ => rfl)

theorem fixed_poll_eq_oneShot (mb h : Nat) (b0 : Bytes) (segs : List Bytes) :
    poll fixedP mb b0 h 0 segs = scanFixed (b0 ++ segs.flatten) h mb :=
  poll_eq_oneShot fixedP (by decide) rfl mb h b0 segs

theorem fullFix_poll_eq_oneShot (mb h : Nat) (b0 : Bytes) (segs : List Bytes) :
    poll fullFixP mb b0 h 0 segs = scanEnd fullFixP (b0 ++ segs.flatten) h mb :=
  poll_eq_oneShot fullFixP (by decide) rfl mb h b0 segs

/-- A shipped-scanner acceptance is never revoked by more bytes. -/
theorem impl_done_stable (p q : Bytes) (start mb e : Nat)
    (h : scanImpl p start mb = .done e) : scanImpl (p ++ q) start mb = .done e :=
  scanEnd_done_stable implP p q start mb e h

/-! ## LF-tolerant recipient (H1-02) -/

/-- First LF. -/
def findLF : Bytes → Option Nat
  | [] => none
  | a :: t => if a = 10 then some 0 else (findLF t).map (· + 1)

def stripCR (c : Bytes) : Bytes := if c.getLast? = some 13 then c.dropLast else c

/-- `1*HEXDIG` followed by nothing or `;` (extensions skipped). -/
def lfSize : Bytes → Nat → Nat → Option Nat
  | [], s, d => if d = 0 then none else some s
  | c :: cs, s, d =>
    if c = 59 then (if d = 0 then none else some s) else
    match hexVal c with
    | none => none
    | some v => lfSize cs (s * 16 + v) (d + 1)

theorem findLF_lt : ∀ {l : Bytes} {k : Nat}, findLF l = some k → k < l.length
  | [], _, h => by simp [findLF] at h
  | a :: t, k, h => by
    simp only [findLF] at h
    split at h
    · simp at h; subst h; simp
    · cases h' : findLF t with
      | none => simp [h'] at h
      | some j => simp [h'] at h; subst h; have := findLF_lt h'; simp; omega

def lfTr (l : Bytes) : Option Nat :=
  match h : findLF l with
  | none => none
  | some k => if stripCR (l.take k) = [] then some (k + 1)
              else (lfTr (l.drop (k + 1))).map (· + (k + 1))
termination_by l.length
decreasing_by have := findLF_lt h; simp only [List.length_drop]; omega

/-- A chunked-body reader that recognises a bare LF as a line terminator
(RFC 9112 §2.2 "MAY"), ignoring a preceding CR. Spec only, not flare code. -/
def lfScan (l : Bytes) : Option (Bytes × Nat) :=
  match h : findLF l with
  | none => none
  | some k =>
    match lfSize (stripCR (l.take k)) 0 0 with
    | none => none
    | some n =>
      if n = 0 then (lfTr (l.drop (k + 1))).map fun e => ([], e + (k + 1)) else
      if l.length < k + 1 + n + 1 then none else
      if l.getD (k + 1 + n) = 13 ∧ l.getD (k + 1 + n + 1) = 10 then
        (lfScan (l.drop (k + 1 + n + 2))).map fun r => ((l.drop (k + 1)).take n ++ r.1, r.2 + (k + 1 + n + 2))
      else if l.getD (k + 1 + n) = 10 then
        (lfScan (l.drop (k + 1 + n + 1))).map fun r => ((l.drop (k + 1)).take n ++ r.1, r.2 + (k + 1 + n + 1))
      else none
termination_by l.length
decreasing_by
  all_goals (have := findLF_lt h; simp only [List.length_drop]; omega)

theorem findLF_append_of_not_mem : ∀ (xs ys : Bytes), 10 ∉ xs → findLF (xs ++ 10 :: ys) = some xs.length
  | [], ys, _ => by simp [findLF]
  | x :: xs, ys, h => by
    simp only [List.mem_cons, not_or] at h
    simp only [List.cons_append, findLF, if_neg (Ne.symm h.1 : x ≠ 10)]
    rw [findLF_append_of_not_mem xs ys h.2]; simp

theorem findCRLF_spec : ∀ {l : Bytes} {k : Nat}, findCRLF l = some k →
    l = l.take k ++ 13 :: 10 :: l.drop (k + 2)
  | [], _, h => by simp [findCRLF] at h
  | [_], _, h => by simp [findCRLF] at h
  | a :: b :: t, k, h => by
    simp only [findCRLF] at h
    split at h
    · rename_i hab; simp at h; subst h; simp [hab.1, hab.2]
    · cases h' : findCRLF (b :: t) with
      | none => simp [h'] at h
      | some j =>
        simp [h'] at h; subst h
        have := findCRLF_spec h'
        conv => lhs; rw [this]
        simp

theorem findLF_of_crlf {l : Bytes} {k : Nat} (h : findCRLF l = some k) (hlf : 10 ∉ l.take k) :
    findLF l = some (k + 1) ∧ stripCR (l.take (k + 1)) = l.take k := by
  have hs := findCRLF_spec h
  have hlen := findCRLF_lt h
  have htk : (l.take k).length = k := List.length_take_of_le (by omega)
  constructor
  · rw [hs, show l.take k ++ 13 :: 10 :: l.drop (k + 2) = (l.take k ++ [13]) ++ 10 :: l.drop (k + 2) by simp,
      findLF_append_of_not_mem]
    · simp [htk]
    · simp [hlf]
  · have h2 := congrArg (List.take (k + 1)) hs
    rw [List.take_append, htk, List.take_take] at h2
    have h3 : (13 :: 10 :: l.drop (k + 2) : Bytes).take (k + 1 - k) = [13] := by
      rw [show k + 1 - k = 1 by omega]; rfl
    rw [h3, show min (k + 1) k = k by omega] at h2
    rw [h2]; simp [stripCR]

theorem parseSize_lfSize (mb : Nat) : ∀ (xs : Bytes) (s d size dg : Nat),
    parseSize mb xs s d = some (size, dg) → dg ≠ 0 → lfSize xs s d = some size
  | [], s, d, size, dg, h, hd => by
    simp [parseSize] at h; obtain ⟨rfl, rfl⟩ := h; simp [lfSize, hd]
  | c :: cs, s, d, size, dg, h, hd => by
    simp only [parseSize] at h
    simp only [lfSize]
    split at h
    · rename_i hc; simp at h; obtain ⟨rfl, rfl⟩ := h; simp [hc, hd]
    · rename_i hc
      rw [if_neg hc]
      cases hv : hexVal c with
      | none => simp [hv] at h
      | some v =>
        simp only [hv] at h ⊢
        split at h
        · simp at h
        · exact parseSize_lfSize mb cs _ _ _ _ h hd

theorem stripCR_crlf : stripCR [13] = [] := by decide

theorem lfTr_of_scanTr (P : Policy) (hP : P.rejectLF = true) :
    ∀ (l : Bytes) (e : Nat), scanTr P l = .done e → lfTr l = some e := by
  intro l
  fun_induction scanTr P l <;> intro e h
  case case3 a b t hab =>
    simp at h; subst h
    obtain ⟨rfl, rfl⟩ := hab
    rw [lfTr]; split
    · simp_all [findLF]
    · rename_i k hk
      simp [findLF] at hk; subst hk; simp [stripCR]
  case case8 a b t hab k hk hcap hlf ih =>
    obtain ⟨e', h1, rfl⟩ := SRes.shift_eq_done.mp h
    have hlf' : 10 ∉ (a :: b :: t).take k := by simpa [hP] using hlf
    obtain ⟨hf, hst⟩ := findLF_of_crlf hk hlf'
    have hk0 : k ≠ 0 := by
      rintro rfl; simp [findCRLF] at hk; exact hab hk
    have hne : (a :: b :: t).take k ≠ [] := by
      have := findCRLF_lt hk; simp at this ⊢; omega
    rw [lfTr]; split
    · simp_all
    · rename_i k2 hk2; rw [hf] at hk2; cases hk2
      rw [if_neg (by rw [hst]; exact hne)]
      have hd : (a :: b :: t).drop (k + 1 + 1) = (a :: b :: t).drop (k + 2) := rfl
      rw [hd, ih e' h1]; simp only [Option.map_some, Option.some.injEq]
  all_goals simp at h

/-- **H1-02 fix meets the spec**: with bare LF rejected inside chunk lines,
every body flare's scanner accepts is framed by an LF-tolerant recipient at
the same end offset, with the same decoded bytes. -/
theorem lfScan_of_scanL (P : Policy) (hP : P.rejectLF = true) (mb : Nat) :
    ∀ (l : Bytes) (tot e adv t : Nat), scanL P mb l tot = (.done e, adv, t) →
    ∃ out, decL l = .ok (out, e) ∧ lfScan l = some (out, e) := by
  intro l tot
  fun_induction scanL P mb l tot <;> intro e adv t h <;> simp only [Prod.mk.injEq] at h
  case case6 l tot k hk hcap hlf digits hd hps =>
    obtain ⟨h1, -, -⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    have hlf' : 10 ∉ l.take k := by simpa [hP] using hlf
    obtain ⟨hf, hst⟩ := findLF_of_crlf hk hlf'
    refine ⟨[], ?_, ?_⟩
    · rw [decL_some hk, parseSize_hexD mb _ 0 0 0 digits hps]
      simp only [if_true]
      rw [decTr_of_scanTr P _ e' h1']; rfl
    · rw [lfScan]; split
      · simp_all
      · rename_i k2 hk2; rw [hf] at hk2; cases hk2
        rw [hst, parseSize_lfSize mb _ 0 0 0 digits hps hd]
        simp only [if_true]
        have hd2 : l.drop (k + 1 + 1) = l.drop (k + 2) := rfl
        rw [hd2, lfTr_of_scanTr P hP _ e' h1']; simp only [Option.map_some]
  case case10 l tot k hk hcap hlf size digits hps hd hs hmb hl hcrlf r ih =>
    obtain ⟨h1, -, -⟩ := h
    obtain ⟨e', h1', rfl⟩ := SRes.shift_eq_done.mp h1
    obtain ⟨out, hout, hlfs⟩ := ih e' r.2.1 r.2.2 (by rw [← h1'])
    have hlf' : 10 ∉ l.take k := by simpa [hP] using hlf
    obtain ⟨hf, hst⟩ := findLF_of_crlf hk hlf'
    refine ⟨(l.drop (k + 2)).take size ++ out, ?_, ?_⟩
    · rw [decL_some hk, parseSize_hexD mb _ 0 0 size digits hps]
      simp only [if_neg hs, if_neg (show ¬ l.length < k + 2 + size by omega), hout]
      rfl
    · rw [lfScan]; split
      · simp_all
      · rename_i k2 hk2; rw [hf] at hk2; cases hk2
        rw [hst, parseSize_lfSize mb _ 0 0 size digits hps hd]
        simp only [if_neg hs]
        have e1 : k + 1 + 1 + size = k + 2 + size := by omega
        have hc : ¬ (l.length < k + 1 + 1 + size + 1) := by omega
        rw [if_neg hc]
        simp only [not_or, Decidable.not_not] at hcrlf
        rw [e1, if_pos hcrlf]
        have e2 : k + 2 + size + 2 = k + 1 + 1 + size + 2 := by omega
        rw [← e1, ← e2, hlfs]
        simp only [Option.map_some]
  all_goals (try split at h) <;> (rcases h with ⟨h1, -, -⟩; simp at h1)

theorem scanEnd_lfSafe (P : Policy) (hP : P.rejectLF = true) (buf : Bytes) (start mb e : Nat)
    (h : scanEnd P buf start mb = .done e) :
    ∃ out, decodeBody buf start = .ok (out, e) ∧
      (lfScan (buf.drop start)).map (fun r => (r.1, r.2 + start)) = some (out, e) := by
  unfold scanEnd scanResume at h
  rcases hr : scanL P mb (buf.drop start) 0 with ⟨r, adv, t⟩
  rw [hr] at h
  obtain ⟨e', rfl, rfl⟩ := SRes.shift_eq_done.mp h
  obtain ⟨out, hd, hl⟩ := lfScan_of_scanL P hP mb _ 0 e' adv t hr
  exact ⟨out, by rw [decodeBody, hd]; rfl, by simp [hl]⟩

theorem impl_agrees_lfTolerant (buf : Bytes) (start mb e : Nat)
    (h : scanImpl buf start mb = .done e) :
    ∃ out, decodeBody buf start = .ok (out, e) ∧
      (lfScan (buf.drop start)).map (fun r => (r.1, r.2 + start)) = some (out, e) :=
  scanEnd_lfSafe implP rfl buf start mb e h

/-- **Scan acceptance implies decode agreement** (any policy, including the
shipped one): when the reactor's scanner says the body ends at `e`,
`decode_chunked_body` succeeds on the same buffer, ends at the same `e`, and
decodes at most `max_body` bytes. -/
theorem scanEnd_decode (P : Policy) (buf : Bytes) (start mb e : Nat)
    (h : scanEnd P buf start mb = .done e) :
    ∃ out, decodeBody buf start = .ok (out, e) ∧ out.length ≤ mb := by
  unfold scanEnd scanResume at h
  rcases hr : scanL P mb (buf.drop start) 0 with ⟨r, adv, t⟩
  rw [hr] at h
  obtain ⟨e', rfl, rfl⟩ := SRes.shift_eq_done.mp h
  obtain ⟨out, hd, hl⟩ := decL_of_scanL P mb _ 0 e' adv t hr
  have := scanL_total_le P mb _ 0 e' adv t (Nat.zero_le _) hr
  exact ⟨out, by rw [decodeBody, hd]; rfl, by omega⟩

end Flare.L3.H1.Chunked
