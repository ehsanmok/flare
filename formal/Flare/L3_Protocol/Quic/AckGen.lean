import Flare.L3_Protocol.Quic.AckExpand

/-!
# QUIC ACK generation: received-packet ranges

Model of the receive-side ACK bookkeeping both drivers share
(flare/quic/_server_support.mojo @59bda50):

* `record` — `_ack_record` (76-124): collect the `[low, high]` pairs, add
  `[pn, pn]`, insertion-sort ascending by `low` (`isort`), merge
  overlapping or adjacent ranges (`mergeAcc`), keep the 32 highest, store
  descending;
* `contains` — `_ack_contains` (60-73), the duplicate filter at
  flare/quic/server.mojo:844;
* `fromRanges` — `_ack_from_ranges` (127-157);
* `Rx`, `recv`, `drain` — the 1-RTT receive path and ACK emission of the
  server driver (server.mojo:844-863, 2240-2268): record every packet,
  owe an ACK after an ack-eliciting one, emit it on the next drain.

Pairs are kept as a list of `(low, high)`; arithmetic is over `Nat`. That
matches the `UInt64` code: packet numbers are below 2^62, so `high + 1`
cannot wrap, and `prev_low - high - 2` is only computed on canonical lists,
where `high + 2 ≤ prev_low` (`Canon`).

Results:
* `record_canon`: the stored list is always canonical (descending,
  disjoint, separated by at least one missing number).
* `merge_exact`, `record_sound`, `record_exact`: before the cap the stored
  ranges are exactly the received numbers; after it, a subset.
* `fromRanges_claimed`, `fromRanges_wellFormed`: the emitted ACK frame
  claims exactly the stored numbers and has no negative range (RFC 9000
  §19.3.1).
* `ack_roundtrip`: parsed back by flare's own `expand_ack_ranges`, the ACK
  retires exactly the stored numbers when they number at most 256.
* `drain_after_recv`: after an ack-eliciting packet the next drain emits an
  ACK, and that ACK claims the packet whenever its range is still stored.
-/
namespace Flare.L3.Quic.AckGen
open Flare.L3.Quic.AckExpand

abbrev Ranges := List (Nat × Nat)

/-- `n` lies in a stored range. -/
def MemR (n : Nat) (l : Ranges) : Prop := ∃ p ∈ l, p.1 ≤ n ∧ n ≤ p.2

/-- Descending, each range non-empty, consecutive ranges separated by at
least one number. -/
def Canon : Ranges → Prop
  | [] => True
  | [p] => p.1 ≤ p.2
  | p :: q :: r => p.1 ≤ p.2 ∧ q.2 + 2 ≤ p.1 ∧ Canon (q :: r)

/-- mirrors flare/quic/_server_support.mojo:96-106 @59bda50 (one insertion
step: the element goes after every `low` not greater than its own) -/
def sortIns (x : Nat × Nat) : Ranges → Ranges
  | [] => [x]
  | y :: ys => if y.1 > x.1 then x :: y :: ys else y :: sortIns x ys

/-- mirrors flare/quic/_server_support.mojo:96-106 @59bda50 -/
def isort (l : Ranges) : Ranges := l.foldl (fun acc x => sortIns x acc) []

/-- The merge loop; the accumulator is `(ml, mh)` reversed (head = last).
mirrors flare/quic/_server_support.mojo:107-115 @59bda50 -/
def mergeAcc : Ranges → Ranges → Ranges
  | acc, [] => acc
  | [], x :: r => mergeAcc [x] r
  | (l, h) :: acc, (a, b) :: r =>
    if a ≤ h + 1 then mergeAcc ((l, max h b) :: acc) r
    else mergeAcc ((a, b) :: (l, h) :: acc) r

def cap : Nat := 32

/-- All merged ranges, descending, before the cap. -/
def merged (flat : Ranges) (pn : Nat) : Ranges := mergeAcc [] (isort (flat ++ [(pn, pn)]))

/-- mirrors flare/quic/_server_support.mojo:76-124 @59bda50 -/
def record (flat : Ranges) (pn : Nat) : Ranges := (merged flat pn).take cap

/-- mirrors flare/quic/_server_support.mojo:60-73 @59bda50 -/
def contains (flat : Ranges) (pn : Nat) : Bool :=
  flat.any (fun p => decide (p.1 ≤ pn ∧ pn ≤ p.2)) ||
    (decide (cap ≤ flat.length) && flat.all (fun p => decide (pn < p.1)))

/-- mirrors flare/quic/_server_support.mojo:127-157 @59bda50 (the ranges
below the first, as `(gap, length)`) -/
def gaps (prevLow : Nat) : Ranges → List (Nat × Nat)
  | [] => []
  | (l, h) :: r => (prevLow - h - 2, h - l) :: gaps l r

/-- `(largest, first_ack_range, ranges)`; `none` is the "empty range set"
raise. mirrors flare/quic/_server_support.mojo:127-157 @59bda50 -/
def fromRanges : Ranges → Option (Nat × Nat × List (Nat × Nat))
  | [] => none
  | (l, h) :: r => some (h, h - l, gaps l r)

/-! ## Sorting -/

theorem mem_sortIns (x : Nat × Nat) : ∀ (l : Ranges) y, y ∈ sortIns x l ↔ y = x ∨ y ∈ l := by
  intro l
  induction l with
  | nil => intro y; simp [sortIns]
  | cons z zs ih =>
    intro y
    simp only [sortIns]
    split
    · simp
    · simp only [List.mem_cons, ih]; constructor <;> rintro (h | h | h) <;> simp_all

theorem sorted_sortIns (x : Nat × Nat) :
    ∀ l : Ranges, l.Pairwise (fun a b => a.1 ≤ b.1) → (sortIns x l).Pairwise (fun a b => a.1 ≤ b.1) := by
  intro l
  induction l with
  | nil => intro _; simp [sortIns]
  | cons z zs ih =>
    intro h
    have hz := List.pairwise_cons.mp h
    simp only [sortIns]
    split
    · rename_i hgt
      refine List.pairwise_cons.mpr ⟨fun a ha => ?_, h⟩
      rcases List.mem_cons.mp ha with rfl | ha
      · omega
      · have := hz.1 a ha; omega
    · rename_i hle
      refine List.pairwise_cons.mpr ⟨fun a ha => ?_, ih hz.2⟩
      rcases (mem_sortIns x zs a).mp ha with rfl | ha
      · omega
      · exact hz.1 a ha

theorem isort_go (l : Ranges) : ∀ acc : Ranges, acc.Pairwise (fun a b => a.1 ≤ b.1) →
    (l.foldl (fun acc x => sortIns x acc) acc).Pairwise (fun a b => a.1 ≤ b.1) ∧
    ∀ y, y ∈ l.foldl (fun acc x => sortIns x acc) acc ↔ y ∈ acc ∨ y ∈ l := by
  induction l with
  | nil => intro acc h; simp [h]
  | cons x xs ih =>
    intro acc h
    have := ih (sortIns x acc) (sorted_sortIns x acc h)
    refine ⟨this.1, fun y => ?_⟩
    rw [List.foldl_cons, this.2, mem_sortIns, List.mem_cons]
    constructor
    · rintro ((rfl | h) | h)
      · exact .inr (.inl rfl)
      · exact .inl h
      · exact .inr (.inr h)
    · rintro (h | rfl | h)
      · exact .inl (.inr h)
      · exact .inl (.inl rfl)
      · exact .inr h

theorem isort_sorted (l : Ranges) : (isort l).Pairwise (fun a b => a.1 ≤ b.1) :=
  (isort_go l [] List.Pairwise.nil).1

theorem mem_isort (l : Ranges) (y : Nat × Nat) : y ∈ isort l ↔ y ∈ l := by
  have := (isort_go l [] List.Pairwise.nil).2 y
  simp only [List.not_mem_nil, false_or] at this
  exact this

/-! ## Merging -/

def HeadLe (acc : Ranges) (r : Ranges) : Prop :=
  match acc with
  | [] => True
  | p :: _ => ∀ x ∈ r, p.1 ≤ x.1

theorem canon_cons_head {l h : Nat} {acc : Ranges} (hc : Canon ((l, h) :: acc)) : l ≤ h := by
  cases acc with
  | nil => exact hc
  | cons q r => exact hc.1

theorem merge_inv (r : Ranges) :
    ∀ acc : Ranges, Canon acc → (∀ x ∈ r, x.1 ≤ x.2) → r.Pairwise (fun a b => a.1 ≤ b.1) →
      HeadLe acc r →
      Canon (mergeAcc acc r) ∧ ∀ n, MemR n (mergeAcc acc r) ↔ MemR n acc ∨ MemR n r := by
  induction r with
  | nil => intro acc hc _ _ _; simp [mergeAcc, hc, MemR]
  | cons x r ih =>
    intro acc hc hv hs hh
    obtain ⟨a, b⟩ := x
    have hab := hv (a, b) List.mem_cons_self
    have hv' : ∀ x ∈ r, x.1 ≤ x.2 := fun x hx => hv x (List.mem_cons_of_mem _ hx)
    have hs' := (List.pairwise_cons.mp hs)
    cases acc with
    | nil =>
      simp only [mergeAcc]
      have := ih [(a, b)] hab hv' hs'.2 (fun x hx => hs'.1 x hx)
      refine ⟨this.1, fun n => ?_⟩
      rw [this.2]; simp [MemR]
    | cons p acc =>
      obtain ⟨l, h⟩ := p
      have hlh := canon_cons_head hc
      have hla : l ≤ a := hh (a, b) List.mem_cons_self
      simp only [mergeAcc]
      split
      · rename_i hm
        have hc' : Canon ((l, max h b) :: acc) := by
          cases acc with
          | nil => show l ≤ max h b; omega
          | cons q r' => exact ⟨by simp only; omega, hc.2.1, hc.2.2⟩
        have := ih _ hc' hv' hs'.2 (fun x hx => Nat.le_trans hla (hs'.1 x hx))
        refine ⟨this.1, fun n => ?_⟩
        rw [this.2]
        simp only [MemR, List.mem_cons]
        constructor
        · rintro (⟨q, hq | hq, hb⟩ | ⟨q, hq, hb⟩)
          · subst hq; simp only at hb
            by_cases hn : n ≤ h
            · exact .inl ⟨(l, h), .inl rfl, by simp only; omega⟩
            · exact .inr ⟨(a, b), .inl rfl, by simp only; omega⟩
          · exact .inl ⟨q, .inr hq, hb⟩
          · exact .inr ⟨q, .inr hq, hb⟩
        · rintro (⟨q, hq | hq, hb⟩ | ⟨q, hq | hq, hb⟩)
          · subst hq; exact .inl ⟨_, .inl rfl, by simp only at hb ⊢; omega⟩
          · exact .inl ⟨q, .inr hq, hb⟩
          · subst hq; exact .inl ⟨_, .inl rfl, by simp only at hb ⊢; omega⟩
          · exact .inr ⟨q, hq, hb⟩
      · rename_i hm
        have hc' : Canon ((a, b) :: (l, h) :: acc) := ⟨hab, by simp only; omega, hc⟩
        have := ih _ hc' hv' hs'.2 (fun x hx => hs'.1 x hx)
        refine ⟨this.1, fun n => ?_⟩
        rw [this.2]
        simp only [MemR, List.mem_cons]
        constructor
        · rintro (⟨q, hq | hq | hq, hb⟩ | ⟨q, hq, hb⟩)
          · exact .inr ⟨q, .inl hq, hb⟩
          · exact .inl ⟨q, .inl hq, hb⟩
          · exact .inl ⟨q, .inr hq, hb⟩
          · exact .inr ⟨q, .inr hq, hb⟩
        · rintro (⟨q, hq | hq, hb⟩ | ⟨q, hq | hq, hb⟩)
          · exact .inl ⟨q, .inr (.inl hq), hb⟩
          · exact .inl ⟨q, .inr (.inr hq), hb⟩
          · exact .inl ⟨q, .inl hq, hb⟩
          · exact .inr ⟨q, hq, hb⟩

def Valid (flat : Ranges) : Prop := ∀ p ∈ flat, p.1 ≤ p.2

theorem merged_inv (flat : Ranges) (pn : Nat) (hv : Valid flat) :
    Canon (merged flat pn) ∧ ∀ n, MemR n (merged flat pn) ↔ MemR n flat ∨ n = pn := by
  have hv' : ∀ x ∈ isort (flat ++ [(pn, pn)]), x.1 ≤ x.2 := by
    intro x hx
    rcases List.mem_append.mp ((mem_isort _ x).mp hx) with h | h
    · exact hv x h
    · simp at h; subst h; simp
  have := merge_inv _ [] trivial hv' (isort_sorted _) trivial
  refine ⟨this.1, fun n => ?_⟩
  unfold merged
  rw [this.2]
  simp only [MemR, List.not_mem_nil, false_and, exists_false, false_or]
  constructor
  · rintro ⟨q, hq, hb⟩
    rcases List.mem_append.mp ((mem_isort _ q).mp hq) with h | h
    · exact .inl ⟨q, h, hb⟩
    · simp at h; subst h; simp at hb; omega
  · rintro (⟨q, hq, hb⟩ | rfl)
    · exact ⟨q, (mem_isort _ q).mpr (List.mem_append_left _ hq), hb⟩
    · exact ⟨(n, n), (mem_isort _ _).mpr (by simp), by simp⟩

theorem canon_valid : ∀ l : Ranges, Canon l → Valid l := by
  intro l
  induction l with
  | nil => intro _ p hp; cases hp
  | cons p r ih =>
    intro hc q hq
    cases r with
    | nil => simp at hq; subst hq; exact hc
    | cons p' r' =>
      rcases List.mem_cons.mp hq with rfl | hq
      · exact hc.1
      · exact ih hc.2.2 q hq

theorem canon_tail {p : Nat × Nat} {r : Ranges} (h : Canon (p :: r)) : Canon r := by
  cases r with
  | nil => trivial
  | cons q r => exact h.2.2

theorem canon_take : ∀ (l : Ranges) k, Canon l → Canon (l.take k) := by
  intro l
  induction l with
  | nil => intro k _; simp [Canon]
  | cons p r ih =>
    intro k hc
    cases k with
    | zero => simp [Canon]
    | succ k =>
      simp only [List.take_succ_cons]
      have ht := ih k (canon_tail hc)
      cases r with
      | nil => simpa using hc
      | cons q r' =>
        cases k with
        | zero => exact (canon_valid _ hc) p List.mem_cons_self
        | succ k => simp only [List.take_succ_cons] at ht ⊢; exact ⟨hc.1, hc.2.1, ht⟩

theorem canon_drop : ∀ (l : Ranges) k, Canon l → Canon (l.drop k) := by
  intro l
  induction l with
  | nil => intro k _; simp [Canon]
  | cons p r ih =>
    intro k hc
    cases k with
    | zero => simpa using hc
    | succ k => simpa using ih k (canon_tail hc)

/-- In a canonical list every later range lies strictly below the head. -/
theorem canon_below : ∀ (p : Nat × Nat) (r : Ranges), Canon (p :: r) → ∀ q ∈ r, q.2 < p.1 := by
  intro p r
  induction r generalizing p with
  | nil => intro _ q hq; cases hq
  | cons q r ih =>
    intro hc x hx
    rcases List.mem_cons.mp hx with rfl | hx
    · have := hc.2.1; omega
    · have h1 := ih q hc.2.2 x hx
      have h2 := hc.2.1
      have h3 := (canon_valid _ hc.2.2) q List.mem_cons_self
      omega

/-! ## `_ack_record` -/

theorem record_canon (flat : Ranges) (pn : Nat) (hv : Valid flat) : Canon (record flat pn) :=
  canon_take _ _ (merged_inv flat pn hv).1

/-- Never claims a number that was not received. -/
theorem record_sound (flat : Ranges) (pn : Nat) (hv : Valid flat) (n : Nat)
    (h : MemR n (record flat pn)) : MemR n flat ∨ n = pn := by
  obtain ⟨q, hq, hb⟩ := h
  exact ((merged_inv flat pn hv).2 n).mp ⟨q, List.mem_of_mem_take hq, hb⟩

/-- Exact while the merged ranges fit under the cap. -/
theorem record_exact (flat : Ranges) (pn : Nat) (hv : Valid flat)
    (hc : (merged flat pn).length ≤ cap) (n : Nat) :
    MemR n (record flat pn) ↔ MemR n flat ∨ n = pn := by
  unfold record; rw [List.take_of_length_le hc]; exact (merged_inv flat pn hv).2 n

theorem canon_take_drop : ∀ (l : Ranges) k, Canon l → ∀ p ∈ l.take k, ∀ q ∈ l.drop k, q.2 < p.1 := by
  intro l
  induction l with
  | nil => intro k _ p hp; simp at hp
  | cons x r ih =>
    intro k hc p hp q hq
    cases k with
    | zero => simp at hp
    | succ k =>
      simp only [List.take_succ_cons, List.drop_succ_cons] at hp hq
      rcases List.mem_cons.mp hp with rfl | hp
      · exact canon_below _ r hc q (List.mem_of_mem_drop hq)
      · exact ih k (canon_tail hc) p hp q hq

/-- Above the cap only lower numbers are dropped: everything kept lies
above everything dropped. -/
theorem record_drops_lowest (flat : Ranges) (pn : Nat) (hv : Valid flat) :
    ∀ p ∈ record flat pn, ∀ q ∈ (merged flat pn).drop cap, q.2 < p.1 :=
  canon_take_drop _ cap (merged_inv flat pn hv).1

/-! ## `_ack_from_ranges` -/

theorem intervalsFrom_gaps : ∀ (r : Ranges) (l h : Nat), Canon ((l, h) :: r) →
    intervalsFrom (l : Int) (gaps l r) = r.map (fun p => ((p.1 : Int), (p.2 : Int))) := by
  intro r
  induction r with
  | nil => intro _ _ _; rfl
  | cons q r ih =>
    obtain ⟨l2, h2⟩ := q
    intro l h hc
    have h1 := hc.2.1
    have h2v := (canon_valid _ hc.2.2) (l2, h2) List.mem_cons_self
    simp only at h1 h2v
    simp only [gaps, intervalsFrom, List.map_cons, List.cons.injEq]
    have e1 : (l : Int) - ((l - h2 - 2 : Nat) : Int) - 2 - ((h2 - l2 : Nat) : Int) = (l2 : Int) := by omega
    have e2 : (l : Int) - ((l - h2 - 2 : Nat) : Int) - 2 = (h2 : Int) := by omega
    refine ⟨by rw [e1, e2], ?_⟩
    rw [e1]
    exact ih l2 h2 hc.2.2

theorem intervals_fromRanges (l h : Nat) (r : Ranges) (hc : Canon ((l, h) :: r)) :
    intervals h (h - l) (gaps l r) = ((l, h) :: r).map (fun p => ((p.1 : Int), (p.2 : Int))) := by
  have hlh := canon_cons_head hc
  unfold intervals
  have e : (h : Int) - ((h - l : Nat) : Int) = (l : Int) := by omega
  rw [e, intervalsFrom_gaps r l h hc]
  rfl

/-- The emitted ACK frame claims exactly the stored numbers. -/
theorem fromRanges_claimed (flat : Ranges) (hc : Canon flat) {largest first : Nat}
    {rs : List (Nat × Nat)} (hf : fromRanges flat = some (largest, first, rs)) (n : Nat) :
    Claimed largest first rs n ↔ MemR n flat := by
  cases flat with
  | nil => cases hf
  | cons p r =>
    obtain ⟨l, h⟩ := p
    simp only [fromRanges, Option.some.injEq, Prod.mk.injEq] at hf
    obtain ⟨rfl, rfl, rfl⟩ := hf
    unfold Claimed
    rw [intervals_fromRanges l h r hc]
    constructor
    · rintro ⟨iv, hiv, hb⟩
      obtain ⟨q, hq, rfl⟩ := List.mem_map.mp hiv
      exact ⟨q, hq, by simp only at hb; omega⟩
    · rintro ⟨q, hq, hb⟩
      exact ⟨_, List.mem_map.mpr ⟨q, hq, rfl⟩, by simp only; omega⟩

/-- The emitted ACK frame has no negative packet number (RFC 9000 §19.3.1),
so the QUIC-03 check accepts it. -/
theorem fromRanges_wellFormed (flat : Ranges) (hc : Canon flat) {largest first : Nat}
    {rs : List (Nat × Nat)} (hf : fromRanges flat = some (largest, first, rs)) :
    WellFormed largest first rs := by
  cases flat with
  | nil => cases hf
  | cons p r =>
    obtain ⟨l, h⟩ := p
    simp only [fromRanges, Option.some.injEq, Prod.mk.injEq] at hf
    obtain ⟨rfl, rfl, rfl⟩ := hf
    intro iv hiv
    rw [intervals_fromRanges l h r hc] at hiv
    obtain ⟨q, _, rfl⟩ := List.mem_map.mp hiv
    simp

/-- End to end: flare's own `expand_ack_ranges` applied to the ACK built
from canonical stored ranges retires exactly the stored numbers, when they
number at most the 256 cap. -/
theorem ack_roundtrip (flat : Ranges) (hc : Canon flat) {largest first : Nat}
    {rs : List (Nat × Nat)} (hf : fromRanges flat = some (largest, first, rs))
    (hsmall : (implList largest first rs).length ≤ 256) (n : Nat) :
    n ∈ expand 256 largest first rs ↔ MemR n flat := by
  have hwf := fromRanges_wellFormed flat hc hf
  constructor
  · intro h
    have := expand_sound 256 largest first rs n h
    exact (fromRanges_claimed flat hc hf n).mp this
  · intro h
    exact expand_complete 256 largest first rs (by decide) hwf hsmall n
      ((fromRanges_claimed flat hc hf n).mpr h)

/-! ## Driver: owe an ACK, emit it on the next drain -/

/-- mirrors flare/quic/server.mojo:364, 844-863 @59bda50 (`rx_1rtt_ranges`,
`rx_1rtt_ack_pending`) -/
structure Rx where
  flat : Ranges := []
  pending : Bool := false

/-- mirrors flare/quic/server.mojo:844-863 @59bda50 (duplicates dropped,
then record, then owe an ACK if the packet was ack-eliciting) -/
def recv (s : Rx) (pn : Nat) (eliciting : Bool) : Rx :=
  if contains s.flat pn then s
  else { flat := record s.flat pn, pending := s.pending || eliciting }

/-- mirrors flare/quic/server.mojo:2240-2268 @59bda50 -/
def drain (s : Rx) : Option (Nat × Nat × List (Nat × Nat)) × Rx :=
  if s.pending ∧ 2 ≤ 2 * s.flat.length then (fromRanges s.flat, { s with pending := false })
  else (none, s)

theorem recv_canon (s : Rx) (pn : Nat) (b : Bool) (hc : Canon s.flat) : Canon (recv s pn b).flat := by
  unfold recv; split
  · exact hc
  · exact record_canon _ _ (canon_valid _ hc)

/-- After a new ack-eliciting packet, the next drain emits an ACK; when the
packet's range is still stored it is claimed, and nothing unreceived is. -/
theorem drain_after_recv (s : Rx) (pn : Nat) (hc : Canon s.flat)
    (hnew : contains s.flat pn = false) :
    ∃ largest first rs, (drain (recv s pn true)).1 = some (largest, first, rs) ∧
      (∀ n, Claimed largest first rs n → MemR n s.flat ∨ n = pn) ∧
      ((merged s.flat pn).length ≤ cap → Claimed largest first rs pn) := by
  have hv := canon_valid _ hc
  have hmem : MemR pn (merged s.flat pn) := ((merged_inv s.flat pn hv).2 pn).mpr (.inr rfl)
  have hne : record s.flat pn ≠ [] := by
    intro h
    obtain ⟨q, hq, _⟩ := hmem
    unfold record at h
    have : merged s.flat pn = [] := by
      cases hm : merged s.flat pn with
      | nil => rfl
      | cons x xs => rw [hm] at h; simp [cap] at h
    rw [this] at hq; cases hq
  have hrc := record_canon s.flat pn hv
  cases hr : record s.flat pn with
  | nil => exact absurd hr hne
  | cons p r =>
    obtain ⟨l, h⟩ := p
    refine ⟨h, h - l, gaps l r, ?_, ?_, ?_⟩
    · have h2 : 2 ≤ 2 * (r.length + 1) := by omega
      simp [drain, recv, hnew, hr, h2, fromRanges]
    · intro n hn
      rw [hr] at hrc
      have := (fromRanges_claimed ((l, h) :: r) hrc rfl n).mp hn
      rw [← hr] at this
      exact record_sound _ _ hv n this
    · intro hcap
      rw [hr] at hrc
      apply (fromRanges_claimed ((l, h) :: r) hrc rfl pn).mpr
      rw [← hr]
      exact (record_exact _ _ hv hcap pn).mpr (.inr rfl)

end Flare.L3.Quic.AckGen
