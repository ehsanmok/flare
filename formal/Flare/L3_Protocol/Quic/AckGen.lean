import Flare.L3_Protocol.Quic.AckExpand

/-!
# QUIC ACK generation: received-packet ranges

Model of the receive-side ACK bookkeeping both drivers share
(flare/quic/_server_support.mojo @59bda50):

* `record` — `_ack_record`: collect the `[low, high]` pairs, add
  `[pn, pn]`, insertion-sort ascending by `low` (`isort`), merge
  overlapping or adjacent ranges (`mergeAcc`), keep the 32 highest, store
  descending. Its in-order fast path (`recordFast`: a number inside the
  newest range is a no-op, one above it extends it) gives the same state on
  every reachable one (`recordFast_eq`);
* `contains` — `_ack_contains`, the duplicate filter at
  flare/quic/server.mojo:844: a number is seen if it lies in a stored range
  or below the floor, which `recordSt` raises past every range the cap drops
  (QUIC-14; the floor is the odd trailing slot of the flat list);
* `fromRanges` — `_ack_from_ranges` (127-157);
* `Rx`, `recv`, `drain` — the 1-RTT receive path and ACK emission of the
  server driver: record every packet, owe an ACK after an ack-eliciting
  one, emit it on the next drain on which `ack_due` holds.

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
* `drain_after_recv`: after an ack-eliciting packet the next drain with
  `ack_due` emits an ACK, and that ACK claims the packet whenever its range
  is still stored (`drain_held`: without `ack_due` it stays owed).
* `never_reaccepts`: over any packet trace, every number already received
  reads as seen, so no packet is processed twice (QUIC-14).
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

/-- mirrors flare/quic/_server_support.mojo#_ack_record sha=018fa7a5b4ab at=12630564 (one insertion
step: the element goes after every `low` not greater than its own) -/
def sortIns (x : Nat × Nat) : Ranges → Ranges
  | [] => [x]
  | y :: ys => if y.1 > x.1 then x :: y :: ys else y :: sortIns x ys

/-- mirrors flare/quic/_server_support.mojo#_ack_record sha=018fa7a5b4ab at=12630564 -/
def isort (l : Ranges) : Ranges := l.foldl (fun acc x => sortIns x acc) []

/-- The merge loop; the accumulator is `(ml, mh)` reversed (head = last).
mirrors flare/quic/_server_support.mojo#_ack_record sha=018fa7a5b4ab at=12630564 -/
def mergeAcc : Ranges → Ranges → Ranges
  | acc, [] => acc
  | [], x :: r => mergeAcc [x] r
  | (l, h) :: acc, (a, b) :: r =>
    if a ≤ h + 1 then mergeAcc ((l, max h b) :: acc) r
    else mergeAcc ((a, b) :: (l, h) :: acc) r

def cap : Nat := 32

/-- All merged ranges, descending, before the cap. -/
def merged (flat : Ranges) (pn : Nat) : Ranges := mergeAcc [] (isort (flat ++ [(pn, pn)]))

/-- mirrors flare/quic/_server_support.mojo#_ack_record sha=018fa7a5b4ab at=12630564 -/
def record (flat : Ranges) (pn : Nat) : Ranges := (merged flat pn).take cap

/-- The tracked state (fixed, QUIC-14): the stored ranges plus the floor, one
above the highest number whose range was ever dropped at the cap. In the
Mojo code the floor is the odd trailing slot of the flat list. -/
structure St where
  flat : Ranges := []
  floor : Nat := 0

/-- The floor after recording `pn` (fixed, QUIC-14): it rises to one above
the highest range the cap drops, and never falls. -/
def floorAfter (s : St) (pn : Nat) : Nat :=
  match (merged s.flat pn).drop cap with
  | [] => s.floor
  | q :: _ => max s.floor (q.2 + 1)

/-- mirrors flare/quic/_server_support.mojo#_ack_record sha=018fa7a5b4ab at=12630564 incl. the floor
slot (fixed, QUIC-14) -/
def recordSt (s : St) (pn : Nat) : St :=
  { flat := record s.flat pn, floor := floorAfter s pn }

/-- mirrors flare/quic/_server_support.mojo#_ack_contains sha=4116dc21abac at=faa8bba1 (fixed, QUIC-14):
in a stored range, or below the floor -/
def contains (s : St) (pn : Nat) : Bool :=
  s.flat.any (fun p => decide (p.1 ≤ pn ∧ pn ≤ p.2)) || decide (pn < s.floor)

/-- mirrors flare/quic/_server_support.mojo#_ack_from_ranges sha=e95413c36735 at=59bda50f (the ranges
below the first, as `(gap, length)`) -/
def gaps (prevLow : Nat) : Ranges → List (Nat × Nat)
  | [] => []
  | (l, h) :: r => (prevLow - h - 2, h - l) :: gaps l r

/-- `(largest, first_ack_range, ranges)`; `none` is the "empty range set"
raise. mirrors flare/quic/_server_support.mojo#_ack_from_ranges sha=e95413c36735 at=59bda50f -/
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

/-- mirrors flare/quic/server.mojo#QuicListener+QuicListener._process_one_packet sha=c86b2a14bdb6 at=12630564 (`rx_1rtt_ranges`,
`rx_1rtt_ack_pending`) -/
structure Rx where
  flat : Ranges := []
  floor : Nat := 0
  pending : Bool := false

/-- mirrors flare/quic/server.mojo#QuicListener._process_one_packet sha=e7525f448f1f at=12630564 (duplicates dropped,
then record, then owe an ACK if the packet was ack-eliciting) -/
def recv (s : Rx) (pn : Nat) (eliciting : Bool) : Rx :=
  if contains ⟨s.flat, s.floor⟩ pn then s
  else { flat := record s.flat pn, floor := floorAfter ⟨s.flat, s.floor⟩ pn,
         pending := s.pending || eliciting }

/-- `due` is `ack_due`: false only while the peer's ACK_FREQUENCY lets the
owed ACK wait (below its threshold and delay, no IMMEDIATE_ACK); the ACK
then stays owed.
mirrors flare/quic/server.mojo#QuicListener._drain_1rtt_coalesced sha=99380341168c at=12630564 -/
def drain (s : Rx) (due : Bool := true) : Option (Nat × Nat × List (Nat × Nat)) × Rx :=
  if s.pending ∧ 2 ≤ 2 * s.flat.length ∧ due then (fromRanges s.flat, { s with pending := false })
  else (none, s)

theorem recv_canon (s : Rx) (pn : Nat) (b : Bool) (hc : Canon s.flat) : Canon (recv s pn b).flat := by
  unfold recv; split
  · exact hc
  · exact record_canon _ _ (canon_valid _ hc)

/-- After a new ack-eliciting packet, the next drain emits an ACK; when the
packet's range is still stored it is claimed, and nothing unreceived is. -/
theorem drain_after_recv (s : Rx) (pn : Nat) (hc : Canon s.flat)
    (hnew : contains ⟨s.flat, s.floor⟩ pn = false) :
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

/-! ## No packet is accepted twice (QUIC-14)

`stepF` is the 1-RTT receive step on the tracked state (server.mojo:844-855):
a duplicate is dropped, anything else recorded. -/

def stepF (s : St) (pn : Nat) : St := if contains s pn then s else recordSt s pn

def runF (pns : List Nat) : St := pns.foldl stepF {}

def Inv (s : St) (R : List Nat) : Prop := Canon s.flat ∧ ∀ n ∈ R, MemR n s.flat ∨ n < s.floor

theorem contains_of {s : St} {n : Nat} (h : MemR n s.flat ∨ n < s.floor) : contains s n = true := by
  unfold contains
  rcases h with ⟨p, hp, hb⟩ | h
  · simp only [Bool.or_eq_true, List.any_eq_true, decide_eq_true_eq]
    exact .inl ⟨p, hp, hb⟩
  · simp [h]

theorem memR_or_floor_of_contains {s : St} {n : Nat} (h : contains s n = true) :
    MemR n s.flat ∨ n < s.floor := by
  unfold contains at h
  simp only [Bool.or_eq_true, List.any_eq_true, decide_eq_true_eq] at h
  rcases h with ⟨p, hp, hb⟩ | h
  · exact .inl ⟨p, hp, hb⟩
  · exact .inr h

theorem drop_head_max : ∀ (l : Ranges) (q : Nat × Nat) (r : Ranges), Canon l → l = q :: r →
    ∀ x ∈ l, x.2 ≤ q.2 := by
  intro l q r hc he x hx
  subst he
  rcases List.mem_cons.mp hx with rfl | hx
  · exact Nat.le_refl _
  · have := canon_below q r hc x hx
    have := (canon_valid _ hc) q List.mem_cons_self
    omega

theorem recordSt_inv (s : St) (R : List Nat) (pn : Nat) (h : Inv s R) : Inv (recordSt s pn) (pn :: R) := by
  have hv := canon_valid _ h.1
  have hm := merged_inv s.flat pn hv
  refine ⟨record_canon _ _ hv, fun n hn => ?_⟩
  have hin : MemR n (merged s.flat pn) ∨ n < s.floor := by
    rcases List.mem_cons.mp hn with rfl | hn
    · exact .inl ((hm.2 n).mpr (.inr rfl))
    · rcases h.2 n hn with h1 | h1
      · exact .inl ((hm.2 n).mpr (.inl h1))
      · exact .inr h1
  have e := List.take_append_drop cap (merged s.flat pn)
  rcases hin with ⟨p, hp, hb⟩ | hlt
  · rw [← e] at hp
    rcases List.mem_append.mp hp with hp | hp
    · exact .inl ⟨p, hp, hb⟩
    · right
      simp only [recordSt, floorAfter]
      have hcd := canon_drop _ cap hm.1
      generalize hd : (merged s.flat pn).drop cap = d at hp hcd
      cases d with
      | nil => cases hp
      | cons q r =>
        have := drop_head_max (q :: r) q r hcd rfl p hp
        simp only; omega
  · right
    simp only [recordSt, floorAfter]
    split <;> omega

theorem stepF_inv (s : St) (R : List Nat) (pn : Nat) (h : Inv s R) : Inv (stepF s pn) (pn :: R) := by
  unfold stepF
  split
  · rename_i hc
    refine ⟨h.1, fun n hn => ?_⟩
    rcases List.mem_cons.mp hn with rfl | hn
    · exact memR_or_floor_of_contains hc
    · exact h.2 n hn
  · exact recordSt_inv s R pn h

theorem runF_go (pns : List Nat) : ∀ (s : St) (R : List Nat), Inv s R →
    Inv (pns.foldl stepF s) (pns.reverse ++ R) := by
  induction pns with
  | nil => intro s R h; simpa using h
  | cons p ps ih =>
    intro s R h
    have := ih (stepF s p) (p :: R) (stepF_inv s R p h)
    simpa using this

/-- **No packet is processed twice** (QUIC-14): over any packet trace, every
packet number already received reads as seen. -/
theorem never_reaccepts (pns : List Nat) : ∀ n ∈ pns, contains (runF pns) n = true := by
  intro n hn
  have := (runF_go pns {} [] ⟨trivial, fun _ h => by cases h⟩).2 n (by simpa using hn)
  exact contains_of this

/-- The floor does not change the stored ranges, and so every ACK frame
sent. -/
theorem recordSt_flat (s : St) (pn : Nat) : (recordSt s pn).flat = record s.flat pn := rfl

theorem drain_held (s : Rx) : drain s false = (none, s) := by
  simp [drain]

/-! ## The in-order fast path of `_ack_record` -/

/-- mirrors flare/quic/_server_support.mojo#_ack_record sha=018fa7a5b4ab at=12630564 (the fast path,
then the full rebuild `recordSt`) -/
def recordFast (s : St) (pn : Nat) : St :=
  match s.flat with
  | (l, h) :: t =>
    if l ≤ pn then
      if pn ≤ h then s
      else if pn = h + 1 then { s with flat := (l, pn) :: t }
      else recordSt s pn
    else recordSt s pn
  | [] => recordSt s pn

theorem isort_desc : ∀ (l acc : Ranges), l.Pairwise (fun a b => b.1 < a.1) →
    (∀ x ∈ l, ∀ y ∈ acc, x.1 < y.1) →
    l.foldl (fun acc x => sortIns x acc) acc = l.reverse ++ acc := by
  intro l
  induction l with
  | nil => intro acc _ _; rfl
  | cons x xs ih =>
    intro acc hp hlt
    have hp' := List.pairwise_cons.mp hp
    have hs : sortIns x acc = x :: acc := by
      cases acc with
      | nil => rfl
      | cons y ys =>
        have := hlt x List.mem_cons_self y List.mem_cons_self
        simp only [sortIns]; rw [if_pos this]
    simp only [List.foldl_cons, hs]
    rw [ih (x :: acc) hp'.2 (fun z hz y hy => by
      rcases List.mem_cons.mp hy with rfl | hy
      · exact hp'.1 z hz
      · exact hlt z (List.mem_cons_of_mem _ hz) y hy)]
    simp

theorem sortIns_last (x : Nat × Nat) : ∀ m : Ranges, (∀ y ∈ m, y.1 ≤ x.1) → sortIns x m = m ++ [x] := by
  intro m
  induction m with
  | nil => intro _; rfl
  | cons y ys ih =>
    intro hm
    simp only [sortIns]
    rw [if_neg (by have := hm y List.mem_cons_self; omega), ih (fun z hz => hm z (List.mem_cons_of_mem _ hz))]
    rfl

theorem mergeAcc_append : ∀ (a b acc : Ranges), mergeAcc acc (a ++ b) = mergeAcc (mergeAcc acc a) b := by
  intro a
  induction a with
  | nil => intro b acc; cases acc <;> rfl
  | cons x xs ih =>
    intro b acc
    obtain ⟨a1, b1⟩ := x
    cases acc with
    | nil => simp only [List.cons_append, mergeAcc]; exact ih b _
    | cons p acc =>
      obtain ⟨l, h⟩ := p
      simp only [List.cons_append, mergeAcc]
      split <;> exact ih b _

theorem canon_desc : ∀ l : Ranges, Canon l → l.Pairwise (fun a b => b.1 < a.1) := by
  intro l
  induction l with
  | nil => intro _; exact List.Pairwise.nil
  | cons p r ih =>
    intro hc
    refine List.Pairwise.cons (fun q hq => ?_) (ih (canon_tail hc))
    have := canon_below p r hc q hq
    have := (canon_valid _ (canon_tail hc)) q hq
    omega

theorem mergeAcc_rev : ∀ t : Ranges, Canon t → mergeAcc [] t.reverse = t := by
  intro t
  induction t with
  | nil => intro _; rfl
  | cons p r ih =>
    intro hc
    rw [List.reverse_cons, mergeAcc_append, ih (canon_tail hc)]
    obtain ⟨pl, ph⟩ := p
    cases r with
    | nil => rfl
    | cons q r' =>
      obtain ⟨ql, qh⟩ := q
      have := hc.2.1
      simp only at this
      simp only [mergeAcc]
      rw [if_neg (by omega)]

theorem merged_fast (l h pn : Nat) (t : Ranges) (hc : Canon ((l, h) :: t)) (hl : l ≤ pn)
    (hh : pn ≤ h + 1) : merged ((l, h) :: t) pn = (l, max h pn) :: t := by
  have hd := canon_desc _ hc
  unfold merged isort
  rw [List.foldl_append, isort_desc _ [] hd (fun _ _ _ hy => by cases hy), List.append_nil]
  simp only [List.foldl_cons, List.foldl_nil]
  rw [sortIns_last _ _ (fun y hy => by
    rcases List.mem_cons.mp (List.mem_reverse.mp hy) with rfl | hy
    · exact hl
    · have := canon_below _ _ hc y hy
      have := (canon_valid _ (canon_tail hc)) y hy
      simp only at this ⊢; omega)]
  rw [mergeAcc_append, mergeAcc_rev _ hc]
  simp only [mergeAcc]
  rw [if_pos hh]

/-- The fast path changes nothing: on every canonical state of at most
`cap` ranges (every reachable one), it equals the full rebuild. -/
theorem recordFast_eq (s : St) (pn : Nat) (hc : Canon s.flat) (hcap : s.flat.length ≤ cap) :
    recordFast s pn = recordSt s pn := by
  unfold recordFast
  split
  · rename_i l h t he
    rw [he] at hc hcap
    by_cases hl : l ≤ pn
    · rw [if_pos hl]
      by_cases hh : pn ≤ h + 1
      · have hm := merged_fast l h pn t hc hl hh
        have hlen : (merged s.flat pn).length ≤ cap := by rw [he, hm]; simpa using hcap
        have hr : recordSt s pn = { s with flat := (l, max h pn) :: t } := by
          unfold recordSt record floorAfter
          rw [List.take_of_length_le hlen, List.drop_of_length_le hlen, he, hm]
        rw [hr]
        by_cases h1 : pn ≤ h
        · rw [if_pos h1, Nat.max_eq_left h1]
          cases s; simp only at he ⊢; rw [he]
        · rw [if_neg h1, if_pos (by omega), Nat.max_eq_right (by omega)]
      · rw [if_neg (by omega), if_neg (by omega)]
    · rw [if_neg hl]
  · rfl

end Flare.L3.Quic.AckGen
