import Flare.Core

/-!
# HandoffQueue and the handoff-target choice

`runtime/handoff.mojo:96-390`. The queue is a circular buffer with a
separate `count`; every `% capacity` is modelled with `modChk`, which
returns `none` (Mojo: trap / UB) on a zero divisor, so "never divides by
zero" is a theorem rather than an assumption. Slots are modelled as a
function `Nat → Int` (the Mojo `List[Int]` of length `capacity`, only
indexed below `capacity`, which the invariant guarantees).
-/
namespace Flare.L2.Handoff

def modChk (a c : Nat) : Option Nat := if c = 0 then none else some (a % c)

structure Q where
  slots : Nat → Int
  head : Nat
  tail : Nat
  count : Nat
  cap : Nat

def Q.empty (cap : Nat) : Q := ⟨fun _ => 0, 0, 0, 0, cap⟩

/-- mirrors flare/runtime/handoff.mojo:150-167 @59bda50
`none` = division by zero; `some (ok, q')`. -/
def pushed (q : Q) (fd : Int) (t : Nat) : Q :=
  { q with slots := fun j => if j = q.tail then fd else q.slots j, tail := t, count := q.count + 1 }

def push (q : Q) (fd : Int) : Option (Bool × Q) :=
  if q.count ≥ q.cap then some (false, q)
  else (modChk (q.tail + 1) q.cap).map fun t => (true, pushed q fd t)

/-- mirrors flare/runtime/handoff.mojo:169-180 @59bda50 -/
def pop (q : Q) : Option (Option Int × Q) :=
  if q.count = 0 then some (none, q)
  else (modChk (q.head + 1) q.cap).map fun h =>
    (some (q.slots q.head), { q with head := h, count := q.count - 1 })

/-- mirrors flare/runtime/handoff.mojo:182-195 @59bda50 (loop of `count`
steps, each doing `idx = (idx + 1) % capacity`). -/
def drainGo (q : Q) : Nat → Nat → Option (List Int)
  | 0, _ => some []
  | n + 1, idx => match modChk (idx + 1) q.cap with
    | none => none
    | some nxt => (drainGo q n nxt).map (q.slots idx :: ·)

def drain (q : Q) : Option (List Int × Q) :=
  (drainGo q q.count q.head).map fun l => (l, { q with head := q.tail, count := 0 })

/-- Abstraction to the spec queue. -/
def abs (q : Q) : List Int := (List.range q.count).map fun i => q.slots ((q.head + i) % q.cap)

def Inv (q : Q) : Prop :=
  q.count ≤ q.cap ∧ (0 < q.cap → q.head < q.cap ∧ q.tail < q.cap ∧ q.tail = (q.head + q.count) % q.cap)

theorem empty_inv (c : Nat) : Inv (Q.empty c) := by
  refine ⟨Nat.zero_le _, fun h => ⟨h, h, ?_⟩⟩; simp [Q.empty, Nat.zero_mod]

/-! Spec: bounded FIFO -/
def specPush (cap : Nat) (l : List Int) (x : Int) : Bool × List Int :=
  if l.length < cap then (true, l ++ [x]) else (false, l)
def specPop : List Int → Option Int × List Int
  | [] => (none, [])
  | x :: xs => (some x, xs)

theorem abs_length (q : Q) : (abs q).length = q.count := by simp [abs]

private theorem mod_ne {h i c n : Nat} (hc : 0 < c) (hi : i < n) (hn : n < c) :
    (h + i) % c ≠ (h + n) % c := by
  intro he
  have hd : c ∣ (h + n) - (h + i) := Nat.dvd_of_mod_eq_zero (Nat.sub_mod_eq_zero_of_mod_eq he.symm)
  have : (h + n) - (h + i) = 0 := Nat.eq_zero_of_dvd_of_lt hd (by omega)
  omega

/-- No division by zero, and refinement of the spec push. -/
theorem push_refines (q : Q) (hi : Inv q) (fd : Int) :
    ∃ ok q', push q fd = some (ok, q') ∧ Inv q' ∧ (ok, abs q') = specPush q.cap (abs q) fd := by
  obtain ⟨hc, hm⟩ := hi
  unfold push specPush; rw [abs_length]
  by_cases hf : q.count ≥ q.cap
  · exact ⟨false, q, by simp [hf], ⟨hc, hm⟩, by simp [show ¬ q.count < q.cap by omega]⟩
  · have hcap : 0 < q.cap := by omega
    obtain ⟨hh, ht, hte⟩ := hm hcap
    refine ⟨true, pushed q fd ((q.tail + 1) % q.cap),
      by simp [hf, modChk, show q.cap ≠ 0 by omega], ⟨by simp only [pushed]; omega, fun _ => ?_⟩, ?_⟩
    · refine ⟨hh, Nat.mod_lt _ hcap, ?_⟩
      simp only [pushed]; rw [hte, Nat.mod_add_mod, Nat.add_assoc]
    · rw [if_pos (by omega)]; simp only [Prod.mk.injEq, true_and]
      unfold abs; simp only [pushed, List.range_succ, List.map_append, List.map_cons, List.map_nil]
      congr 1
      · apply List.map_congr_left; intro i hi'
        simp only [List.mem_range] at hi'
        rw [if_neg]; rw [hte]; exact mod_ne hcap hi' (by omega)
      · simp [hte]

theorem pop_refines (q : Q) (hi : Inv q) :
    ∃ r q', pop q = some (r, q') ∧ Inv q' ∧ (r, abs q') = specPop (abs q) := by
  obtain ⟨hc, hm⟩ := hi
  unfold pop
  by_cases h0 : q.count = 0
  · refine ⟨none, q, by simp [h0], ⟨hc, hm⟩, ?_⟩
    simp [abs, h0, specPop]
  · have hcap : 0 < q.cap := by omega
    obtain ⟨hh, ht, hte⟩ := hm hcap
    refine ⟨some (q.slots q.head), { q with head := (q.head + 1) % q.cap, count := q.count - 1 },
      by simp [h0, modChk, show q.cap ≠ 0 by omega],
      ⟨by simp only; omega, fun _ => ⟨Nat.mod_lt _ hcap, ht, ?_⟩⟩, ?_⟩
    · simp only; rw [hte, Nat.mod_add_mod]; congr 1; omega
    · obtain ⟨n, hn⟩ : ∃ n, q.count = n + 1 := ⟨q.count - 1, by omega⟩
      unfold abs; rw [hn]
      simp only [List.range_succ_eq_map, List.map_cons, List.map_map, specPop, Nat.add_zero,
        Nat.mod_eq_of_lt hh, Prod.mk.injEq, true_and, Nat.add_sub_cancel]
      apply List.map_congr_left; intro i _
      simp only [Function.comp, Nat.mod_add_mod]; congr 2; omega

private theorem drainGo_eq (q : Q) (hcap : 0 < q.cap) (n idx : Nat) (hidx : idx < q.cap) :
    drainGo q n idx = some ((List.range n).map fun i => q.slots ((idx + i) % q.cap)) := by
  induction n generalizing idx with
  | zero => rfl
  | succ n ih =>
    simp only [drainGo, modChk, show q.cap ≠ 0 by omega, if_false]
    rw [ih _ (Nat.mod_lt _ hcap)]
    simp only [Option.map_some, List.range_succ_eq_map, List.map_cons, List.map_map,
      Nat.add_zero, Nat.mod_eq_of_lt hidx, Option.some.injEq, List.cons.injEq, true_and]
    apply List.map_congr_left; intro i _
    simp only [Function.comp, Nat.mod_add_mod]; congr 2; omega

theorem drain_refines (q : Q) (hi : Inv q) :
    ∃ l q', drain q = some (l, q') ∧ Inv q' ∧ l = abs q ∧ abs q' = [] := by
  obtain ⟨hc, hm⟩ := hi
  by_cases hcap : 0 < q.cap
  · obtain ⟨hh, ht, hte⟩ := hm hcap
    refine ⟨abs q, { q with head := q.tail, count := 0 }, ?_,
      ⟨Nat.zero_le _, fun _ => ⟨ht, ht, ?_⟩⟩, rfl, by simp [abs]⟩
    · simp [drain, drainGo_eq q hcap _ _ hh, abs]
    · simp [Nat.mod_eq_of_lt ht]
  · have h0 : q.count = 0 := by omega
    refine ⟨[], { q with head := q.tail, count := 0 }, by simp [drain, h0, drainGo],
      ⟨Nat.zero_le _, fun h => absurd h hcap⟩, by simp [abs, h0], by simp [abs]⟩

/-- `capacity = 0` never divides by zero (push refuses, pop/drain see an
empty queue). -/
theorem cap_zero_safe (fd : Int) :
    (push (Q.empty 0) fd).isSome ∧ (pop (Q.empty 0)).isSome ∧ (drain (Q.empty 0)).isSome := by
  simp [push, pop, drain, Q.empty, drainGo]

/-! ## peek_idle_worker / choose_handoff_target -/

/-- Scan loop of `peek_idle_worker` (handoff.mojo:327-333). -/
def peekGo (excl : Int) : List Nat → Nat → Int → Nat → Int × Nat
  | [], _, b, bs => (b, bs)
  | s :: rest, i, b, bs =>
    if (i : Int) = excl then peekGo excl rest (i + 1) b bs
    else if s < bs then peekGo excl rest (i + 1) i s
    else peekGo excl rest (i + 1) b bs

/-- mirrors flare/runtime/handoff.mojo:312-334 @59bda50
`sizes[i]` = `queues[i].size()`; `initBest` is `capacity + 1` in flare. -/
def peekWith (initBest : Nat) (enabled : Bool) (_cap : Nat) (sizes : List Nat) (excl : Int) : Int :=
  if !enabled then -1
  else if sizes.length ≤ 1 then -1
  else (peekGo excl sizes 0 (-1) (initBest)).1

def peekIdle (enabled : Bool) (cap : Nat) (sizes : List Nat) (excl : Int) : Int :=
  peekWith (cap + 1) enabled cap sizes excl

/-- The minimal fix: only peers strictly below capacity qualify. -/
def peekIdleFixed (enabled : Bool) (cap : Nat) (sizes : List Nat) (excl : Int) : Int :=
  peekWith cap enabled cap sizes excl

theorem peekGo_spec (excl : Int) (l : List Nat) (i : Nat) (b : Int) (bs : Nat) :
    ((peekGo excl l i b bs).1 = b ∧ (peekGo excl l i b bs).2 = bs ∧
       ∀ k (hk : k < l.length), (i + k : Int) ≠ excl → bs ≤ l[k]) ∨
    (∃ k, ∃ hk : k < l.length, (peekGo excl l i b bs).1 = ((i + k : Nat) : Int) ∧
       ((i + k : Nat) : Int) ≠ excl ∧ l[k] = (peekGo excl l i b bs).2 ∧ l[k] < bs) := by
  induction l generalizing i b bs with
  | nil => left; simp [peekGo]
  | cons s rest ih =>
    simp only [peekGo]
    split
    · rename_i he
      rcases ih (i + 1) b bs with ⟨h1, h2, h3⟩ | ⟨k, hk, h1, h2, h3, h4⟩
      · left; refine ⟨h1, h2, fun k hk hne => ?_⟩
        cases k with
        | zero => simp at hne; exact absurd he hne
        | succ k => simp only [List.getElem_cons_succ]; apply h3 k (by simpa using hk); push_cast at hne ⊢; omega
      · right; refine ⟨k + 1, by simpa using hk, ?_, ?_, by simpa using h3, by simpa using h4⟩
        · rw [h1]; congr 1; omega
        · rw [show i + (k + 1) = i + 1 + k by omega]; exact h2
    · rename_i he
      split
      · rename_i hlt
        rcases ih (i + 1) (i : Int) s with ⟨h1, h2, _⟩ | ⟨k, hk, h1, h2, h3, h4⟩
        · right; exact ⟨0, by simp, by rw [h1]; simp, by simpa using he, by simp [h2], hlt⟩
        · right; refine ⟨k + 1, by simpa using hk, ?_, ?_, by simpa using h3, by simp; omega⟩
          · rw [h1]; congr 1; omega
          · rw [show i + (k + 1) = i + 1 + k by omega]; exact h2
      · rename_i hge
        rcases ih (i + 1) b bs with ⟨h1, h2, h3⟩ | ⟨k, hk, h1, h2, h3, h4⟩
        · left; refine ⟨h1, h2, fun k hk hne => ?_⟩
          cases k with
          | zero => simp; omega
          | succ k => simp only [List.getElem_cons_succ]; apply h3 k (by simpa using hk); push_cast at hne ⊢; omega
        · right; refine ⟨k + 1, by simpa using hk, ?_, ?_, by simpa using h3, by simpa using h4⟩
          · rw [h1]; congr 1; omega
          · rw [show i + (k + 1) = i + 1 + k by omega]; exact h2

/-- Fixed peek: the result is -1, or a peer ≠ exclude whose queue is strictly
below capacity; and -1 (with handoff enabled and ≥ 2 workers) only when every
peer queue is full. -/
theorem peekFixed_below_capacity (cap : Nat) (sizes : List Nat) (excl : Int) (en : Bool) :
    let r := peekIdleFixed en cap sizes excl
    (r = -1 ∨ ∃ k, ∃ hk : k < sizes.length, r = k ∧ (k : Int) ≠ excl ∧ sizes[k] < cap) ∧
    (en = true → 2 ≤ sizes.length → r = -1 →
      ∀ k (hk : k < sizes.length), (k : Int) ≠ excl → cap ≤ sizes[k]) := by
  simp only [peekIdleFixed, peekWith]
  cases en
  · simp
  · by_cases hl : sizes.length ≤ 1
    · simp only [hl]; refine ⟨by simp, fun _ h => by omega⟩
    · simp only [Bool.not_true, Bool.false_eq_true, if_false, hl]
      rcases peekGo_spec excl sizes 0 (-1) cap with ⟨h1, _, h3⟩ | ⟨k, hk, h1, h2, h3, h4⟩
      · refine ⟨Or.inl h1, fun _ _ _ k hk hne => h3 k hk (by simpa using hne)⟩
      · refine ⟨Or.inr ⟨k, hk, by simpa using h1, by simpa using h2, h4⟩, fun _ _ hr => ?_⟩
        rw [h1] at hr; omega

/-- mirrors flare/runtime/handoff.mojo:336-365 @59bda50 -/
def chooseTarget (enabled : Bool) (cap : Nat) (sizes : List Nat) (thr : Int)
    (local_ : Int) (localLoad : Int) : Int :=
  if !enabled then -1
  else if sizes.length ≤ 1 then -1
  else
    let peer := peekIdle enabled cap sizes local_
    if peer < 0 then -1
    else
      let peerLoad : Int := sizes.getD peer.toNat 0
      if localLoad - peerLoad ≥ thr then peer else -1

/-- `choose_handoff_target` returns -1 or a peer other than the local worker
whose queue depth is at least `steal_threshold` below the local load. -/
theorem chooseTarget_spec (en : Bool) (cap : Nat) (sizes : List Nat) (thr local_ ll : Int) :
    let r := chooseTarget en cap sizes thr local_ ll
    r = -1 ∨ (r ≠ local_ ∧ ∃ k, ∃ hk : k < sizes.length, r = k ∧ ll - (sizes[k] : Int) ≥ thr) := by
  simp only [chooseTarget]
  split; · simp
  split; · simp
  rename_i hen hl
  have hen' : en = true := by simpa using hen
  subst hen'
  simp only [peekIdle, peekWith, Bool.not_true, Bool.false_eq_true, if_false, hl]
  rcases peekGo_spec local_ sizes 0 (-1) (cap + 1) with ⟨h1, _, _⟩ | ⟨k, hk, h1, h2, _, _⟩
  · rw [h1]; simp
  · rw [h1]; simp only [Nat.zero_add] at h2 ⊢
    have hk0 : ¬ ((k : Int) < 0) := by omega
    simp only [hk0, if_false, Int.toNat_natCast]
    split
    · rename_i hge; right; refine ⟨h2, k, hk, rfl, ?_⟩
      simpa [List.getD_eq_getElem?_getD, hk] using hge
    · left; rfl

end Flare.L2.Handoff
