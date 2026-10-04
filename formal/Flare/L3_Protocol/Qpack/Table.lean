/-!
# QPACK dynamic table (RFC 9204 §3.2)

A model of `QpackDynamicTable`: an insert-ordered entry log whose oldest
entry has absolute index `dropped`. Entries are abstract (`α`) with a size
function `esz` (RFC 9204 §3.2.1: name + value + 32, so `esz ≥ 32`, though the
invariants below need nothing about `esz`).

Arithmetic is over `Nat`. Every quantity the Mojo code computes in `UInt64`
(`size`, `capacity - sz`, `size - esz e`) is shown to stay between `0` and
`maxCapacity`, so with `maxCapacity < 2^64` the UInt64 operations never wrap
and coincide with the `Nat` ones (`evict_noUnderflow`, `insert_noUnderflow`).

Theorems:
* `Inv` (`size = Σ esz`, `size ≤ capacity ≤ maxCapacity`) holds initially and
  is preserved by `setCapacity` and `insert` (`inv_init`, `inv_setCapacity`,
  `inv_insert`);
* `insertCount` grows by exactly one per successful insert and never moves
  on eviction (`insertCount_insert`, `insertCount_evictTo`);
* absolute indices are stable: an entry that survives eviction keeps its
  absolute index, and the new entry lands at the old `insertCount`
  (`getAbs_insert`, `getAbs_insert_new`).
-/
namespace Flare.L3.Qpack.Table

structure Table (α : Type) where
  entries : List α
  capacity : Nat
  maxCapacity : Nat
  size : Nat
  dropped : Nat

variable {α : Type} (esz : α → Nat)

def sumSize : List α → Nat
  | [] => 0
  | e :: es => esz e + sumSize es

/-- mirrors flare/qpack/dynamic.mojo:93-98 @59bda50 -/
def Table.init (cap : Nat) : Table α :=
  { entries := [], capacity := cap, maxCapacity := cap, size := 0, dropped := 0 }

/-- mirrors flare/qpack/dynamic.mojo:100-102 @59bda50 -/
def Table.insertCount (t : Table α) : Nat := t.dropped + t.entries.length

/-- mirrors flare/qpack/dynamic.mojo:126-136 @59bda50 (the `while` loop,
by structural recursion on the entry list). -/
def evictTo (target : Nat) : Table α → Table α
  | ⟨[], c, m, s, d⟩ => ⟨[], c, m, s, d⟩
  | ⟨e :: es, c, m, s, d⟩ =>
    if s > target then evictTo target ⟨es, c, m, s - esz e, d + 1⟩
    else ⟨e :: es, c, m, s, d⟩
termination_by t => t.entries.length

/-- mirrors flare/qpack/dynamic.mojo:108-124 @59bda50 (`none` = raised
QPACK_ENCODER_STREAM_ERROR). -/
def setCapacity (t : Table α) (cap : Nat) : Option (Table α) :=
  if cap > t.maxCapacity then none
  else some (evictTo esz cap { t with capacity := cap })

/-- mirrors flare/qpack/dynamic.mojo:138-148 @59bda50 (`none` = `False`). -/
def insert (t : Table α) (h : α) : Option (Table α) :=
  let sz := esz h
  if sz > t.capacity then none
  else
    let t' := evictTo esz (t.capacity - sz) t
    some { t' with size := t'.size + sz, entries := t'.entries ++ [h] }

/-- mirrors flare/qpack/dynamic.mojo:150-158 @59bda50 -/
def Table.getAbs (t : Table α) (i : Nat) : Option α :=
  if i < t.dropped ∨ i ≥ t.dropped + t.entries.length then none
  else t.entries[i - t.dropped]?

/-- The table invariant. -/
def Inv (t : Table α) : Prop :=
  t.size = sumSize esz t.entries ∧ t.size ≤ t.capacity ∧ t.capacity ≤ t.maxCapacity

theorem inv_init (cap : Nat) : Inv esz (Table.init cap : Table α) := by
  simp [Inv, Table.init, sumSize]

/-- Eviction keeps `size = Σ`, ends at or below the target (or empty),
never changes capacity, and only advances `dropped` by what it drops. -/
theorem evictTo_spec (target : Nat) :
    ∀ (t : Table α), t.size = sumSize esz t.entries →
      let t' := evictTo esz target t
      t'.size = sumSize esz t'.entries ∧ t'.size ≤ max target t.size ∧
      (t'.size ≤ target ∨ t'.entries = []) ∧
      t'.capacity = t.capacity ∧ t'.maxCapacity = t.maxCapacity ∧
      t'.insertCount = t.insertCount ∧
      t'.dropped ≥ t.dropped ∧
      t.entries.drop (t'.dropped - t.dropped) = t'.entries
  | ⟨[], c, m, s, d⟩, h => by
      simp [evictTo, Table.insertCount] at *; omega
  | ⟨e :: es, c, m, s, d⟩, h => by
      unfold evictTo
      simp only [sumSize] at h
      by_cases hs : s > target
      · simp only [hs, if_true]
        have ih := evictTo_spec target ⟨es, c, m, s - esz e, d + 1⟩ (by simp; omega)
        simp only [Table.insertCount, List.length_cons] at ih ⊢
        obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := ih
        refine ⟨h1, by omega, h3, h4, h5, by omega, by omega, ?_⟩
        have : (evictTo esz target ⟨es, c, m, s - esz e, d + 1⟩).dropped - d
            = (evictTo esz target ⟨es, c, m, s - esz e, d + 1⟩).dropped - (d + 1) + 1 := by
          omega
        rw [this, List.drop_succ_cons]; exact h8
      · simp only [hs, if_false]
        simp [Table.insertCount, sumSize]; omega
termination_by t => t.entries.length

theorem insertCount_evictTo (target : Nat) (t : Table α)
    (h : t.size = sumSize esz t.entries) :
    (evictTo esz target t).insertCount = t.insertCount :=
  (evictTo_spec esz target t h).2.2.2.2.2.1

/-- Eviction never subtracts more than the running size (no UInt64
underflow in `self.size -= entry_size(self.entries[0])`). -/
theorem evict_noUnderflow (e : α) (es : List α) (s : Nat)
    (h : s = sumSize esz (e :: es)) : esz e ≤ s := by
  simp [sumSize] at h; omega

theorem inv_setCapacity (t : Table α) (cap : Nat) (t' : Table α)
    (hi : Inv esz t) (hs : setCapacity esz t cap = some t') : Inv esz t' := by
  unfold setCapacity at hs
  by_cases hc : cap > t.maxCapacity
  · simp [hc] at hs
  · simp only [hc, if_false, Option.some.injEq] at hs
    subst hs
    obtain ⟨h1, h2, h3⟩ := hi
    have := evictTo_spec esz cap { t with capacity := cap } (by simpa using h1)
    obtain ⟨e1, _, e3, e4, e5, _⟩ := this
    refine ⟨e1, ?_, ?_⟩
    · rcases e3 with e3 | e3
      · rw [e4]; exact e3
      · rw [e1, e3]; simp [sumSize]
    · rw [e4, e5]; simp; omega

/-- `capacity - sz` in `insert` cannot underflow. -/
theorem insert_noUnderflow (t : Table α) (h : α) (hle : ¬ esz h > t.capacity) :
    esz h ≤ t.capacity := by omega

theorem sumSize_append (xs ys : List α) :
    sumSize esz (xs ++ ys) = sumSize esz xs + sumSize esz ys := by
  induction xs with
  | nil => simp [sumSize]
  | cons x xs ih => simp [sumSize, ih]; omega

theorem inv_insert (t : Table α) (h : α) (t' : Table α)
    (hi : Inv esz t) (hs : insert esz t h = some t') : Inv esz t' := by
  unfold insert at hs
  by_cases hc : esz h > t.capacity
  · simp [hc] at hs
  · simp only [hc, if_false, Option.some.injEq] at hs
    subst hs
    obtain ⟨h1, h2, h3⟩ := hi
    obtain ⟨e1, _, e3, e4, e5, _⟩ := evictTo_spec esz (t.capacity - esz h) t h1
    refine ⟨?_, ?_, ?_⟩
    · simp only; rw [sumSize_append, ← e1]; simp [sumSize]
    · simp only; rw [e4]
      rcases e3 with e3 | e3
      · omega
      · rw [e1, e3]; simp [sumSize]; omega
    · simp only; rw [e4, e5]; exact h3

theorem insertCount_insert (t : Table α) (h : α) (t' : Table α)
    (hi : Inv esz t) (hs : insert esz t h = some t') :
    t'.insertCount = t.insertCount + 1 := by
  unfold insert at hs
  by_cases hc : esz h > t.capacity
  · simp [hc] at hs
  · simp only [hc, if_false, Option.some.injEq] at hs
    subst hs
    have := insertCount_evictTo esz (t.capacity - esz h) t hi.1
    simp only [Table.insertCount] at this ⊢
    simp; omega

/-- The new entry lands at absolute index `t.insertCount`. -/
theorem getAbs_insert_new (t : Table α) (h : α) (t' : Table α)
    (hi : Inv esz t) (hs : insert esz t h = some t') :
    t'.getAbs t.insertCount = some h := by
  have hic := insertCount_insert esz t h t' hi hs
  unfold insert at hs
  by_cases hc : esz h > t.capacity
  · simp [hc] at hs
  · simp only [hc, if_false, Option.some.injEq] at hs
    subst hs
    obtain ⟨_, _, _, _, _, e6, e7, _⟩ := evictTo_spec esz (t.capacity - esz h) t hi.1
    unfold Table.insertCount at e6 hic ⊢
    unfold Table.getAbs
    simp only [List.length_append, List.length_singleton] at hic ⊢
    rw [if_neg (by omega)]
    have : t.dropped + t.entries.length - (evictTo esz (t.capacity - esz h) t).dropped
        = (evictTo esz (t.capacity - esz h) t).entries.length := by omega
    rw [this]; simp

/-- Absolute-index stability: any entry the new table resolves, the old
table resolved identically, except the freshly inserted one. -/
theorem getAbs_insert (t : Table α) (h : α) (t' : Table α)
    (hi : Inv esz t) (hs : insert esz t h = some t') (i : Nat) (x : α)
    (hx : t'.getAbs i = some x) :
    t.getAbs i = some x ∨ (i = t.insertCount ∧ x = h) := by
  have hic := insertCount_insert esz t h t' hi hs
  unfold insert at hs
  by_cases hc : esz h > t.capacity
  · simp [hc] at hs
  · simp only [hc, if_false, Option.some.injEq] at hs
    subst hs
    obtain ⟨_, _, _, _, _, e6, e7, e8⟩ := evictTo_spec esz (t.capacity - esz h) t hi.1
    generalize hT : evictTo esz (t.capacity - esz h) t = T at e6 e7 e8 hic hx
    simp only [Table.getAbs, Table.insertCount] at hx hic e6 ⊢
    simp only [List.length_append, List.length_singleton] at hic hx
    by_cases hr : i < T.dropped ∨ i ≥ T.dropped + (T.entries.length + 1)
    · simp [hr] at hx
    · rw [if_neg hr] at hx
      by_cases hlast : i - T.dropped = T.entries.length
      · right; refine ⟨by omega, ?_⟩
        rw [hlast] at hx; simp at hx; exact hx.symm
      · left
        have hlt : i - T.dropped < T.entries.length := by omega
        rw [List.getElem?_append_left hlt] at hx
        rw [if_neg (by omega)]
        rw [← e8] at hx
        rw [List.getElem?_drop] at hx
        have : T.dropped - t.dropped + (i - T.dropped) = i - t.dropped := by omega
        rw [this] at hx; exact hx

end Flare.L3.Qpack.Table
