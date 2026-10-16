import Flare.L3_Protocol.Qpack.Table

/-!
# QPACK encoder lookups (`find`, `find_name`) and the Required Insert Count

`findBy p t` mirrors `QpackDynamicTable.find` (`p` = name and value equal)
and `find_name` (`p` = name equal): the absolute index of the first, that is
oldest, entry satisfying `p`, or `none` for -1. `findBy_some` and
`findBy_none` characterise it through `Table.getAbs`: the result is an
in-table absolute index whose entry satisfies `p`, no older entry does, and
`none` exactly when no entry does.

`ric` mirrors the first pass of `encode_field_section_dynamic`: one more
than the largest absolute index referenced (full match, else name match),
0 when nothing is referenced. `ric_bound` shows every referenced index is
below it, so with Base = RIC each relative index `RIC - 1 - abs` is in range
(see `FieldSection.rel_roundtrip`).
-/
namespace Flare.L3.Qpack.Encoder
open Flare.L3.Qpack.Table

variable {α : Type}

def firstIdx (p : α → Bool) : List α → Option Nat
  | [] => none
  | e :: es => if p e then some 0 else (firstIdx p es).map (· + 1)

theorem firstIdx_none (p : α → Bool) :
    ∀ es : List α, firstIdx p es = none ↔ ∀ e ∈ es, p e = false := by
  intro es
  induction es with
  | nil => simp [firstIdx]
  | cons e es ih =>
    simp only [firstIdx, List.mem_cons, forall_eq_or_imp]
    cases he : p e <;> simp [ih]

theorem firstIdx_some (p : α → Bool) :
    ∀ (es : List α) (i : Nat), firstIdx p es = some i →
      ∃ h : i < es.length, p es[i] = true ∧ ∀ j (hj : j < i), p (es[j]'(by omega)) = false := by
  intro es
  induction es with
  | nil => intro i h; simp [firstIdx] at h
  | cons e es ih =>
    intro i h
    simp only [firstIdx] at h
    cases he : p e
    · rw [he] at h
      simp only [Bool.false_eq_true, ↓reduceIte, Option.map_eq_some_iff] at h
      obtain ⟨k, hk, rfl⟩ := h
      obtain ⟨hl, hp, hj⟩ := ih k hk
      refine ⟨by simp; omega, by simpa using hp, ?_⟩
      intro j hj'
      cases j with
      | zero => simpa using he
      | succ j => simpa using hj j (by omega)
    · rw [he] at h
      simp only [↓reduceIte, Option.some.injEq] at h
      subst h
      exact ⟨by simp, by simpa using he, fun j hj => absurd hj (Nat.not_lt_zero _)⟩

/-- mirrors flare/qpack/dynamic.mojo#QpackDynamicTable.find+QpackDynamicTable.find_name sha=60adbb252aa5 at=59bda50f (`find`)
(`find_name`); `none` is -1 -/
def findBy (p : α → Bool) (t : Table α) : Option Nat :=
  (firstIdx p t.entries).map (t.dropped + ·)

theorem getAbs_of (t : Table α) (i : Nat) (h : i < t.entries.length) :
    t.getAbs (t.dropped + i) = some t.entries[i] := by
  unfold Table.getAbs
  rw [if_neg (by omega)]
  simp

theorem findBy_some (p : α → Bool) (t : Table α) (a : Nat) (h : findBy p t = some a) :
    t.dropped ≤ a ∧ a < t.insertCount ∧ (∃ e, t.getAbs a = some e ∧ p e = true) ∧
      ∀ b e, t.dropped ≤ b → b < a → t.getAbs b = some e → p e = false := by
  simp only [findBy, Option.map_eq_some_iff] at h
  obtain ⟨i, hi, rfl⟩ := h
  obtain ⟨hl, hp, hj⟩ := firstIdx_some p _ i hi
  refine ⟨by omega, by unfold Table.insertCount; omega, ⟨_, getAbs_of t i hl, hp⟩, ?_⟩
  intro b e hb hba he
  have : b = t.dropped + (b - t.dropped) := by omega
  rw [this, getAbs_of t _ (by omega)] at he
  cases he
  exact hj _ (by omega)

theorem findBy_none (p : α → Bool) (t : Table α) :
    findBy p t = none ↔ ∀ a e, t.getAbs a = some e → p e = false := by
  simp only [findBy, Option.map_eq_none_iff, firstIdx_none]
  constructor
  · intro h a e he
    unfold Table.getAbs at he
    split at he
    · cases he
    · exact h e (List.mem_of_getElem? he)
  · intro h e he
    obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem he
    exact h _ _ (getAbs_of t i hi)

/-- mirrors flare/qpack/dynamic.mojo#encode_field_section_dynamic sha=473b0e74a422 at=59bda50f -/
def ric (full name : α → Option Nat) (hs : List α) : Nat :=
  hs.foldl (fun m h => match full h <|> name h with
    | some i => max m (i + 1)
    | none => m) 0

theorem ric_go (full name : α → Option Nat) (hs : List α) :
    ∀ m, m ≤ hs.foldl (fun m h => match full h <|> name h with
      | some i => max m (i + 1)
      | none => m) m ∧
    ∀ h ∈ hs, ∀ i, (full h <|> name h) = some i →
      i < hs.foldl (fun m h => match full h <|> name h with
        | some i => max m (i + 1)
        | none => m) m := by
  induction hs with
  | nil => intro m; simp
  | cons h hs ih =>
    intro m
    simp only [List.foldl_cons, List.mem_cons, forall_eq_or_imp]
    cases hf : (full h <|> name h) with
    | none =>
      simp only [hf]
      obtain ⟨h1, h2⟩ := ih m
      exact ⟨h1, by simp, h2⟩
    | some j =>
      simp only [hf]
      obtain ⟨h1, h2⟩ := ih (max m (j + 1))
      refine ⟨by omega, ?_, h2⟩
      intro i hi
      cases hi
      omega

/-- Every index the encoder references is below its Required Insert Count. -/
theorem ric_bound (full name : α → Option Nat) (hs : List α) (h : α) (hh : h ∈ hs) (i : Nat)
    (hi : (full h <|> name h) = some i) : i < ric full name hs :=
  (ric_go full name hs 0).2 h hh i hi

/-! ## The shipped `QpackEncoder` (QPACK-06)

Until acknowledgments are tracked the encoder references no dynamic entry
(so no stream can block a decoder that allows none) and refuses an insert
that would evict (so no absolute index already handed out goes stale). -/

/-- `QpackEncoder.encode` encodes against an empty `QpackDynamicTable(0)`;
`full` / `name` are the `find` / `find_name` predicates.
mirrors flare/qpack/dynamic.mojo#QpackEncoder.encode sha=5f64c00e40aa at=ea1b9282 (fixed, QPACK-06) -/
def implRic (full name : α → α → Bool) (hs : List α) : Nat :=
  ric (fun h => findBy (full h) (Table.init 0)) (fun h => findBy (name h) (Table.init 0)) hs

/-- `QpackEncoder.insert` refuses an entry that does not fit in the free
space (`size + entry_size > capacity`) instead of evicting.
mirrors flare/qpack/dynamic.mojo#QpackEncoder.insert sha=1e111b96504d at=ea1b9282 (fixed, QPACK-06) -/
def implInsert (esz : α → Nat) (t : Table α) (h : α) : Option (Table α) :=
  if t.size + esz h > t.capacity then none else Flare.L3.Qpack.Table.insert esz t h

theorem ric_none (hs : List α) : ric (fun _ : α => (none : Option Nat)) (fun _ => none) hs = 0 := by
  unfold ric
  suffices ∀ m, hs.foldl (fun m (h : α) => match ((none : Option Nat) <|> none) with
    | some i => max m (i + 1)
    | none => m) m = m from this 0
  intro m
  induction hs generalizing m with
  | nil => rfl
  | cons h hs ih => exact ih m

theorem implRic_zero (full name : α → α → Bool) (hs : List α) : implRic full name hs = 0 :=
  ric_none hs

theorem evictTo_noop (esz : α → Nat) (target : Nat) (t : Table α) (h : t.size ≤ target) :
    evictTo esz target t = t := by
  obtain ⟨es, c, m, s, d⟩ := t
  cases es with
  | nil => rw [evictTo]
  | cons e es =>
    rw [evictTo]
    simp only at h
    rw [if_neg (by omega)]

/-- The insert never evicts: the absolute indices already handed out stay
valid. -/
theorem implInsert_noEvict (esz : α → Nat) (t t' : Table α) (h : α)
    (ht : implInsert esz t h = some t') :
    t'.dropped = t.dropped ∧ t'.entries = t.entries ++ [h] := by
  unfold implInsert at ht
  split at ht
  · cases ht
  · next hle =>
    unfold Flare.L3.Qpack.Table.insert at ht
    rw [if_neg (by omega)] at ht
    rw [evictTo_noop esz _ t (by omega)] at ht
    cases ht
    exact ⟨rfl, rfl⟩

/-- **RFC 9204 §2.1.1, §2.1.2** with Known Received Count 0: the encoder's
RIC never exceeds it (no stream can block), and no insert evicts. -/
theorem encoder_spec (full name : α → α → Bool) (esz : α → Nat) (hs : List α) (t t' : Table α)
    (h : α) (ht : implInsert esz t h = some t') :
    implRic full name hs ≤ 0 ∧ t'.dropped = t.dropped :=
  ⟨Nat.le_of_eq (implRic_zero full name hs), (implInsert_noEvict esz t t' h ht).1⟩

end Flare.L3.Qpack.Encoder
