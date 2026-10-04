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

/-- mirrors flare/qpack/dynamic.mojo:160-168 (`find`) and 170-175
(`find_name`) @59bda50; `none` is -1 -/
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

/-- mirrors flare/qpack/dynamic.mojo:418-430 @59bda50 -/
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

end Flare.L3.Qpack.Encoder
