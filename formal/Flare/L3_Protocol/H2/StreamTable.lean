import Flare.L3_Protocol.H2.Conn

/-!
# Stream-table lemmas

`get`/`put`/`erase` over the association list that models `StreamSlab`
(`stream_slab.mojo`): lookups after an update, the active-stream count,
and key uniqueness.
-/
namespace Flare.L3.H2.Conn

theorem find_putL_self (l : List (Nat × Stream)) (k : Nat) (s : Stream) :
    (putL l k s).find? (·.1 == k) = some (k, s) := by
  induction l with
  | nil => simp [putL]
  | cons p t ih =>
    unfold putL
    by_cases h : p.1 = k
    · simp [h]
    · simp [h, ih]

theorem find_putL_other (l : List (Nat × Stream)) (k j : Nat) (s : Stream) (h : j ≠ k) :
    (putL l k s).find? (·.1 == j) = l.find? (·.1 == j) := by
  induction l with
  | nil => simp [putL]; omega
  | cons p t ih =>
    unfold putL
    by_cases hp : p.1 = k
    · simp only [hp, if_true, List.find?_cons]
      have : (k == j) = false := by simp; omega
      simp [this]
    · simp only [hp, if_false, List.find?_cons, ih]

@[simp] theorem get_put_self (c : Conn) (k : Nat) (s : Stream) : get (put c k s) k = some s := by
  simp [get, put, find_putL_self]

theorem get_put_other (c : Conn) (k j : Nat) (s : Stream) (h : j ≠ k) :
    get (put c k s) j = get c j := by
  simp only [get, put]; rw [find_putL_other _ _ _ _ h]

theorem get_put (c : Conn) (k j : Nat) (s : Stream) :
    get (put c k s) j = if j = k then some s else get c j := by
  by_cases h : j = k
  · subst h; simp
  · rw [get_put_other _ _ _ _ h]; simp [h]

@[simp] theorem get_erase_self (c : Conn) (k : Nat) : get (erase c k) k = none := by
  simp only [get, erase]
  rw [Option.map_eq_none_iff, List.find?_eq_none]
  intro x hx; simp [List.mem_filter] at hx; simp; exact hx.2

theorem find_filter_other (l : List (Nat × Stream)) (P : Nat × Stream → Bool) (j : Nat)
    (h : ∀ p ∈ l, p.1 = j → P p = true) :
    (l.filter P).find? (·.1 == j) = l.find? (·.1 == j) := by
  induction l with
  | nil => rfl
  | cons p t ih =>
    have iht := ih (fun q hq => h q (List.mem_cons_of_mem _ hq))
    by_cases hp : P p = true
    · rw [List.filter_cons_of_pos hp]; simp only [List.find?_cons]; split <;> simp_all
    · rw [List.filter_cons_of_neg hp]
      have : p.1 ≠ j := fun e => hp (h p (List.mem_cons_self ..) e)
      simp only [List.find?_cons]
      have : (p.1 == j) = false := by simp; omega
      simp [this, iht]

theorem get_erase_other (c : Conn) (k j : Nat) (h : j ≠ k) : get (erase c k) j = get c j := by
  simp only [get, erase]
  rw [find_filter_other]
  intro p _ hp; simp; omega

theorem mem_iff (c : Conn) (k : Nat) : mem c k = true ↔ ∃ s, get c k = some s := by
  simp [mem, Option.isSome_iff_exists]

theorem mem_false (c : Conn) (k : Nat) : mem c k = false ↔ get c k = none := by
  simp [mem]

/-! ## The active count under `put` (first-occurrence semantics) -/

theorem countP_putL (l : List (Nat × Stream)) (k : Nat) (s : Stream) :
    (putL l k s).countP (fun p => isActive p.2) +
      (match l.find? (·.1 == k) with | some p => if isActive p.2 then 1 else 0 | none => 0) =
    l.countP (fun p => isActive p.2) + (if isActive s then 1 else 0) := by
  induction l with
  | nil => simp [putL]
  | cons p t ih =>
    unfold putL
    by_cases h : p.1 = k
    · simp only [h, if_true, List.countP_cons, List.find?_cons, beq_self_eq_true]
      by_cases ha : isActive p.2 <;> by_cases hs : isActive s <;> simp [ha, hs] <;> omega
    · have hb : (p.1 == k) = false := by simp; omega
      simp only [h, if_false, List.countP_cons, List.find?_cons, hb]
      by_cases ha : isActive p.2 <;> simp [ha] at ih ⊢ <;> omega

/-- The active count after `put c k s`, given the old entry. -/
theorem activeCount_put (c : Conn) (k : Nat) (s : Stream) :
    activeCount (put c k s) + (match get c k with | some o => if isActive o then 1 else 0 | none => 0) =
    activeCount c + (if isActive s then 1 else 0) := by
  have := countP_putL c.streams k s
  simp only [activeCount, put, get]
  cases hf : c.streams.find? (·.1 == k) <;> simp_all

/-! ## Unique keys -/

def NoDupK (l : List (Nat × Stream)) : Prop := (l.map (·.1)).Nodup

theorem putL_keys (l : List (Nat × Stream)) (k : Nat) (s : Stream) :
    ∀ j, j ∈ (putL l k s).map (·.1) ↔ j = k ∨ j ∈ l.map (·.1) := by
  induction l with
  | nil => simp [putL]
  | cons p t ih =>
    intro j
    unfold putL
    by_cases h : p.1 = k
    · simp only [h, if_true, List.map_cons, List.mem_cons]; simp
    · simp only [h, if_false, List.map_cons, List.mem_cons, ih]; exact or_left_comm

theorem nodupK_putL (l : List (Nat × Stream)) (k : Nat) (s : Stream) (h : NoDupK l) :
    NoDupK (putL l k s) := by
  induction l with
  | nil => simp [NoDupK, putL]
  | cons p t ih =>
    unfold NoDupK at h ⊢
    simp only [List.map_cons, List.nodup_cons] at h
    unfold putL
    by_cases hp : p.1 = k
    · simp only [hp, if_true, List.map_cons, List.nodup_cons]; rw [← hp]; exact h
    · simp only [hp, if_false, List.map_cons, List.nodup_cons]
      refine ⟨?_, ih h.2⟩
      rw [putL_keys]; intro hc; rcases hc with hc | hc
      · exact hp hc
      · exact h.1 hc

theorem nodupK_filter (l : List (Nat × Stream)) (P : Nat × Stream → Bool) (h : NoDupK l) :
    NoDupK (l.filter P) := by
  unfold NoDupK at *
  induction l with
  | nil => simp
  | cons p t ih =>
    simp only [List.map_cons, List.nodup_cons] at h
    by_cases hp : P p = true
    · rw [List.filter_cons_of_pos hp]; simp only [List.map_cons, List.nodup_cons]
      refine ⟨fun hm => h.1 ?_, ih h.2⟩
      simp only [List.mem_map, List.mem_filter] at hm ⊢
      obtain ⟨q, ⟨hq, _⟩, he⟩ := hm; exact ⟨q, hq, he⟩
    · rw [List.filter_cons_of_neg hp]; exact ih h.2

theorem find_of_mem_nodup (l : List (Nat × Stream)) (p : Nat × Stream) (h : NoDupK l) (hp : p ∈ l) :
    l.find? (·.1 == p.1) = some p := by
  induction l with
  | nil => cases hp
  | cons q t ih =>
    unfold NoDupK at h; simp only [List.map_cons, List.nodup_cons] at h
    rcases List.mem_cons.mp hp with e | e
    · subst e; simp
    · have hne : q.1 ≠ p.1 := fun hq => h.1 (by rw [hq]; exact List.mem_map_of_mem e)
      have : (q.1 == p.1) = false := by simp; omega
      simp [List.find?_cons, this, ih h.2 e]

/-- The keys of the table. -/
theorem get_some_mem (c : Conn) (k : Nat) (s : Stream) (h : get c k = some s) :
    k ∈ c.streams.map (·.1) := by
  simp only [get, Option.map_eq_some_iff] at h
  obtain ⟨p, hp, rfl⟩ := h
  have hm := List.mem_of_find?_eq_some hp
  have hk := List.find?_some hp
  simp at hk; rw [← hk]; exact List.mem_map_of_mem hm

theorem get_none_of_not_key (c : Conn) (k : Nat) (h : k ∉ c.streams.map (·.1)) : get c k = none := by
  cases hg : get c k with
  | none => rfl
  | some s => exact absurd (get_some_mem c k s hg) h

theorem get_filter (c : Conn) (P : Nat × Stream → Bool) (k : Nat) (h : NoDupK c.streams) :
    get { c with streams := c.streams.filter P } k =
      match get c k with | some s => if P (k, s) then some s else none | none => none := by
  cases hg : get c k with
  | none =>
    show get _ k = none
    simp only [get, Option.map_eq_none_iff, List.find?_eq_none] at hg ⊢
    intro q hq hqk
    exact hg q (List.mem_filter.mp hq).1 hqk
  | some s =>
    have hp : c.streams.find? (·.1 == k) = some (k, s) := by
      simp only [get, Option.map_eq_some_iff] at hg
      obtain ⟨⟨k', s'⟩, hp, he⟩ := hg
      have hk : k' = k := by have := List.find?_some hp; simpa using this
      simp at he; subst hk; subst he; exact hp
    have hm := List.mem_of_find?_eq_some hp
    show get _ k = if P (k, s) then some s else none
    by_cases hP : P (k, s) = true
    · have hm' : (k, s) ∈ c.streams.filter P := List.mem_filter.mpr ⟨hm, hP⟩
      have h2 := find_of_mem_nodup _ (k, s) (nodupK_filter _ P h) hm'
      simp only [get]
      rw [show ((k, s).1) = k from rfl] at h2
      rw [h2]; simp [hP]
    · simp only [hP, Bool.false_eq_true, if_false]
      simp only [get, Option.map_eq_none_iff, List.find?_eq_none]
      intro q hq hqk
      simp only [List.mem_filter] at hq
      have hqk' : q.1 = k := by simpa using hqk
      have h2 := find_of_mem_nodup _ q h hq.1
      rw [hqk', hp] at h2
      cases h2; exact hP hq.2

end Flare.L3.H2.Conn
