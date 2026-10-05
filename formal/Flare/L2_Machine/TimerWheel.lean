import Flare.Core

/-!
# TimerWheel: hashed timing wheel with an overflow list

Model of `flare/runtime/timer_wheel.mojo` (512 slots, 1 ms per slot, an
overflow list promoted once per rotation, lazy cancel, and the `_jump`
fast path for gaps longer than one rotation).

* Times are `Nat`. The Mojo fields are `UInt64`; the two agree as long as
  `tick + after_ms < 2^64`, which holds whenever the clock is below `2^63`
  (`after_ms` is a Mojo `Int`, so at most `2^63 - 1`). Every UInt64
  subtraction in the Mojo code is guarded by a comparison, so `Nat`
  truncated subtraction coincides with it.
* `wheel` and `entries` are functions (`List[List[UInt64]]` indexed
  `0..511`, `Dict[UInt64, _TimerEntry]`). `fired` records timer ids; the
  token reported is the entry's token at that moment (tokens never change
  after `schedule`).
* Spec: an abstract set of active timers (`Act`). `advance now` fires
  exactly the active timers with `fireAt ≤ now`, each once, and removes
  them (`FiresUpTo`, `advance_spec`).
-/
namespace Flare.L2.TimerWheel

/-- `_TimerEntry` (fields `fire_at_ms`, `token`, `active`). -/
structure Entry where
  fireAt : Nat
  token : Nat
  active : Bool
  deriving DecidableEq, Repr

structure TW where
  wheel : Nat → List Nat
  overflow : List Nat
  entries : Nat → Option Entry
  slot : Nat
  tick : Nat
  nextId : Nat

/-- point update of a function (Dict / List slot assignment) -/
def upd {α : Type} (f : Nat → α) (k : Nat) (v : α) : Nat → α :=
  fun x => if x = k then v else f x

@[simp] theorem upd_same {α : Type} (f : Nat → α) (k : Nat) (v : α) : upd f k v k = v := by
  simp [upd]
theorem upd_apply {α : Type} (f : Nat → α) (k : Nat) (v : α) (x : Nat) :
    upd f k v x = if x = k then v else f x := rfl
theorem upd_ne {α : Type} (f : Nat → α) {k x : Nat} (v : α) (h : x ≠ k) : upd f k v x = f x := by
  simp [upd, h]

/-- mirrors flare/runtime/timer_wheel.mojo:102-117 @59bda50 -/
def init (now : Nat) : TW :=
  { wheel := fun _ => [], overflow := [], entries := fun _ => none,
    slot := 0, tick := now, nextId := 0 }

/-- the clamp `delay = after_ms if after_ms >= 1 else 1` -/
def delayOf (after : Int) : Nat := if after ≥ 1 then after.toNat else 1

/-- mirrors flare/runtime/timer_wheel.mojo:119-144 @59bda50 -/
def schedule (s : TW) (after : Int) (token : Nat) : TW × Nat :=
  let id := s.nextId + 1
  let delay := delayOf after
  let fireAt := s.tick + delay
  let entries := upd s.entries id (some ⟨fireAt, token, true⟩)
  if delay < 512 then
    let j := (s.slot + delay) % 512
    ({ s with nextId := id, entries := entries, wheel := upd s.wheel j (s.wheel j ++ [id]) }, id)
  else
    ({ s with nextId := id, entries := entries, overflow := s.overflow ++ [id] }, id)

/-- mirrors flare/runtime/timer_wheel.mojo:146-167 @59bda50 -/
def cancel (s : TW) (id : Nat) : TW × Bool :=
  match s.entries id with
  | some e =>
    if e.active then ({ s with entries := upd s.entries id (some { e with active := false }) }, true)
    else (s, false)
  | none => (s, false)

/-! ## The per-tick drain and the overflow promotion -/

/-- one iteration of the slot drain loop.
mirrors flare/runtime/timer_wheel.mojo:221-227 @59bda50 -/
def drainOne (st : (Nat → Option Entry) × List Nat) (eid : Nat) :
    (Nat → Option Entry) × List Nat :=
  match st.1 eid with
  | some e => (upd st.1 eid none, if e.active then st.2 ++ [eid] else st.2)
  | none => st

/-- Re-bucketing of one live timer `eid` (entry `e`) against tick `T`; the
callers guarantee `T < e.fireAt`.
mirrors flare/runtime/timer_wheel.mojo:248-255 and :287-293 @59bda50 -/
def putB (T slot : Nat) (r : (Nat → List Nat) × List Nat) (eid : Nat) (e : Entry) :
    (Nat → List Nat) × List Nat :=
  if e.fireAt - T < 512 then
    let target := (slot + (e.fireAt - T)) % 512
    (upd r.1 target (r.1 target ++ [eid]), r.2)
  else (r.1, r.2 ++ [eid])

structure TState (σ : Type) where
  entries : Nat → Option Entry
  fired : List Nat
  rest : σ

/-- The per-id decision shared by the overflow-promotion loop and the
classification loop of `_jump`: skip a missing id, drop a cancelled one,
fire a due one, otherwise hand the live entry to `put`.
mirrors flare/runtime/timer_wheel.mojo:238-255 and :274-285 @59bda50 -/
def triage {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (st : TState σ) (eid : Nat) :
    TState σ :=
  match st.entries eid with
  | none => st
  | some e =>
    if e.active = false then { st with entries := upd st.entries eid none }
    else if e.fireAt ≤ T then
      { st with entries := upd st.entries eid none, fired := st.fired ++ [eid] }
    else { st with rest := put st.rest eid e }

/-- One tick: advance the clock FIRST, drain the slot, promote at slot 0.
mirrors flare/runtime/timer_wheel.mojo:208-256 @59bda50 -/
def stepTick (s : TW) : TW × List Nat :=
  let tick := s.tick + 1
  let slot := (s.slot + 1) % 512
  let ids := s.wheel slot
  let wheel := upd s.wheel slot []
  let d := ids.foldl drainOne (s.entries, [])
  if slot = 0 ∧ s.overflow ≠ [] then
    let p := s.overflow.foldl (triage tick (putB tick slot)) ⟨d.1, d.2, (wheel, [])⟩
    ({ s with tick := tick, slot := slot, wheel := p.rest.1, entries := p.entries,
              overflow := p.rest.2 }, p.fired)
  else
    ({ s with tick := tick, slot := slot, wheel := wheel, entries := d.1 }, d.2)

/-- `while self._current_tick_ms < now_ms: ...` runs `now - tick` times. -/
def ticks : Nat → TW → TW × List Nat
  | 0, s => (s, [])
  | n + 1, s =>
    let r1 := stepTick s
    let r2 := ticks n r1.1
    (r2.1, r1.2 ++ r2.2)

/-! ## `_jump` -/

/-- mirrors flare/runtime/timer_wheel.mojo:286-293 @59bda50 -/
def rebucketOne (now slot : Nat) (E : Nat → Option Entry)
    (st : (Nat → List Nat) × List Nat) (eid : Nat) : (Nat → List Nat) × List Nat :=
  match E eid with
  | none => st
  | some e => putB now slot st eid e

/-- ids collected by `_jump`: slots `slot+1 .. slot+512` (mod 512) in that
order, then the overflow list.
mirrors flare/runtime/timer_wheel.mojo:261-271 @59bda50 -/
def jumpIds (s : TW) : List Nat :=
  (List.range 512).flatMap (fun d => s.wheel ((s.slot + (d + 1)) % 512)) ++ s.overflow

/-- the d-loop of `_jump` visits every slot `0..511` (so clearing them
all, as the model does, is faithful) -/
theorem jump_visits_every_slot (slot j : Nat) (hj : j < 512) :
    ∃ d, d < 512 ∧ (slot + (d + 1)) % 512 = j :=
  ⟨(j + 511 * 512 + 511 - slot % 512) % 512, by omega, by omega⟩

/-- mirrors flare/runtime/timer_wheel.mojo:258-293 @59bda50 -/
def jump (s : TW) (now : Nat) : TW × List Nat :=
  let c := (jumpIds s).foldl (triage now (fun (later : List Nat) eid _ => later ++ [eid]))
    ⟨s.entries, [], []⟩
  let r := c.rest.foldl (rebucketOne now s.slot c.entries) (fun _ => [], [])
  ({ s with tick := now, wheel := r.1, overflow := r.2, entries := c.entries }, c.fired)

/-- mirrors flare/runtime/timer_wheel.mojo:169-256 @59bda50 -/
def advance (s : TW) (now : Nat) : TW × List Nat :=
  if now > s.tick ∧ now - s.tick > 512 then jump s now
  else ticks (now - s.tick) s

/-! ## `next_fire_ms` -/

/-- first `d ∈ [d0, d0 + n)` whose slot `(slot + d) & 511` is non-empty -/
def scan (s : TW) : Nat → Nat → Option Nat
  | 0, _ => none
  | n + 1, d => if s.wheel ((s.slot + d) % 512) ≠ [] then some d else scan s n (d + 1)

/-- Pre-fix `next_fire_ms` (flare/runtime/timer_wheel.mojo:310-333 @59bda50), kept for the
RT-01 counterexample: it scans a full rotation and falls back to `tick + 512`
when only overflow timers remain. -/
def nextFireOld (s : TW) : Nat :=
  match scan s 512 1 with
  | some d => s.tick + d
  | none => if s.overflow ≠ [] then s.tick + 512 else s.tick + 0xFFFFFFFF

/-- How far `next_fire_ms` scans, and its fallback when only overflow timers
remain: an overflow timer is promoted (and can fire) at the next slot-0
boundary `tick + (512 - slot)`, so while the overflow list is non-empty the
scan and the fallback stop there. -/
def hintLimit (s : TW) : Nat := if s.overflow ≠ [] then 512 - s.slot else 512

/-- mirrors flare/runtime/timer_wheel.mojo `next_fire_ms` (fixed, RT-01) -/
def nextFire (s : TW) : Nat :=
  match scan s (hintLimit s) 1 with
  | some d => s.tick + d
  | none => if s.overflow ≠ [] then s.tick + hintLimit s else s.tick + 0xFFFFFFFF

/-! ## Invariant -/

/-- `x` is an active timer of `s` with entry `e`. -/
def Act (s : TW) (x : Nat) (e : Entry) : Prop := s.entries x = some e ∧ e.active = true

/-- The wheel invariant. Stale ids (no entry) may sit in lists: the Mojo
loops skip them with `eid in self._entries`, so they are harmless and the
invariant does not need `Nodup`. -/
structure Inv (s : TW) : Prop where
  slot_lt : s.slot < 512
  wheel_ok : ∀ j id, id ∈ s.wheel j → id ≤ s.nextId ∧ ∀ e, s.entries id = some e →
    s.tick < e.fireAt ∧ e.fireAt - s.tick < 512 ∧ j = (s.slot + (e.fireAt - s.tick)) % 512
  ov_ok : ∀ id, id ∈ s.overflow → id ≤ s.nextId ∧ ∀ e, s.entries id = some e →
    s.tick + (512 - s.slot) ≤ e.fireAt
  complete : ∀ id e, s.entries id = some e → (∃ j, id ∈ s.wheel j) ∨ id ∈ s.overflow
  fresh : ∀ id, s.nextId < id → s.entries id = none

theorem inv_init (now : Nat) : Inv (init now) where
  slot_lt := by simp [init]
  wheel_ok := by simp [init]
  ov_ok := by simp [init]
  complete := by simp [init]
  fresh := by simp [init]

/-- every live timer is strictly in the future -/
theorem Inv.fire_gt {s : TW} (h : Inv s) {x : Nat} {e : Entry} (hx : s.entries x = some e) :
    s.tick < e.fireAt := by
  rcases h.complete x e hx with ⟨j, hj⟩ | ho
  · exact ((h.wheel_ok j x hj).2 e hx).1
  · have := (h.ov_ok x ho).2 e hx; have := h.slot_lt; omega

theorem Inv.le_next {s : TW} (h : Inv s) {x : Nat} {e : Entry} (hx : s.entries x = some e) :
    x ≤ s.nextId := by
  rcases Nat.lt_or_ge s.nextId x with hlt | hle
  · rw [h.fresh x hlt] at hx; cases hx
  · exact hle

theorem Act.unique {s : TW} {x : Nat} {e e' : Entry} (h : Act s x e) (h' : Act s x e') : e = e' := by
  have := h.1.symm.trans h'.1; cases this; rfl

/-! ## schedule / cancel -/

theorem delayOf_pos (after : Int) : 1 ≤ delayOf after := by
  unfold delayOf; split <;> omega

/-- entries after `schedule`: the fresh id, or an old entry -/
theorem sched_entries {s : TW} (h : Inv s) (delay token x : Nat) (e : Entry)
    (hx : upd s.entries (s.nextId + 1) (some ⟨s.tick + delay, token, true⟩) x = some e) :
    (x = s.nextId + 1 ∧ e = ⟨s.tick + delay, token, true⟩) ∨ (x ≤ s.nextId ∧ s.entries x = some e) := by
  by_cases hxn : x = s.nextId + 1
  · subst hxn; simp at hx; exact Or.inl ⟨rfl, hx.symm⟩
  · rw [upd_ne _ _ hxn] at hx; exact Or.inr ⟨h.le_next hx, hx⟩

theorem inv_schedule {s : TW} (h : Inv s) (after : Int) (token : Nat) :
    Inv (schedule s after token).1 := by
  have hs := h.slot_lt
  have hdpos := delayOf_pos after
  simp only [schedule]
  generalize delayOf after = delay at hdpos ⊢
  have hE := sched_entries h delay token
  split
  · rename_i hlt
    refine ⟨hs, ?_, ?_, ?_, ?_⟩ <;> dsimp only
    · intro j id hid
      rw [upd_apply] at hid
      split at hid
      · rename_i hj; subst hj
        rcases List.mem_append.1 hid with hid | hid
        · obtain ⟨hle, hw⟩ := h.wheel_ok _ id hid
          refine ⟨by omega, fun e he => ?_⟩
          rcases hE id e he with ⟨rfl, _⟩ | ⟨_, he⟩
          · omega
          · exact hw e he
        · simp only [List.mem_singleton] at hid; subst hid
          refine ⟨Nat.le_refl _, fun e he => ?_⟩
          rcases hE _ e he with ⟨_, rfl⟩ | ⟨h1, _⟩
          · dsimp only; omega
          · omega
      · obtain ⟨hle, hw⟩ := h.wheel_ok j id hid
        refine ⟨by omega, fun e he => ?_⟩
        rcases hE id e he with ⟨rfl, _⟩ | ⟨_, he⟩
        · omega
        · exact hw e he
    · intro id hid
      obtain ⟨hle, hw⟩ := h.ov_ok id hid
      refine ⟨by omega, fun e he => ?_⟩
      rcases hE id e he with ⟨rfl, _⟩ | ⟨_, he⟩
      · omega
      · exact hw e he
    · intro id e he
      rcases hE id e he with ⟨rfl, _⟩ | ⟨_, he⟩
      · exact Or.inl ⟨(s.slot + delay) % 512, by simp⟩
      · rcases h.complete id e he with ⟨j, hj⟩ | ho
        · refine Or.inl ⟨j, ?_⟩
          rw [upd_apply]; split
          · rename_i hj'; subst hj'; exact List.mem_append_left _ hj
          · exact hj
        · exact Or.inr ho
    · intro id hid
      rw [upd_ne _ _ (by omega)]; exact h.fresh id (by omega)
  · rename_i hlt
    refine ⟨hs, ?_, ?_, ?_, ?_⟩ <;> dsimp only
    · intro j id hid
      obtain ⟨hle, hw⟩ := h.wheel_ok j id hid
      refine ⟨by omega, fun e he => ?_⟩
      rcases hE id e he with ⟨rfl, _⟩ | ⟨_, he⟩
      · omega
      · exact hw e he
    · intro id hid
      rcases List.mem_append.1 hid with hid | hid
      · obtain ⟨hle, hw⟩ := h.ov_ok id hid
        refine ⟨by omega, fun e he => ?_⟩
        rcases hE id e he with ⟨rfl, _⟩ | ⟨_, he⟩
        · omega
        · exact hw e he
      · simp only [List.mem_singleton] at hid; subst hid
        refine ⟨Nat.le_refl _, fun e he => ?_⟩
        rcases hE _ e he with ⟨_, rfl⟩ | ⟨h1, _⟩
        · dsimp only; omega
        · omega
    · intro id e he
      rcases hE id e he with ⟨rfl, _⟩ | ⟨_, he⟩
      · exact Or.inr (by simp)
      · rcases h.complete id e he with hj | ho
        · exact Or.inl hj
        · exact Or.inr (List.mem_append_left _ ho)
    · intro id hid
      rw [upd_ne _ _ (by omega)]; exact h.fresh id (by omega)

/-- `schedule` returns a fresh id `≥ 1` (0 is reserved, as documented) and
adds exactly one active timer, due `max after 1` ms after the current tick. -/
theorem schedule_spec {s : TW} (h : Inv s) (after : Int) (token : Nat) :
    let r := schedule s after token
    r.2 = s.nextId + 1 ∧ 1 ≤ r.2 ∧ r.1.nextId = s.nextId + 1 ∧ r.1.tick = s.tick ∧
    (∀ x e, Act r.1 x e ↔ Act s x e ∨ (x = r.2 ∧ e = ⟨s.tick + delayOf after, token, true⟩)) := by
  have hfresh : s.entries (s.nextId + 1) = none := h.fresh _ (by omega)
  simp only [schedule]
  generalize delayOf after = delay
  have key : ∀ t : TW, t.entries = upd s.entries (s.nextId + 1) (some ⟨s.tick + delay, token, true⟩) →
      ∀ x e, Act t x e ↔ Act s x e ∨ (x = s.nextId + 1 ∧ e = ⟨s.tick + delay, token, true⟩) := by
    intro t ht x e
    unfold Act; rw [ht]
    by_cases hx : x = s.nextId + 1
    · subst hx; rw [hfresh, upd_same]; constructor
      · rintro ⟨he, _⟩; exact Or.inr ⟨rfl, (Option.some.inj he).symm⟩
      · rintro (⟨he, _⟩ | ⟨_, rfl⟩); cases he; exact ⟨rfl, rfl⟩
    · rw [upd_ne _ _ hx]; constructor
      · exact Or.inl
      · rintro (h | ⟨h, _⟩); exact h; exact absurd h hx
  split
  · exact ⟨rfl, by omega, rfl, rfl, key _ rfl⟩
  · exact ⟨rfl, by omega, rfl, rfl, key _ rfl⟩

theorem inv_cancel {s : TW} (h : Inv s) (id : Nat) : Inv (cancel s id).1 := by
  unfold cancel
  split
  · rename_i e he
    split
    · -- only the active flag changes; fireAt is kept
      have key : ∀ x e', upd s.entries id (some { e with active := false }) x = some e' →
          ∃ e0, s.entries x = some e0 ∧ e'.fireAt = e0.fireAt := by
        intro x e' hx
        by_cases hxi : x = id
        · subst hxi; rw [upd_same] at hx
          exact ⟨e, he, by rw [← Option.some.inj hx]⟩
        · rw [upd_ne _ _ hxi] at hx; exact ⟨e', hx, rfl⟩
      refine ⟨h.slot_lt, ?_, ?_, ?_, ?_⟩ <;> dsimp only
      · intro j x hx
        refine ⟨(h.wheel_ok j x hx).1, fun e' he' => ?_⟩
        obtain ⟨e0, h0, hf⟩ := key x e' he'
        rw [hf]; exact (h.wheel_ok j x hx).2 e0 h0
      · intro x hx
        refine ⟨(h.ov_ok x hx).1, fun e' he' => ?_⟩
        obtain ⟨e0, h0, hf⟩ := key x e' he'
        rw [hf]; exact (h.ov_ok x hx).2 e0 h0
      · intro x e' he'
        obtain ⟨e0, h0, _⟩ := key x e' he'
        exact h.complete x e0 h0
      · intro x hx
        have hne : x ≠ id := by
          intro hxi; subst hxi; rw [h.fresh x hx] at he; cases he
        rw [upd_ne _ _ hne]; exact h.fresh x hx
    · exact h
  · exact h

/-- `cancel` returns `true` iff the id names an active timer, and afterwards
exactly that timer is no longer active. -/
theorem cancel_spec (s : TW) (id : Nat) :
    ((cancel s id).2 = true ↔ ∃ e, Act s id e) ∧
    (∀ x e, Act (cancel s id).1 x e ↔ Act s x e ∧ x ≠ id) ∧
    (cancel s id).1.tick = s.tick ∧ (cancel s id).1.nextId = s.nextId := by
  unfold cancel Act
  cases he : s.entries id with
  | none =>
    refine ⟨by simp, fun x e => ?_, rfl, rfl⟩
    constructor
    · intro hx; refine ⟨hx, ?_⟩; rintro rfl; rw [he] at hx; cases hx.1
    · exact fun h => h.1
  | some e =>
    simp only
    by_cases ha : e.active = true
    · rw [if_pos ha]
      refine ⟨by simp [ha], fun x e' => ?_, rfl, rfl⟩
      dsimp only
      by_cases hx : x = id
      · subst hx; rw [upd_same]; constructor
        · rintro ⟨h1, h2⟩; cases h1; cases h2
        · rintro ⟨_, h⟩; exact absurd rfl h
      · rw [upd_ne _ _ hx]; simp [hx]
    · rw [if_neg ha]
      refine ⟨by simp [ha], fun x e' => ?_, rfl, rfl⟩
      constructor
      · intro hx; refine ⟨hx, ?_⟩; rintro rfl; rw [he] at hx
        cases hx.1; exact ha hx.2
      · exact fun h => h.1

/-! ## Fold lemmas -/

/-- the fired list after one drain step -/
def drainF (E : Nat → Option Entry) (F : List Nat) (a : Nat) : List Nat :=
  match E a with
  | some e => if e.active then F ++ [a] else F
  | none => F

theorem drainOne_eq (E : Nat → Option Entry) (F : List Nat) (a : Nat) :
    drainOne (E, F) a = (upd E a none, drainF E F a) := by
  simp only [drainOne, drainF]
  cases hEa : E a with
  | none =>
    simp only [Prod.mk.injEq, and_true]
    funext x; by_cases hx : x = a
    · subst hx; rw [upd_same, hEa]
    · rw [upd_ne _ _ hx]
  | some e => rfl

theorem drainF_mem (E : Nat → Option Entry) (F : List Nat) (a x : Nat) :
    x ∈ drainF E F a ↔ x ∈ F ∨ (x = a ∧ ∃ e, E x = some e ∧ e.active = true) := by
  unfold drainF
  cases hEa : E a with
  | none =>
    constructor
    · exact Or.inl
    · rintro (h | ⟨rfl, e, he, _⟩); exact h; rw [hEa] at he; cases he
  | some e =>
    simp only
    cases hact : e.active
    · rw [if_neg (by decide : ¬ (false = true))]; constructor
      · exact Or.inl
      · rintro (h | ⟨rfl, e', he', ha⟩); exact h
        rw [hEa] at he'; cases he'; rw [hact] at ha; cases ha
    · rw [if_pos rfl, List.mem_append, List.mem_singleton]; constructor
      · rintro (h | rfl); exact Or.inl h; exact Or.inr ⟨rfl, e, hEa, hact⟩
      · rintro (h | ⟨rfl, _⟩); exact Or.inl h; exact Or.inr rfl

theorem drainF_nodup (E : Nat → Option Entry) (F : List Nat) (a : Nat)
    (hn : F.Nodup) (hF : ∀ x ∈ F, E x = none) :
    (drainF E F a).Nodup ∧ ∀ x ∈ drainF E F a, upd E a none x = none := by
  have hF' : ∀ x ∈ F, upd E a none x = none := by
    intro x hx; by_cases hxa : x = a
    · subst hxa; exact upd_same _ _ _
    · rw [upd_ne _ _ hxa]; exact hF x hx
  unfold drainF
  cases hEa : E a with
  | none => exact ⟨hn, hF'⟩
  | some e =>
    simp only
    cases e.active
    · exact ⟨hn, hF'⟩
    · rw [if_pos rfl]; refine ⟨?_, ?_⟩
      · rw [List.nodup_append]; refine ⟨hn, by simp, ?_⟩
        intro x hx y hy; simp only [List.mem_singleton] at hy; subst hy
        intro hxa; subst hxa; rw [hF x hx] at hEa; cases hEa
      · intro x hx; rcases List.mem_append.1 hx with hx | hx
        · exact hF' x hx
        · simp only [List.mem_singleton] at hx; subst hx; exact upd_same _ _ _

theorem drain_fold (L : List Nat) : ∀ (E : Nat → Option Entry) (F : List Nat),
    (L.foldl drainOne (E, F)).1 = (fun x => if x ∈ L then none else E x) ∧
    (∀ x, x ∈ (L.foldl drainOne (E, F)).2 ↔ x ∈ F ∨ (x ∈ L ∧ ∃ e, E x = some e ∧ e.active = true)) ∧
    (F.Nodup → (∀ x ∈ F, E x = none) → (L.foldl drainOne (E, F)).2.Nodup) := by
  induction L with
  | nil => intro E F; exact ⟨by simp, by simp, fun h _ => h⟩
  | cons a L ih =>
    intro E F
    rw [List.foldl_cons, drainOne_eq]
    obtain ⟨ih1, ih2, ih3⟩ := ih (upd E a none) (drainF E F a)
    refine ⟨?_, ?_, ?_⟩
    · rw [ih1]; funext x
      by_cases hxa : x = a
      · subst hxa; simp
      · rw [upd_ne _ _ hxa]; simp [hxa]
    · intro x; rw [ih2, drainF_mem]
      by_cases hxa : x = a
      · subst hxa; simp
      · rw [upd_ne _ _ hxa]; simp [hxa]
    · intro hn hF
      obtain ⟨h1, h2⟩ := drainF_nodup E F a hn hF
      exact ih3 h1 h2

/-- live entries kept (handed to `put`) by `triage` -/
def keepF (E : Nat → Option Entry) (T x : Nat) : Option (Nat × Entry) :=
  match E x with
  | some e => if e.active = true ∧ T < e.fireAt then some (x, e) else none
  | none => none

theorem mem_keep (E : Nat → Option Entry) (T : Nat) (L : List Nat) (x : Nat) (e : Entry) :
    (x, e) ∈ L.filterMap (keepF E T) ↔ x ∈ L ∧ E x = some e ∧ e.active = true ∧ T < e.fireAt := by
  rw [List.mem_filterMap]
  constructor
  · rintro ⟨y, hy, hk⟩
    unfold keepF at hk
    split at hk
    · rename_i e' he'
      split at hk
      · rename_i hc
        cases hk; exact ⟨hy, he', hc.1, hc.2⟩
      · cases hk
    · cases hk
  · rintro ⟨hx, he, ha, ht⟩
    exact ⟨x, hx, by simp [keepF, he, ha, ht]⟩

theorem triage_entries {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (st : TState σ)
    (a x : Nat) (e : Entry) :
    (triage T put st a).entries x = some e ↔
      st.entries x = some e ∧ ¬ (x = a ∧ (e.active = false ∨ e.fireAt ≤ T)) := by
  unfold triage
  cases hEa : st.entries a with
  | none =>
    constructor
    · intro hx; refine ⟨hx, ?_⟩; rintro ⟨rfl, _⟩; rw [hEa] at hx; cases hx
    · exact fun h => h.1
  | some ea =>
    simp only
    have rm : (upd st.entries a none x = some e ↔
        st.entries x = some e ∧ ¬ (x = a ∧ (e.active = false ∨ e.fireAt ≤ T))) ↔
        (st.entries x = some e → x = a → ¬ (e.active = false ∨ e.fireAt ≤ T) → False) := by
      by_cases hxa : x = a
      · subst hxa; rw [upd_same]
        constructor
        · intro hiff hx _ hc; exact absurd (hiff.2 ⟨hx, fun h => hc h.2⟩) (by simp)
        · intro hk; constructor
          · intro h; cases h
          · rintro ⟨hx, hc⟩; exact (hk hx rfl (fun h => hc ⟨rfl, h⟩)).elim
      · rw [upd_ne _ _ hxa]; constructor
        · intro _ _ h; exact absurd h hxa
        · intro _; exact ⟨fun h => ⟨h, fun h' => hxa h'.1⟩, fun h => h.1⟩
    by_cases hA : ea.active = false
    · rw [if_pos hA]; dsimp only; rw [rm]
      intro hx hxa hc; subst hxa; rw [hEa] at hx; cases hx; exact hc (Or.inl hA)
    · rw [if_neg hA]
      by_cases hF : ea.fireAt ≤ T
      · rw [if_pos hF]; dsimp only; rw [rm]
        intro hx hxa hc; subst hxa; rw [hEa] at hx; cases hx; exact hc (Or.inr hF)
      · rw [if_neg hF]; dsimp only; constructor
        · intro hx; refine ⟨hx, ?_⟩; rintro ⟨rfl, hc⟩; rw [hEa] at hx; cases hx
          rcases hc with hc | hc; exact hA hc; exact hF hc
        · exact fun h => h.1

theorem triage_fired {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (st : TState σ)
    (a x : Nat) :
    x ∈ (triage T put st a).fired ↔
      x ∈ st.fired ∨ (x = a ∧ ∃ e, st.entries x = some e ∧ e.active = true ∧ e.fireAt ≤ T) := by
  unfold triage
  have no : ∀ ea, st.entries a = some ea → ¬ (ea.active = true ∧ ea.fireAt ≤ T) →
      (x ∈ st.fired ↔ x ∈ st.fired ∨
        (x = a ∧ ∃ e, st.entries x = some e ∧ e.active = true ∧ e.fireAt ≤ T)) := by
    intro ea hEa hc; constructor
    · exact Or.inl
    · rintro (h | ⟨rfl, e, he, h1, h2⟩); exact h
      rw [hEa] at he; cases he; exact absurd ⟨h1, h2⟩ hc
  cases hEa : st.entries a with
  | none =>
    constructor
    · exact Or.inl
    · rintro (h | ⟨rfl, e, he, _⟩); exact h; rw [hEa] at he; cases he
  | some ea =>
    simp only
    by_cases hA : ea.active = false
    · rw [if_pos hA]; dsimp only
      exact no ea hEa (fun h => by rw [hA] at h; cases h.1)
    · rw [if_neg hA]
      by_cases hF : ea.fireAt ≤ T
      · rw [if_pos hF]; dsimp only; rw [List.mem_append, List.mem_singleton]; constructor
        · rintro (h | rfl); exact Or.inl h
          exact Or.inr ⟨rfl, ea, hEa, by simpa using hA, hF⟩
        · rintro (h | ⟨rfl, _⟩); exact Or.inl h; exact Or.inr rfl
      · rw [if_neg hF]; dsimp only
        exact no ea hEa (fun h => hF h.2)

theorem triage_rest {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (st : TState σ) (a : Nat) :
    (triage T put st a).rest =
      (match keepF st.entries T a with
       | some p => put st.rest p.1 p.2
       | none => st.rest) ∧
    keepF (triage T put st a).entries T = keepF st.entries T := by
  unfold triage
  cases hEa : st.entries a with
  | none => simp [keepF, hEa]
  | some ea =>
    simp only
    have rmK : keepF (upd st.entries a none) T = keepF st.entries T →
        keepF st.entries T a = none → True := fun _ _ => trivial
    have rm : (¬ (ea.active = true ∧ T < ea.fireAt)) →
        keepF (upd st.entries a none) T = keepF st.entries T := by
      intro hc; funext x
      by_cases hxa : x = a
      · subst hxa; simp [keepF, hEa, hc]
      · simp only [keepF]; rw [upd_ne _ _ hxa]
    have _ := rmK
    by_cases hA : ea.active = false
    · rw [if_pos hA]; dsimp only
      refine ⟨by simp [keepF, hEa, hA], rm (by simp [hA])⟩
    · rw [if_neg hA]
      have hA' : ea.active = true := by simpa using hA
      by_cases hF : ea.fireAt ≤ T
      · rw [if_pos hF]; dsimp only
        refine ⟨?_, rm (by omega)⟩
        simp [keepF, hEa, hA', show ¬ T < ea.fireAt by omega]
      · rw [if_neg hF]; dsimp only
        refine ⟨?_, rfl⟩
        simp [keepF, hEa, hA', show T < ea.fireAt by omega]

theorem triage_nodup {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (st : TState σ) (a : Nat)
    (hn : st.fired.Nodup) (hF : ∀ x ∈ st.fired, st.entries x = none) :
    (triage T put st a).fired.Nodup ∧
      ∀ x ∈ (triage T put st a).fired, (triage T put st a).entries x = none := by
  have hent : ∀ x, st.entries x = none → (triage T put st a).entries x = none := by
    intro x hx
    cases h' : (triage T put st a).entries x with
    | none => rfl
    | some e => rw [((triage_entries T put st a x e).1 h').1] at hx; cases hx
  refine ⟨?_, fun x hx => ?_⟩
  · unfold triage
    cases hEa : st.entries a with
    | none => exact hn
    | some ea =>
      simp only
      by_cases hA : ea.active = false
      · rw [if_pos hA]; exact hn
      · rw [if_neg hA]
        by_cases hFt : ea.fireAt ≤ T
        · rw [if_pos hFt]; dsimp only
          rw [List.nodup_append]; refine ⟨hn, by simp, ?_⟩
          intro x hx y hy; simp only [List.mem_singleton] at hy; subst hy; intro hxa; subst hxa
          rw [hF x hx] at hEa; cases hEa
        · rw [if_neg hFt]; exact hn
  · rcases (triage_fired T put st a x).1 hx with hx | ⟨rfl, e, he, _, hdue⟩
    · exact hent x (hF x hx)
    · cases h' : (triage T put st x).entries x with
      | none => rfl
      | some e' =>
        have := (triage_entries T put st x x e').1 h'
        rw [he] at this; cases this.1
        exact absurd ⟨rfl, Or.inr hdue⟩ this.2

theorem triage_fold {σ : Type} (T : Nat) (put : σ → Nat → Entry → σ) (L : List Nat) :
    ∀ st : TState σ,
    (∀ x e, (L.foldl (triage T put) st).entries x = some e ↔
        st.entries x = some e ∧ ¬ (x ∈ L ∧ (e.active = false ∨ e.fireAt ≤ T))) ∧
    (∀ x, x ∈ (L.foldl (triage T put) st).fired ↔ x ∈ st.fired ∨
        (x ∈ L ∧ ∃ e, st.entries x = some e ∧ e.active = true ∧ e.fireAt ≤ T)) ∧
    (L.foldl (triage T put) st).rest =
        (L.filterMap (keepF st.entries T)).foldl (fun r p => put r p.1 p.2) st.rest ∧
    (st.fired.Nodup → (∀ x ∈ st.fired, st.entries x = none) →
        (L.foldl (triage T put) st).fired.Nodup) := by
  induction L with
  | nil => intro st; exact ⟨by simp, by simp, rfl, fun h _ => h⟩
  | cons a L ih =>
    intro st
    rw [List.foldl_cons]
    obtain ⟨ih1, ih2, ih3, ih4⟩ := ih (triage T put st a)
    have s1 := triage_entries T put st a
    have s2 := triage_fired T put st a
    obtain ⟨s3, s3k⟩ := triage_rest T put st a
    refine ⟨?_, ?_, ?_, ?_⟩
    · intro x e; rw [ih1, s1]; simp only [List.mem_cons]
      constructor
      · rintro ⟨⟨h1, h2⟩, h3⟩; refine ⟨h1, ?_⟩; rintro ⟨hx | hx, h⟩
        · exact h2 ⟨hx, h⟩
        · exact h3 ⟨hx, h⟩
      · rintro ⟨h1, h2⟩
        exact ⟨⟨h1, fun h => h2 ⟨Or.inl h.1, h.2⟩⟩, fun h => h2 ⟨Or.inr h.1, h.2⟩⟩
    · intro x; rw [ih2, s2]; simp only [List.mem_cons]
      constructor
      · rintro ((h | ⟨rfl, h⟩) | ⟨hxL, e, he, h1, h2⟩)
        · exact Or.inl h
        · exact Or.inr ⟨Or.inl rfl, h⟩
        · exact Or.inr ⟨Or.inr hxL, e, ((s1 x e).1 he).1, h1, h2⟩
      · rintro (h | ⟨hx | hx, e, he, h1, h2⟩)
        · exact Or.inl (Or.inl h)
        · exact Or.inl (Or.inr ⟨hx, e, he, h1, h2⟩)
        · by_cases hxa : x = a
          · exact Or.inl (Or.inr ⟨hxa, e, he, h1, h2⟩)
          · refine Or.inr ⟨hx, e, (s1 x e).2 ⟨he, fun h => hxa h.1⟩, h1, h2⟩
    · rw [ih3, s3k, s3, List.filterMap_cons]
      cases keepF st.entries T a <;> rfl
    · intro hn hF
      obtain ⟨h1, h2⟩ := triage_nodup T put st a hn hF
      exact ih4 h1 h2

/-! ## Bucketing folds -/

theorem putB_fold (T slot : Nat) (P : List (Nat × Entry)) :
    ∀ r : (Nat → List Nat) × List Nat,
    (∀ j x, x ∈ (P.foldl (fun r p => putB T slot r p.1 p.2) r).1 j ↔ x ∈ r.1 j ∨
        ∃ e, (x, e) ∈ P ∧ e.fireAt - T < 512 ∧ j = (slot + (e.fireAt - T)) % 512) ∧
    (∀ x, x ∈ (P.foldl (fun r p => putB T slot r p.1 p.2) r).2 ↔ x ∈ r.2 ∨
        ∃ e, (x, e) ∈ P ∧ 512 ≤ e.fireAt - T) := by
  induction P with
  | nil => intro r; simp
  | cons p P ih =>
    intro r
    rw [List.foldl_cons]
    obtain ⟨ih1, ih2⟩ := ih (putB T slot r p.1 p.2)
    obtain ⟨x0, e0⟩ := p
    dsimp only at ih1 ih2 ⊢
    refine ⟨fun j x => ?_, fun x => ?_⟩
    · rw [ih1]; unfold putB
      by_cases hw : e0.fireAt - T < 512
      · rw [if_pos hw]; dsimp only
        rw [upd_apply]
        by_cases hj : j = (slot + (e0.fireAt - T)) % 512
        · rw [if_pos hj, List.mem_append, List.mem_singleton]; subst hj
          constructor
          · rintro ((h | rfl) | ⟨e, he, h1, h2⟩)
            · exact Or.inl h
            · exact Or.inr ⟨e0, List.mem_cons_self, hw, rfl⟩
            · exact Or.inr ⟨e, List.mem_cons_of_mem _ he, h1, h2⟩
          · rintro (h | ⟨e, he, h1, h2⟩)
            · exact Or.inl (Or.inl h)
            · rcases List.mem_cons.1 he with he | he
              · cases he; exact Or.inl (Or.inr rfl)
              · exact Or.inr ⟨e, he, h1, h2⟩
        · rw [if_neg hj]
          constructor
          · rintro (h | ⟨e, he, h1, h2⟩)
            · exact Or.inl h
            · exact Or.inr ⟨e, List.mem_cons_of_mem _ he, h1, h2⟩
          · rintro (h | ⟨e, he, h1, h2⟩)
            · exact Or.inl h
            · rcases List.mem_cons.1 he with he | he
              · cases he; exact absurd h2 hj
              · exact Or.inr ⟨e, he, h1, h2⟩
      · rw [if_neg hw]; dsimp only
        constructor
        · rintro (h | ⟨e, he, h1, h2⟩)
          · exact Or.inl h
          · exact Or.inr ⟨e, List.mem_cons_of_mem _ he, h1, h2⟩
        · rintro (h | ⟨e, he, h1, h2⟩)
          · exact Or.inl h
          · rcases List.mem_cons.1 he with he | he
            · cases he; exact absurd h1 hw
            · exact Or.inr ⟨e, he, h1, h2⟩
    · rw [ih2]; unfold putB
      by_cases hw : e0.fireAt - T < 512
      · rw [if_pos hw]; dsimp only
        constructor
        · rintro (h | ⟨e, he, h1⟩)
          · exact Or.inl h
          · exact Or.inr ⟨e, List.mem_cons_of_mem _ he, h1⟩
        · rintro (h | ⟨e, he, h1⟩)
          · exact Or.inl h
          · rcases List.mem_cons.1 he with he | he
            · cases he; omega
            · exact Or.inr ⟨e, he, h1⟩
      · rw [if_neg hw]; dsimp only
        rw [List.mem_append, List.mem_singleton]
        constructor
        · rintro ((h | rfl) | ⟨e, he, h1⟩)
          · exact Or.inl h
          · exact Or.inr ⟨e0, List.mem_cons_self, by omega⟩
          · exact Or.inr ⟨e, List.mem_cons_of_mem _ he, h1⟩
        · rintro (h | ⟨e, he, h1⟩)
          · exact Or.inl (Or.inl h)
          · rcases List.mem_cons.1 he with he | he
            · cases he; exact Or.inl (Or.inr rfl)
            · exact Or.inr ⟨e, he, h1⟩

theorem rebucket_eq (now slot : Nat) (E : Nat → Option Entry) (P : List (Nat × Entry))
    (hP : ∀ p ∈ P, E p.1 = some p.2) :
    ∀ r, (P.map Prod.fst).foldl (rebucketOne now slot E) r =
      P.foldl (fun r p => putB now slot r p.1 p.2) r := by
  induction P with
  | nil => intro r; rfl
  | cons p P ih =>
    intro r
    simp only [List.map_cons, List.foldl_cons]
    have hp : rebucketOne now slot E r p.1 = putB now slot r p.1 p.2 := by
      unfold rebucketOne; rw [hP p List.mem_cons_self]
    rw [hp]; exact ih (fun q hq => hP q (List.mem_cons_of_mem _ hq)) _

theorem keep_map_fst (E : Nat → Option Entry) (T : Nat) (L : List Nat) :
    ∀ later : List Nat,
    (L.filterMap (keepF E T)).foldl (fun r p => (fun (later : List Nat) eid (_ : Entry) =>
      later ++ [eid]) r p.1 p.2) later = later ++ (L.filterMap (keepF E T)).map Prod.fst := by
  generalize L.filterMap (keepF E T) = P
  induction P with
  | nil => intro l; simp
  | cons p P ih => intro l; simp only [List.foldl_cons, List.map_cons]; rw [ih]; simp

/-! ## The spec of one `advance`-like step -/

/-- What advancing the clock to `T` must do: the fired list is duplicate-free
and holds exactly the active timers due by `T`; afterwards the active timers
are exactly the old ones not yet due; the invariant is kept. -/
structure FiresUpTo (s : TW) (T : Nat) (r : TW × List Nat) : Prop where
  inv : Inv r.1
  nodup : r.2.Nodup
  fired : ∀ x, x ∈ r.2 ↔ ∃ e, Act s x e ∧ e.fireAt ≤ T
  left : ∀ x e, Act r.1 x e ↔ Act s x e ∧ T < e.fireAt
  nextId : r.1.nextId = s.nextId

theorem FiresUpTo.congr {s : TW} {T T' : Nat} {r : TW × List Nat} (h : FiresUpTo s T r)
    (hT : ∀ x e, Act s x e → (e.fireAt ≤ T ↔ e.fireAt ≤ T')) : FiresUpTo s T' r where
  inv := h.inv
  nodup := h.nodup
  fired x := by
    rw [h.fired]; constructor
    · rintro ⟨e, he, hl⟩; exact ⟨e, he, (hT x e he).1 hl⟩
    · rintro ⟨e, he, hl⟩; exact ⟨e, he, (hT x e he).2 hl⟩
  left x e := by
    rw [h.left]; constructor
    · rintro ⟨he, hl⟩; refine ⟨he, ?_⟩; have := hT x e he; omega
    · rintro ⟨he, hl⟩; refine ⟨he, ?_⟩; have := hT x e he; omega
  nextId := h.nextId

/-! ## One tick -/

/-- an id in the slot about to be drained is due exactly at the next tick -/
theorem Inv.in_next {s : TW} (h : Inv s) {x : Nat} {e : Entry}
    (hx : x ∈ s.wheel ((s.slot + 1) % 512)) (he : s.entries x = some e) :
    e.fireAt = s.tick + 1 := by
  have := (h.wheel_ok _ x hx).2 e he; have := h.slot_lt; omega

/-- a timer due at the next tick sits in the next slot, or in the overflow
list when the next slot is 0 -/
theorem Inv.due_next {s : TW} (h : Inv s) {x : Nat} {e : Entry} (he : s.entries x = some e)
    (hf : e.fireAt = s.tick + 1) :
    x ∈ s.wheel ((s.slot + 1) % 512) ∨ (s.slot = 511 ∧ x ∈ s.overflow) := by
  have hs := h.slot_lt
  rcases h.complete x e he with ⟨j, hj⟩ | ho
  · have := (h.wheel_ok j x hj).2 e he
    left; have : j = (s.slot + 1) % 512 := by omega
    rw [← this]; exact hj
  · have := (h.ov_ok x ho).2 e he; right; exact ⟨by omega, ho⟩

/-- an id in any other slot is one tick closer after the tick -/
theorem Inv.stay {s : TW} (h : Inv s) {x j : Nat} {e : Entry} (hx : x ∈ s.wheel j)
    (hj : j ≠ (s.slot + 1) % 512) (he : s.entries x = some e) :
    s.tick + 1 < e.fireAt ∧ e.fireAt - (s.tick + 1) < 512 ∧
      j = ((s.slot + 1) % 512 + (e.fireAt - (s.tick + 1))) % 512 := by
  have := (h.wheel_ok j x hx).2 e he; have := h.slot_lt; omega

theorem stepTick_spec {s : TW} (h : Inv s) :
    FiresUpTo s (s.tick + 1) (stepTick s) ∧ (stepTick s).1.tick = s.tick + 1 ∧
      (stepTick s).1.slot = (s.slot + 1) % 512 := by
  have hs := h.slot_lt
  obtain ⟨d1, d2, d3⟩ := drain_fold (s.wheel ((s.slot + 1) % 512)) s.entries []
  have d3' := d3 List.nodup_nil (by simp)
  simp only [stepTick]
  generalize List.foldl drainOne (s.entries, []) (s.wheel ((s.slot + 1) % 512)) = D at d1 d2 d3' ⊢
  have hD1 : ∀ x e, D.1 x = some e ↔ x ∉ s.wheel ((s.slot + 1) % 512) ∧ s.entries x = some e := by
    intro x e; rw [d1]; by_cases hx : x ∈ s.wheel ((s.slot + 1) % 512) <;> simp [hx]
  have hD2 : ∀ x, x ∈ D.2 ↔ x ∈ s.wheel ((s.slot + 1) % 512) ∧
      ∃ e, s.entries x = some e ∧ e.active = true := by
    intro x; rw [d2]; simp
  have hD2n : ∀ x ∈ D.2, D.1 x = none := by
    intro x hx; rw [d1]; simp [((hD2 x).1 hx).1]
  -- fired-by-drain ids are exactly the active timers in the drained slot
  have hD2f : ∀ x, x ∈ D.2 → ∃ e, Act s x e ∧ e.fireAt ≤ s.tick + 1 := by
    intro x hx
    obtain ⟨hxi, e, he, ha⟩ := (hD2 x).1 hx
    exact ⟨e, ⟨he, ha⟩, Nat.le_of_eq (h.in_next hxi he)⟩
  split
  · -- promotion at the slot-0 boundary
    rename_i hB
    obtain ⟨hB0, hBne⟩ := hB
    have hs511 : s.slot = 511 := by omega
    obtain ⟨t1, t2, t3, t4⟩ := triage_fold (s.tick + 1) (putB (s.tick + 1) ((s.slot + 1) % 512))
      s.overflow ⟨D.1, D.2, (upd s.wheel ((s.slot + 1) % 512) [], [])⟩
    dsimp only at t1 t2 t3 t4
    have t4' := t4 d3' hD2n
    obtain ⟨p1, p2⟩ := putB_fold (s.tick + 1) ((s.slot + 1) % 512)
      (s.overflow.filterMap (keepF D.1 (s.tick + 1))) (upd s.wheel ((s.slot + 1) % 512) [], [])
    rw [← t3] at p1 p2
    dsimp only at p1 p2
    generalize List.foldl (triage (s.tick + 1) (putB (s.tick + 1) ((s.slot + 1) % 512))) _ s.overflow
      = P at t1 t2 t4' p1 p2 ⊢
    have hK := fun x e => mem_keep D.1 (s.tick + 1) s.overflow x e
    -- entries after the tick
    have hP1 : ∀ x e, P.entries x = some e ↔ (x ∉ s.wheel ((s.slot + 1) % 512) ∧
        s.entries x = some e) ∧ ¬ (x ∈ s.overflow ∧ (e.active = false ∨ e.fireAt ≤ s.tick + 1)) := by
      intro x e; rw [t1, hD1]
    have hW0 : ∀ j x, x ∈ upd s.wheel ((s.slot + 1) % 512) [] j ↔
        j ≠ (s.slot + 1) % 512 ∧ x ∈ s.wheel j := by
      intro j x; rw [upd_apply]; by_cases hj : j = (s.slot + 1) % 512 <;> simp [hj]
    refine ⟨⟨⟨by dsimp only; omega, ?_, ?_, ?_, ?_⟩, t4', ?_, ?_, rfl⟩, rfl, rfl⟩
    · -- wheel_ok
      intro j x hx
      dsimp only at hx ⊢
      rcases (p1 j x).1 hx with hx | ⟨e, hke, hw, hj⟩
      · obtain ⟨hj, hx⟩ := (hW0 j x).1 hx
        refine ⟨(h.wheel_ok j x hx).1, fun e he => ?_⟩
        obtain ⟨⟨_, he⟩, _⟩ := (hP1 x e).1 he
        exact h.stay hx hj he
      · obtain ⟨hxo, hDx, _, hlt⟩ := (hK x e).1 hke
        refine ⟨(h.ov_ok x hxo).1, fun e' he' => ?_⟩
        have := (t1 x e').1 he'
        rw [hDx] at this; cases this.1
        exact ⟨hlt, hw, hj⟩
    · -- ov_ok
      intro x hx
      dsimp only at hx ⊢
      rcases (p2 x).1 hx with hx | ⟨e, hke, hw⟩
      · cases hx
      · obtain ⟨hxo, hDx, _, _⟩ := (hK x e).1 hke
        refine ⟨(h.ov_ok x hxo).1, fun e' he' => ?_⟩
        have := (t1 x e').1 he'
        rw [hDx] at this; cases this.1
        omega
    · -- complete
      intro x e he
      dsimp only at he ⊢
      obtain ⟨⟨hxi, hEx⟩, hnot⟩ := (hP1 x e).1 he
      rcases h.complete x e hEx with ⟨j, hj⟩ | ho
      · have hjne : j ≠ (s.slot + 1) % 512 := by rintro rfl; exact hxi hj
        exact Or.inl ⟨j, (p1 j x).2 (Or.inl ((hW0 j x).2 ⟨hjne, hj⟩))⟩
      · have ha : e.active = true := by
          cases hae : e.active
          · exact absurd ⟨ho, Or.inl hae⟩ hnot
          · rfl
        have hlt : s.tick + 1 < e.fireAt := by
          rcases Nat.lt_or_ge (s.tick + 1) e.fireAt with h1 | h1
          · exact h1
          · exact absurd ⟨ho, Or.inr h1⟩ hnot
        have hke : (x, e) ∈ s.overflow.filterMap (keepF D.1 (s.tick + 1)) :=
          (hK x e).2 ⟨ho, (hD1 x e).2 ⟨hxi, hEx⟩, ha, hlt⟩
        by_cases hw : e.fireAt - (s.tick + 1) < 512
        · exact Or.inl ⟨_, (p1 _ x).2 (Or.inr ⟨e, hke, hw, rfl⟩)⟩
        · exact Or.inr ((p2 x).2 (Or.inr ⟨e, hke, by omega⟩))
    · -- fresh
      intro x hx
      dsimp only at hx ⊢
      cases hPx : P.entries x with
      | none => rfl
      | some e => exact absurd ((hP1 x e).1 hPx).1.2 (by rw [h.fresh x hx]; simp)
    · -- fired
      intro x
      rw [t2]; constructor
      · rintro (hx | ⟨hxo, e, hDx, ha, hle⟩)
        · exact hD2f x hx
        · exact ⟨e, ⟨((hD1 x e).1 hDx).2, ha⟩, hle⟩
      · rintro ⟨e, ⟨he, ha⟩, hle⟩
        have hf : e.fireAt = s.tick + 1 := by have := h.fire_gt he; omega
        by_cases hxi : x ∈ s.wheel ((s.slot + 1) % 512)
        · exact Or.inl ((hD2 x).2 ⟨hxi, e, he, ha⟩)
        · rcases h.due_next he hf with hx' | ⟨_, hxo⟩
          · exact absurd hx' hxi
          · exact Or.inr ⟨hxo, e, (hD1 x e).2 ⟨hxi, he⟩, ha, hle⟩
    · -- left
      intro x e
      unfold Act; dsimp only
      rw [hP1]; constructor
      · rintro ⟨⟨⟨hxi, he⟩, hnot⟩, ha⟩
        refine ⟨⟨he, ha⟩, ?_⟩
        rcases Nat.lt_or_ge (s.tick + 1) e.fireAt with h1 | h1
        · exact h1
        · have hf : e.fireAt = s.tick + 1 := by have := h.fire_gt he; omega
          rcases h.due_next he hf with hx' | ⟨_, hxo⟩
          · exact absurd hx' hxi
          · exact absurd ⟨hxo, Or.inr h1⟩ hnot
      · rintro ⟨⟨he, ha⟩, hlt⟩
        have hxi : x ∉ s.wheel ((s.slot + 1) % 512) := fun hx => by
          have := h.in_next hx he; omega
        refine ⟨⟨⟨hxi, he⟩, ?_⟩, ha⟩
        rintro ⟨_, hc | hc⟩
        · rw [ha] at hc; cases hc
        · omega
  · -- no promotion
    rename_i hA
    refine ⟨⟨⟨by dsimp only; omega, ?_, ?_, ?_, ?_⟩, d3', ?_, ?_, rfl⟩, rfl, rfl⟩
    · intro j x hx
      dsimp only at hx ⊢
      rw [upd_apply] at hx
      by_cases hj : j = (s.slot + 1) % 512
      · rw [if_pos hj] at hx; cases hx
      · rw [if_neg hj] at hx
        refine ⟨(h.wheel_ok j x hx).1, fun e he => ?_⟩
        exact h.stay hx hj ((hD1 x e).1 he).2
    · intro x hx
      dsimp only at hx ⊢
      refine ⟨(h.ov_ok x hx).1, fun e he => ?_⟩
      have := (h.ov_ok x hx).2 e ((hD1 x e).1 he).2
      have hne : (s.slot + 1) % 512 ≠ 0 := fun h0 => hA ⟨h0, List.ne_nil_of_mem hx⟩
      omega
    · intro x e he
      dsimp only at he ⊢
      obtain ⟨hxi, hEx⟩ := (hD1 x e).1 he
      rcases h.complete x e hEx with ⟨j, hj⟩ | ho
      · have hjne : j ≠ (s.slot + 1) % 512 := by rintro rfl; exact hxi hj
        exact Or.inl ⟨j, by rw [upd_ne _ _ hjne]; exact hj⟩
      · exact Or.inr ho
    · intro x hx
      dsimp only
      rw [d1]; simp [h.fresh x hx]
    · intro x; constructor
      · exact hD2f x
      · rintro ⟨e, ⟨he, ha⟩, hle⟩
        have hf : e.fireAt = s.tick + 1 := by have := h.fire_gt he; omega
        rcases h.due_next he hf with hx' | ⟨h511, hxo⟩
        · exact (hD2 x).2 ⟨hx', e, he, ha⟩
        · exact absurd ⟨by omega, List.ne_nil_of_mem hxo⟩ hA
    · intro x e
      unfold Act; dsimp only
      rw [hD1]; constructor
      · rintro ⟨⟨hxi, he⟩, ha⟩
        refine ⟨⟨he, ha⟩, ?_⟩
        rcases Nat.lt_or_ge (s.tick + 1) e.fireAt with h1 | h1
        · exact h1
        · have hf : e.fireAt = s.tick + 1 := by have := h.fire_gt he; omega
          rcases h.due_next he hf with hx' | ⟨h511, hxo⟩
          · exact absurd hx' hxi
          · exact absurd ⟨by omega, List.ne_nil_of_mem hxo⟩ hA
      · rintro ⟨⟨he, ha⟩, hlt⟩
        have hxi : x ∉ s.wheel ((s.slot + 1) % 512) := fun hx => by
          have := h.in_next hx he; omega
        exact ⟨⟨hxi, he⟩, ha⟩

/-- In tick mode every active timer fires in exactly the tick that reaches
its `fireAt`: no early fire and no late fire, at single-tick resolution. -/
theorem stepTick_fires_exactly {s : TW} (h : Inv s) {x : Nat} {e : Entry} (hx : Act s x e) :
    x ∈ (stepTick s).2 ↔ e.fireAt = s.tick + 1 := by
  rw [(stepTick_spec h).1.fired]
  have := h.fire_gt hx.1
  constructor
  · rintro ⟨e', he', hle⟩; rw [Act.unique hx he'] at this ⊢; omega
  · intro hf; exact ⟨e, hx, by omega⟩

/-! ## Many ticks -/

theorem ticks_spec : ∀ (n : Nat) {s : TW}, Inv s →
    FiresUpTo s (s.tick + n) (ticks n s) ∧ (ticks n s).1.tick = s.tick + n
  | 0, s, h => by
    refine ⟨⟨h, List.nodup_nil, fun x => ?_, fun x e => ?_, rfl⟩, rfl⟩
    · simp only [ticks, List.not_mem_nil, false_iff]
      rintro ⟨e, he, hle⟩; have := h.fire_gt he.1; omega
    · simp only [ticks, Nat.add_zero]
      constructor
      · intro he; exact ⟨he, h.fire_gt he.1⟩
      · exact fun h => h.1
  | n + 1, s, h => by
    obtain ⟨S1, hT1, _⟩ := stepTick_spec h
    obtain ⟨S2, hT2⟩ := ticks_spec n S1.inv
    rw [hT1] at S2 hT2
    simp only [ticks]
    refine ⟨⟨S2.inv, ?_, fun x => ?_, fun x e => ?_, ?_⟩, by rw [hT2]; omega⟩
    · rw [List.nodup_append]
      refine ⟨S1.nodup, S2.nodup, fun a ha b hb hab => ?_⟩
      subst hab
      obtain ⟨e1, he1, hle1⟩ := (S1.fired a).1 ha
      obtain ⟨e2, he2, _⟩ := (S2.fired a).1 hb
      obtain ⟨he2', hlt2⟩ := (S1.left a e2).1 he2
      rw [Act.unique he1 he2'] at hle1; omega
    · rw [List.mem_append, S1.fired, S2.fired]
      constructor
      · rintro (⟨e, he, hle⟩ | ⟨e, he, hle⟩)
        · exact ⟨e, he, by omega⟩
        · exact ⟨e, ((S1.left x e).1 he).1, by omega⟩
      · rintro ⟨e, he, hle⟩
        by_cases h1 : e.fireAt ≤ s.tick + 1
        · exact Or.inl ⟨e, he, h1⟩
        · exact Or.inr ⟨e, (S1.left x e).2 ⟨he, by omega⟩, by omega⟩
    · rw [S2.left, S1.left]; constructor
      · rintro ⟨⟨he, _⟩, h2⟩; exact ⟨he, by omega⟩
      · rintro ⟨he, h2⟩; exact ⟨⟨he, by omega⟩, by omega⟩
    · rw [S2.nextId, S1.nextId]

/-! ## `_jump` -/

theorem mem_jumpIds_of_entry {s : TW} (h : Inv s) {x : Nat} {e : Entry}
    (he : s.entries x = some e) : x ∈ jumpIds s := by
  unfold jumpIds
  rw [List.mem_append, List.mem_flatMap]
  rcases h.complete x e he with ⟨j, hj⟩ | ho
  · left
    have hj512 : j < 512 := by have := (h.wheel_ok j x hj).2 e he; omega
    obtain ⟨d, hd, hdj⟩ := jump_visits_every_slot s.slot j hj512
    exact ⟨d, List.mem_range.2 hd, by rw [hdj]; exact hj⟩
  · exact Or.inr ho

theorem le_next_of_mem_jumpIds {s : TW} (h : Inv s) {x : Nat} (hx : x ∈ jumpIds s) :
    x ≤ s.nextId := by
  unfold jumpIds at hx
  rw [List.mem_append, List.mem_flatMap] at hx
  rcases hx with ⟨d, _, hd⟩ | ho
  · exact (h.wheel_ok _ x hd).1
  · exact (h.ov_ok x ho).1

theorem jump_spec {s : TW} (h : Inv s) (now : Nat) :
    FiresUpTo s now (jump s now) ∧ (jump s now).1.tick = now ∧ (jump s now).1.slot = s.slot := by
  obtain ⟨c1, c2, c3, c4⟩ := triage_fold now (fun (later : List Nat) eid (_ : Entry) => later ++ [eid])
    (jumpIds s) ⟨s.entries, [], []⟩
  dsimp only at c1 c2 c3 c4
  rw [keep_map_fst, List.nil_append] at c3
  have c4' := c4 List.nodup_nil (by simp)
  have hK := fun x e => mem_keep s.entries now (jumpIds s) x e
  simp only [jump]
  generalize List.foldl (triage now fun later eid _ => later ++ [eid]) ⟨s.entries, [], []⟩ (jumpIds s)
    = C at c1 c2 c3 c4' ⊢
  rw [c3, rebucket_eq now s.slot C.entries _ (fun p hp => by
    obtain ⟨hx, he, ha, hlt⟩ := (hK p.1 p.2).1 hp
    exact (c1 p.1 p.2).2 ⟨he, fun ⟨_, hc⟩ => by rcases hc with hc | hc <;> simp_all; omega⟩)]
  obtain ⟨q1, q2⟩ := putB_fold now s.slot ((jumpIds s).filterMap (keepF s.entries now))
    (fun _ => [], [])
  dsimp only at q1 q2
  generalize List.foldl (fun r p => putB now s.slot r p.1 p.2) (fun _ => [], [])
    ((jumpIds s).filterMap (keepF s.entries now)) = R at q1 q2 ⊢
  refine ⟨⟨⟨h.slot_lt, ?_, ?_, ?_, ?_⟩, c4', ?_, ?_, by trivial⟩, by trivial, by trivial⟩
  · intro j x hx
    dsimp only at hx ⊢
    rcases (q1 j x).1 hx with hx | ⟨e, hke, hw, hj⟩
    · cases hx
    · obtain ⟨hxL, hEx, _, hlt⟩ := (hK x e).1 hke
      refine ⟨le_next_of_mem_jumpIds h hxL, fun e' he' => ?_⟩
      have := (c1 x e').1 he'
      rw [hEx] at this; cases this.1
      exact ⟨hlt, hw, hj⟩
  · intro x hx
    dsimp only at hx ⊢
    rcases (q2 x).1 hx with hx | ⟨e, hke, hw⟩
    · cases hx
    · obtain ⟨hxL, hEx, _, hlt⟩ := (hK x e).1 hke
      refine ⟨le_next_of_mem_jumpIds h hxL, fun e' he' => ?_⟩
      have := (c1 x e').1 he'
      rw [hEx] at this; cases this.1
      omega
  · intro x e he
    dsimp only at he ⊢
    obtain ⟨hEx, hnot⟩ := (c1 x e).1 he
    have hxL := mem_jumpIds_of_entry h hEx
    have ha : e.active = true := by
      cases hae : e.active
      · exact absurd ⟨hxL, Or.inl hae⟩ hnot
      · rfl
    have hlt : now < e.fireAt := by
      rcases Nat.lt_or_ge now e.fireAt with h1 | h1
      · exact h1
      · exact absurd ⟨hxL, Or.inr h1⟩ hnot
    have hke := (hK x e).2 ⟨hxL, hEx, ha, hlt⟩
    by_cases hw : e.fireAt - now < 512
    · exact Or.inl ⟨_, (q1 _ x).2 (Or.inr ⟨e, hke, hw, rfl⟩)⟩
    · exact Or.inr ((q2 x).2 (Or.inr ⟨e, hke, by omega⟩))
  · intro x hx
    dsimp only
    cases hCx : C.entries x with
    | none => rfl
    | some e => have := ((c1 x e).1 hCx).1; rw [h.fresh x hx] at this; cases this
  · intro x
    rw [c2]; constructor
    · rintro (hx | ⟨_, e, he, ha, hle⟩)
      · cases hx
      · exact ⟨e, ⟨he, ha⟩, hle⟩
    · rintro ⟨e, ⟨he, ha⟩, hle⟩
      exact Or.inr ⟨mem_jumpIds_of_entry h he, e, he, ha, hle⟩
  · intro x e
    unfold Act; dsimp only
    rw [c1]; constructor
    · rintro ⟨⟨he, hnot⟩, ha⟩
      refine ⟨⟨he, ha⟩, ?_⟩
      rcases Nat.lt_or_ge now e.fireAt with h1 | h1
      · exact h1
      · exact absurd ⟨mem_jumpIds_of_entry h he, Or.inr h1⟩ hnot
    · rintro ⟨⟨he, ha⟩, hlt⟩
      refine ⟨⟨he, ?_⟩, ha⟩
      rintro ⟨_, hc | hc⟩
      · rw [ha] at hc; cases hc
      · omega

/-! ## `advance`: the headline theorems -/

/-- **Refinement of `advance`.** From any state satisfying the invariant,
`advance now` fires exactly the active timers with `fireAt ≤ now`, each
once, leaves exactly the later ones active, and moves the clock to
`max tick now`. -/
theorem advance_spec {s : TW} (h : Inv s) (now : Nat) :
    FiresUpTo s now (advance s now) ∧ (advance s now).1.tick = max s.tick now := by
  unfold advance
  split
  · rename_i hj
    obtain ⟨hs, ht, _⟩ := jump_spec h now
    exact ⟨hs, by rw [ht]; omega⟩
  · obtain ⟨hs, ht⟩ := ticks_spec (now - s.tick) h
    refine ⟨hs.congr fun x e he => ?_, by rw [ht]; omega⟩
    have := h.fire_gt he.1; omega

/-- No early fire: everything `advance now` reports was an active timer due
by `now`. -/
theorem advance_no_early_fire {s : TW} (h : Inv s) (now x : Nat) (hx : x ∈ (advance s now).2) :
    ∃ e, Act s x e ∧ e.fireAt ≤ now :=
  ((advance_spec h now).1.fired x).1 hx

/-- No late fire: every active timer due by `now` is reported by
`advance now`, and no active timer due by `now` survives it. -/
theorem advance_no_late_fire {s : TW} (h : Inv s) (now x : Nat) (e : Entry) :
    (Act s x e → e.fireAt ≤ now → x ∈ (advance s now).2) ∧
    (Act (advance s now).1 x e → now < e.fireAt) :=
  ⟨fun ha hle => ((advance_spec h now).1.fired x).2 ⟨e, ha, hle⟩,
   fun ha => (((advance_spec h now).1.left x e).1 ha).2⟩

/-- A backwards (or equal) `now` is a no-op. -/
theorem advance_backwards_noop (s : TW) (now : Nat) (hn : now ≤ s.tick) :
    advance s now = (s, []) := by
  unfold advance
  rw [if_neg (by omega), show now - s.tick = 0 by omega]; rfl

/-- **`_jump` is equivalent to ticking**: for a gap of any length the jump
fires the same timers (as a set; the order differs only as documented),
leaves the same active timers, and ends at the same clock. -/
theorem jump_equiv_ticks {s : TW} (h : Inv s) (now : Nat) (hn : s.tick ≤ now) :
    (jump s now).2.Perm (ticks (now - s.tick) s).2 ∧
    (∀ x e, Act (jump s now).1 x e ↔ Act (ticks (now - s.tick) s).1 x e) ∧
    (jump s now).1.tick = (ticks (now - s.tick) s).1.tick ∧
    (jump s now).1.nextId = (ticks (now - s.tick) s).1.nextId := by
  obtain ⟨J, hJt, _⟩ := jump_spec h now
  obtain ⟨T, hTt⟩ := ticks_spec (now - s.tick) h
  rw [show s.tick + (now - s.tick) = now by omega] at T hTt
  refine ⟨(List.perm_ext_iff_of_nodup J.nodup T.nodup).2 fun x => by rw [J.fired, T.fired],
    fun x e => by rw [J.left, T.left], by rw [hJt, hTt], by rw [J.nextId, T.nextId]⟩

/-! ## Traces: cancel never fires, each timer fires at most once -/

inductive Op where
  | schedule (after : Int) (token : Nat)
  | cancel (id : Nat)
  | advance (now : Nat)

def exec (s : TW) : Op → TW × List Nat
  | .schedule a t => ((schedule s a t).1, [])
  | .cancel id => ((cancel s id).1, [])
  | .advance now => advance s now

def run : TW → List Op → TW × List Nat
  | s, [] => (s, [])
  | s, o :: os =>
    let r := exec s o
    let r' := run r.1 os
    (r'.1, r.2 ++ r'.2)

theorem inv_exec {s : TW} (h : Inv s) (o : Op) : Inv (exec s o).1 := by
  cases o with
  | schedule a t => exact inv_schedule h a t
  | cancel id => exact inv_cancel h id
  | advance now => exact (advance_spec h now).1.inv

/-- Every state reachable from `init` satisfies the invariant. -/
theorem inv_run : ∀ (os : List Op) {s : TW}, Inv s → Inv (run s os).1
  | [], _, h => h
  | _ :: os, _, h => inv_run os (inv_exec h _)

/-- One op never re-activates an inactive, already-issued id, and only
active ids fire. -/
theorem exec_act {s : TW} (h : Inv s) (o : Op) :
    (exec s o).1.nextId ≥ s.nextId ∧
    (∀ x e, x ≤ s.nextId → Act (exec s o).1 x e → Act s x e) ∧
    (∀ x, x ∈ (exec s o).2 → (∃ e, Act s x e) ∧ ∀ e, ¬ Act (exec s o).1 x e) := by
  cases o with
  | schedule a t =>
    obtain ⟨hid, _, hn, _, hA⟩ := schedule_spec h a t
    refine ⟨by simp only [exec]; omega, fun x e hx ha => ?_, fun x hx => by cases hx⟩
    rcases (hA x e).1 ha with ha | ⟨rfl, _⟩
    · exact ha
    · omega
  | cancel id =>
    obtain ⟨_, hA, _, hn⟩ := cancel_spec s id
    exact ⟨by simp only [exec]; omega, fun x e _ ha => ((hA x e).1 ha).1, fun x hx => by cases hx⟩
  | advance now =>
    have S := (advance_spec h now).1
    refine ⟨by simp only [exec]; rw [S.nextId]; omega, fun x e _ ha => ((S.left x e).1 ha).1,
      fun x hx => ?_⟩
    obtain ⟨e, he, hle⟩ := (S.fired x).1 hx
    refine ⟨⟨e, he⟩, fun e' he' => ?_⟩
    obtain ⟨he'', hlt⟩ := (S.left x e').1 he'
    rw [Act.unique he he''] at hle; omega

/-- An issued id that is not active never fires again, whatever happens
next. -/
theorem never_fires : ∀ (os : List Op) {s : TW} {x : Nat}, Inv s → x ≤ s.nextId →
    (∀ e, ¬ Act s x e) → x ∉ (run s os).2
  | [], _, _, _, _, _ => List.not_mem_nil
  | o :: os, s, x, h, hx, hna => by
    obtain ⟨hn, hA, hF⟩ := exec_act h o
    simp only [run, List.mem_append, not_or]
    refine ⟨fun hf => ?_, never_fires os (inv_exec h o) (by omega) fun e he => hna e (hA x e hx he)⟩
    obtain ⟨⟨e, he⟩, _⟩ := hF x hf
    exact hna e he

/-- **Cancel never fires**: after `cancel id` of an issued id, that id is
never reported by any later sequence of operations. -/
theorem cancel_never_fires {s : TW} (h : Inv s) (id : Nat) (hid : id ≤ s.nextId) (os : List Op) :
    id ∉ (run (cancel s id).1 os).2 := by
  obtain ⟨_, hA, _, hn⟩ := cancel_spec s id
  exact never_fires os (inv_cancel h id) (by rw [hn]; exact hid)
    fun e he => ((hA id e).1 he).2 rfl

/-- **Each timer fires at most once** over any trace. -/
theorem run_nodup : ∀ (os : List Op) {s : TW}, Inv s → (run s os).2.Nodup
  | [], _, _ => List.nodup_nil
  | o :: os, s, h => by
    simp only [run]
    rw [List.nodup_append]
    obtain ⟨hn, _, hF⟩ := exec_act h o
    refine ⟨?_, run_nodup os (inv_exec h o), fun a ha b hb hab => ?_⟩
    · cases o with
      | schedule => exact List.nodup_nil
      | cancel => exact List.nodup_nil
      | advance now => exact (advance_spec h now).1.nodup
    · subst hab
      obtain ⟨⟨e, he⟩, hna⟩ := hF a ha
      exact never_fires os (inv_exec h o) (by have := h.le_next he.1; omega) hna hb

/-! ## `next_fire_ms` -/

theorem scan_some (s : TW) : ∀ n d d', scan s n d = some d' →
    d ≤ d' ∧ d' < d + n ∧ s.wheel ((s.slot + d') % 512) ≠ []
  | 0, _, _, h => by cases h
  | n + 1, d, d', h => by
    simp only [scan] at h
    split at h
    · cases h; exact ⟨Nat.le_refl _, by omega, by assumption⟩
    · obtain ⟨h1, h2, h3⟩ := scan_some s n (d + 1) d' h; exact ⟨by omega, by omega, h3⟩

theorem scan_finds (s : TW) (k : Nat) (hk : s.wheel ((s.slot + k) % 512) ≠ []) :
    ∀ n d, d ≤ k → k < d + n → ∃ d', scan s n d = some d' ∧ d' ≤ k
  | 0, _, _, h => by omega
  | n + 1, d, h1, h2 => by
    simp only [scan]
    split
    · exact ⟨d, rfl, h1⟩
    · rename_i hne
      have hdk : d ≠ k := by rintro rfl; exact hne hk
      exact scan_finds s k hk n (d + 1) (by omega) (by omega)

/-- the shipped hint is a lower bound on every pending fire time -/
theorem nextFire_lower_bound {s : TW} (h : Inv s) {x : Nat} {e : Entry} (hx : Act s x e) :
    nextFire s ≤ e.fireAt := by
  have hs := h.slot_lt
  by_cases hov : s.overflow ≠ []
  · have hl : hintLimit s = 512 - s.slot := by simp [hintLimit, hov]
    have hbound : nextFire s ≤ s.tick + (512 - s.slot) := by
      unfold nextFire
      rw [hl]
      cases hh : scan s (512 - s.slot) 1 with
      | some d => have := (scan_some s _ 1 d hh).2.1; simp; omega
      | none => simp [hov]
    rcases h.complete x e hx.1 with ⟨j, hj⟩ | ho
    · obtain ⟨hlt, hd, hjd⟩ := (h.wheel_ok j x hj).2 e hx.1
      by_cases hk : e.fireAt - s.tick ≤ 512 - s.slot
      · have hne : s.wheel ((s.slot + (e.fireAt - s.tick)) % 512) ≠ [] := by
          rw [← hjd]; exact List.ne_nil_of_mem hj
        obtain ⟨d', hs', hle⟩ := scan_finds s _ hne (512 - s.slot) 1 (by omega) (by omega)
        unfold nextFire
        rw [hl, hs']
        simp only
        omega
      · omega
    · have := (h.ov_ok x ho).2 e hx.1
      omega
  · have hov' : s.overflow = [] := by simpa using hov
    have hl : hintLimit s = 512 := by simp [hintLimit, hov']
    rcases h.complete x e hx.1 with ⟨j, hj⟩ | ho
    · obtain ⟨hlt, hd, hjd⟩ := (h.wheel_ok j x hj).2 e hx.1
      have hne : s.wheel ((s.slot + (e.fireAt - s.tick)) % 512) ≠ [] := by
        rw [← hjd]; exact List.ne_nil_of_mem hj
      obtain ⟨d', hs', hle⟩ := scan_finds s _ hne 512 1 (by omega) (by omega)
      unfold nextFire
      rw [hl, hs']
      simp only
      omega
    · rw [hov'] at ho; cases ho

/-- with an empty overflow list the shipped hint is the pre-fix one -/
theorem nextFire_eq_old_no_overflow (s : TW) (hov : s.overflow = []) : nextFire s = nextFireOld s := by
  have hl : hintLimit s = 512 := by simp [hintLimit, hov]
  unfold nextFire nextFireOld
  rw [hl, hov]

/-- with an empty overflow list the pre-fix hint is already a lower bound;
RT-01 needs a non-empty overflow list -/
theorem nextFireOld_lower_bound_no_overflow {s : TW} (h : Inv s) (hov : s.overflow = [])
    {x : Nat} {e : Entry} (hx : Act s x e) : nextFireOld s ≤ e.fireAt := by
  rw [← nextFire_eq_old_no_overflow s hov]
  exact nextFire_lower_bound h hx

end Flare.L2.TimerWheel
