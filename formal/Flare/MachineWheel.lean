import Flare.Machine
import Flare.L2_Machine.TimerWheel

/-!
# The worker loop on the real timer wheel

`Flare.Machine` uses the timer wheel at the level of its spec: a list of
active timers, `advance now` fires the ones due by `now` (in scheduling
order), `cancel` removes one. `Flare.L2.TimerWheel` models
`flare/runtime/timer_wheel.mojo` itself and proves it meets that spec
(`schedule_spec`, `cancel_spec`, `advance_spec`). This file connects the two.

* `ltsAny`: the worker where every poll may fire the due timers in **any**
  order (the real wheel fires in slot order, not scheduling order).
  `inv_any`, `no_stale_timer_any`: the bookkeeping invariant and the
  no-stale-timer theorem hold for every order. `reachable_le_any`: every
  state of the scheduling-order machine is a state of `ltsAny`.
* `R`: the real wheel's active timers (id, token = fd, fire time) are exactly
  the machine wheel's timers. `R_init`, `R_schedule`, `R_cancel`,
  `R_advance`: every wheel operation the worker performs preserves `R`
  (forward simulation), and `advance` fires exactly the machine timers due
  by `now`, each once.
* `real_wheel_poll`: given `R`, the timers the real wheel fires, in its own
  order, are an allowed firing of `ltsAny`, so that poll preserves `Inv`.

The worker calls `wheel.advance(now)` at every iteration before it schedules
anything (flare/http/_unified_reactor_impl.mojo:1112-1113 and 750-767 @59bda50), so the
wheel's `tick` equals the machine's `now` whenever it schedules;
`R_schedule` takes that as a hypothesis.
-/
namespace Flare.MachineWheel
open Flare.Machine
open Flare.L2

/-! ## Any firing order -/

section AnyOrder
variable {S : Type}

/-- `pollStep` with the fired timers given explicitly, in any order. -/
def pollStepWith (c : Cfg S) (now : Nat) (toks : List Fd) (fired : List Timer) : Cfg S :=
  fireAll true now { c with now := now, batch := toks, wheel := c.wheel.filter (fun t => now < t.due) }
    fired

theorem pollStep_eq_with (c : Cfg S) (now : Nat) (toks : List Fd) :
    pollStep true c now toks = pollStepWith c now toks (c.wheel.filter (fun t => t.due ≤ now)) := rfl

/-- The poll fires exactly the due timers, in some order, none twice. -/
def FiredOk (c : Cfg S) (now : Nat) (fired : List Timer) : Prop :=
  fired.Pairwise (fun a b => a.id ≠ b.id) ∧ ∀ t, t ∈ fired ↔ t ∈ c.wheel ∧ t.due ≤ now

theorem pollStepWith_inv {c : Cfg S} (h : Machine.Inv c) (now : Nat) (toks : List Fd)
    (fired : List Timer) (hf : FiredOk c now fired) :
    Machine.Inv (pollStepWith c now toks fired) := by
  have hmem : ∀ t ∈ fired, t ∈ c.wheel ∧ t.due ≤ now := fun t ht => (hf.2 t).1 ht
  unfold pollStepWith
  apply fireAll_inv
  · refine ⟨?_, ?_, ?_, h.kills⟩
    · intro t ht; exact h.own t (List.mem_filter.1 ht).1
    · intro t ht; exact h.fresh t (List.mem_filter.1 ht).1
    · exact h.nodup.sublist List.filter_sublist
  · intro t ht; exact (hmem t ht).2
  · intro t ht
    obtain ⟨l, a, b, _⟩ := h.own t (hmem t ht).1
    exact ⟨l, a, b⟩
  · exact List.Pairwise.imp_of_mem
      (fun ha hb hab e => hab (h.tok_unique (hmem _ ha).1 (hmem _ hb).1 e)) hf.1

theorem filter_firedOk {c : Cfg S} (h : Machine.Inv c) (now : Nat) :
    FiredOk c now (c.wheel.filter (fun t => t.due ≤ now)) :=
  ⟨h.nodup.sublist List.filter_sublist, fun t => by simp [List.mem_filter]⟩

end AnyOrder

/-- The worker (with flare's cancel-on-cleanup) where each poll fires the due
timers in some order. -/
def stepAny (M : ConnModel) (P : Params) (c : Cfg M.S) (lab : Label M.I) (c' : Cfg M.S) : Prop :=
  match lab with
  | .poll now toks =>
    (c.batch = [] ∧ c.now ≤ now ∧ toks.all (fun k => k = P.listenerTok || (c.conns k).isSome) = true) ∧
      ∃ fired, FiredOk c now fired ∧ c' = pollStepWith c now toks fired
  | .accept fd r => step M P c (.accept fd r) = some c'
  | .acceptDone => step M P c .acceptDone = some c'
  | .dispatch i => step M P c (.dispatch i) = some c'

def ltsAny (M : ConnModel) (P : Params) : LTS (Cfg M.S) (Label M.I) :=
  { init := fun c => c = initCfg, step := stepAny M P }

section AnyLts
variable (M : ConnModel) (P : Params)

/-- **Any firing order keeps the bookkeeping invariant.** -/
theorem inv_any (hP : P.cancelOnCleanup = true) : (ltsAny M P).Inductive Machine.Inv := by
  refine ⟨fun c hc => by subst hc; exact inv_init, fun c lab c' h hs => ?_⟩
  cases lab with
  | poll now toks =>
    obtain ⟨_, fired, hf, rfl⟩ := hs
    exact pollStepWith_inv h now toks fired hf
  | accept fd r => exact inv_step M P hP c c' _ h hs
  | acceptDone => exact inv_step M P hP c c' _ h hs
  | dispatch i => exact inv_step M P hP c c' _ h hs

/-- **No stale timer, whatever order the wheel fires in.** -/
theorem no_stale_timer_any (hP : P.cancelOnCleanup = true) (c : Cfg M.S)
    (hr : (ltsAny M P).Reachable c) : ∀ k ∈ c.kills, k.victim = k.armer :=
  fun k hk => (((inv_any M P hP).reachable c hr).kills k hk).1

/-- A step of the scheduling-order machine from an `Inv` state is a step of
`ltsAny`. -/
theorem lts_le_any (hP : P.cancelOnCleanup = true) (c c' : Cfg M.S) (lab : Label M.I)
    (h : Machine.Inv c) (hs : (lts M P).step c lab c') : (ltsAny M P).step c lab c' := by
  change step M P c lab = some c' at hs
  cases lab with
  | poll now toks =>
    simp only [step] at hs
    split at hs
    · rename_i hg
      cases hs
      exact ⟨hg, _, filter_firedOk h now, by rw [hP]; rfl⟩
    · cases hs
  | accept fd r => exact hs
  | acceptDone => exact hs
  | dispatch i => exact hs

theorem reachable_le_any (hP : P.cancelOnCleanup = true) (c : Cfg M.S)
    (hr : (lts M P).Reachable c) : (ltsAny M P).Reachable c := by
  obtain ⟨c₀, ls, hi, hrun⟩ := hr
  have key : ∀ {a ls b}, Machine.Inv a → (lts M P).Run a ls b → (ltsAny M P).Run a ls b := by
    intro a ls b ha hrun
    induction hrun with
    | nil => exact .nil _
    | cons hs _ ih => exact .cons (lts_le_any M P hP _ _ _ ha hs) (ih (inv_step M P hP _ _ _ ha hs))
  have h0 : Machine.Inv c₀ := by
    have : c₀ = initCfg := hi
    subst this; exact inv_init
  exact ⟨c₀, ls, hi, key h0 hrun⟩

end AnyLts

/-! ## The real wheel simulates the machine's wheel -/

/-- The real wheel's active timers (id, fd token, fire time) are exactly the
machine wheel's timers. -/
def R (s : TimerWheel.TW) (w : List Timer) : Prop :=
  ∀ id tok due, (∃ e, TimerWheel.Act s id e ∧ e.token = tok ∧ e.fireAt = due) ↔
    ∃ t ∈ w, t.id = id ∧ t.tok = tok ∧ t.due = due

theorem R_init (now : Nat) : R (TimerWheel.init now) [] := by
  intro id tok due; simp [TimerWheel.Act, TimerWheel.init]

theorem delayOf_nat (ms : Nat) (h : 1 ≤ ms) : TimerWheel.delayOf (ms : Int) = ms := by
  unfold TimerWheel.delayOf; split <;> omega

/-- `timers[fd] = wheel.schedule(ms, UInt64(fd))` on both sides, with the
wheel advanced to `now` (its `tick`) and the id the real wheel returns. -/
theorem R_schedule {s : TimerWheel.TW} {w : List Timer} (h : TimerWheel.Inv s) (hR : R s w)
    (ms tok g : Nat) (hms : 1 ≤ ms) :
    R (TimerWheel.schedule s ms tok).1
      (w ++ [⟨(TimerWheel.schedule s ms tok).2, tok, s.tick + ms, g⟩]) := by
  have hs := (TimerWheel.schedule_spec h (ms : Int) tok).2.2.2.2
  rw [delayOf_nat ms hms] at hs
  intro id tk due
  constructor
  · rintro ⟨e, ha, rfl, rfl⟩
    rcases (hs id e).1 ha with ha' | ⟨rfl, rfl⟩
    · obtain ⟨t, ht, a, b, c⟩ := (hR id e.token e.fireAt).1 ⟨e, ha', rfl, rfl⟩
      exact ⟨t, List.mem_append_left _ ht, a, b, c⟩
    · exact ⟨_, List.mem_append_right _ (List.mem_singleton_self _), rfl, rfl, rfl⟩
  · rintro ⟨t, ht, rfl, rfl, rfl⟩
    rcases List.mem_append.1 ht with ht | ht
    · obtain ⟨e, ha, a, b⟩ := (hR t.id t.tok t.due).2 ⟨t, ht, rfl, rfl, rfl⟩
      exact ⟨e, (hs t.id e).2 (.inl ha), a, b⟩
    · rw [List.mem_singleton] at ht; subst ht
      exact ⟨_, (hs _ _).2 (.inr ⟨rfl, rfl⟩), rfl, rfl⟩

/-- `wheel.cancel(tid)` on both sides. -/
theorem R_cancel {s : TimerWheel.TW} {w : List Timer} (hR : R s w) (tid : Nat) :
    R (TimerWheel.cancel s tid).1 (w.filter (fun t => t.id ≠ tid)) := by
  have hc := (TimerWheel.cancel_spec s tid).2.1
  intro id tk due
  constructor
  · rintro ⟨e, ha, rfl, rfl⟩
    obtain ⟨ha', hne⟩ := (hc id e).1 ha
    obtain ⟨t, ht, a, b, c⟩ := (hR id e.token e.fireAt).1 ⟨e, ha', rfl, rfl⟩
    exact ⟨t, List.mem_filter.2 ⟨ht, by simp [a, hne]⟩, a, b, c⟩
  · rintro ⟨t, ht, rfl, rfl, rfl⟩
    obtain ⟨ht, hne⟩ := List.mem_filter.1 ht
    obtain ⟨e, ha, a, b⟩ := (hR t.id t.tok t.due).2 ⟨t, ht, rfl, rfl, rfl⟩
    exact ⟨e, (hc t.id e).2 ⟨ha, by simpa using hne⟩, a, b⟩

/-- `wheel.advance(now)` on both sides: what is left corresponds, the fired
ids are distinct and are exactly the machine timers due by `now`. -/
theorem R_advance {s : TimerWheel.TW} {w : List Timer} (h : TimerWheel.Inv s) (hR : R s w)
    (now : Nat) :
    R (TimerWheel.advance s now).1 (w.filter (fun t => now < t.due)) ∧
    (TimerWheel.advance s now).2.Nodup ∧
    (∀ x, x ∈ (TimerWheel.advance s now).2 ↔ ∃ t ∈ w, t.id = x ∧ t.due ≤ now) := by
  have hf := (TimerWheel.advance_spec h now).1
  refine ⟨?_, hf.nodup, ?_⟩
  · intro id tk due
    constructor
    · rintro ⟨e, ha, rfl, rfl⟩
      obtain ⟨ha', hlt⟩ := (hf.left id e).1 ha
      obtain ⟨t, ht, a, b, c⟩ := (hR id e.token e.fireAt).1 ⟨e, ha', rfl, rfl⟩
      exact ⟨t, List.mem_filter.2 ⟨ht, by simp [c, hlt]⟩, a, b, c⟩
    · rintro ⟨t, ht, rfl, rfl, rfl⟩
      obtain ⟨ht, hlt⟩ := List.mem_filter.1 ht
      obtain ⟨e, ha, a, b⟩ := (hR t.id t.tok t.due).2 ⟨t, ht, rfl, rfl, rfl⟩
      exact ⟨e, (hf.left t.id e).2 ⟨ha, by rw [b]; simpa using hlt⟩, a, b⟩
  · intro x
    rw [hf.fired x]
    constructor
    · rintro ⟨e, ha, hle⟩
      obtain ⟨t, ht, a, _, c⟩ := (hR x e.token e.fireAt).1 ⟨e, ha, rfl, rfl⟩
      exact ⟨t, ht, a, by rw [c]; exact hle⟩
    · rintro ⟨t, ht, rfl, hle⟩
      obtain ⟨e, ha, _, b⟩ := (hR t.id t.tok t.due).2 ⟨t, ht, rfl, rfl, rfl⟩
      exact ⟨e, ha, by rw [b]; exact hle⟩

theorem pw_id_unique {w : List Timer} (h : w.Pairwise (fun a b => a.id ≠ b.id)) :
    ∀ {a b : Timer}, a ∈ w → b ∈ w → a.id = b.id → a = b := by
  induction w with
  | nil => intro a b ha; cases ha
  | cons x xs ih =>
    intro a b ha hb hab
    rw [List.pairwise_cons] at h
    rcases List.mem_cons.1 ha with ea | ha'
    · rcases List.mem_cons.1 hb with eb | hb'
      · rw [ea, eb]
      · subst ea; exact absurd hab (h.1 b hb')
    · rcases List.mem_cons.1 hb with eb | hb'
      · subst eb; exact absurd hab.symm (h.1 a ha')
      · exact ih h.2 ha' hb' hab

theorem lift_ids {w : List Timer} :
    ∀ ids : List Nat, (∀ x ∈ ids, ∃ t ∈ w, t.id = x) →
      ∃ fired : List Timer, fired.map (·.id) = ids ∧ ∀ t ∈ fired, t ∈ w
  | [], _ => ⟨[], rfl, fun _ h => by cases h⟩
  | x :: xs, h => by
    obtain ⟨t, ht, rfl⟩ := h x (List.mem_cons_self ..)
    obtain ⟨fs, hm, hs⟩ := lift_ids xs (fun y hy => h y (List.mem_cons_of_mem _ hy))
    refine ⟨t :: fs, by simp [hm], fun u hu => ?_⟩
    rcases List.mem_cons.1 hu with rfl | hu
    · exact ht
    · exact hs u hu

/-- **The real wheel drives a correct poll.** If the real wheel corresponds
to the machine's, the timers it fires at `advance now`, taken in its own
order, are an allowed firing for `ltsAny` (exactly the due timers, none
twice), so the poll preserves `Inv`; and what remains in the real wheel
corresponds to what remains in the machine's. -/
theorem real_wheel_poll {S : Type} {c : Cfg S} (hI : Machine.Inv c) {s : TimerWheel.TW}
    (hT : TimerWheel.Inv s) (hR : R s c.wheel) (now : Nat) (toks : List Fd) :
    ∃ fired : List Timer, fired.map (·.id) = (TimerWheel.advance s now).2 ∧
      FiredOk c now fired ∧ Machine.Inv (pollStepWith c now toks fired) ∧
      R (TimerWheel.advance s now).1 (c.wheel.filter (fun t => now < t.due)) := by
  obtain ⟨hR', hnd, hfired⟩ := R_advance hT hR now
  obtain ⟨fired, hmap, hsub⟩ := lift_ids (w := c.wheel) _ (fun x hx => by
    obtain ⟨t, ht, a, _⟩ := (hfired x).1 hx; exact ⟨t, ht, a⟩)
  have hpw : fired.Pairwise (fun a b => a.id ≠ b.id) := by
    rw [← hmap] at hnd; exact List.pairwise_map.1 hnd
  have hok : FiredOk c now fired := by
    refine ⟨hpw, fun t => ⟨fun ht => ?_, fun ⟨ht, hle⟩ => ?_⟩⟩
    · have hx : t.id ∈ (TimerWheel.advance s now).2 := by
        rw [← hmap]; exact List.mem_map_of_mem ht
      obtain ⟨t', ht', a, b⟩ := (hfired _).1 hx
      have := pw_id_unique hI.nodup ht' (hsub t ht) a
      subst this; exact ⟨ht', b⟩
    · have hx : t.id ∈ (TimerWheel.advance s now).2 := (hfired _).2 ⟨t, ht, rfl, hle⟩
      rw [← hmap] at hx
      obtain ⟨t'', ht'', a⟩ := List.mem_map.1 hx
      have := pw_id_unique hI.nodup (hsub t'' ht'') ht a
      subst this; exact ht''
  exact ⟨fired, hmap, hok, pollStepWith_inv hI now toks fired hok, hR'⟩

end Flare.MachineWheel
