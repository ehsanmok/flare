import Flare.Machine

/-!
# Several reactor workers in one process, and progress of one worker

`HttpServer.serve` with `num_workers > 1` runs one `Flare.Machine` worker per
thread (flare/runtime/scheduler.mojo, `Scheduler.start`). With
`SO_REUSEPORT` each worker has its own listener; the kernel hands each new
connection to exactly one of them. All workers share the process's fd table,
so `accept` in any worker returns an fd that is open nowhere else: not a
live connection of any worker and not any worker's listener.

`Sys` is the interleaving of `n` workers under that one global constraint.

* `sys_component_reachable`: every worker of a reachable system is a
  reachable single-worker machine, so every single-worker theorem holds per
  worker (`sys_no_stale_timer`, `sys_conn_invariant_lifts`, `sys_routing_ok`).
* `sys_disjoint`: no fd is a live connection of two workers at once, so a
  close in one worker can never act on another worker's connection.
* `no_deadlock`, `batch_progress`: a worker always has an enabled step, and
  every step that handles a harvested token shortens the batch, so every
  token `poll` returned is handled before the next `poll`
  (`poll_needs_empty_batch`).

The shared-listener mode (`register_exclusive` on one fd) is the L5 model
(`Flare.L5_Concurrency`).
-/
namespace Flare.Machine

section Dom
variable {M : ConnModel}

@[simp] theorem cancelFd_batch {S : Type} (c : Cfg S) (f : Fd) : (cancelFd c f).batch = c.batch := by
  unfold cancelFd; split <;> rfl

theorem dispatchAt_batch (P : Params) (c : Cfg M.S) (f : Fd) (i : M.I) :
    (dispatchAt M P c f i).batch = c.batch := by
  unfold dispatchAt
  split
  · rfl
  · split
    · simp [cleanup, setConn]; split <;> simp
    · unfold applyStep; split
      · simp [setConn]
      · split <;> simp [schedule, setConn]

/-- A step adds a live connection on `x` only by accepting `x`. -/
theorem step_dom (P : Params) (c c' : Cfg M.S) (lab : Label M.I)
    (hs : step M P c lab = some c') (x : Fd) (hx : (c'.conns x).isSome = true) :
    (c.conns x).isSome = true ∨ ∃ r, lab = .accept x r := by
  cases e : c.conns x with
  | some _ => exact .inl rfl
  | none =>
  cases lab with
  | poll now toks =>
    simp only [step] at hs; split at hs
    · cases hs
      cases e' : (pollStep P.cancelOnCleanup c now toks).conns x with
      | none => rw [e'] at hx; cases hx
      | some l =>
        unfold pollStep at e'
        have h1 := fireAll_conns_sub P.cancelOnCleanup now _ _ x l e'
        simp only at h1; rw [e] at h1; cases h1
    · cases hs
  | accept fd regOk =>
    simp only [step] at hs; split at hs
    · cases hs
      cases regOk
      · simp only [acceptOr] at hx; rw [e] at hx; cases hx
      · by_cases hxf : x = fd
        · subst hxf; exact .inr ⟨true, rfl⟩
        · simp only [acceptOr] at hx
          rw [acceptStep_conns_other M c hxf, e] at hx; cases hx
    · cases hs
  | acceptDone =>
    simp only [step] at hs; split at hs
    · cases hs; simp only at hx; rw [e] at hx; cases hx
    · cases hs
  | dispatch i =>
    simp only [step] at hs
    cases hb : c.batch with
    | nil => simp [hb] at hs
    | cons f rest =>
      simp only [hb] at hs
      split at hs
      · cases hs
      · cases hs
        by_cases hxf : x = f
        · subst hxf
          have hd : dispatchAt M P { c with batch := rest } x i = { c with batch := rest } := by
            simp only [dispatchAt, e]
          rw [hd] at hx; simp only at hx; rw [e] at hx; cases hx
        · rw [dispatchAt_conns_other M P _ i hxf] at hx; simp only at hx; rw [e] at hx; cases hx

end Dom

/-! ## Progress of one worker -/

section Progress
variable (M : ConnModel) (P : Params)

/-- `reactor.poll` is only called once the previous batch is fully handled. -/
theorem poll_needs_empty_batch (c c' : Cfg M.S) (now : Nat) (toks : List Fd)
    (hs : step M P c (.poll now toks) = some c') : c.batch = [] := by
  simp only [step] at hs; split at hs
  · rename_i h; exact h.1
  · cases hs

/-- **Batch progress.** While harvested tokens remain, some step handles the
head token and shortens the batch (`acceptDone` for the listener, `dispatch`
for a client). -/
theorem batch_progress (i : M.I) (c : Cfg M.S) (h : c.batch ≠ []) :
    ∃ lab c', step M P c lab = some c' ∧ c'.batch.length < c.batch.length := by
  cases hb : c.batch with
  | nil => exact absurd hb h
  | cons f rest =>
    by_cases hf : f = 0
    · subst hf
      exact ⟨.acceptDone, { c with batch := rest }, by simp [step, hb], by simp⟩
    · refine ⟨.dispatch i, dispatchAt M P { c with batch := rest } f i, ?_, ?_⟩
      · simp [step, hb, hf]
      · rw [dispatchAt_batch]; simp

/-- **No deadlock.** A worker always has an enabled step: it handles its
batch, or polls when the batch is empty. -/
theorem no_deadlock (i : M.I) (c : Cfg M.S) : ∃ lab c', step M P c lab = some c' := by
  by_cases h : c.batch = []
  · exact ⟨.poll c.now [], pollStep P.cancelOnCleanup c c.now [], by simp [step, h]⟩
  · obtain ⟨lab, c', hs, _⟩ := batch_progress M P i c h
    exact ⟨lab, c', hs⟩

end Progress

/-! ## Several workers sharing one fd table -/

abbrev Sys (S : Type) (n : Nat) := Fin n → Cfg S

def updW {S : Type} {n : Nat} (w : Sys S n) (k : Fin n) (c : Cfg S) : Sys S n :=
  fun j => if j = k then c else w j

/-- `fd` is open nowhere in the process: no worker has it as a connection or
as its listener. -/
def fdFree {S : Type} {n : Nat} (P : Fin n → Params) (w : Sys S n) (fd : Fd) : Bool :=
  decide (∀ j : Fin n, ((w j).conns fd).isNone = true ∧ fd ≠ (P j).lfd)

def labOk {S I : Type} {n : Nat} (P : Fin n → Params) (w : Sys S n) : Label I → Bool
  | .accept fd _ => fdFree P w fd
  | _ => true

/-- One step of worker `k`, subject to the process-wide fd table. -/
def sysStep (M : ConnModel) {n : Nat} (P : Fin n → Params) (w : Sys M.S n) :
    Fin n × Label M.I → Option (Sys M.S n)
  | (k, lab) => if labOk P w lab then (step M (P k) (w k) lab).map (updW w k) else none

def sysLts (M : ConnModel) {n : Nat} (P : Fin n → Params) : LTS (Sys M.S n) (Fin n × Label M.I) :=
  LTS.ofFn (fun w => w = fun _ => initCfg) (sysStep M P)

section Sys
variable {M : ConnModel} {n : Nat} {P : Fin n → Params}

theorem sysStep_inv {w w' : Sys M.S n} {k : Fin n} {lab : Label M.I}
    (hs : sysStep M P w (k, lab) = some w') :
    labOk P w lab = true ∧ ∃ c', step M (P k) (w k) lab = some c' ∧ w' = updW w k c' := by
  simp only [sysStep] at hs
  split at hs
  · rename_i hok
    cases e : step M (P k) (w k) lab with
    | none => rw [e] at hs; cases hs
    | some c' => rw [e] at hs; cases hs; exact ⟨hok, c', rfl, rfl⟩
  · cases hs

theorem run_snoc {S L : Type} (T : LTS S L) :
    ∀ {s ls s'}, T.Run s ls s' → ∀ {l s''}, T.step s' l s'' → T.Run s (ls ++ [l]) s''
  | _, _, _, .nil _, _, _, h => .cons h (.nil _)
  | _, _, _, .cons h1 hr, _, _, h => .cons h1 (run_snoc T hr h)

theorem reachable_step {S L : Type} (T : LTS S L) {s s' : S} {l : L}
    (hr : T.Reachable s) (h : T.step s l s') : T.Reachable s' := by
  obtain ⟨s₀, ls, hi, hrun⟩ := hr
  exact ⟨s₀, ls ++ [l], hi, run_snoc T hrun h⟩

/-- **Each worker is a single-worker machine.** -/
theorem sys_component_reachable (w : Sys M.S n) (hr : (sysLts M P).Reachable w) (k : Fin n) :
    (lts M (P k)).Reachable (w k) := by
  have hind : (sysLts M P).Inductive (fun w => ∀ k, (lts M (P k)).Reachable (w k)) := by
    refine ⟨fun w hw k => ?_, fun w lab w' h hs k => ?_⟩
    · subst hw; exact ⟨initCfg, [], rfl, .nil _⟩
    · obtain ⟨j, l⟩ := lab
      obtain ⟨_, c', hc, rfl⟩ := sysStep_inv hs
      by_cases hk : k = j
      · subst hk; simp only [updW, ↓reduceIte]
        exact reachable_step (lts M (P k)) (h k) hc
      · simp only [updW, if_neg hk]; exact h k
  exact hind.reachable w hr k

/-- **No fd is live in two workers.** -/
theorem sys_disjoint (w : Sys M.S n) (hr : (sysLts M P).Reachable w) :
    ∀ a b : Fin n, a ≠ b → ∀ x, ((w a).conns x).isSome = true → ((w b).conns x).isNone = true := by
  have hind : (sysLts M P).Inductive
      (fun w => ∀ a b : Fin n, a ≠ b → ∀ x, ((w a).conns x).isSome = true →
        ((w b).conns x).isNone = true) := by
    refine ⟨fun w hw => ?_, fun w lab w' h hs => ?_⟩
    · subst hw; intro a b _ x hx; simp [initCfg] at hx
    · obtain ⟨j, l⟩ := lab
      obtain ⟨hok, c', hc, rfl⟩ := sysStep_inv hs
      have hfree : ∀ x r, l = .accept x r → ∀ b, ((w b).conns x).isNone = true := by
        intro x r hl b
        subst hl
        simp only [labOk, fdFree, decide_eq_true_eq] at hok
        exact (hok b).1
      intro a b hab x hx
      by_cases ha : a = j
      · subst ha
        have hb : b ≠ a := fun e => hab e.symm
        simp only [updW, ↓reduceIte] at hx
        simp only [updW, if_neg hb]
        rcases step_dom (P a) (w a) c' l hc x hx with h1 | ⟨r, hl⟩
        · exact h a b hab x h1
        · exact hfree x r hl b
      · simp only [updW, if_neg ha] at hx
        by_cases hb : b = j
        · subst hb
          simp only [updW, ↓reduceIte]
          cases e : c'.conns x with
          | none => rfl
          | some _ =>
            have hs' : (c'.conns x).isSome = true := by rw [e]; rfl
            rcases step_dom (P b) (w b) c' l hc x hs' with h1 | ⟨r, hl⟩
            · have := h b a (fun e => hab e.symm) x h1
              rw [Option.isNone_iff_eq_none] at this
              rw [this] at hx; cases hx
            · have := hfree x r hl a
              rw [Option.isNone_iff_eq_none] at this
              rw [this] at hx; cases hx
        · simp only [updW, if_neg hb]; exact h a b hab x hx
  exact hind.reachable w hr

/-- Idle timers never close another incarnation, in any worker. -/
theorem sys_no_stale_timer (hP : ∀ k, (P k).cancelOnCleanup = true) (w : Sys M.S n)
    (hr : (sysLts M P).Reachable w) (k : Fin n) : ∀ t ∈ (w k).kills, t.victim = t.armer :=
  no_stale_timer M (P k) (hP k) (w k) (sys_component_reachable w hr k)

/-- Connection invariants hold on every live connection of every worker. -/
theorem sys_conn_invariant_lifts (Q : M.S → Prop) (h0 : Q M.init)
    (hstep : ∀ s i, Q s → Q (M.onEvent s i).1) (w : Sys M.S n)
    (hr : (sysLts M P).Reachable w) (k : Fin n) :
    ∀ f l, (w k).conns f = some l → Q l.st :=
  conn_invariant_lifts M (P k) Q h0 hstep (w k) (sys_component_reachable w hr k)

/-- With fd 0 in use, no worker has a connection on the listener token. -/
theorem sys_routing_ok (hP : ∀ k, (P k).stdinOpen = true) (w : Sys M.S n)
    (hr : (sysLts M P).Reachable w) (k : Fin n) : (w k).conns 0 = none :=
  routing_ok M (P k) (hP k) (w k) (sys_component_reachable w hr k)

end Sys
end Flare.Machine
