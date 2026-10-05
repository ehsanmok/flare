import Flare.Core.LTS

/-!
# Scheduler lifecycle: workers, stop flag, drain and teardown

`flare/runtime/scheduler.mojo` starts `n` worker threads
(`flare/runtime/_worker.mojo`), each holding a heap context (frontend copy,
listener fd, stop-flag address, stats address), a per-worker stats cell and
a per-worker `SO_REUSEPORT` listener; all workers share one heap stop flag.
`drain(timeout_ms)` (:778-901) flips the flag, waits up to the deadline for
each worker's `WORKER_STAT_DONE` slot, joins the workers that finished,
detaches the rest, reads the stats cells and frees the resources.
`shutdown()` (:746-760) is the same with every worker joined; it is the
`hard` configuration below (`drain(timeout_ms <= 0)` takes the same path).

## Semantics

Interleaving small-step semantics over a shared heap. The heap is the stop
flag (value `stop`, freed bit `stopF`) and, per worker, freed bits for the
context, the stats cell and the listener. Each worker is a program counter
(`WPc`); the drain thread is `MPc`. Every step that dereferences a heap
cell ORs that cell's freed bit into the ghost flag `uaf`. The scheduler of
the interleaving is the unconstrained choice of label; there is no
fairness assumption, so a worker "stuck in a handler" is simply a worker
that is not scheduled.

Allocation happens in `Scheduler.start` before any worker is spawned
(:361-575), so the initial state has everything allocated and every worker
at `start`.

## Memory model

Sequential-consistency abstraction. The stop flag is one byte written with
a release store and read with acquire loads (`scheduler_stats.mojo:26-46`);
the stats slots likewise (:76-95). Each is a single location, so its
modification order is total and the SC interleaving can produce every
value an acquire load can return. The free of a joined worker's resources
is ordered after all of that worker's accesses by `pthread_join`
(happens-before from thread termination to join return). For detached
workers no ordering argument is needed in the fixed configuration because
nothing they can reach is ever freed. These arguments are stated here, not
proved in Lean.

## Environment assumption

`pthread_join` / `pthread_detach` on a live, joinable handle succeed
(the `except: pass` at :853 and :680 then never fires). A join step is
only enabled once the joined worker has terminated. This is discharged in
`Flare.L5.Lifecycle`: under POSIX the calls fail on a live handle only for a
self-join (`live_handle_calls`), which no in-repo caller performs
(`impl_safe_of_external_caller`); what flare does otherwise is
`impl_freed_under_live_iff`.

## Abstractions

* The frontend's serve loop is abstracted to: load the stop flag, exit if
  set, otherwise one `serve` iteration touching the context (the frontend
  lives in it), the listener and the stats cell. Any handler runs inside
  `serve`.
* Freeing is one step (`free`); the frees are monotone and nothing reads in
  between, so splitting it would only add interleavings with the same
  outcome for `uaf`.
* The drain wait loop is over-approximated: any number of single-worker
  samples of `WORKER_STAT_DONE` in any order, and the deadline can expire at
  any point. This is sound for safety; the counterexample traces sample
  every worker once, as the Mojo loop does.
* The shared-listener mode (`FLARE_REUSEPORT_WORKERS=0`) is modelled in
  `Flare.L5.SharedListener` (the workers hold only the fd number, not the
  heap `TcpListener`); `start`'s rollback and the stuck-branch index
  bookkeeping in `Flare.L5.Lifecycle`.
-/
namespace Flare.L5.Scheduler

/-- Worker program counter.
mirrors flare/runtime/_worker.mojo:99-162 @59bda50 -/
inductive WPc where
  | start   -- :110-136 read the context (stop address, pinning)
  | loop    -- frontend serve loop: `load_stop_flag(stopping)`
  | serve   -- one reactor iteration / handler: context, listener, stats
  | doneSt  -- :156 `store_worker_stat(ctx.stats_addr, WORKER_STAT_DONE, 1)`
  | ret     -- :161-162 return from the pthread start routine
  | term    -- thread terminated
  deriving DecidableEq, Repr

/-- Per-worker state: the program counter, the shared `WORKER_STAT_DONE`
slot, the drain thread's snapshot `done[i]`, what the drain did to the
handle, and the freed bits of this worker's heap cells.
mirrors flare/runtime/scheduler.mojo:243-277 @59bda50 -/
structure WS where
  pc : WPc
  done : Bool
  seen : Bool
  joined : Bool
  detached : Bool
  ctxF : Bool
  statsF : Bool
  lisF : Bool
  deriving DecidableEq, Repr

/-- Drain thread program counter.
mirrors flare/runtime/scheduler.mojo:815-901 @59bda50 -/
inductive MPc where
  | signal          -- :820 `_signal_and_close_listener` (store stop := True)
  | wait            -- :831-844 sample `WORKER_STAT_DONE` until all done or deadline
  | sweep (k : Nat) -- :846-855 join worker k if done[k], else detach it
  | report          -- :869-885 read every stats cell
  | free            -- :890-900 stuck-worker carve-out + `_free_resources`
  | fin
  deriving DecidableEq, Repr

structure St where
  ws : List WS
  stop : Bool
  stopF : Bool
  m : MPc
  uaf : Bool
  deriving DecidableEq, Repr

/-- `hard`: `timeout_ms <= 0` or `shutdown()` (every worker joined).
`fixStop`: the CONC-03 fix (leak the stop flag when a worker is detached).
`fixLis`: the CONC-04 fix (free the non-stuck workers' listeners). -/
structure Cfg where
  hard : Bool
  fixStop : Bool
  fixLis : Bool
  deriving DecidableEq, Repr

inductive Lbl where
  | w (i : Nat)      -- worker i takes a step
  | sample (i : Nat) -- the drain thread samples worker i's DONE slot
  | m                -- the drain thread takes its next (deterministic) step
  deriving DecidableEq, Repr

def w0 : WS := ⟨.start, false, false, false, false, false, false, false⟩

/-- State right after `Scheduler.start` returned with `n` workers.
mirrors flare/runtime/scheduler.mojo:361-641 @59bda50 -/
def init (n : Nat) : St := ⟨List.replicate n w0, false, false, .signal, false⟩

def Freed (w : WS) : Bool := w.ctxF || w.statsF || w.lisF

/-- One worker step: the new worker state and whether it dereferenced a
freed cell. mirrors flare/runtime/_worker.mojo:110-162 @59bda50 -/
def wStep (stop stopF : Bool) (w : WS) : Option (WS × Bool) :=
  match w.pc with
  | .start => some ({ w with pc := .loop }, w.ctxF)
  | .loop => some ({ w with pc := if stop then .doneSt else .serve }, stopF)
  | .serve => some ({ w with pc := .loop }, w.ctxF || w.lisF || w.statsF)
  | .doneSt => some ({ w with pc := .ret, done := true }, w.ctxF || w.statsF)
  | .ret => some ({ w with pc := .term }, false)
  | .term => none

/-- The free policy after the sweep. Pre-fix (`fixStop = fixLis = false`):
the stuck workers' ctx and stats entries are popped, the whole per-worker
listener list is cleared as soon as any worker is stuck, and
`_free_resources` frees what is left, including the stop flag. Shipped
(`fixStop`, CONC-03; `fixLis`, CONC-04): the stop flag is leaked
(`self._stopping_addr = 0`) when a worker was detached, and only the stuck
workers' listeners are dropped from the list that gets freed.
mirrors flare/runtime/scheduler.mojo:890-935,703-744 (fixed, CONC-03, CONC-04) -/
def freeAll (c : Cfg) (s : St) : St :=
  let anyDet := s.ws.any (·.detached)
  { s with
    ws := s.ws.map fun w =>
      { w with ctxF := !w.detached, statsF := !w.detached,
               lisF := if c.fixLis then !w.detached else !anyDet },
    stopF := if c.fixStop then !anyDet else true,
    m := .fin }

/-- One drain-thread step. mirrors flare/runtime/scheduler.mojo:815-901 @59bda50 -/
def mStep (c : Cfg) (s : St) : Option St :=
  match s.m with
  | .signal => some { s with stop := true, m := .wait, uaf := s.uaf || s.stopF }
  | .wait =>
    some { s with m := .sweep 0,
                  ws := if c.hard then s.ws.map (fun w => { w with seen := true }) else s.ws }
  | .sweep k =>
    match s.ws[k]? with
    | none => some { s with m := .report }
    | some w =>
      if w.seen then
        if w.pc = .term then
          some { s with ws := s.ws.set k { w with joined := true }, m := .sweep (k + 1) }
        else none
      else some { s with ws := s.ws.set k { w with detached := true }, m := .sweep (k + 1) }
  | .report => some { s with m := .free, uaf := s.uaf || s.ws.any (·.statsF) }
  | .free => some (freeAll c s)
  | .fin => none

/-- mirrors flare/runtime/scheduler.mojo:831-844 and flare/runtime/_worker.mojo:110-162 @59bda50 -/
def step (c : Cfg) (s : St) : Lbl → Option St
  | .w i =>
    match s.ws[i]? with
    | none => none
    | some w =>
      (wStep s.stop s.stopF w).map fun p => { s with ws := s.ws.set i p.1, uaf := s.uaf || p.2 }
  | .sample i =>
    if c.hard = false ∧ s.m = .wait then
      match s.ws[i]? with
      | none => none
      | some w => some { s with ws := s.ws.set i { w with seen := w.done }, uaf := s.uaf || w.statsF }
    else none
  | .m => mStep c s

def lts (c : Cfg) (n : Nat) : LTS St Lbl := LTS.ofFn (· = init n) (step c)

/-- The pre-fix code (59bda50): `drain(timeout_ms > 0)`, before CONC-03 and
CONC-04 were fixed. Kept so the counterexamples stay checkable. -/
def cfgImpl : Cfg := ⟨false, false, false⟩
/-- The code at 59bda50: `shutdown()` / `drain(timeout_ms <= 0)`. -/
def cfgShutdown : Cfg := ⟨true, false, false⟩
/-- `drain(timeout_ms > 0)` as shipped: the CONC-03 fix (the stop flag is
leaked when a worker is detached) and the CONC-04 fix (only the stuck
workers' listeners are dropped from the freed list) are both in. -/
def cfgShipped : Cfg := ⟨false, true, true⟩
/-- `drain(timeout_ms > 0)` with both fixes (the shipped drain). -/
def cfgFixed : Cfg := ⟨false, true, true⟩

/-! ## Specification -/

/-- No step ever dereferenced a freed cell. -/
def MemSafe (s : St) : Prop := s.uaf = false

/-- Nothing a live worker can reference is freed: a worker that has not
terminated still has its context, stats cell and listener, and the stop
flag is allocated. -/
def LiveRefsAllocated (s : St) : Prop :=
  ∀ w ∈ s.ws, w.pc ≠ .term → Freed w = false ∧ s.stopF = false

/-- After drain, only detached workers keep resources: every other worker's
context, stats cell and listener are freed, and the stop flag is freed when
no worker was detached (drain docstring, scheduler.mojo:799-803). -/
def NoLeak (s : St) : Prop :=
  s.m = .fin →
    (∀ w ∈ s.ws, w.detached = false → w.ctxF = true ∧ w.statsF = true ∧ w.lisF = true) ∧
    ((∀ w ∈ s.ws, w.detached = false) → s.stopF = true)

/-! ## Inductive invariant -/

def Decided (w : WS) : Prop := w.joined = true ∨ w.detached = true

/-- Per-worker facts. -/
def WI (c : Cfg) (w : WS) : Prop :=
  (Freed w = true → w.joined = true) ∧
  (w.joined = true → w.pc = .term) ∧
  (w.done = true → w.pc = .ret ∨ w.pc = .term) ∧
  (c.hard = false → w.seen = true → w.done = true) ∧
  (c.hard = true → w.detached = false)

def NoneFreed (s : St) : Prop := s.stopF = false ∧ ∀ w ∈ s.ws, Freed w = false

/-- Facts indexed by the drain thread's program counter. -/
def MI (c : Cfg) (s : St) : MPc → Prop
  | .signal => NoneFreed s
  | .wait => s.stop = true ∧ NoneFreed s
  | .sweep k => s.stop = true ∧ NoneFreed s ∧
      (∀ j w, j < k → s.ws[j]? = some w → Decided w) ∧
      (c.hard = true → ∀ w ∈ s.ws, w.seen = true)
  | .report | .free => s.stop = true ∧ NoneFreed s ∧ ∀ w ∈ s.ws, Decided w
  | .fin => s.stop = true ∧ (∀ w ∈ s.ws, Decided w) ∧
      (∀ w ∈ s.ws, w.detached = false →
        w.ctxF = true ∧ w.statsF = true ∧
        ((c.fixLis = true ∨ ∀ v ∈ s.ws, v.detached = false) → w.lisF = true)) ∧
      ((∀ w ∈ s.ws, w.detached = false) → s.stopF = true) ∧
      (s.stopF = true → c.fixStop = false ∨ ∀ w ∈ s.ws, w.detached = false)

def Core (c : Cfg) (s : St) : Prop := (∀ w ∈ s.ws, WI c w) ∧ MI c s s.m

/-- The memory-safety part, inductive only when `fixStop ∨ hard`. -/
def SI (s : St) : Prop := s.uaf = false ∧ (s.stopF = true → ∀ w ∈ s.ws, w.joined = true)

/-! ### List lemmas -/

theorem forall_set {P : WS → Prop} {l : List WS} {i : Nat} {w' : WS}
    (h : ∀ x ∈ l, P x) (hw : P w') : ∀ x ∈ l.set i w', P x := by
  intro x hx
  rcases List.mem_or_eq_of_mem_set hx with hx | hx
  · exact h x hx
  · exact hx ▸ hw

theorem idx_set {Q : WS → Prop} {l : List WS} {i k : Nat} {w w' : WS}
    (hi : l[i]? = some w) (h : ∀ j x, j < k → l[j]? = some x → Q x) (hq : Q w → Q w') :
    ∀ j x, j < k → (l.set i w')[j]? = some x → Q x := by
  intro j x hj hx
  rw [List.getElem?_set] at hx
  by_cases hij : i = j
  · subst hij
    have hlt : i < l.length := by
      rcases Nat.lt_or_ge i l.length with h' | h'
      · exact h'
      · rw [List.getElem?_eq_none h'] at hi; cases hi
    simp only [if_true, hlt, Option.some.injEq] at hx
    subst hx; exact hq (h i w hj hi)
  · simp only [hij, if_false] at hx; exact h j x hj hx

theorem idx_set_succ {Q : WS → Prop} {l : List WS} {k : Nat} {w w' : WS}
    (hk : l[k]? = some w) (h : ∀ j x, j < k → l[j]? = some x → Q x) (hq : Q w') :
    ∀ j x, j < k + 1 → (l.set k w')[j]? = some x → Q x := by
  intro j x hj hx
  rw [List.getElem?_set] at hx
  by_cases hkj : k = j
  · subst hkj
    have hlt : k < l.length := by
      rcases Nat.lt_or_ge k l.length with h' | h'
      · exact h'
      · rw [List.getElem?_eq_none h'] at hk; cases hk
    simp only [if_true, hlt, Option.some.injEq] at hx
    exact hx ▸ hq
  · simp only [hkj, if_false] at hx; exact h j x (by omega) hx

theorem idx_none {Q : WS → Prop} {l : List WS} {k : Nat} (hk : l[k]? = none)
    (h : ∀ j x, j < k → l[j]? = some x → Q x) : ∀ x ∈ l, Q x := by
  intro x hx
  obtain ⟨j, hj, rfl⟩ := List.mem_iff_getElem.mp hx
  have : k ≥ l.length := List.getElem?_eq_none_iff.mp hk
  exact h j _ (by omega) (List.getElem?_eq_getElem hj)

theorem mem_of_get {l : List WS} {i : Nat} {w : WS} (h : l[i]? = some w) : w ∈ l :=
  List.mem_of_getElem? h

/-! ### Preservation -/

theorem wStep_wi (c : Cfg) (stop stopF : Bool) (w w' : WS) (b : Bool)
    (hw : WI c w) (h : wStep stop stopF w = some (w', b)) :
    WI c w' ∧ Freed w' = Freed w ∧ w'.joined = w.joined ∧ w'.detached = w.detached ∧
      w'.seen = w.seen ∧ w.pc ≠ .term ∧ (b = true → Freed w = true ∨ stopF = true) ∧
      (w'.ctxF = w.ctxF ∧ w'.statsF = w.statsF ∧ w'.lisF = w.lisF) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := hw
  unfold wStep at h
  cases hp : w.pc <;> simp only [hp, Option.some.injEq, Prod.mk.injEq, reduceCtorEq] at h
  all_goals
    obtain ⟨rfl, rfl⟩ := h
    have hj : w.joined = false := by
      cases hjj : w.joined
      · rfl
      · have := h2 hjj; simp [hp] at this
    simp only [WI, Freed] at h1 ⊢
    refine ⟨⟨?_, ?_, ?_, ?_, ?_⟩, ?_⟩ <;>
      simp_all <;> (try split) <;> simp_all <;>
      (try (rcases h3 rfl with h | h <;> simp_all))

theorem core_init (c : Cfg) (n : Nat) : Core c (init n) := by
  refine ⟨?_, ?_⟩
  · intro w hw
    rw [init, List.mem_replicate] at hw
    obtain ⟨_, rfl⟩ := hw
    simp [WI, w0, Freed]
  · simp only [init, MI, NoneFreed, true_and]
    intro w hw
    rw [List.mem_replicate] at hw
    obtain ⟨_, rfl⟩ := hw
    rfl

theorem core_step_w (c : Cfg) (s s' : St) (i : Nat) (I : Core c s)
    (h : step c s (.w i) = some s') : Core c s' := by
  obtain ⟨hW, hM⟩ := I
  simp only [step] at h
  split at h
  · cases h
  · rename_i w hi
    cases hs : wStep s.stop s.stopF w with
    | none => simp [hs] at h
    | some p =>
      obtain ⟨w', b⟩ := p
      simp only [hs, Option.map_some, Option.some.injEq] at h
      subst h
      obtain ⟨hwi, hF, hJ, hD, hSn, -, -, e1⟩ := wStep_wi c _ _ w w' b (hW w (mem_of_get hi)) hs
      refine ⟨forall_set hW hwi, ?_⟩
      have hdec : Decided w → Decided w' := by simp [Decided, hJ, hD]
      have hfr : Freed w = false → Freed w' = false := by simp [hF]
      have hdet : w.detached = false → w'.detached = false := by simp [hD]
      simp only
      cases hm : s.m <;> simp only [hm, MI, NoneFreed] at hM ⊢
      · exact ⟨hM.1, forall_set hM.2 (hfr (hM.2 w (mem_of_get hi)))⟩
      · exact ⟨hM.1, hM.2.1, forall_set hM.2.2 (hfr (hM.2.2 w (mem_of_get hi)))⟩
      · obtain ⟨a1, ⟨a2, a3⟩, a4, a5⟩ := hM
        refine ⟨a1, ⟨a2, forall_set a3 (hfr (a3 w (mem_of_get hi)))⟩, idx_set hi a4 hdec, ?_⟩
        intro hh; exact forall_set (a5 hh) (by rw [hSn]; exact a5 hh w (mem_of_get hi))
      all_goals first
        | (obtain ⟨a1, ⟨a2, a3⟩, a4⟩ := hM
           exact ⟨a1, ⟨a2, forall_set a3 (hfr (a3 w (mem_of_get hi)))⟩,
             forall_set a4 (hdec (a4 w (mem_of_get hi)))⟩)
        | skip
      -- fin
      obtain ⟨a1, a2, a3, a4, a5⟩ := hM
      have hwm := mem_of_get hi
      have hall : (∀ v ∈ s.ws.set i w', v.detached = false) → ∀ v ∈ s.ws, v.detached = false := by
        intro hv v hvm
        by_cases hvw : v = w
        · subst hvw
          have : w' ∈ s.ws.set i w' := by
            rw [List.mem_iff_getElem]
            have hlt : i < s.ws.length := by
              rcases Nat.lt_or_ge i s.ws.length with h' | h'
              · exact h'
              · rw [List.getElem?_eq_none h'] at hi; cases hi
            exact ⟨i, by simpa using hlt, by simp⟩
          rw [← hD]; exact hv _ this
        · -- v occurs in s.ws at an index; if that index is i then v = w
          obtain ⟨j, hj, rfl⟩ := List.mem_iff_getElem.mp hvm
          by_cases hij : i = j
          · subst hij
            have : s.ws[i]? = some s.ws[i] := List.getElem?_eq_getElem hj
            rw [hi] at this; cases this; exact absurd rfl hvw
          · apply hv
            rw [List.mem_iff_getElem]
            exact ⟨j, by simpa using hj, by simp [hij]⟩
      refine ⟨a1, forall_set a2 (hdec (a2 w hwm)), ?_, fun hv => a4 (hall hv), ?_⟩
      · intro v hv hvd
        rcases List.mem_or_eq_of_mem_set hv with hv | hv
        · obtain ⟨b1, b2, b3⟩ := a3 v hv hvd
          exact ⟨b1, b2, fun hh => b3 (hh.imp id hall)⟩
        · rw [hv] at hvd ⊢
          obtain ⟨b1, b2, b3⟩ := a3 w hwm (by rw [← hD]; exact hvd)
          rw [e1.1, e1.2.1, e1.2.2]
          exact ⟨b1, b2, fun hh => b3 (hh.imp id hall)⟩
      · intro hst
        rcases a5 hst with h5 | h5
        · exact Or.inl h5
        · exact Or.inr (forall_set h5 (by rw [hD]; exact h5 w hwm))

theorem core_step_sample (c : Cfg) (s s' : St) (i : Nat) (I : Core c s)
    (h : step c s (.sample i) = some s') : Core c s' := by
  obtain ⟨hW, hM⟩ := I
  simp only [step] at h
  split at h
  · rename_i hc
    obtain ⟨hh, hm⟩ := hc
    split at h
    · cases h
    · rename_i w hi
      simp only [Option.some.injEq] at h; subst h
      have hwm := mem_of_get hi
      obtain ⟨h1, h2, h3, h4, h5⟩ := hW w hwm
      refine ⟨forall_set hW ⟨by simpa [Freed] using h1, h2, h3, fun _ hs => hs, fun h' => h5 h'⟩, ?_⟩
      simp only [hm, MI, NoneFreed] at hM ⊢
      exact ⟨hM.1, hM.2.1, forall_set hM.2.2 (by simpa [Freed] using hM.2.2 w hwm)⟩
  · cases h

theorem core_step_m (c : Cfg) (s s' : St) (I : Core c s)
    (h : step c s .m = some s') : Core c s' := by
  obtain ⟨hW, hM⟩ := I
  simp only [step, mStep] at h
  cases hm : s.m <;> simp only [hm, MI, NoneFreed] at h hM
  · -- signal
    simp only [Option.some.injEq] at h; subst h
    refine ⟨hW, ?_⟩
    simp only [MI, NoneFreed]
    exact ⟨trivial, hM⟩
  · -- wait
    simp only [Option.some.injEq] at h; subst h
    obtain ⟨a1, a2, a3⟩ := hM
    by_cases hh : c.hard = true
    · simp only [hh, if_true]
      refine ⟨?_, a1, ⟨a2, ?_⟩, fun _ _ hj => absurd hj (Nat.not_lt_zero _), ?_⟩
      · intro w hw
        obtain ⟨v, hv, rfl⟩ := List.mem_map.mp hw
        obtain ⟨h1, h2, h3, h4, h5⟩ := hW v hv
        refine ⟨by simpa [Freed] using h1, h2, h3, ?_, h5⟩
        intro h'
        exact absurd (h'.symm.trans hh) Bool.false_ne_true
      · intro w hw
        obtain ⟨v, hv, rfl⟩ := List.mem_map.mp hw
        simpa [Freed] using a3 v hv
      · intro _ w hw
        obtain ⟨v, _, rfl⟩ := List.mem_map.mp hw
        rfl
    · have hh' : c.hard = false := by simpa using hh
      simp only [hh', Bool.false_eq_true, if_false]
      refine ⟨hW, a1, ⟨a2, a3⟩, fun _ _ hj => absurd hj (Nat.not_lt_zero _), ?_⟩
      intro h'
      exact absurd (hh'.symm.trans h') Bool.false_ne_true
  · -- sweep k
    rename_i k
    obtain ⟨a1, ⟨a2, a3⟩, a4, a5⟩ := hM
    split at h
    · rename_i hk
      simp only [Option.some.injEq] at h; subst h
      exact ⟨hW, a1, ⟨a2, a3⟩, idx_none hk a4⟩
    · rename_i w hk
      have hwm := mem_of_get hk
      obtain ⟨h1, h2, h3, h4, h5⟩ := hW w hwm
      have hfw : Freed w = false := a3 w hwm
      split at h
      · rename_i hseen
        split at h
        · rename_i hterm
          simp only [Option.some.injEq] at h; subst h
          refine ⟨forall_set hW ⟨fun _ => rfl, fun _ => hterm, h3, h4, h5⟩, a1,
            ⟨a2, forall_set a3 (by simpa [Freed] using hfw)⟩,
            idx_set_succ hk a4 (Or.inl rfl), fun hh => forall_set (a5 hh) hseen⟩
        · cases h
      · rename_i hseen
        simp only [Option.some.injEq] at h; subst h
        have hsoft : c.hard = false := by
          cases hh : c.hard
          · rfl
          · have := a5 hh w hwm; rw [this] at hseen; exact absurd rfl hseen
        refine ⟨forall_set hW ⟨by simpa [Freed] using h1, h2, h3, h4,
            fun h' => by rw [hsoft] at h'; cases h'⟩, a1,
          ⟨a2, forall_set a3 (by simpa [Freed] using hfw)⟩,
          idx_set_succ hk a4 (Or.inr rfl), fun h' => by rw [hsoft] at h'; cases h'⟩
  · -- report
    simp only [Option.some.injEq] at h; subst h
    exact ⟨hW, hM⟩
  · -- free
    simp only [Option.some.injEq] at h; subst h
    obtain ⟨a1, ⟨a2, a3⟩, a4⟩ := hM
    simp only [freeAll]
    have hany : (s.ws.any (·.detached) = false) ↔ ∀ v ∈ s.ws, v.detached = false := by
      simp
    refine ⟨?_, ?_⟩
    · intro w hw
      obtain ⟨v, hv, rfl⟩ := List.mem_map.mp hw
      obtain ⟨h1, h2, h3, h4, h5⟩ := hW v hv
      refine ⟨?_, h2, h3, h4, h5⟩
      have hd := a4 v hv
      intro hf
      rcases hd with hd | hd
      · exact hd
      · exfalso
        have : s.ws.any (·.detached) = true := List.any_eq_true.mpr ⟨v, hv, hd⟩
        simp [Freed, hd, this] at hf
    · simp only [MI]
      refine ⟨a1, ?_, ?_, ?_, ?_⟩
      · intro w hw
        obtain ⟨v, hv, rfl⟩ := List.mem_map.mp hw
        exact a4 v hv
      · intro w hw hd
        obtain ⟨v, hv, rfl⟩ := List.mem_map.mp hw
        simp only at hd ⊢
        refine ⟨by simp [hd], by simp [hd], ?_⟩
        intro hh
        rcases hh with hh | hh
        · simp [hh, hd]
        · have hall : ∀ u ∈ s.ws, u.detached = false := by
            intro u hu
            have := hh _ (List.mem_map.mpr ⟨u, hu, rfl⟩)
            simpa using this
          have := hany.mpr hall
          cases c.fixLis <;> simp [hd, this]
      · intro hall
        have hall' : ∀ u ∈ s.ws, u.detached = false := by
          intro u hu
          have := hall _ (List.mem_map.mpr ⟨u, hu, rfl⟩)
          simpa using this
        have := hany.mpr hall'
        cases c.fixStop <;> simp [this]
      · intro hst
        cases hfs : c.fixStop
        · exact Or.inl rfl
        · right
          simp only [hfs, if_true, Bool.not_eq_true'] at hst
          intro w hw
          obtain ⟨v, hv, rfl⟩ := List.mem_map.mp hw
          exact hany.mp hst v hv
  · -- fin
    cases h

theorem core_inductive (c : Cfg) (n : Nat) : (lts c n).Inductive (Core c) := by
  refine ⟨fun s h => h ▸ core_init c n, ?_⟩
  intro s l s' I h
  cases l with
  | w i => exact core_step_w c s s' i I h
  | sample i => exact core_step_sample c s s' i I h
  | m => exact core_step_m c s s' I h

/-! ### Memory safety -/

/-- Core facts imply that a live worker's references are allocated, given
`SI` for the stop flag. -/
theorem live_of_core (c : Cfg) (s : St) (I : Core c s) (S : SI s) : LiveRefsAllocated s := by
  intro w hw hpc
  obtain ⟨h1, h2, -, -, -⟩ := I.1 w hw
  have hj : w.joined = false := by
    cases hjj : w.joined
    · rfl
    · exact absurd (h2 hjj) hpc
  refine ⟨?_, ?_⟩
  · cases hf : Freed w
    · rfl
    · rw [h1 hf] at hj; cases hj
  · cases hs : s.stopF
    · rfl
    · rw [S.2 hs w hw] at hj; cases hj

theorem si_step (c : Cfg) (hc : c.fixStop = true ∨ c.hard = true) (s s' : St) (l : Lbl)
    (I : Core c s) (S : SI s) (h : step c s l = some s') : SI s' := by
  have I' : Core c s' := by
    cases l with
    | w i => exact core_step_w c s s' i I h
    | sample i => exact core_step_sample c s s' i I h
    | m => exact core_step_m c s s' I h
  obtain ⟨S1, S2⟩ := S
  cases l with
  | w i =>
    simp only [step] at h
    split at h
    · cases h
    · rename_i w hi
      cases hs : wStep s.stop s.stopF w with
      | none => simp [hs] at h
      | some p =>
        obtain ⟨w', b⟩ := p
        simp only [hs, Option.map_some, Option.some.injEq] at h
        subst h
        have hwm := mem_of_get hi
        obtain ⟨-, -, hJ, -, -, hpc, hb, -⟩ := wStep_wi c _ _ w w' b (I.1 w hwm) hs
        obtain ⟨hl1, hl2⟩ := live_of_core c s I ⟨S1, S2⟩ w hwm hpc
        have hb' : b = false := by
          cases hbb : b
          · rfl
          · rcases hb hbb with h' | h' <;> simp_all
        refine ⟨by simp [S1, hb'], ?_⟩
        intro hst
        exact forall_set (S2 hst) (by rw [hJ]; exact S2 hst w hwm)
  | sample i =>
    simp only [step] at h
    split at h
    · rename_i hc'
      split at h
      · cases h
      · rename_i w hi
        simp only [Option.some.injEq] at h; subst h
        have hM := I.2
        simp only [hc'.2, MI, NoneFreed] at hM
        have hf := hM.2.2 w (mem_of_get hi)
        simp only [Freed, Bool.or_eq_false_iff] at hf
        refine ⟨by simp [S1, hf.1.2], fun hst => ?_⟩
        exact forall_set (S2 hst) (S2 hst w (mem_of_get hi))
    · cases h
  | m =>
    have hM := I.2
    have hM' := I'.2
    simp only [step, mStep] at h
    cases hm : s.m <;> simp only [hm, MI, NoneFreed] at h hM
    · simp only [Option.some.injEq] at h; subst h
      exact ⟨by simp [S1, hM.1], fun hst => by simp [hM.1] at hst⟩
    · simp only [Option.some.injEq] at h; subst h
      refine ⟨S1, fun hst => by simp [hM.2.1] at hst⟩
    · obtain ⟨-, ⟨a2, -⟩, -⟩ := hM
      have : s'.stopF = false := by
        split at h
        · simp only [Option.some.injEq] at h; subst h; exact a2
        · split at h
          · split at h
            · simp only [Option.some.injEq] at h; subst h; exact a2
            · cases h
          · simp only [Option.some.injEq] at h; subst h; exact a2
      have hu : s'.uaf = s.uaf := by
        split at h
        · simp only [Option.some.injEq] at h; subst h; rfl
        · split at h
          · split at h
            · simp only [Option.some.injEq] at h; subst h; rfl
            · cases h
          · simp only [Option.some.injEq] at h; subst h; rfl
      exact ⟨hu ▸ S1, fun hst => by rw [this] at hst; cases hst⟩
    · simp only [Option.some.injEq] at h; subst h
      obtain ⟨-, ⟨a2, a3⟩, -⟩ := hM
      have : s.ws.any (·.statsF) = false := by
        rw [Bool.eq_false_iff]; intro ha
        obtain ⟨w, hw, hs⟩ := List.any_eq_true.mp ha
        have := a3 w hw; simp [Freed, hs] at this
      exact ⟨by simp [S1, this], fun hst => by simp [a2] at hst⟩
    · simp only [Option.some.injEq] at h; subst h
      obtain ⟨-, ⟨-, -⟩, a4⟩ := hM
      refine ⟨S1, ?_⟩
      -- after the free step: stopF true forces no detached worker
      have hfin := I'.2
      simp only [freeAll, MI] at hfin
      obtain ⟨-, -, -, -, b5⟩ := hfin
      intro hst w hw
      obtain ⟨v, hv, rfl⟩ := List.mem_map.mp hw
      have hnd : v.detached = false := by
        rcases b5 hst with hb | hb
        · rcases hc with hc | hc
          · rw [hc] at hb; cases hb
          · exact (I.1 v hv).2.2.2.2 hc
        · simpa using hb _ (List.mem_map.mpr ⟨v, hv, rfl⟩)
      rcases a4 v hv with hd | hd
      · exact hd
      · rw [hnd] at hd; cases hd
    · cases h

def CoreSI (c : Cfg) (s : St) : Prop := Core c s ∧ SI s

theorem coreSI_inductive (c : Cfg) (hc : c.fixStop = true ∨ c.hard = true) (n : Nat) :
    (lts c n).Inductive (CoreSI c) := by
  refine ⟨fun s h => ?_, fun s l s' I h => ⟨(core_inductive c n).step s l s' I.1 h,
    si_step c hc s s' l I.1 I.2 h⟩⟩
  subst h
  exact ⟨core_init c n, rfl, fun h => by cases h⟩

/-- The general safety theorem: whenever drain leaks the stop flag with a
detached worker (`fixStop`), or detaches nobody (`hard`), no step ever
dereferences a freed cell and nothing a live worker can reference is
freed. Any number of workers, every interleaving. Proved. -/
theorem safe_of_cfg (c : Cfg) (hc : c.fixStop = true ∨ c.hard = true) (n : Nat) :
    ∀ s, (lts c n).Reachable s → MemSafe s ∧ LiveRefsAllocated s := by
  intro s hr
  have I := (coreSI_inductive c hc n).reachable s hr
  exact ⟨I.2.1, live_of_core c s I.1 I.2⟩

/-- No leak beyond the detached workers' resources, whenever the
non-stuck workers' listeners are kept for freeing (`fixLis`) or nobody is
detached (`hard`). Proved, general. -/
theorem noLeak_of_cfg (c : Cfg) (hc : c.fixLis = true ∨ c.hard = true) (n : Nat) :
    ∀ s, (lts c n).Reachable s → NoLeak s := by
  intro s hr hm
  have I := (core_inductive c n).reachable s hr
  obtain ⟨hW, hM⟩ := I
  simp only [hm, MI] at hM
  obtain ⟨-, -, a3, a4, -⟩ := hM
  refine ⟨fun w hw hd => ?_, a4⟩
  obtain ⟨b1, b2, b3⟩ := a3 w hw hd
  refine ⟨b1, b2, b3 ?_⟩
  rcases hc with hc | hc
  · exact Or.inl hc
  · exact Or.inr fun v hv => (hW v hv).2.2.2.2 hc

/-- With the fix, a worker that is still running after drain returned (a
detached one) reads an allocated stop flag holding `True`, so its next
serve-loop check exits. Proved, general. -/
theorem detached_sees_stop (c : Cfg) (hc : c.fixStop = true ∨ c.hard = true) (n : Nat) :
    ∀ s, (lts c n).Reachable s → s.m = .fin → ∀ w ∈ s.ws, w.pc ≠ .term →
      s.stop = true ∧ s.stopF = false := by
  intro s hr hm w hw hpc
  have I := (coreSI_inductive c hc n).reachable s hr
  have hM := I.1.2
  simp only [hm, MI] at hM
  exact ⟨hM.1, (live_of_core c s I.1 I.2 w hw hpc).2⟩

/-- In a soft drain, a worker whose DONE slot was seen set is at its final
return or terminated, so the join waits at most for that one step. Proved,
general. -/
theorem soft_join_bounded (c : Cfg) (hs : c.hard = false) (n : Nat) :
    ∀ s, (lts c n).Reachable s → ∀ w ∈ s.ws, w.seen = true → w.pc = .ret ∨ w.pc = .term := by
  intro s hr w hw hseen
  have I := (core_inductive c n).reachable s hr
  obtain ⟨-, -, h3, h4, -⟩ := I.1 w hw
  exact h3 (h4 hs hseen)

/-- Headline (code at 59bda50, `shutdown()` and `drain(timeout_ms <= 0)`):
memory safe and leak free. Proved, general. -/
theorem shutdown_safe (n : Nat) :
    ∀ s, (lts cfgShutdown n).Reachable s → MemSafe s ∧ LiveRefsAllocated s ∧ NoLeak s :=
  fun s hr => ⟨(safe_of_cfg cfgShutdown (Or.inr rfl) n s hr).1,
    (safe_of_cfg cfgShutdown (Or.inr rfl) n s hr).2, noLeak_of_cfg cfgShutdown (Or.inr rfl) n s hr⟩

/-- Headline (fixed `drain(timeout_ms > 0)`): memory safe, nothing a live
worker can reference is freed, and nothing but the detached workers'
resources (and then the stop flag) is leaked. Proved, general. -/
theorem fixed_safe (n : Nat) :
    ∀ s, (lts cfgFixed n).Reachable s → MemSafe s ∧ LiveRefsAllocated s ∧ NoLeak s :=
  fun s hr => ⟨(safe_of_cfg cfgFixed (Or.inl rfl) n s hr).1,
    (safe_of_cfg cfgFixed (Or.inl rfl) n s hr).2, noLeak_of_cfg cfgFixed (Or.inl rfl) n s hr⟩

/-! ## Executable traces -/

def exec (c : Cfg) : St → List Lbl → Option St
  | s, [] => some s
  | s, l :: ls => (step c s l).bind fun s' => exec c s' ls

theorem run_of_exec (c : Cfg) (n : Nat) :
    ∀ s ls s', exec c s ls = some s' → (lts c n).Run s ls s' := by
  intro s ls
  induction ls generalizing s with
  | nil => intro s' h; simp [exec] at h; subst h; exact .nil _
  | cons l ls ih =>
    intro s' h
    simp only [exec] at h
    cases hs : step c s l with
    | none => simp [hs] at h
    | some t => simp only [hs, Option.bind_some] at h; exact .cons hs (ih t s' h)

theorem reachable_of_exec (c : Cfg) (n : Nat) (ls : List Lbl) (s : St)
    (h : exec c (init n) ls = some s) : (lts c n).Reachable s :=
  ⟨init n, ls, rfl, run_of_exec c n _ _ _ h⟩

/-! ## Bounded exhaustive exploration

`explore` is a fuel-bounded depth-first search returning the set of visited
states. Its result is used only as a certificate: `check` verifies that the
initial state is in the set, that the set is closed under `step` and that
the property holds on every member; `check_sound` shows that this implies
the property on every reachable state, whatever `explore` returned. -/

def labels (n : Nat) : List Lbl :=
  (List.range n).map Lbl.w ++ (List.range n).map Lbl.sample ++ [Lbl.m]

def succs (c : Cfg) (s : St) : List St := (labels s.ws.length).filterMap (step c s)

theorem lt_of_get {l : List WS} {i : Nat} {w : WS} (h : l[i]? = some w) : i < l.length := by
  rcases Nat.lt_or_ge i l.length with h' | h'
  · exact h'
  · rw [List.getElem?_eq_none h'] at h; cases h

theorem mem_succs (c : Cfg) (s s' : St) (l : Lbl) (h : step c s l = some s') :
    s' ∈ succs c s := by
  refine List.mem_filterMap.mpr ⟨l, ?_, h⟩
  simp only [labels, List.mem_append, List.mem_map, List.mem_range, List.mem_singleton]
  cases l with
  | w i =>
    simp only [step] at h
    split at h
    · cases h
    · rename_i hi; exact Or.inl (Or.inl ⟨i, lt_of_get hi, rfl⟩)
  | sample i =>
    simp only [step] at h
    split at h
    · split at h
      · cases h
      · rename_i hi; exact Or.inl (Or.inr ⟨i, lt_of_get hi, rfl⟩)
    · cases h
  | m => exact Or.inr rfl

/-- A search key for the visited set (meant to be injective on states with
a fixed worker count; soundness does not depend on it). -/
def pcCode : WPc → Nat
  | .start => 0 | .loop => 1 | .serve => 2 | .doneSt => 3 | .ret => 4 | .term => 5

def bc (b : Bool) : Nat := if b then 1 else 0

def encW (w : WS) : Nat :=
  pcCode w.pc + 6 * (bc w.done + 2 * (bc w.seen + 2 * (bc w.joined + 2 * (bc w.detached +
    2 * (bc w.ctxF + 2 * (bc w.statsF + 2 * bc w.lisF))))))

def mCode : MPc → Nat
  | .signal => 0 | .wait => 1 | .report => 2 | .free => 3 | .fin => 4 | .sweep k => 5 + k

def enc (s : St) : Nat :=
  bc s.uaf + 2 * (bc s.stop + 2 * (bc s.stopF + 2 * (mCode s.m +
    64 * s.ws.foldr (fun w acc => encW w + 768 * acc) 0)))

/-- Visited set: a binary search tree on `enc`. -/
inductive Tree where
  | leaf
  | node (l : Tree) (k : Nat) (s : St) (r : Tree)

inductive Tree.Mem (x : St) : Tree → Prop where
  | here {l k r} : Tree.Mem x (.node l k x r)
  | left {l k s r} : Tree.Mem x l → Tree.Mem x (.node l k s r)
  | right {l k s r} : Tree.Mem x r → Tree.Mem x (.node l k s r)

def Tree.find (k : Nat) (x : St) : Tree → Bool
  | .leaf => false
  | .node l k' s r =>
    if Nat.blt k k' then find k x l else if Nat.blt k' k then find k x r else decide (s = x)

def Tree.insert (k : Nat) (x : St) : Tree → Tree
  | .leaf => .node .leaf k x .leaf
  | .node l k' s r =>
    if Nat.blt k k' then .node (insert k x l) k' s r
    else if Nat.blt k' k then .node l k' s (insert k x r) else .node l k' s r

def Tree.all (p : St → Bool) : Tree → Bool
  | .leaf => true
  | .node l _ s r => p s && all p l && all p r

theorem Tree.find_sound (k : Nat) (x : St) : ∀ t, Tree.find k x t = true → Tree.Mem x t := by
  intro t
  induction t with
  | leaf => intro h; cases h
  | node l k' s r ihl ihr =>
    intro h
    simp only [Tree.find] at h
    split at h
    · exact .left (ihl h)
    · split at h
      · exact .right (ihr h)
      · rw [decide_eq_true_eq] at h; subst h; exact .here

theorem Tree.all_sound (p : St → Bool) : ∀ t, Tree.all p t = true → ∀ x, Tree.Mem x t → p x = true := by
  intro t
  induction t with
  | leaf => intro _ x hx; cases hx
  | node l k s r ihl ihr =>
    intro h x hx
    simp only [Tree.all, Bool.and_eq_true] at h
    cases hx with
    | here => exact h.1.1
    | left hx => exact ihl h.1.2 x hx
    | right hx => exact ihr h.2 x hx

def explore (c : Cfg) : Nat → List St → Tree → Tree
  | 0, _, V => V
  | _ + 1, [], V => V
  | f + 1, s :: work, V =>
    if V.find (enc s) s then explore c f work V
    else explore c f (succs c s ++ work) (V.insert (enc s) s)

def Closed (c : Cfg) (P : St → Bool) (V : Tree) : Bool :=
  V.all fun s => P s && (succs c s).all fun t => V.find (enc t) t

def check (c : Cfg) (n : Nat) (P : St → Bool) (fuel : Nat) : Bool :=
  let V := explore c fuel [init n] .leaf
  V.find (enc (init n)) (init n) && Closed c P V

theorem check_sound (c : Cfg) (n : Nat) (P : St → Bool) (fuel : Nat)
    (h : check c n P fuel = true) : ∀ s, (lts c n).Reachable s → P s = true := by
  simp only [check, Bool.and_eq_true] at h
  obtain ⟨hi, hc⟩ := h
  generalize explore c fuel [init n] .leaf = V at hi hc
  have hc' := Tree.all_sound _ V hc
  have ind : (lts c n).Inductive (Tree.Mem · V) := by
    refine ⟨fun s hs => hs ▸ Tree.find_sound _ _ V hi, fun s l s' hs h => ?_⟩
    have := hc' s hs
    simp only [Bool.and_eq_true, List.all_eq_true] at this
    exact Tree.find_sound _ _ V (this.2 s' (mem_succs c s s' l h))
  intro s hr
  have := hc' s (ind.reachable s hr)
  simp only [Bool.and_eq_true] at this
  exact this.1

/-- Boolean versions of the specification. -/
def specB (s : St) : Bool :=
  !s.uaf &&
  s.ws.all (fun w => w.pc == .term || (!Freed w && !s.stopF)) &&
  (s.m != .fin ||
    (s.ws.all (fun w => w.detached || (w.ctxF && w.statsF && w.lisF)) &&
     (!(s.ws.all (fun w => !w.detached)) || s.stopF)))

/-- Bounded (1 and 2 workers, every interleaving, exhaustive): the fixed
drain meets `specB`. The general proof is `fixed_safe`; this is an
independent check of the same model by state enumeration. -/
theorem bounded_fixed : check cfgFixed 1 specB 400 = true ∧ check cfgFixed 2 specB 4000 = true := by
  decide +kernel

/-- Bounded (1 and 2 workers): `shutdown()` meets `specB`. -/
theorem bounded_shutdown :
    check cfgShutdown 1 specB 400 = true ∧ check cfgShutdown 2 specB 4000 = true := by
  decide +kernel

/-- The explorer is not vacuous: on the code at 59bda50 (`drain(timeout_ms >
0)`, one worker) it reports a violation. -/
theorem bounded_impl_fails : check cfgImpl 1 specB 400 = false := by
  decide +kernel

end Flare.L5.Scheduler
