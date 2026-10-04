import Flare.Core.LTS

/-!
# AsyncRT task cell: interleaving semantics

`flare/runtime/_asyncrt.mojo` runs a `ThreadHandle` task on Mojo's AsyncRT
pool. Each task owns a four-slot heap *cell* (`arg`, `state`, `started`,
`chain`). Two threads race on it:

* the **trampoline** (`_asyncrt_trampoline`) on a pool worker: store
  `started`, load `arg`, run `start`, CAS `state` RUNNING -> DONE, then
  complete the chain; if the CAS lost (state was DETACHED) it completes the
  chain and destroys the cell itself;
* the **owner** holding the `ThreadHandle`: `join` (`asyncrt_join`: wait on
  the chain, destroy the cell, then the handle zeroes `_thread_id`),
  `detach` (`asyncrt_detach`: CAS RUNNING -> DETACHED; if that fails wait
  on the chain and destroy), `wait_started` (poll `started`), or dropping
  the handle (no `__del__`, so nothing runs).

## Semantics

A state is the shared heap (`cs`, `started`, `chain`, `frees`) plus each
thread's program counter. Every atomic operation (one load, store, CAS,
chain `Complete`, chain `Wait` return, `DestroyChain`+`free`) is one step,
and the scheduler picks either thread at any point (`Step` has no
fairness constraint). Every step that dereferences the cell sets `uaf`
when the cell has already been freed, and every destroy increments
`frees`, so "no use after free" is `uaf = false` and "no double free" is
`frees ≤ 1`.

## Memory model (assumption, stated explicitly)

Sequential consistency. Justification against the Mojo orderings:
`_cas_state` uses `Atomic.compare_exchange` with the stdlib default
(`_DEFAULT_COMPARISON_ORDERING = SEQUENTIAL` on CPU targets), `_load` is
ACQUIRE and the `started` store is RELEASE. All cross-thread decisions are
made on the single location `state` via RMWs, whose modification order is
total under any ordering, so the CAS-winner case split is exact. All data
flow from the task to the owner (the start routine's effects, `result`
here) goes through the chain: `Complete` = `copy().emplace()` (release)
and `Wait` = `await` (acquire) in `Mojo/lib/CompilerRT/AsyncRT.cpp`.

## AsyncRT assumptions (encoded in the step relation)

* AR-1: `KGEN_CompilerRT_AsyncRT_Complete` reads the cell only *before*
  the chain becomes available (`unwrap(chain).copy().emplace()`: the copy
  takes its own reference first). Modelled by `tCompleteWon` (touches the
  cell, publishes) followed by `tTail` (does not touch the cell unless
  `Cfg.tailTouches`). `ar1_load_bearing` shows the protocol is unsafe
  without AR-1.
* AR-2: `Wait` returns only after `Complete` published (`oJoinWait`,
  `oDetachWait` require `chain`).
* AR-3: the start routine does not touch the cell (it receives `arg`).
-/
namespace Flare.L5.AsyncRT

/-- Cell slot `[1]`: `_STATE_RUNNING = 0`, `_STATE_DONE = 1`,
`_STATE_DETACHED = 2`. -/
inductive CS | running | done | detached
  deriving DecidableEq, Repr

/-- Trampoline program counter.
mirrors flare/runtime/_asyncrt.mojo:139-168 @59bda50 -/
inductive TPc
  | queued       -- enqueued by Execute, not yet picked up
  | started      -- after `started := 1` (line 156)
  | argLoaded    -- after `_load(cell, _CELL_ARG)` (line 159)
  | ran          -- `start(arg)` returned (line 160)
  | wonPre       -- CAS RUNNING -> DONE succeeded (line 161)
  | wonTail      -- Complete published the chain, still returning (line 162)
  | lostPre      -- CAS failed: state was DETACHED (line 163)
  | lostDestroy  -- chain completed, about to destroy (line 167)
  | exit
  deriving DecidableEq, Repr

/-- Owner (handle holder) program counter.
mirrors flare/runtime/_asyncrt.mojo:203-262 and
flare/runtime/_thread.mojo:211-232,246-270,276-287 @59bda50 -/
inductive OPc
  | idle
  | waitStarted    -- polling `started` (asyncrt_wait_started, line 251)
  | joinWait       -- in `_chain_wait` (line 210)
  | joinDestroy    -- about to `_destroy_cell` (line 211)
  | joinRet        -- asyncrt_join returned, handle zeroes id (_thread.mojo:231)
  | detachCas      -- about to CAS RUNNING -> DETACHED (line 222)
  | detachWait     -- CAS failed, in `_chain_wait` (line 223)
  | detachDestroy  -- about to `_destroy_cell` (line 224)
  | detachRet      -- asyncrt_detach returned, handle zeroes id (_thread.mojo:269)
  deriving DecidableEq, Repr

structure St where
  cs : CS
  /-- cell slot `[2]` -/
  started : Bool
  /-- the start routine's effects (its result) have been produced -/
  result : Bool
  /-- the cell's `AsyncValueRef<Chain>` has been completed -/
  chain : Bool
  /-- number of `_destroy_cell` calls so far -/
  frees : Nat
  /-- some step dereferenced the cell after it was freed -/
  uaf : Bool
  tpc : TPc
  opc : OPc
  /-- the owner's `ThreadHandle._thread_id ≠ 0` -/
  live : Bool
  /-- the handle was dropped while live (no `__del__` runs) -/
  dropped : Bool
  /-- `join()` has returned to the owner -/
  joined : Bool
  deriving DecidableEq, Repr

/-- Model knobs. The real system is `Cfg.real`; the others exist only to
show which ingredients the safety proof depends on. -/
structure Cfg where
  /-- `Complete` touches the cell after publishing (violates AR-1) -/
  tailTouches : Bool
  /-- the handle's `_thread_id == 0` short-circuit is in force -/
  guard : Bool

def Cfg.real : Cfg := ⟨false, true⟩

/-- mirrors flare/runtime/_asyncrt.mojo:180-199 @59bda50 (zeroed cell,
state RUNNING, chain initialised, enqueued) -/
def init : St :=
  { cs := .running, started := false, result := false, chain := false,
    frees := 0, uaf := false, tpc := .queued, opc := .idle, live := true,
    dropped := false, joined := false }

/-- Dereferencing the cell: flags a use after free. -/
def St.touch (s : St) : Bool := if s.frees = 0 then s.uaf else true

/-- The `uaf` flag after `Complete` returns on the DONE path (AR-1: no
cell access after publishing, unless `tailTouches`). -/
def tailUaf (c : Cfg) (s : St) : Bool := if c.tailTouches then s.touch else s.uaf

/-- Step labels: one per atomic operation. -/
inductive Ev
  | tStart | tLoadArg | tRun | tCas | tComplete | tTail | tDestroy
  | oJoin | oDetach | oWaitStarted | oPoll | oDrop
  | oWait | oDestroy | oCas | oZero
  deriving DecidableEq, Repr

/-- The interleaving small-step relation. Trampoline steps fire whenever
`tpc` allows, owner steps whenever `opc` allows; the scheduler is the
non-deterministic choice of constructor.
mirrors flare/runtime/_asyncrt.mojo:139-262 @59bda50 and
flare/runtime/_thread.mojo:211-232,246-270,276-287 @59bda50 -/
inductive Step (c : Cfg) : St → Ev → St → Prop
  -- trampoline (_asyncrt.mojo:155-168)
  | tStart (s : St) : s.tpc = .queued →
      Step c s .tStart { s with started := true, uaf := s.touch, tpc := .started }
  | tLoadArg (s : St) : s.tpc = .started →
      Step c s .tLoadArg { s with uaf := s.touch, tpc := .argLoaded }
  | tRun (s : St) : s.tpc = .argLoaded →
      Step c s .tRun { s with result := true, tpc := .ran }
  | tCasWin (s : St) : s.tpc = .ran → s.cs = .running →
      Step c s .tCas { s with cs := .done, uaf := s.touch, tpc := .wonPre }
  | tCasLose (s : St) : s.tpc = .ran → s.cs ≠ .running →
      Step c s .tCas { s with uaf := s.touch, tpc := .lostPre }
  | tCompleteWon (s : St) : s.tpc = .wonPre →
      Step c s .tComplete { s with chain := true, uaf := s.touch, tpc := .wonTail }
  | tTail (s : St) : s.tpc = .wonTail →
      Step c s .tTail
        { s with uaf := tailUaf c s, tpc := .exit }
  | tCompleteLost (s : St) : s.tpc = .lostPre →
      Step c s .tComplete { s with chain := true, uaf := s.touch, tpc := .lostDestroy }
  | tDestroy (s : St) : s.tpc = .lostDestroy →
      Step c s .tDestroy { s with frees := s.frees + 1, uaf := s.touch, tpc := .exit }
  -- owner: handle-level entry points (_thread.mojo:225-232, 265-270, 286-287)
  | oJoin (s : St) : s.opc = .idle → (s.live = true ∨ c.guard = false) →
      Step c s .oJoin { s with opc := .joinWait }
  | oDetach (s : St) : s.opc = .idle → (s.live = true ∨ c.guard = false) →
      Step c s .oDetach { s with opc := .detachCas }
  | oWaitStarted (s : St) : s.opc = .idle → (s.live = true ∨ c.guard = false) →
      Step c s .oWaitStarted { s with opc := .waitStarted }
  | oNoop (s : St) (e : Ev) : s.opc = .idle → s.live = false → c.guard = true →
      (e = .oJoin ∨ e = .oDetach ∨ e = .oWaitStarted) → Step c s e s
  | oDrop (s : St) : s.opc = .idle → s.live = true →
      Step c s .oDrop { s with live := false, dropped := true }
  -- owner: asyncrt_wait_started (_asyncrt.mojo:251)
  | oPollYes (s : St) : s.opc = .waitStarted → s.started = true →
      Step c s .oPoll { s with uaf := s.touch, opc := .idle }
  | oPollNo (s : St) : s.opc = .waitStarted → s.started = false →
      Step c s .oPoll { s with uaf := s.touch }
  -- owner: asyncrt_join (_asyncrt.mojo:209-211), then _thread.mojo:231
  | oJoinWait (s : St) : s.opc = .joinWait → s.chain = true →
      Step c s .oWait { s with uaf := s.touch, opc := .joinDestroy }
  | oJoinDestroy (s : St) : s.opc = .joinDestroy →
      Step c s .oDestroy { s with frees := s.frees + 1, uaf := s.touch, opc := .joinRet }
  | oJoinRet (s : St) : s.opc = .joinRet →
      Step c s .oZero { s with live := false, joined := true, opc := .idle }
  -- owner: asyncrt_detach (_asyncrt.mojo:221-224), then _thread.mojo:269
  | oCasWin (s : St) : s.opc = .detachCas → s.cs = .running →
      Step c s .oCas { s with cs := .detached, uaf := s.touch, opc := .detachRet }
  | oCasLose (s : St) : s.opc = .detachCas → s.cs ≠ .running →
      Step c s .oCas { s with uaf := s.touch, opc := .detachWait }
  | oDetachWait (s : St) : s.opc = .detachWait → s.chain = true →
      Step c s .oWait { s with uaf := s.touch, opc := .detachDestroy }
  | oDetachDestroy (s : St) : s.opc = .detachDestroy →
      Step c s .oDestroy { s with frees := s.frees + 1, uaf := s.touch, opc := .detachRet }
  | oDetachRet (s : St) : s.opc = .detachRet →
      Step c s .oZero { s with live := false, opc := .idle }

/-- The LTS of the cell protocol under configuration `c`. -/
def cell (c : Cfg) : LTS St Ev where
  init s := s = init
  step := Step c

/-! ## Executable step function (deterministic once the label is fixed) -/

/-- Executable successor: given the scheduled operation, the next state.
mirrors flare/runtime/_asyncrt.mojo:139-262 @59bda50 -/
def stepFn (c : Cfg) (s : St) : Ev → Option St
  | .tStart => if s.tpc = .queued then
      some { s with started := true, uaf := s.touch, tpc := .started } else none
  | .tLoadArg => if s.tpc = .started then
      some { s with uaf := s.touch, tpc := .argLoaded } else none
  | .tRun => if s.tpc = .argLoaded then some { s with result := true, tpc := .ran } else none
  | .tCas => if s.tpc = .ran then
      (if s.cs = .running then some { s with cs := .done, uaf := s.touch, tpc := .wonPre }
       else some { s with uaf := s.touch, tpc := .lostPre }) else none
  | .tComplete =>
      if s.tpc = .wonPre then some { s with chain := true, uaf := s.touch, tpc := .wonTail }
      else if s.tpc = .lostPre then
        some { s with chain := true, uaf := s.touch, tpc := .lostDestroy }
      else none
  | .tTail => if s.tpc = .wonTail then
      some { s with uaf := tailUaf c s, tpc := .exit } else none
  | .tDestroy => if s.tpc = .lostDestroy then
      some { s with frees := s.frees + 1, uaf := s.touch, tpc := .exit } else none
  | .oJoin => if s.opc = .idle then
      (if s.live = true ∨ c.guard = false then some { s with opc := .joinWait } else some s)
      else none
  | .oDetach => if s.opc = .idle then
      (if s.live = true ∨ c.guard = false then some { s with opc := .detachCas } else some s)
      else none
  | .oWaitStarted => if s.opc = .idle then
      (if s.live = true ∨ c.guard = false then some { s with opc := .waitStarted } else some s)
      else none
  | .oDrop => if s.opc = .idle ∧ s.live = true then
      some { s with live := false, dropped := true } else none
  | .oPoll => if s.opc = .waitStarted then
      (if s.started = true then some { s with uaf := s.touch, opc := .idle }
       else some { s with uaf := s.touch }) else none
  | .oWait =>
      if s.opc = .joinWait ∧ s.chain = true then some { s with uaf := s.touch, opc := .joinDestroy }
      else if s.opc = .detachWait ∧ s.chain = true then
        some { s with uaf := s.touch, opc := .detachDestroy }
      else none
  | .oDestroy =>
      if s.opc = .joinDestroy then
        some { s with frees := s.frees + 1, uaf := s.touch, opc := .joinRet }
      else if s.opc = .detachDestroy then
        some { s with frees := s.frees + 1, uaf := s.touch, opc := .detachRet }
      else none
  | .oCas => if s.opc = .detachCas then
      (if s.cs = .running then some { s with cs := .detached, uaf := s.touch, opc := .detachRet }
       else some { s with uaf := s.touch, opc := .detachWait }) else none
  | .oZero =>
      if s.opc = .joinRet then some { s with live := false, joined := true, opc := .idle }
      else if s.opc = .detachRet then some { s with live := false, opc := .idle }
      else none

/-- The relational and executable semantics agree. -/
theorem step_iff_stepFn (c : Cfg) (s s' : St) (e : Ev) :
    Step c s e s' ↔ stepFn c s e = some s' := by
  constructor
  · intro h
    cases h <;> simp_all [stepFn] <;> grind
  · intro h
    cases e <;> simp only [stepFn] at h <;> (repeat' split at h) <;>
      (try simp only [Option.some.injEq, reduceCtorEq] at h) <;> (try subst h) <;>
      first
        | exact Step.tStart _ ‹_›
        | exact Step.tLoadArg _ ‹_›
        | exact Step.tRun _ ‹_›
        | exact Step.tCasWin _ ‹_› ‹_›
        | exact Step.tCasLose _ ‹_› ‹_›
        | exact Step.tCompleteWon _ ‹_›
        | exact Step.tCompleteLost _ ‹_›
        | exact Step.tTail _ ‹_›
        | exact Step.tDestroy _ ‹_›
        | exact Step.oJoin _ ‹_› ‹_›
        | exact Step.oDetach _ ‹_› ‹_›
        | exact Step.oWaitStarted _ ‹_› ‹_›
        | (apply Step.oNoop _ _ ‹_› <;> grind)
        | exact Step.oDrop _ (by grind) (by grind)
        | exact Step.oPollYes _ ‹_› ‹_›
        | exact Step.oPollNo _ ‹_› (by grind)
        | exact Step.oJoinWait _ (by grind) (by grind)
        | exact Step.oDetachWait _ (by grind) (by grind)
        | exact Step.oJoinDestroy _ ‹_›
        | exact Step.oDetachDestroy _ ‹_›
        | exact Step.oCasWin _ ‹_› ‹_›
        | exact Step.oCasLose _ ‹_› ‹_›
        | exact Step.oJoinRet _ ‹_›
        | exact Step.oDetachRet _ ‹_›

/-! ## The inductive invariant (real configuration, all interleavings) -/

/-- Inductive invariant of the real protocol. Trampoline clauses `t*` pin
the heap per trampoline pc, owner clauses `o*` per owner pc; the CAS on
`cs` is what makes the two sides' "who frees" decisions exclusive. -/
def Inv (s : St) : Prop :=
  -- heap safety
  s.frees ≤ 1 ∧ s.uaf = false ∧
  (s.frees = 1 → s.chain = true) ∧
  (s.chain = true → s.result = true ∧ s.cs ≠ .running) ∧
  (s.tpc ≠ .queued → s.started = true) ∧
  -- trampoline
  ((s.tpc = .queued ∨ s.tpc = .started ∨ s.tpc = .argLoaded) →
      s.result = false ∧ s.chain = false ∧ s.cs ≠ .done) ∧
  (s.tpc = .ran → s.result = true ∧ s.chain = false ∧ s.cs ≠ .done) ∧
  (s.tpc = .wonPre → s.cs = .done ∧ s.result = true ∧ s.chain = false) ∧
  (s.tpc = .wonTail → s.cs = .done ∧ s.chain = true) ∧
  (s.tpc = .lostPre → s.cs = .detached ∧ s.result = true ∧ s.chain = false) ∧
  (s.tpc = .lostDestroy → s.cs = .detached ∧ s.chain = true ∧ s.frees = 0) ∧
  (s.tpc = .exit → s.chain = true ∧ (s.cs = .done ∨ (s.cs = .detached ∧ s.frees = 1))) ∧
  -- owner
  (((s.opc = .idle ∧ s.live = true) ∨ s.opc = .waitStarted ∨ s.opc = .joinWait ∨
      s.opc = .joinDestroy ∨ s.opc = .detachCas) →
      s.live = true ∧ s.cs ≠ .detached ∧ s.frees = 0 ∧ s.dropped = false ∧ s.joined = false) ∧
  (s.opc = .joinDestroy → s.chain = true) ∧
  (s.opc = .joinRet → s.live = true ∧ s.dropped = false ∧ s.joined = false ∧
      s.frees = 1 ∧ s.cs = .done) ∧
  ((s.opc = .detachWait ∨ s.opc = .detachDestroy) → s.live = true ∧ s.cs = .done ∧
      s.frees = 0 ∧ s.dropped = false ∧ s.joined = false) ∧
  (s.opc = .detachDestroy → s.chain = true) ∧
  (s.opc = .detachRet → s.live = true ∧ s.dropped = false ∧ s.joined = false ∧
      (s.cs = .detached ∨ (s.cs = .done ∧ s.frees = 1))) ∧
  ((s.opc = .idle ∧ s.live = false) →
      s.dropped = true ∨ s.cs = .detached ∨ (s.cs = .done ∧ s.frees = 1)) ∧
  (s.joined = true → s.opc = .idle ∧ s.live = false ∧ s.cs = .done ∧ s.frees = 1) ∧
  (s.dropped = true → s.opc = .idle ∧ s.live = false ∧ s.joined = false)

theorem inv_init : Inv init := by
  simp [Inv, init]

theorem inv_step (s : St) (e : Ev) (s' : St) (h : Inv s) (hs : Step Cfg.real s e s') :
    Inv s' := by
  have hcs : ∀ x : CS, x = .running ∨ x = .done ∨ x = .detached := by
    intro x; cases x <;> simp
  have htp : ∀ x : TPc, x = .queued ∨ x = .started ∨ x = .argLoaded ∨ x = .ran ∨
      x = .wonPre ∨ x = .wonTail ∨ x = .lostPre ∨ x = .lostDestroy ∨ x = .exit := by
    intro x; cases x <;> simp
  have hop : ∀ x : OPc, x = .idle ∨ x = .waitStarted ∨ x = .joinWait ∨ x = .joinDestroy ∨
      x = .joinRet ∨ x = .detachCas ∨ x = .detachWait ∨ x = .detachDestroy ∨
      x = .detachRet := by
    intro x; cases x <;> simp
  have h1 := hcs s.cs
  have h2 := htp s.tpc
  have h3 := hop s.opc
  unfold Inv at *
  cases hs <;> simp only [St.touch, tailUaf, Cfg.real] at * <;> grind

/-- **General inductive invariant** of the AsyncRT cell over every
interleaving of trampoline and owner. -/
theorem inv_inductive : (cell Cfg.real).Inductive Inv where
  init := by intro s h; cases h; exact inv_init
  step := inv_step

/-! ## Headline properties -/

/-- No double free: `_destroy_cell` runs at most once in any reachable state. -/
theorem free_at_most_once (s : St) (h : (cell Cfg.real).Reachable s) : s.frees ≤ 1 :=
  (inv_inductive.reachable s h).1

/-- No access after free: no step ever dereferences a freed cell. -/
theorem no_use_after_free (s : St) (h : (cell Cfg.real).Reachable s) : s.uaf = false :=
  (inv_inductive.reachable s h).2.1

/-- The chain is completed (and the task's result produced) before the cell
is destroyed. -/
theorem chain_before_free (s : St) (h : (cell Cfg.real).Reachable s) (hf : s.frees = 1) :
    s.chain = true ∧ s.result = true := by
  have hi := inv_inductive.reachable s h
  unfold Inv at hi
  have hc := hi.2.2.1 hf
  exact ⟨hc, (hi.2.2.2.1 hc).1⟩

/-- `join` returns only after the task reached DONE, completed its chain
and produced its result, and the cell has been freed exactly once. -/
theorem join_returns_after_done (s : St) (h : (cell Cfg.real).Reachable s)
    (hj : s.joined = true) :
    s.cs = .done ∧ s.chain = true ∧ s.result = true ∧ s.frees = 1 := by
  have hi := inv_inductive.reachable s h
  unfold Inv at hi
  grind

/-- A quiescent state: the task has exited and the owner is not inside a
call and no longer holds a live handle. -/
def Terminal (s : St) : Prop := s.tpc = .exit ∧ s.opc = .idle ∧ s.live = false

/-- No leak: unless the handle was dropped without `join`/`detach`, every
terminal state has freed the cell (exactly once, by `free_at_most_once`). -/
theorem no_leak (s : St) (h : (cell Cfg.real).Reachable s) (ht : Terminal s)
    (hd : s.dropped = false) : s.frees = 1 := by
  have hi := inv_inductive.reachable s h
  unfold Inv Terminal at *
  grind

/-- Freed exactly once in every terminal state reached via join or detach. -/
theorem freed_exactly_once (s : St) (h : (cell Cfg.real).Reachable s) (ht : Terminal s)
    (hd : s.dropped = false) : s.frees = 1 ∧ s.uaf = false :=
  ⟨no_leak s h ht hd, no_use_after_free s h⟩

/-- Deadlock freedom: in every reachable non-terminal state some thread can
make a non-stuttering step (in particular a waiting `join`/`detach` is
never blocked forever once the task has run). -/
theorem progress (s : St) (h : (cell Cfg.real).Reachable s)
    (hn : s.tpc ≠ .exit ∨ (s.opc ≠ .idle)) : ∃ e s', Step Cfg.real s e s' ∧ s' ≠ s := by
  have hi := inv_inductive.reachable s h
  unfold Inv at hi
  by_cases ht : s.tpc = .exit
  · have hc : s.chain = true := (hi.2.2.2.2.2.2.2.2.2.2.2.1 ht).1
    have hst : s.started = true := hi.2.2.2.2.1 (by simp [ht])
    have ho : s.opc ≠ .idle := by grind
    cases hop : s.opc with
    | idle => exact absurd hop ho
    | waitStarted => exact ⟨_, _, .oPollYes s hop hst, by intro e; have := congrArg St.opc e; simp_all⟩
    | joinWait => exact ⟨_, _, .oJoinWait s hop hc, by intro e; have := congrArg St.opc e; simp_all⟩
    | joinDestroy => exact ⟨_, _, .oJoinDestroy s hop, by intro e; have := congrArg St.opc e; simp_all⟩
    | joinRet => exact ⟨_, _, .oJoinRet s hop, by intro e; have := congrArg St.opc e; simp_all⟩
    | detachCas =>
      by_cases hr : s.cs = .running
      · exact ⟨_, _, .oCasWin s hop hr, by intro e; have := congrArg St.opc e; simp_all⟩
      · exact ⟨_, _, .oCasLose s hop hr, by intro e; have := congrArg St.opc e; simp_all⟩
    | detachWait => exact ⟨_, _, .oDetachWait s hop hc, by intro e; have := congrArg St.opc e; simp_all⟩
    | detachDestroy => exact ⟨_, _, .oDetachDestroy s hop, by intro e; have := congrArg St.opc e; simp_all⟩
    | detachRet => exact ⟨_, _, .oDetachRet s hop, by intro e; have := congrArg St.opc e; simp_all⟩
  · have tne : ∀ t : TPc, s.tpc = t → ∀ s' : St, s'.tpc ≠ t → s' ≠ s := by
      intro t h1 s' h2 e; subst e; exact h2 h1
    cases htp : s.tpc with
    | exit => exact absurd htp ht
    | queued => exact ⟨_, _, .tStart s htp, tne _ htp _ (by simp)⟩
    | started => exact ⟨_, _, .tLoadArg s htp, tne _ htp _ (by simp)⟩
    | argLoaded => exact ⟨_, _, .tRun s htp, tne _ htp _ (by simp)⟩
    | ran =>
      by_cases hr : s.cs = .running
      · exact ⟨_, _, .tCasWin s htp hr, tne _ htp _ (by simp)⟩
      · exact ⟨_, _, .tCasLose s htp hr, tne _ htp _ (by simp)⟩
    | wonPre => exact ⟨_, _, .tCompleteWon s htp, tne _ htp _ (by simp)⟩
    | wonTail => exact ⟨_, _, .tTail s htp, tne _ htp _ (by simp)⟩
    | lostPre => exact ⟨_, _, .tCompleteLost s htp, tne _ htp _ (by simp)⟩
    | lostDestroy => exact ⟨_, _, .tDestroy s htp, tne _ htp _ (by simp)⟩

/-! ## Repeated / out-of-order owner calls (handle guard in force) -/

/-- Join twice, detach after join, detach after detach, join after detach,
`wait_started` after either: once the handle is zeroed every call is a
no-op on the shared state. -/
theorem calls_after_zero_are_noops (s s' : St) (e : Ev)
    (he : e = .oJoin ∨ e = .oDetach ∨ e = .oWaitStarted)
    (hi : s.opc = .idle) (hl : s.live = false) (hs : Step Cfg.real s e s') : s' = s := by
  cases hs <;> simp_all [Cfg.real]

/-- Detach racing the trampoline's CAS: whichever CAS wins, exactly one
side frees. Here: the trampoline's CAS wins first, so the owner's detach
CAS fails, waits on the chain and frees; the trampoline never frees. -/
example : ∃ s', (cell Cfg.real).Run init
    [.tStart, .tLoadArg, .tRun, .tCas, .oDetach, .oCas, .tComplete, .oWait, .oDestroy,
     .tTail, .oZero] s' ∧ Terminal s' ∧ s'.frees = 1 ∧ s'.uaf = false :=
  ⟨_, .cons (.tStart _ rfl) <| .cons (.tLoadArg _ rfl) <| .cons (.tRun _ rfl) <|
      .cons (.tCasWin _ rfl rfl) <| .cons (.oDetach _ rfl (.inl rfl)) <|
      .cons (.oCasLose _ rfl (by simp)) <| .cons (.tCompleteWon _ rfl) <|
      .cons (.oDetachWait _ rfl rfl) <| .cons (.oDetachDestroy _ rfl) <|
      .cons (.tTail _ rfl) <| .cons (.oDetachRet _ rfl) <| .nil _,
   by simp [Terminal], rfl, rfl⟩

/-! ## Which ingredients the proof needs -/

/-- AR-1 is load-bearing: if `Complete` touched the cell after making the
chain available, a joiner woken by it could free the cell first. -/
theorem ar1_load_bearing :
    ∃ s', (cell ⟨true, true⟩).Run init
      [.tStart, .tLoadArg, .tRun, .tCas, .tComplete, .oJoin, .oWait, .oDestroy, .tTail] s' ∧
      s'.uaf = true :=
  ⟨_, .cons (.tStart _ rfl) <| .cons (.tLoadArg _ rfl) <| .cons (.tRun _ rfl) <|
      .cons (.tCasWin _ rfl rfl) <| .cons (.tCompleteWon _ rfl) <|
      .cons (.oJoin _ rfl (.inl rfl)) <| .cons (.oJoinWait _ rfl rfl) <|
      .cons (.oJoinDestroy _ rfl) <| .cons (.tTail _ rfl) <| .nil _,
   rfl⟩

/-- The handle's `_thread_id` zeroing is load-bearing: without it, a
`join` after a successful `detach` double-frees the cell (the trampoline
frees it on the DETACHED path, the joiner frees it again). Mojo's move-only
handle plus the zeroing in `_thread.mojo:231,269` rule this out. -/
theorem guard_load_bearing :
    ∃ s', (cell ⟨false, false⟩).Run init
      [.oDetach, .oCas, .oZero, .oJoin, .tStart, .tLoadArg, .tRun, .tCas, .tComplete,
       .tDestroy, .oWait, .oDestroy] s' ∧ s'.frees = 2 ∧ s'.uaf = true :=
  ⟨_, .cons (.oDetach _ rfl (.inl rfl)) <| .cons (.oCasWin _ rfl rfl) <|
      .cons (.oDetachRet _ rfl) <| .cons (.oJoin _ rfl (.inr rfl)) <|
      .cons (.tStart _ rfl) <| .cons (.tLoadArg _ rfl) <| .cons (.tRun _ rfl) <|
      .cons (.tCasLose _ rfl (by simp)) <| .cons (.tCompleteLost _ rfl) <|
      .cons (.tDestroy _ rfl) <| .cons (.oJoinWait _ rfl rfl) <|
      .cons (.oJoinDestroy _ rfl) <| .nil _,
   rfl, rfl⟩

/-- Dropping a live handle (no `__del__`) leaks the cell: documented
contract in `_thread.mojo:20-22` ("join before dropping, or detach"). -/
theorem drop_leaks :
    ∃ s', (cell Cfg.real).Run init
      [.oDrop, .tStart, .tLoadArg, .tRun, .tCas, .tComplete, .tTail] s' ∧
      Terminal s' ∧ s'.frees = 0 :=
  ⟨_, .cons (.oDrop _ rfl rfl) <| .cons (.tStart _ rfl) <| .cons (.tLoadArg _ rfl) <|
      .cons (.tRun _ rfl) <| .cons (.tCasWin _ rfl rfl) <| .cons (.tCompleteWon _ rfl) <|
      .cons (.tTail _ rfl) <| .nil _,
   by simp [Terminal, init], rfl⟩

end Flare.L5.AsyncRT
