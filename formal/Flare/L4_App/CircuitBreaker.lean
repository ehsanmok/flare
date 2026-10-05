import Flare.Core.LTS

/-!
# CircuitBreaker (flare/http/reliability.mojo:413-485)

The breaker keeps a leaked 3-slot cell shared by every worker copy:
`[0]` state (0 closed, 1 open, 2 half-open), `[1]` consecutive failures,
`[2]` opened-at ns. Unlike `RateLimit`, `serve` takes no lock: the entry
check (:460-472) and the outcome bookkeeping (:473-485) are separate, and
the inner handler runs in between. Concurrent workers can therefore
interleave whole requests, so the model is an LTS whose labels are request
*arrivals* (the entry check) and request *completions* (the outcome
bookkeeping), with any number of requests in flight.

Granularity: arrival and completion are each one atomic step. This is
coarser than the Mojo code (each is several separate atomic loads/stores),
so every trace of the model is a trace of the code; counterexamples found
here are real. Properties proved for the *fixed* model assume the fix makes
the entry atomic (compare-and-swap on the OPEN -> HALF_OPEN transition), as
the repro's fix text says.

Time is a ghost-free `Int` clock (ns, `perf_counter_ns`); `cooldown` is
`cooldown_ms * 1_000_000` (no wrap for `cooldown_ms < 9.2·10^12`).

Spec (written from the docstring :414-427 and the module docstring
:31-34): after `failure_threshold` consecutive failures the breaker opens
and fast-fails for `cooldown_ms` *from the moment it opened*; then exactly
one probe is let through (half-open); success closes, failure re-opens.
Ghost fields: `openedAt` (true time the breaker last (re)opened) and
`halfAdmits` (admissions since the breaker last entered half-open).

`stepG fix41 fix42` is the transliteration, with two switches for the two
minimal fixes (`false false` is the pre-fix code at 59bda50, `stepOld`):
* `fix41`: stamp opened-at with the completion time, not the arrival time
  (APP-41, fixed: the shipped code, `stepShipped`);
* `fix42`: fast-fail arrivals while half-open (APP-42, not yet fixed).

Results:
* `step_counts_inv` (impl, general): `fails ≥ 0`, closed → `fails < thr`,
  open/half-open → `fails ≥ thr` in every reachable state.
* `step_success_closes`, `step_failure_reopens`, `step_open_rejects`
  (impl, general): the sequential transition rules.
* `Flare.Bugs.APP_41`, `Flare.Bugs.APP_42`: counterexample traces for the
  cooldown and single-probe clauses, and proofs that the fixed models meet
  them.
-/
namespace Flare.L4.CircuitBreaker

inductive Br | closed | opn | half
  deriving DecidableEq, Repr

structure Cell where
  st : Br
  fails : Int
  opened : Int
  deriving DecidableEq, Repr

structure Req where
  id : Nat
  start : Int
  deriving DecidableEq, Repr

structure S where
  cell : Cell
  inflight : List Req
  clock : Int
  openedAt : Int
  halfAdmits : Nat
  deriving DecidableEq, Repr

inductive Lbl
  | arrive (id : Nat) (now : Int)
  | finish (id : Nat) (now : Int) (failed : Bool)
  deriving DecidableEq, Repr

def initS : S := ⟨⟨.closed, 0, 0⟩, [], 0, 0, 0⟩

/-- Entry check of `serve` (threshold > 0). A fast-fail (503) leaves the
cell untouched; an admission adds the request to the in-flight set.
mirrors flare/http/reliability.mojo:460-472 (fixed, APP-41) -/
def arrive (fix42 : Bool) (cooldown : Int) (s : S) (id : Nat) (now : Int) : S :=
  let s := { s with clock := now }
  if s.cell.st = .opn ∧ now - s.cell.opened < cooldown then s
  else if fix42 ∧ s.cell.st = .half then s
  else if s.cell.st = .opn then
    { s with cell := { s.cell with st := .half }, halfAdmits := 1,
             inflight := s.inflight ++ [⟨id, now⟩] }
  else if s.cell.st = .half then
    { s with halfAdmits := s.halfAdmits + 1, inflight := s.inflight ++ [⟨id, now⟩] }
  else { s with inflight := s.inflight ++ [⟨id, now⟩] }

/-- `_record_failure(now)` / `_record_success()` after the inner call;
`start` is the `now` read on entry (:461), `now` the completion time. The
shipped code (`fix41`) passes `perf_counter_ns()` read at the completion to
`_record_failure` (:481, :484); the pre-fix code passed `start`.
mirrors flare/http/reliability.mojo:447-452, 473-485 (fixed, APP-41) -/
def finish (fix41 : Bool) (thr : Int) (s : S) (r : Req) (now : Int) (failed : Bool) : S :=
  let s := { s with clock := now, inflight := s.inflight.erase r }
  if failed then
    let f := s.cell.fails + 1
    if f ≥ thr then
      { s with cell := ⟨.opn, f, if fix41 then now else r.start⟩, openedAt := now }
    else { s with cell := { s.cell with fails := f } }
  else { s with cell := { s.cell with fails := 0, st := .closed } }

/-- Executable step: arrivals need a fresh id, completions an in-flight
id; the clock is monotone (`Flare.Assumptions.MonotoneClock`).
mirrors flare/http/reliability.mojo:460-485 (fixed, APP-41) -/
def stepG (fix41 fix42 : Bool) (thr cooldown : Int) (s : S) : Lbl → Option S
  | .arrive id now =>
    if s.clock ≤ now ∧ (s.inflight.all fun r => r.id != id) then
      some (arrive fix42 cooldown s id now)
    else none
  | .finish id now failed =>
    if s.clock ≤ now then
      match s.inflight.find? (fun r => r.id == id) with
      | some r => some (finish fix41 thr s r now failed)
      | none => none
    else none

/-- The pre-fix code (59bda50), before APP-41 was fixed. -/
def stepOld (thr cooldown : Int) : S → Lbl → Option S := stepG false false thr cooldown

/-- The shipped code: APP-41 is fixed (the opening is stamped with the
completion time); APP-42 is not yet. -/
def stepShipped (thr cooldown : Int) : S → Lbl → Option S := stepG true false thr cooldown

def lts (fix41 fix42 : Bool) (thr cooldown : Int) : LTS S Lbl :=
  LTS.ofFn (fun s => s = initS) (stepG fix41 fix42 thr cooldown)

/-- Failure-count invariant. -/
def CountsInv (thr : Int) (s : S) : Prop :=
  0 ≤ s.cell.fails ∧ (s.cell.st = .closed → s.cell.fails < thr) ∧
  (s.cell.st ≠ .closed → thr ≤ s.cell.fails)

theorem counts_inductive (f41 f42 : Bool) (thr cd : Int) (hthr : 0 < thr) :
    (lts f41 f42 thr cd).Inductive (CountsInv thr) where
  init := by
    intro s hs; subst hs; simp [CountsInv, initS]; omega
  step := by
    intro s l s' hinv hstep
    obtain ⟨h0, h1, h2⟩ := hinv
    simp only [lts, LTS.ofFn] at hstep
    cases l with
    | arrive id now =>
      simp only [stepG] at hstep
      split at hstep
      · injection hstep with hstep; subst hstep
        simp only [arrive]
        split
        · exact ⟨h0, h1, h2⟩
        · split
          · exact ⟨h0, h1, h2⟩
          · split
            · next hst => refine ⟨h0, by simp, fun _ => h2 (by rw [hst]; simp)⟩
            · split <;> exact ⟨h0, h1, h2⟩
      · cases hstep
    | finish id now failed =>
      simp only [stepG] at hstep
      split at hstep
      · split at hstep
        · next r _ =>
          injection hstep with hstep; subst hstep
          simp only [finish]
          split
          · split
            · next hf => refine ⟨by simp; omega, by simp, fun _ => by simp; omega⟩
            · next hf =>
              refine ⟨by simp; omega, fun _ => by simp; omega, fun hc => ?_⟩
              simp at hc; have := h2 hc; simp; omega
          · refine ⟨by simp, fun _ => by simp; omega, fun hc => by simp at hc⟩
        · cases hstep
      · cases hstep

/-- Every reachable state of the pre-fix code satisfies the failure-count
bounds. -/
theorem step_counts_inv (thr cd : Int) (hthr : 0 < thr) (s : S)
    (h : (lts false false thr cd).Reachable s) : CountsInv thr s :=
  (counts_inductive false false thr cd hthr).reachable s h

/-- Every reachable state of the shipped code satisfies the failure-count
bounds. -/
theorem step_counts_inv_shipped (thr cd : Int) (hthr : 0 < thr) (s : S)
    (h : (lts true false thr cd).Reachable s) : CountsInv thr s :=
  (counts_inductive true false thr cd hthr).reachable s h

/-- While open and within the cooldown, every arrival fast-fails: the cell
and the in-flight set are unchanged. -/
theorem step_open_rejects (f42 : Bool) (cd : Int) (s : S) (id : Nat) (now : Int)
    (ho : s.cell.st = .opn) (hc : now - s.cell.opened < cd) :
    arrive f42 cd s id now = { s with clock := now } := by
  simp [arrive, ho, hc]

/-- A success always closes the breaker and clears the failure count
(in particular a successful half-open probe closes it). -/
theorem step_success_closes (f41 : Bool) (thr : Int) (s : S) (r : Req) (now : Int) :
    (finish f41 thr s r now false).cell.st = .closed ∧
    (finish f41 thr s r now false).cell.fails = 0 := by
  simp [finish]

/-- A failure while half-open (or open) re-opens the breaker, given the
count invariant. -/
theorem step_failure_reopens (f41 : Bool) (thr : Int) (s : S) (r : Req) (now : Int)
    (hinv : CountsInv thr s) (hst : s.cell.st ≠ .closed) :
    (finish f41 thr s r now true).cell.st = .opn := by
  have := hinv.2.2 hst
  simp only [finish]
  rw [if_pos trivial, if_pos (show s.cell.fails + 1 ≥ thr by omega)]

end Flare.L4.CircuitBreaker

namespace Flare.L4.CircuitBreaker

/-- Run a list of labels with the executable step function. -/
def runAll (f41 f42 : Bool) (thr cd : Int) : S → List Lbl → Option S
  | s, [] => some s
  | s, l :: ls => match stepG f41 f42 thr cd s l with
    | some s' => runAll f41 f42 thr cd s' ls
    | none => none

theorem runAll_run (f41 f42 : Bool) (thr cd : Int) :
    ∀ (ls : List Lbl) (s s' : S), runAll f41 f42 thr cd s ls = some s' →
      (lts f41 f42 thr cd).Run s ls s'
  | [], s, s', h => by simp [runAll] at h; subst h; exact .nil _
  | l :: ls, s, s', h => by
    simp only [runAll] at h
    split at h
    · next s1 h1 => exact .cons h1 (runAll_run f41 f42 thr cd ls s1 s' h)
    · cases h

theorem reachable_of_runAll (f41 f42 : Bool) (thr cd : Int) (ls : List Lbl) (s : S)
    (h : runAll f41 f42 thr cd initS ls = some s) : (lts f41 f42 thr cd).Reachable s :=
  ⟨initS, ls, rfl, runAll_run f41 f42 thr cd ls initS s h⟩

/-- Spec clause (cooldown): every OPEN -> HALF_OPEN transition is an
arrival at least `cooldown` after the breaker (re)opened. -/
def CooldownOK (M : LTS S Lbl) (cd : Int) : Prop :=
  ∀ s l s', M.Reachable s → M.step s l s' → s.cell.st = .opn → s'.cell.st = .half →
    ∃ id now, l = .arrive id now ∧ cd ≤ now - s.openedAt

/-- Spec clause (single probe): while half-open at most one request has
been admitted since the breaker entered half-open. -/
def SingleProbe (M : LTS S Lbl) : Prop :=
  ∀ s, M.Reachable s → s.cell.st = .half → s.halfAdmits ≤ 1

end Flare.L4.CircuitBreaker
