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
so every trace of the model is a trace of the code, given that the entry's
OPEN -> HALF_OPEN transition is a compare-and-swap (APP-42).

Time is a ghost-free `Int` clock (ns, `perf_counter_ns`); `cooldown` is
`cooldown_ms * 1_000_000` (no wrap for `cooldown_ms < 9.2·10^12`).

Spec (written from the docstring :414-427 and the module docstring
:31-34): after `failure_threshold` consecutive failures the breaker opens
and fast-fails for `cooldown_ms` *from the moment it opened*; then exactly
one probe is let through (half-open); success closes, failure re-opens.
Ghost fields: `openedAt` (true time the breaker last (re)opened) and
`halfAdmits` (admissions since the breaker last entered half-open).

`step` is the transliteration of the shipped code: opened-at is stamped
with the completion time (APP-41) and arrivals fast-fail while half-open,
the OPEN -> HALF_OPEN claim being a compare-and-swap (APP-42).

Results, for every threshold and cooldown:
* `step_counts_inv`: `fails ≥ 0`, closed → `fails < thr`, open/half-open →
  `fails ≥ thr` in every reachable state.
* `step_success_closes`, `step_failure_reopens`, `step_open_rejects`: the
  sequential transition rules.
* `cooldown_respected`, `single_probe`: the cooldown and single-probe
  clauses.
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
mirrors flare/http/reliability.mojo#CircuitBreaker.serve sha=d30e4014ab39 at=664a9c00 (fixed, APP-41, APP-42) -/
def arrive (cooldown : Int) (s : S) (id : Nat) (now : Int) : S :=
  let s := { s with clock := now }
  if s.cell.st = .opn ∧ now - s.cell.opened < cooldown then s
  else if s.cell.st = .half then s
  else if s.cell.st = .opn then
    { s with cell := { s.cell with st := .half }, halfAdmits := 1,
             inflight := s.inflight ++ [⟨id, now⟩] }
  else { s with inflight := s.inflight ++ [⟨id, now⟩] }

/-- `_record_failure(now)` / `_record_success()` after the inner call;
`now` is `perf_counter_ns()` read at the completion (:498, :503).
mirrors flare/http/reliability.mojo#CircuitBreaker._record_failure+CircuitBreaker.serve sha=22216d500479 at=664a9c00 (fixed, APP-41) -/
def finish (thr : Int) (s : S) (r : Req) (now : Int) (failed : Bool) : S :=
  let s := { s with clock := now, inflight := s.inflight.erase r }
  if failed then
    let f := s.cell.fails + 1
    if f ≥ thr then
      { s with cell := ⟨.opn, f, now⟩, openedAt := now }
    else { s with cell := { s.cell with fails := f } }
  else { s with cell := { s.cell with fails := 0, st := .closed } }

/-- Executable step: arrivals need a fresh id, completions an in-flight
id; the clock is monotone (`Flare.Assumptions.MonotoneClock`).
mirrors flare/http/reliability.mojo#CircuitBreaker.serve sha=d30e4014ab39 at=664a9c00 (fixed, APP-41, APP-42) -/
def step (thr cooldown : Int) (s : S) : Lbl → Option S
  | .arrive id now =>
    if s.clock ≤ now ∧ (s.inflight.all fun r => r.id != id) then
      some (arrive cooldown s id now)
    else none
  | .finish id now failed =>
    if s.clock ≤ now then
      match s.inflight.find? (fun r => r.id == id) with
      | some r => some (finish thr s r now failed)
      | none => none
    else none

def lts (thr cooldown : Int) : LTS S Lbl :=
  LTS.ofFn (fun s => s = initS) (step thr cooldown)

/-- Spec clause (cooldown): every OPEN -> HALF_OPEN transition is an
arrival at least `cooldown` after the breaker (re)opened. -/
def CooldownOK (M : LTS S Lbl) (cd : Int) : Prop :=
  ∀ s l s', M.Reachable s → M.step s l s' → s.cell.st = .opn → s'.cell.st = .half →
    ∃ id now, l = .arrive id now ∧ cd ≤ now - s.openedAt

/-- Spec clause (single probe): while half-open at most one request has
been admitted since the breaker entered half-open. -/
def SingleProbe (M : LTS S Lbl) : Prop :=
  ∀ s, M.Reachable s → s.cell.st = .half → s.halfAdmits ≤ 1

/-- Failure-count invariant. -/
def CountsInv (thr : Int) (s : S) : Prop :=
  0 ≤ s.cell.fails ∧ (s.cell.st = .closed → s.cell.fails < thr) ∧
  (s.cell.st ≠ .closed → thr ≤ s.cell.fails)

theorem counts_inductive (thr cd : Int) (hthr : 0 < thr) :
    (lts thr cd).Inductive (CountsInv thr) where
  init := by
    intro s hs; subst hs; simp [CountsInv, initS]; omega
  step := by
    intro s l s' hinv hstep
    obtain ⟨h0, h1, h2⟩ := hinv
    simp only [lts, LTS.ofFn] at hstep
    cases l with
    | arrive id now =>
      simp only [step] at hstep
      split at hstep
      · injection hstep with hstep; subst hstep
        simp only [arrive]
        split
        · exact ⟨h0, h1, h2⟩
        · split
          · exact ⟨h0, h1, h2⟩
          · split
            · next hst => refine ⟨h0, by simp, fun _ => h2 (by rw [hst]; simp)⟩
            · exact ⟨h0, h1, h2⟩
      · cases hstep
    | finish id now failed =>
      simp only [step] at hstep
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

/-- Every reachable state satisfies the failure-count bounds. -/
theorem step_counts_inv (thr cd : Int) (hthr : 0 < thr) (s : S)
    (h : (lts thr cd).Reachable s) : CountsInv thr s :=
  (counts_inductive thr cd hthr).reachable s h

/-- While open and within the cooldown, every arrival fast-fails: the cell
and the in-flight set are unchanged. -/
theorem step_open_rejects (cd : Int) (s : S) (id : Nat) (now : Int)
    (ho : s.cell.st = .opn) (hc : now - s.cell.opened < cd) :
    arrive cd s id now = { s with clock := now } := by
  simp [arrive, ho, hc]

/-- A success always closes the breaker and clears the failure count
(in particular a successful half-open probe closes it). -/
theorem step_success_closes (thr : Int) (s : S) (r : Req) (now : Int) :
    (finish thr s r now false).cell.st = .closed ∧
    (finish thr s r now false).cell.fails = 0 := by
  simp [finish]

/-- A failure while half-open (or open) re-opens the breaker, given the
count invariant. -/
theorem step_failure_reopens (thr : Int) (s : S) (r : Req) (now : Int)
    (hinv : CountsInv thr s) (hst : s.cell.st ≠ .closed) :
    (finish thr s r now true).cell.st = .opn := by
  have := hinv.2.2 hst
  simp only [finish]
  rw [if_pos trivial, if_pos (show s.cell.fails + 1 ≥ thr by omega)]

/-! ## The cooldown clause (APP-41) -/

/-- Ghost invariant: while open, the stored opened-at equals the true
opening time. -/
def StampInv (s : S) : Prop := s.cell.st = .opn → s.cell.opened = s.openedAt

theorem stamp_inductive (thr cd : Int) : (lts thr cd).Inductive StampInv where
  init := by intro s hs; subst hs; simp [StampInv, initS]
  step := by
    intro s l s' hinv hstep
    simp only [lts, LTS.ofFn] at hstep
    cases l with
    | arrive id now =>
      simp only [step] at hstep
      split at hstep
      · injection hstep with hstep; subst hstep
        simp only [arrive]
        split
        · exact hinv
        · split
          · exact hinv
          · split
            · intro h; simp at h
            · exact hinv
      · cases hstep
    | finish id now failed =>
      simp only [step] at hstep
      split at hstep
      · split at hstep
        · injection hstep with hstep; subst hstep
          simp only [finish]
          split
          · split
            · intro _; simp
            · exact hinv
          · intro h; simp at h
        · cases hstep
      · cases hstep

/-- `finish` never produces HALF_OPEN from OPEN. -/
theorem finish_not_half (thr : Int) (s : S) (r : Req) (now : Int) (b : Bool)
    (ho : s.cell.st = .opn) : (finish thr s r now b).cell.st ≠ .half := by
  simp only [finish]
  split
  · split
    · simp
    · simp [ho]
  · simp

/-- The breaker moves to half-open only on an arrival at least `cooldown`
after it (re)opened. -/
theorem cooldown_respected (thr cd : Int) : CooldownOK (lts thr cd) cd := by
  intro s l s' hr hstep ho hh
  have hinv := (stamp_inductive thr cd).reachable s hr
  simp only [lts, LTS.ofFn] at hstep
  cases l with
  | arrive id now =>
    refine ⟨id, now, rfl, ?_⟩
    simp only [step] at hstep
    split at hstep
    · injection hstep with hstep; subst hstep
      simp only [arrive] at hh
      by_cases hc : now - s.cell.opened < cd
      · simp [ho, hc] at hh
      · have := hinv ho; omega
    · cases hstep
  | finish id now failed =>
    exfalso
    simp only [step] at hstep
    split at hstep
    · split at hstep
      · next r _ =>
        injection hstep with hstep; subst hstep
        exact finish_not_half thr s r now failed ho hh
      · cases hstep
    · cases hstep

/-! ## The single-probe clause (APP-42) -/

def HalfInv (s : S) : Prop := s.cell.st = .half → s.halfAdmits ≤ 1

theorem half_inductive (thr cd : Int) : (lts thr cd).Inductive HalfInv where
  init := by intro s hs; subst hs; simp [HalfInv, initS]
  step := by
    intro s l s' hinv hstep
    simp only [lts, LTS.ofFn] at hstep
    cases l with
    | arrive id now =>
      simp only [step] at hstep
      split at hstep
      · injection hstep with hstep; subst hstep
        simp only [arrive]
        split
        · exact hinv
        · split
          · exact hinv
          · split
            · intro _; simp
            · exact hinv
      · cases hstep
    | finish id now failed =>
      simp only [step] at hstep
      split at hstep
      · split at hstep
        · injection hstep with hstep; subst hstep
          simp only [finish]
          split
          · split
            · intro h; simp at h
            · exact hinv
          · intro h; simp at h
        · cases hstep
      · cases hstep

/-- While half-open, at most one request has been let through. -/
theorem single_probe (thr cd : Int) : SingleProbe (lts thr cd) :=
  fun s hr => (half_inductive thr cd).reachable s hr

end Flare.L4.CircuitBreaker
