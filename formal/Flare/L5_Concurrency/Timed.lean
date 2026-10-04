import Flare.Core.LTS

/-!
# Teardown with a clock: how long after the stop until every worker is done

`Flare.L5.SharedListener` and `Flare.L5.Scheduler` are untimed: they show a
worker *can* leave its loop once the stop flag is set, not *when*. Here the
same worker loop and the same teardown thread run against a discrete clock
(one `tick` = one unit, read as 1 ms), so the bound can be stated.

A worker of every flare server loop that `Scheduler` runs is

* `reg`: register / arm the listener, then
* `check`: `while not load_stop_flag(...)`,
* `poll`: wait for events (epoll/kqueue: `reactor.poll(_poll_timeout_ms(wheel))`,
  `flare/http/_server_reactor_epoll.mojo:163-167`; io_uring buffer ring:
  `ureactor.poll(1, ...)`, `flare/http/_server_reactor_uring.mojo:848-852`),
* `ready`: the wait returned, the thread is runnable but may not be on a CPU,
* `batch`: run the batch (accepts, connection steps, handlers), back to `check`,
* `clean`: after the loop, the worker's own teardown (force-close of its
  connections, `WORKER_STAT_DONE`), then `done`.

The kernel ends a `poll` (label `k i`). With a capped wait it can always do
so (`Cfg.capped`: the timeout argument is at most the cap,
`pollTimeout_le_cap`); with an uncapped wait only a completion can, which
needs traffic (`TS.traffic`).

The teardown thread is `Scheduler.shutdown` (`flare/runtime/scheduler.mojo:746-760`)
or `drain(D)` (:778-901) with the CONC-05 fix applied; that fix moves the
listener close to `_free_resources` and changes no timing, so the steps are:
`sig` (store the stop flag), for `drain` a `wait` until every worker
returned or the deadline passed (taking the `done[]` snapshot), then `pass k`
for each worker (join it, or detach it if the snapshot says it was stuck),
then `free`, then `fin`.

## Hypotheses

Time is not under the program's control, so the bound holds under explicit
hypotheses on every state of the run (`Hyp`, the conjunction of):

* `PollReturns`: a wait returns within `cap + ε` of being entered (`ε` is the
  kernel's timer slack plus the time to enter the wait);
* `FairW` / `FairM`: the OS scheduler runs a runnable thread within `σ`;
* `HandlerBound`: one batch (handlers, and `_accept_loop_fd`, which accepts
  until `EAGAIN` and so also depends on the arrival rate) takes at most `η`;
* `TeardownBound`: a worker's post-loop teardown takes at most `τ`.

Under them every worker is `done` within `bound P = cap + ε + σ + η + σ + τ`
of the stop (`worker_done_by`), `shutdown` and `drain` finish within
`bound P + (n + w + 2)·σ` (`teardown_done_by`, `w` = 1 for drain), and a
drain whose deadline exceeds `bound P` detaches no worker (`drain_joins_all`).
`Flare.Bugs.CONC_07` shows the io_uring buffer-ring loop does not satisfy
`PollReturns` and that without it no bound exists.
-/
namespace Flare.L5.Timed

/-- `_poll_timeout_ms` on naturals: `nf` is `wheel.next_fire_ms()` (at most
the wheel's tick plus 2^32, so `nf - now` fits an `Int`), `now` is
`_monotonic_ms()`.
mirrors flare/http/_reactor/lifecycle.mojo:31-47 @59bda50 -/
def pollTimeout (nf now cap : Nat) : Nat :=
  if nf ≤ now then 1 else if nf - now < cap then nf - now else cap

theorem pollTimeout_le_cap (nf now cap : Nat) (h : 1 ≤ cap) : pollTimeout nf now cap ≤ cap := by
  unfold pollTimeout; split
  · exact h
  · split <;> omega

theorem pollTimeout_pos (nf now cap : Nat) (h : 1 ≤ cap) : 1 ≤ pollTimeout nf now cap := by
  unfold pollTimeout; split
  · exact Nat.le_refl 1
  · split <;> omega

/-- Worker phase.
mirrors flare/http/_server_reactor_epoll.mojo:150-266 and
flare/http/_server_reactor_uring.mojo:842-981 @59bda50 -/
inductive TPc where
  | reg | check | poll | ready | batch | clean | done
  deriving DecidableEq, Repr

/-- A worker: its phase and the time it entered it. -/
structure TW where
  pc : TPc
  since : Nat
  deriving DecidableEq, Repr

/-- Teardown thread; the argument is the time the phase was entered.
mirrors flare/runtime/scheduler.mojo:746-760,815-901 @59bda50 -/
inductive MPc where
  | sig
  | wait (t : Nat)
  | pass (k t : Nat)
  | free (t : Nat)
  | fin (t : Nat)
  deriving DecidableEq, Repr

structure TS where
  now : Nat
  stop : Option Nat
  ws : List TW
  m : MPc
  snap : List Bool
  traffic : Bool
  deriving DecidableEq, Repr

/-- `capped`: the loop's wait has a timeout of at most the cap (every
epoll/kqueue loop); `drain = some D`: `drain(D)` with `D > 0`, `none`:
`shutdown()` / `drain(timeout_ms <= 0)`. -/
structure Cfg where
  capped : Bool
  drain : Option Nat
  deriving DecidableEq, Repr

structure Params where
  cap : Nat
  ε : Nat
  σ : Nat
  η : Nat
  τ : Nat
  deriving DecidableEq, Repr

inductive Lbl where
  | tick
  | w (i : Nat)
  | k (i : Nat)
  | sig
  | m
  deriving DecidableEq, Repr

def isDone (w : TW) : Bool := decide (w.pc = .done)

def allDone (s : TS) : Bool := s.ws.all isDone

def init (n : Nat) (tr : Bool) : TS := ⟨0, none, List.replicate n ⟨.reg, 0⟩, .sig, [], tr⟩

/-- Next phase on a worker's own step (`poll` is ended by the kernel).
mirrors flare/http/_server_reactor_epoll.mojo:155-266 @59bda50 -/
def wNext (stop : Option Nat) : TPc → Option TPc
  | .reg => some .check
  | .check => some (if stop.isSome then .clean else .poll)
  | .poll => none
  | .ready => some .batch
  | .batch => some .check
  | .clean => some .done
  | .done => none

/-- mirrors flare/runtime/scheduler.mojo:829-862,890-900 @59bda50 -/
def mStep (c : Cfg) (s : TS) : Option TS :=
  match s.m with
  | .sig => none
  | .wait _ =>
    match c.drain, s.stop with
    | some D, some t0 =>
      if allDone s = true ∨ t0 + D ≤ s.now then
        some { s with m := .pass 0 s.now, snap := s.ws.map isDone }
      else none
    | _, _ => none
  | .pass k _ =>
    match s.ws[k]? with
    | none => some { s with m := .free s.now }
    | some w =>
      if c.drain.isSome = true ∧ s.snap[k]? = some false then some { s with m := .pass (k + 1) s.now }
      else if w.pc = .done then some { s with m := .pass (k + 1) s.now }
      else none
  | .free _ => some { s with m := .fin s.now }
  | .fin _ => none

/-- mirrors flare/http/_server_reactor_epoll.mojo:155-266,
flare/http/_server_reactor_uring.mojo:842-981 and
flare/runtime/scheduler.mojo:655-668,746-760,815-901 @59bda50 -/
def step (c : Cfg) (s : TS) : Lbl → Option TS
  | .tick => some { s with now := s.now + 1 }
  | .w i =>
    match s.ws[i]? with
    | none => none
    | some w => (wNext s.stop w.pc).map fun p => { s with ws := s.ws.set i ⟨p, s.now⟩ }
  | .k i =>
    match s.ws[i]? with
    | none => none
    | some w =>
      if w.pc = .poll ∧ (c.capped = true ∨ s.traffic = true) then
        some { s with ws := s.ws.set i ⟨.ready, s.now⟩ }
      else none
  | .sig =>
    if s.m = .sig ∧ s.stop = none then
      some { s with stop := some s.now,
                    m := match c.drain with
                      | some _ => .wait s.now
                      | none => .pass 0 s.now }
    else none
  | .m => mStep c s

/-! ## Hypotheses -/

/-- A wait returns within `cap + ε` (the kernel honours the timeout). -/
def PollReturns (P : Params) (s : TS) : Prop :=
  ∀ w ∈ s.ws, w.pc = .poll → s.now ≤ w.since + P.cap + P.ε

/-- OS fairness for workers: a runnable worker runs within `σ`. -/
def FairW (P : Params) (s : TS) : Prop :=
  ∀ w ∈ s.ws, (w.pc = .reg ∨ w.pc = .check ∨ w.pc = .ready) → s.now ≤ w.since + P.σ

/-- OS fairness for the teardown thread: once its next step is enabled
(for `wait`: every worker returned, or the deadline passed; for `pass k`:
worker `k` returned, or the snapshot says detach), it runs within `σ`. -/
def FairM (P : Params) (c : Cfg) (s : TS) : Prop :=
  match s.m with
  | .sig => True
  | .wait t =>
    (allDone s = true → s.now ≤ t + P.σ ∨ ∃ w ∈ s.ws, s.now ≤ w.since + P.σ) ∧
    (match c.drain, s.stop with
     | some D, some t0 => s.now ≤ t + P.σ ∨ s.now ≤ t0 + D + P.σ
     | _, _ => True)
  | .pass k t =>
    match s.ws[k]? with
    | none => s.now ≤ t + P.σ
    | some w =>
      ((c.drain.isSome = true ∧ s.snap[k]? = some false) → s.now ≤ t + P.σ) ∧
      (w.pc = .done → s.now ≤ t + P.σ ∨ s.now ≤ w.since + P.σ)
  | .free t => s.now ≤ t + P.σ
  | .fin _ => True

/-- One batch (handlers included) takes at most `η`. -/
def HandlerBound (P : Params) (s : TS) : Prop :=
  ∀ w ∈ s.ws, w.pc = .batch → s.now ≤ w.since + P.η

/-- A worker's post-loop teardown takes at most `τ`. -/
def TeardownBound (P : Params) (s : TS) : Prop :=
  ∀ w ∈ s.ws, w.pc = .clean → s.now ≤ w.since + P.τ

def Hyp (P : Params) (c : Cfg) (s : TS) : Prop :=
  PollReturns P s ∧ FairW P s ∧ FairM P c s ∧ HandlerBound P s ∧ TeardownBound P s

/-- The runs in which every state satisfies `H`. -/
def ltsH (c : Cfg) (H : TS → Prop) (n : Nat) : LTS TS Lbl where
  init s := ∃ tr, s = init n tr
  step s l s' := step c s l = some s' ∧ H s ∧ H s'

/-- The per-worker bound after the stop. -/
def bound (P : Params) : Nat := P.cap + P.ε + P.σ + P.η + P.σ + P.τ

/-- Teardown-thread bound after the stop. -/
def mBound (P : Params) (c : Cfg) (n : Nat) : Nat :=
  bound P + (n + (if c.drain.isSome then 1 else 0) + 2) * P.σ

/-! ## Invariant -/

/-- Worst-case time still needed from entering a phase until `done`, once
the stop is set. -/
def rem (P : Params) : TPc → Nat
  | .reg => P.σ + (P.σ + P.τ)
  | .check => P.σ + P.τ
  | .poll => bound P
  | .ready => P.σ + (P.η + (P.σ + P.τ))
  | .batch => P.η + (P.σ + P.τ)
  | .clean => P.τ
  | .done => 0

/-- What the hypotheses allow a non-`done` phase to last. -/
def lim (P : Params) : TPc → Nat
  | .reg => P.σ
  | .check => P.σ
  | .poll => P.cap + P.ε
  | .ready => P.σ
  | .batch => P.η
  | .clean => P.τ
  | .done => 0

theorem rem_le (P : Params) (p : TPc) : rem P p ≤ bound P := by
  cases p <;> simp only [rem, bound] <;> omega

theorem lim_le_rem (P : Params) (p : TPc) : lim P p ≤ rem P p := by
  cases p <;> simp only [rem, lim, bound] <;> omega

theorem hyp_lim {P : Params} {c : Cfg} {s : TS} (h : Hyp P c s) {w : TW} (hw : w ∈ s.ws)
    (hd : w.pc ≠ .done) : s.now ≤ w.since + lim P w.pc := by
  obtain ⟨hp, hf, -, hb, ht⟩ := h
  cases hpc : w.pc with
  | reg => simpa [lim] using hf w hw (by simp [hpc])
  | check => simpa [lim] using hf w hw (by simp [hpc])
  | poll => have := hp w hw hpc; simp only [lim]; omega
  | ready => simpa [lim] using hf w hw (by simp [hpc])
  | batch => simpa [lim] using hb w hw hpc
  | clean => simpa [lim] using ht w hw hpc
  | done => exact absurd hpc hd

/-- Worker part of the invariant. -/
def InvW (P : Params) (s : TS) : Prop :=
  (∀ w ∈ s.ws, w.since ≤ s.now) ∧
  (∀ t0, s.stop = some t0 → ∀ w ∈ s.ws, w.since + rem P w.pc ≤ t0 + bound P)

/-- The worker bound on a single state. -/
theorem notDone_le {P : Params} {c : Cfg} {s : TS} (I : InvW P s) (h : Hyp P c s) {t0 : Nat}
    (hs : s.stop = some t0) {w : TW} (hw : w ∈ s.ws) (hd : w.pc ≠ .done) :
    s.now ≤ t0 + bound P := by
  have h1 := hyp_lim h hw hd
  have h2 := I.2 t0 hs w hw
  have h3 := lim_le_rem P w.pc
  omega

theorem done_le {P : Params} {s : TS} (I : InvW P s) {t0 : Nat} (hs : s.stop = some t0)
    {w : TW} (hw : w ∈ s.ws) (hd : w.pc = .done) : w.since ≤ t0 + bound P := by
  have := I.2 t0 hs w hw; rw [hd] at this; simpa [rem] using this

theorem notAllDone {s : TS} (h : allDone s = false) : ∃ w ∈ s.ws, w.pc ≠ .done := by
  simp only [allDone, List.all_eq_false, isDone] at h
  simpa using h

theorem allDone_mem {s : TS} (h : allDone s = true) {w : TW} (hw : w ∈ s.ws) : w.pc = .done := by
  simp only [allDone, List.all_eq_true, isDone, decide_eq_true_eq] at h
  exact h w hw

/-- Teardown part of the invariant. -/
def InvM (P : Params) (c : Cfg) (n : Nat) (s : TS) : Prop :=
  s.ws.length = n ∧
  (s.m = .sig ↔ s.stop = none) ∧
  (∀ t, s.m = .wait t → s.stop = some t) ∧
  (∀ k t t0, s.m = .pass k t → s.stop = some t0 →
      k ≤ n ∧ t ≤ t0 + bound P + (k + (if c.drain.isSome then 1 else 0)) * P.σ) ∧
  (∀ t t0, s.m = .free t → s.stop = some t0 →
      t ≤ t0 + bound P + (n + (if c.drain.isSome then 1 else 0) + 1) * P.σ) ∧
  (∀ t t0, s.m = .fin t → s.stop = some t0 → t ≤ t0 + mBound P c n) ∧
  (∀ D, c.drain = some D → bound P < D → (∀ t, s.m ≠ .wait t) → ∀ b ∈ s.snap, b = true)

def J (P : Params) (c : Cfg) (n : Nat) (s : TS) : Prop :=
  InvW P s ∧ InvM P c n s ∧ Hyp P c s

theorem mem_set {l : List TW} {i : Nat} {a w : TW} (h : w ∈ l.set i a) : w ∈ l ∨ w = a :=
  List.mem_or_eq_of_mem_set h

theorem hyp_init (P : Params) (c : Cfg) (n : Nat) (tr : Bool) : Hyp P c (init n tr) := by
  refine ⟨?_, ?_, trivial, ?_, ?_⟩ <;> intro w hw <;>
    simp only [init, List.mem_replicate] at hw <;> obtain ⟨-, rfl⟩ := hw <;> simp [init]

theorem J_init (P : Params) (c : Cfg) (n : Nat) (tr : Bool) : J P c n (init n tr) := by
  refine ⟨⟨?_, ?_⟩, ⟨by simp [init], by simp [init], ?_, ?_, ?_, ?_, ?_⟩, hyp_init P c n tr⟩
  · intro w hw; simp only [init, List.mem_replicate] at hw; obtain ⟨-, rfl⟩ := hw; simp [init]
  · intro t0 h; simp [init] at h
  · intro t h; simp [init] at h
  · intro k t t0 h; simp [init] at h
  · intro t t0 h; simp [init] at h
  · intro t t0 h; simp [init] at h
  · intro D _ _ _ b hb; simp [init] at hb

/-- Preservation of the worker part for a worker's own step. -/
theorem invW_wstep {P : Params} {c : Cfg} {s : TS} (I : InvW P s) (h : Hyp P c s) {i : Nat}
    {w : TW} (hw : s.ws[i]? = some w) {p : TPc} (hp : wNext s.stop w.pc = some p) :
    InvW P { s with ws := s.ws.set i ⟨p, s.now⟩ } := by
  have hwm := List.mem_of_getElem? hw
  have hd : w.pc ≠ .done := by intro e; rw [e] at hp; cases hp
  refine ⟨?_, ?_⟩
  · intro x hx
    rcases mem_set hx with hx | rfl
    · exact I.1 x hx
    · exact Nat.le_refl _
  · intro t0 hs x hx
    rcases mem_set hx with hx | rfl
    · exact I.2 t0 hs x hx
    · have h1 := hyp_lim h hwm hd
      have h2 := I.2 t0 hs w hwm
      simp only at hs ⊢
      cases hpc : w.pc <;> rw [hpc] at hp h1 h2 <;> simp [wNext, hs] at hp <;> subst hp <;>
        simp only [rem, lim, bound] at h1 h2 ⊢ <;> omega

/-- The teardown step leaves the workers, the stop flag and the clock alone. -/
theorem mStep_frame {c : Cfg} {s s' : TS} (hst : mStep c s = some s') :
    s'.ws = s.ws ∧ s'.stop = s.stop ∧ s'.now = s.now := by
  unfold mStep at hst
  split at hst
  · cases hst
  · split at hst
    · split at hst
      · simp only [Option.some.injEq] at hst; subst hst; exact ⟨rfl, rfl, rfl⟩
      · cases hst
    · cases hst
  · split at hst
    · simp only [Option.some.injEq] at hst; subst hst; exact ⟨rfl, rfl, rfl⟩
    · split at hst
      · simp only [Option.some.injEq] at hst; subst hst; exact ⟨rfl, rfl, rfl⟩
      · split at hst
        · simp only [Option.some.injEq] at hst; subst hst; exact ⟨rfl, rfl, rfl⟩
        · cases hst
  · simp only [Option.some.injEq] at hst; subst hst; exact ⟨rfl, rfl, rfl⟩
  · cases hst

theorem invW_step (P : Params) (c : Cfg) (s s' : TS) (l : Lbl) (I : InvW P s) (h : Hyp P c s)
    (hst : step c s l = some s') : InvW P s' := by
  cases l with
  | tick =>
    simp only [step, Option.some.injEq] at hst; subst hst
    exact ⟨fun w hw => Nat.le_succ_of_le (I.1 w hw), I.2⟩
  | w i =>
    simp only [step] at hst
    split at hst
    · cases hst
    · rename_i w hw
      cases hp : wNext s.stop w.pc with
      | none => simp [hp] at hst
      | some p =>
        simp only [hp, Option.map_some, Option.some.injEq] at hst; subst hst
        exact invW_wstep I h hw hp
  | k i =>
    simp only [step] at hst
    split at hst
    · cases hst
    · rename_i w hw
      split at hst
      · rename_i hc
        simp only [Option.some.injEq] at hst; subst hst
        refine ⟨?_, ?_⟩
        · intro x hx
          rcases mem_set hx with hx | rfl
          · exact I.1 x hx
          · exact Nat.le_refl _
        · intro t0 hs x hx
          rcases mem_set hx with hx | rfl
          · exact I.2 t0 hs x hx
          · have hwm := List.mem_of_getElem? hw
            have h1 := h.1 w hwm hc.1
            have h2 := I.2 t0 hs w hwm
            rw [hc.1] at h2
            simp only [rem, bound] at h1 h2 ⊢; omega
      · cases hst
  | sig =>
    simp only [step] at hst
    split at hst
    · simp only [Option.some.injEq] at hst; subst hst
      refine ⟨I.1, ?_⟩
      intro t0 hs w hw
      simp only [Option.some.injEq] at hs; subst hs
      have := I.1 w hw; have := rem_le P w.pc; omega
    · cases hst
  | m =>
    simp only [step] at hst
    obtain ⟨e1, e2, e3⟩ := mStep_frame hst
    exact ⟨by rw [e1, e3]; exact I.1, by rw [e1, e2]; exact I.2⟩

/-- Steps other than the teardown thread's own leave `InvM` alone. -/
theorem invM_other (P : Params) (c : Cfg) (n : Nat) (s s' : TS) (l : Lbl) (M : InvM P c n s)
    (hl : l ≠ .m) (hst : step c s l = some s') : InvM P c n s' := by
  obtain ⟨m1, m2, m3, m4, m5, m6, m7⟩ := M
  cases l with
  | tick =>
    simp only [step, Option.some.injEq] at hst; subst hst
    exact ⟨m1, m2, m3, m4, m5, m6, m7⟩
  | w i =>
    simp only [step] at hst
    split at hst
    · cases hst
    · simp only [Option.map_eq_some_iff] at hst
      obtain ⟨p, -, rfl⟩ := hst
      exact ⟨by simpa using m1, m2, m3, m4, m5, m6, m7⟩
  | k i =>
    simp only [step] at hst
    split at hst
    · cases hst
    · split at hst
      · simp only [Option.some.injEq] at hst; subst hst
        exact ⟨by simpa using m1, m2, m3, m4, m5, m6, m7⟩
      · cases hst
  | sig =>
    simp only [step] at hst
    split at hst
    · rename_i hc
      simp only [Option.some.injEq] at hst; subst hst
      refine ⟨m1, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · cases c.drain <;> simp
      · intro t ht; cases hd : c.drain <;> simp [hd] at ht; subst ht; rfl
      · intro k t t0 ht hs
        simp only [Option.some.injEq] at hs; subst hs
        cases hd : c.drain <;> simp only [hd] at ht <;> cases ht
        simp
      · intro t t0 ht; cases hd : c.drain <;> simp [hd] at ht
      · intro t t0 ht; cases hd : c.drain <;> simp [hd] at ht
      · intro D hD _ hw
        rw [hD] at hw
        exact absurd rfl (hw s.now)
    · cases hst
  | m => exact absurd rfl hl

theorem invM_mstep (P : Params) (c : Cfg) (n : Nat) (s s' : TS) (hJ : J P c n s)
    (hst : mStep c s = some s') : InvM P c n s' := by
  obtain ⟨I, ⟨m1, m2, m3, m4, m5, m6, m7⟩, h⟩ := hJ
  have fm := h.2.2.1
  unfold FairM at fm
  unfold mStep at hst
  cases hm : s.m with
  | sig => simp [hm] at hst
  | fin t => simp [hm] at hst
  | free t =>
    simp only [hm, Option.some.injEq] at hst; subst hst
    simp only [hm] at fm
    have hs0 : s.stop ≠ none := fun e => by have := m2.mpr e; rw [hm] at this; cases this
    obtain ⟨t0, ht0⟩ := Option.ne_none_iff_exists'.mp hs0
    have := m5 t t0 hm ht0
    refine ⟨m1, ⟨(fun e => by cases e), (fun e => by simp only at e; rw [ht0] at e; cases e)⟩,
      (fun _ e => by cases e), (fun _ _ _ e => by cases e), (fun _ _ e => by cases e), ?_, ?_⟩
    · intro t' t0' ht' hs'
      simp only [MPc.fin.injEq] at ht'; subst ht'
      simp only at hs'; rw [ht0] at hs'; simp only [Option.some.injEq] at hs'; subst hs'
      simp only [mBound]
      have e : (n + (if c.drain.isSome = true then 1 else 0) + 2) * P.σ =
          (n + (if c.drain.isSome = true then 1 else 0) + 1) * P.σ + P.σ := Nat.succ_mul _ _
      omega
    · intro D hD hB _; exact m7 D hD hB (fun t' e => by rw [hm] at e; cases e)
  | wait t =>
    simp only [hm] at hst fm
    have ht := m3 t hm
    cases hd : c.drain with
    | none => simp [hd, ht] at hst
    | some D =>
      simp only [hd, ht] at hst fm
      split at hst
      · rename_i hc
        simp only [Option.some.injEq] at hst; subst hst
        have hnow : s.now ≤ t + bound P + P.σ := by
          cases had : allDone s with
          | true =>
            rcases fm.1 had with e | ⟨w, hw, e⟩
            · omega
            · have := done_le I ht hw (allDone_mem had hw); omega
          | false =>
            obtain ⟨w, hw, hnd⟩ := notAllDone had
            have := notDone_le I h ht hw hnd; omega
        refine ⟨m1, ⟨(fun e => by cases e), (fun e => by simp at e)⟩,
          (fun _ e => by cases e), ?_, (fun _ _ e => by cases e), (fun _ _ e => by cases e), ?_⟩
        · intro k t' t0 hk hs
          simp only [MPc.pass.injEq] at hk; obtain ⟨rfl, rfl⟩ := hk
          simp only [Option.some.injEq] at hs; subst hs
          simp only [hd, Option.isSome_some, if_true]
          omega
        · intro D' hD' hB _ b hb
          rw [hd] at hD'; simp only [Option.some.injEq] at hD'; subst hD'
          simp only [List.mem_map] at hb
          obtain ⟨w, hw, rfl⟩ := hb
          cases had : allDone s with
          | true => simp only [isDone, allDone_mem had hw, decide_true]
          | false =>
            obtain ⟨w', hw', hnd⟩ := notAllDone had
            have := notDone_le I h ht hw' hnd
            rcases hc with hc | hc
            · rw [had] at hc; cases hc
            · omega
      · cases hst
  | pass k t =>
    simp only [hm] at hst fm
    have hs0 : s.stop ≠ none := fun e => by have := m2.mpr e; rw [hm] at this; cases this
    obtain ⟨t0, ht0⟩ := Option.ne_none_iff_exists'.mp hs0
    obtain ⟨hkn, htb⟩ := m4 k t t0 hm ht0
    have m7' : ∀ D, c.drain = some D → bound P < D → ∀ b ∈ s.snap, b = true :=
      fun D hD hB => m7 D hD hB (fun t' e => by rw [hm] at e; cases e)
    split at hst
    · rename_i hk
      simp only [hk] at fm
      simp only [Option.some.injEq] at hst; subst hst
      have hkn' : k = n := by
        have := List.getElem?_eq_none_iff.mp hk; omega
      subst hkn'
      refine ⟨m1, ⟨(fun e => by cases e), (fun e => by simp only at e; rw [ht0] at e; cases e)⟩,
        (fun _ e => by cases e), (fun _ _ _ e => by cases e), ?_, (fun _ _ e => by cases e),
        fun D hD hB _ => m7' D hD hB⟩
      intro t' t0' ht' hs'
      simp only [MPc.free.injEq] at ht'; subst ht'
      simp only at hs'; rw [ht0] at hs'; simp only [Option.some.injEq] at hs'; subst hs'
      have e : (k + (if c.drain.isSome = true then 1 else 0) + 1) * P.σ =
          (k + (if c.drain.isSome = true then 1 else 0)) * P.σ + P.σ := Nat.succ_mul _ _
      omega
    · rename_i w hk
      simp only [hk] at fm
      have post : ∀ s'', s''.ws = s.ws → s''.stop = s.stop → s''.snap = s.snap →
          s''.m = .pass (k + 1) s.now →
          s.now ≤ t0 + bound P + (k + (if c.drain.isSome = true then 1 else 0) + 1) * P.σ →
          InvM P c n s'' := by
        intro s'' e1 e2 e3 e4 hle
        have hklt : k < n := by
          rw [← m1]; exact (List.getElem?_eq_some_iff.mp hk).1
        refine ⟨by rw [e1]; exact m1, ⟨(fun e => by rw [e4] at e; cases e),
          (fun e => by rw [e2, ht0] at e; cases e)⟩, (fun _ e => by rw [e4] at e; cases e), ?_,
          (fun _ _ e => by rw [e4] at e; cases e), (fun _ _ e => by rw [e4] at e; cases e),
          fun D hD hB _ => by rw [e3]; exact m7' D hD hB⟩
        intro k' t' t0' hk' hs'
        rw [e4] at hk'; simp only [MPc.pass.injEq] at hk'; obtain ⟨rfl, rfl⟩ := hk'
        rw [e2, ht0] at hs'; simp only [Option.some.injEq] at hs'; subst hs'
        refine ⟨by omega, ?_⟩
        have e : (k + 1 + (if c.drain.isSome = true then 1 else 0)) * P.σ =
            (k + (if c.drain.isSome = true then 1 else 0) + 1) * P.σ := by
          congr 1; omega
        rw [e]; exact hle
      have stepB : (k + (if c.drain.isSome = true then 1 else 0) + 1) * P.σ =
          (k + (if c.drain.isSome = true then 1 else 0)) * P.σ + P.σ := Nat.succ_mul _ _
      split at hst
      · rename_i hdet
        simp only [Option.some.injEq] at hst; subst hst
        have := fm.1 hdet
        exact post _ rfl rfl rfl rfl (by omega)
      · split at hst
        · rename_i hdn
          simp only [Option.some.injEq] at hst; subst hst
          have hwm := List.mem_of_getElem? hk
          have hwd := done_le I ht0 hwm hdn
          rcases fm.2 hdn with e | e
          · exact post _ rfl rfl rfl rfl (by omega)
          · exact post _ rfl rfl rfl rfl (by omega)
        · cases hst

theorem J_step (P : Params) (c : Cfg) (n : Nat) (s s' : TS) (l : Lbl) (hJ : J P c n s)
    (hst : step c s l = some s') (h' : Hyp P c s') : J P c n s' := by
  refine ⟨invW_step P c s s' l hJ.1 hJ.2.2 hst, ?_, h'⟩
  by_cases hl : l = .m
  · subst hl; exact invM_mstep P c n s s' hJ hst
  · exact invM_other P c n s s' l hJ.2.1 hl hst

theorem J_inductive (P : Params) (c : Cfg) (n : Nat) : (ltsH c (Hyp P c) n).Inductive (J P c n) where
  init := by rintro s ⟨tr, rfl⟩; exact J_init P c n tr
  step := fun s l s' hJ ⟨hst, _, h'⟩ => J_step P c n s s' l hJ hst h'

/-! ## Headline properties -/

/-- Every worker is `done` within `bound P` of the stop, in every run that
meets the hypotheses, for any number of workers and either teardown. -/
theorem worker_done_by (P : Params) (c : Cfg) (n : Nat) (s : TS)
    (hr : (ltsH c (Hyp P c) n).Reachable s) {t0 : Nat} (hs : s.stop = some t0)
    (ht : t0 + bound P < s.now) : ∀ w ∈ s.ws, w.pc = .done := by
  obtain ⟨I, -, h⟩ := (J_inductive P c n).reachable s hr
  intro w hw
  cases hpc : w.pc
  all_goals first
    | rfl
    | (have := notDone_le I h hs hw (by rw [hpc]; decide); omega)

/-- `shutdown()` and `drain(D)` (with the CONC-05 fix) return within
`mBound P c n` of the stop. -/
theorem teardown_done_by (P : Params) (c : Cfg) (n : Nat) (s : TS)
    (hr : (ltsH c (Hyp P c) n).Reachable s) {t0 : Nat} (hs : s.stop = some t0)
    (ht : t0 + mBound P c n < s.now) : ∃ t, s.m = .fin t := by
  obtain ⟨I, ⟨m1, m2, m3, m4, m5, -, -⟩, h⟩ := (J_inductive P c n).reachable s hr
  have fm := h.2.2.1
  simp only [FairM] at fm
  simp only [mBound] at ht
  have hσ : P.σ ≤ (n + (if c.drain.isSome = true then 1 else 0) + 2) * P.σ :=
    Nat.le_mul_of_pos_left _ (by omega)
  have mono : ∀ a, a ≤ n + (if c.drain.isSome = true then 1 else 0) + 1 →
      a * P.σ + P.σ ≤ (n + (if c.drain.isSome = true then 1 else 0) + 2) * P.σ := by
    intro a ha
    rw [← Nat.succ_mul]
    exact Nat.mul_le_mul_right _ (by omega)
  cases hm : s.m with
  | fin t => exact ⟨t, rfl⟩
  | sig => exact absurd (m2.mp hm) (by rw [hs]; simp)
  | free t =>
    simp only [hm] at fm
    have := m5 t t0 hm hs
    have := mono _ (Nat.le_refl _)
    omega
  | wait t =>
    simp only [hm] at fm
    have htt := m3 t hm; rw [hs] at htt; simp only [Option.some.injEq] at htt; subst htt
    cases had : allDone s with
    | true =>
      rcases fm.1 had with e | ⟨w, hw, e⟩
      · omega
      · have := done_le I hs hw (allDone_mem had hw); omega
    | false =>
      obtain ⟨w, hw, hnd⟩ := notAllDone had
      have := notDone_le I h hs hw hnd; omega
  | pass k t =>
    simp only [hm] at fm
    obtain ⟨hkn, htb⟩ := m4 k t t0 hm hs
    have hk1 := mono (k + (if c.drain.isSome = true then 1 else 0)) (by split <;> omega)
    split at fm
    · omega
    · rename_i w hk
      have hwm := List.mem_of_getElem? hk
      by_cases hdet : c.drain.isSome = true ∧ s.snap[k]? = some false
      · have := fm.1 hdet; omega
      · by_cases hdn : w.pc = .done
        · rcases fm.2 hdn with e | e
          · omega
          · have := done_le I hs hwm hdn; omega
        · have := notDone_le I h hs hwm hdn; omega

/-- A drain whose deadline exceeds `bound P` detaches no worker: its
snapshot says every worker returned, so the stuck-worker branch (and the
listener / context leak that comes with it) is never taken. -/
theorem drain_joins_all (P : Params) (c : Cfg) (n D : Nat) (hD : c.drain = some D)
    (hB : bound P < D) (s : TS) (hr : (ltsH c (Hyp P c) n).Reachable s)
    (hm : ∀ t, s.m ≠ .wait t) : ∀ b ∈ s.snap, b = true :=
  ((J_inductive P c n).reachable s hr).2.1.2.2.2.2.2.2 D hD hB hm

/-- With the epoll/kqueue cap of 100 ms the per-worker bound is
`100 + ε + 2σ + η + τ` ms. -/
theorem bound_epoll (ε σ η τ : Nat) : bound ⟨100, ε, σ, η, τ⟩ = 100 + ε + 2 * σ + η + τ := by
  simp only [bound]; omega

/-! ## Non-vacuity: a run meeting every hypothesis that hits the bound -/

def exec (c : Cfg) : TS → List Lbl → Option TS
  | s, [] => some s
  | s, l :: ls => (step c s l).bind fun s' => exec c s' ls

instance (P : Params) (c : Cfg) (s : TS) : Decidable (FairM P c s) := by
  unfold FairM
  split
  · exact instDecidableTrue
  · split <;> exact inferInstance
  · split <;> exact inferInstance
  · exact inferInstance
  · exact instDecidableTrue

instance (P : Params) (c : Cfg) (s : TS) : Decidable (Hyp P c s) := by
  unfold Hyp PollReturns FairW HandlerBound TeardownBound; exact inferInstance

/-- `exec`, checking `Hyp` on every state it passes through. -/
def execH (P : Params) (c : Cfg) : TS → List Lbl → Option TS
  | s, [] => if Hyp P c s then some s else none
  | s, l :: ls =>
    if Hyp P c s then (step c s l).bind fun s' => execH P c s' ls else none

theorem run_of_execH (P : Params) (c : Cfg) (n : Nat) :
    ∀ (s : TS) (ls : List Lbl) (s' : TS), execH P c s ls = some s' →
      Hyp P c s ∧ Hyp P c s' ∧ (ltsH c (Hyp P c) n).Run s ls s'
  | s, [], s', h => by
    simp only [execH] at h; split at h
    · simp only [Option.some.injEq] at h; subst h; rename_i hh; exact ⟨hh, hh, .nil _⟩
    · cases h
  | s, l :: ls, s', h => by
    simp only [execH] at h; split at h
    · rename_i hh
      simp only [Option.bind_eq_some_iff] at h
      obtain ⟨s₁, h₁, h₂⟩ := h
      obtain ⟨hs₁, hs', hr⟩ := run_of_execH P c n s₁ ls s' h₂
      exact ⟨hh, hs', .cons ⟨h₁, hh, hs₁⟩ hr⟩
    · cases h

def pEx : Params := ⟨2, 1, 1, 1, 1⟩

/-- One worker, stop at 0, the wait entered just before: it returns at
`cap + ε`, waits `σ` for a CPU, runs a batch for `η`, re-checks after `σ`
and tears down for `τ`, so it is `done` exactly at `bound pEx = 7`. -/
def traceTight : List Lbl :=
  [.w 0, .w 0, .sig, .tick, .tick, .tick, .k 0, .tick, .w 0, .tick, .w 0, .tick, .w 0,
   .tick, .w 0]

theorem traceTight_result :
    execH pEx ⟨true, none⟩ (init 1 false) traceTight =
      some ⟨7, some 0, [⟨.done, 7⟩], .pass 0 0, [], false⟩ := by decide

theorem bound_tight : ∃ s, (ltsH ⟨true, none⟩ (Hyp pEx ⟨true, none⟩) 1).Reachable s ∧
    s.stop = some 0 ∧ s.now = bound pEx ∧ s.ws = [⟨.done, bound pEx⟩] :=
  ⟨_, ⟨_, traceTight, ⟨false, rfl⟩, (run_of_execH pEx _ 1 _ _ _ traceTight_result).2.2⟩,
    rfl, rfl, rfl⟩

end Flare.L5.Timed
