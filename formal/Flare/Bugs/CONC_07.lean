import Flare.L5_Concurrency.Timed

/-!
# CONC-07: an idle io_uring worker never sees the stop flag

Status: resolved. The io_uring loops wait with
`ureactor.poll(1, completions, 64, URING_STOP_POLL_MS)` (100 ms), which
blocks in `io_uring_enter` with `IORING_ENTER_EXT_ARG` and a timeout
(flare/runtime/io_uring.mojo `io_uring_enter_timeout`), so the loop is
`capped` and the shipped config is `cfgUringShipped`. The counterexamples
below are about the pre-fix, uncapped configs `cfgUringShutdown` and
`cfgUringDrain`; `fixed_meets_spec` is stated about `cfgUringShipped`.

Before the fix, the io_uring buffer-ring loop (flare/http/_server_reactor_uring.mojo:784-998
@59bda50), which `HttpFrontend` runs when io_uring is available and
`config.use_bufring` is set (flare/http/frontend.mojo:126-160), builds its
ring with `enable_wakeup=False` (:820-824) and waits with
`ureactor.poll(1, completions, 64)` (:852). With nothing ready, `poll(1)`
blocks in `io_uring_enter(min_complete=1)` with no timeout
(flare/runtime/uring_reactor.mojo:834-836). The stop flag is read only
at the top of the loop (:848), so an idle worker reads it again only when
some completion arrives (a new connection, data on a kept-alive one).

`Scheduler.shutdown` stores the flag and then `pthread_join`s every worker
(flare/runtime/scheduler.mojo:746-760); nothing wakes the ring, so on an idle
server it blocks until a client connects. `drain(D)` waits `D` ms and then
detaches every idle worker (:829-852), however large `D` is, leaking its
context, stats cell and listeners. `HttpServer.serve(num_workers > 1)` with
`FLARE_BUFRING_HANDLER=1` reaches the hang through `close()`
(flare/http/server.mojo:1302-1336).

In `Flare.L5.Timed` terms the loop is not `capped`: the kernel can end its
wait only on a completion, which needs traffic. Every timing hypothesis
except `PollReturns` can hold (`HypNoPoll`), and then no bound exists:
`shutdown_never_returns` gives, for every `N`, a run in which `N` ms after
the stop the worker is still in its wait and shutdown is still joining it;
`drain_detaches_idle` gives, for every deadline `D` (in particular
`D > bound P`, where the capped loops are covered by
`Flare.L5.Timed.drain_joins_all`), a drain that ends with the idle worker
detached.

Fix: bound the wait, for example by keeping one `IORING_OP_TIMEOUT` (100 ms,
relative) armed and re-arming it on its completion; the loop is then
`capped` and `Flare.L5.Timed.worker_done_by`, `teardown_done_by` and
`drain_joins_all` apply with `cap = 100`.
-/
namespace Flare.Bugs.CONC_07
open Flare.L5.Timed

/-- Pre-fix: `poll(1)` with no timeout (not `capped`). -/
def cfgUringShutdown : Cfg := ⟨false, none⟩
/-- Pre-fix, `drain(D)`. -/
def cfgUringDrain (D : Nat) : Cfg := ⟨false, some D⟩
/-- Shipped: mirrors flare/http/_server_reactor_uring.mojo:856-998
(fixed, CONC-07): the wait is capped at `URING_STOP_POLL_MS = 100`. -/
def cfgUringShipped (dr : Option Nat) : Cfg := ⟨true, dr⟩

/-- Every hypothesis of `Flare.L5.Timed.Hyp` except `PollReturns`. -/
def HypNoPoll (P : Params) (c : Cfg) (s : TS) : Prop :=
  FairW P s ∧ FairM P c s ∧ HandlerBound P s ∧ TeardownBound P s

theorem run_append {c : Cfg} {H : TS → Prop} {n : Nat} {s s' s'' : TS} {l₁ l₂ : List Lbl}
    (h₁ : (ltsH c H n).Run s l₁ s') (h₂ : (ltsH c H n).Run s' l₂ s'') :
    (ltsH c H n).Run s (l₁ ++ l₂) s'' := by
  induction h₁ with
  | nil => exact h₂
  | cons hs _ ih => exact .cons hs (ih h₂)

theorem ticks {c : Cfg} {H : TS → Prop} {n : Nat} (f : Nat → TS)
    (hf : ∀ k, step c (f k) .tick = some (f (k + 1))) :
    ∀ N a, (∀ k, k ≤ a + N → H (f k)) → (ltsH c H n).Run (f a) (List.replicate N .tick) (f (a + N))
  | 0, a, _ => .nil _
  | N + 1, a, hH => by
    have ih := ticks (n := n) f hf N (a + 1) (fun k hk => hH k (by omega))
    rw [show a + 1 + N = a + (N + 1) by omega] at ih
    exact .cons ⟨hf a, hH a (by omega), hH (a + 1) (by omega)⟩ ih

/-- The worker has armed and entered its wait, the stop was set at 0. -/
def sPoll (now : Nat) (stop : Option Nat) (m : MPc) (snap : List Bool) : TS :=
  ⟨now, stop, [⟨.poll, 0⟩], m, snap, false⟩

def s1 : TS := ⟨0, none, [⟨.check, 0⟩], .sig, [], false⟩

theorem hyp_prefix (P : Params) (c : Cfg) :
    HypNoPoll P c (init 1 false) ∧ HypNoPoll P c s1 ∧ HypNoPoll P c (sPoll 0 none .sig []) := by
  refine ⟨?_, ?_, ?_⟩ <;>
    simp [HypNoPoll, FairW, FairM, HandlerBound, TeardownBound, init, s1, sPoll]

/-- Register, pass the check, enter the wait, then the stop. -/
theorem prefix_run (P : Params) (c : Cfg) (m : MPc)
    (hsig : step c (sPoll 0 none .sig []) .sig = some (sPoll 0 (some 0) m []))
    (hm : HypNoPoll P c (sPoll 0 (some 0) m [])) :
    (ltsH c (HypNoPoll P c) 1).Run (init 1 false) [.w 0, .w 0, .sig] (sPoll 0 (some 0) m []) := by
  obtain ⟨h0, h1, h2⟩ := hyp_prefix P c
  exact .cons ⟨rfl, h0, h1⟩ (.cons ⟨rfl, h1, h2⟩ (.cons ⟨hsig, h2, hm⟩ (.nil _)))

/-- For every `N`: `N` ms after the stop, with every hypothesis but a bounded
wait holding throughout, the idle worker is still waiting and `shutdown` is
still joining it. -/
theorem shutdown_never_returns (P : Params) (N : Nat) :
    ∃ s, (ltsH cfgUringShutdown (HypNoPoll P cfgUringShutdown) 1).Reachable s ∧
      s.stop = some 0 ∧ s.now = N ∧ s.ws = [⟨.poll, 0⟩] ∧ s.m = .pass 0 0 := by
  have hH : ∀ k, HypNoPoll P cfgUringShutdown (sPoll k (some 0) (.pass 0 0) []) := by
    intro k
    simp [HypNoPoll, FairW, FairM, HandlerBound, TeardownBound, sPoll, cfgUringShutdown]
  have hr := run_append (prefix_run P cfgUringShutdown (.pass 0 0) rfl (hH 0))
    (ticks (c := cfgUringShutdown) (n := 1) (fun k => sPoll k (some 0) (.pass 0 0) [])
      (fun _ => rfl) N 0 (fun k _ => hH k))
  exact ⟨_, ⟨_, _, ⟨false, rfl⟩, hr⟩, rfl, by simp [sPoll], rfl, rfl⟩

/-- In those states the wait has lasted longer than `cap + ε`: the
`PollReturns` hypothesis is what the io_uring loop lacks. -/
theorem not_pollReturns (P : Params) (N : Nat) (h : P.cap + P.ε < N) :
    ¬ PollReturns P (sPoll N (some 0) (.pass 0 0) []) := by
  intro hp
  have := hp ⟨.poll, 0⟩ (by simp [sPoll]) rfl
  simp only [sPoll] at this
  omega

/-- `drain(D)`, for every `D`: the idle worker misses the deadline and is
detached (snapshot `[false]`), and drain returns with it still waiting. -/
theorem drain_detaches_idle (P : Params) (D : Nat) :
    ∃ s, (ltsH (cfgUringDrain D) (HypNoPoll P (cfgUringDrain D)) 1).Reachable s ∧
      s.m = .fin D ∧ s.snap = [false] ∧ s.ws = [⟨.poll, 0⟩] := by
  let c := cfgUringDrain D
  have hW : ∀ k, k ≤ D → HypNoPoll P c (sPoll k (some 0) (.wait 0) []) := by
    intro k hk
    simp [HypNoPoll, FairW, FairM, HandlerBound, TeardownBound, sPoll, c, cfgUringDrain, allDone,
      isDone]
    omega
  have hT : ∀ m, (m = .pass 0 D ∨ m = .pass 1 D ∨ m = .free D ∨ m = .fin D) →
      HypNoPoll P c (sPoll D (some 0) m [false]) := by
    intro m hm
    rcases hm with rfl | rfl | rfl | rfl <;>
      simp [HypNoPoll, FairW, FairM, HandlerBound, TeardownBound, sPoll, c, cfgUringDrain]
  have hr1 := run_append (prefix_run P c (.wait 0) rfl (hW 0 (Nat.zero_le _)))
    (ticks (c := c) (n := 1) (fun k => sPoll k (some 0) (.wait 0) []) (fun _ => rfl) D 0
      (fun k hk => hW k (by omega)))
  have e1 : step c (sPoll D (some 0) (.wait 0) []) .m = some (sPoll D (some 0) (.pass 0 D) [false]) := by
    simp [step, mStep, sPoll, c, cfgUringDrain, allDone, isDone]
  have e2 : step c (sPoll D (some 0) (.pass 0 D) [false]) .m = some (sPoll D (some 0) (.pass 1 D) [false]) := by
    simp [step, mStep, sPoll, c, cfgUringDrain]
  have e3 : step c (sPoll D (some 0) (.pass 1 D) [false]) .m = some (sPoll D (some 0) (.free D) [false]) := by
    simp [step, mStep, sPoll]
  have e4 : step c (sPoll D (some 0) (.free D) [false]) .m = some (sPoll D (some 0) (.fin D) [false]) := by
    simp [step, mStep, sPoll]
  have hr2 : (ltsH c (HypNoPoll P c) 1).Run (sPoll (0 + D) (some 0) (.wait 0) []) [.m, .m, .m, .m]
      (sPoll D (some 0) (.fin D) [false]) := by
    rw [Nat.zero_add]
    exact .cons ⟨e1, hW D (Nat.le_refl _), hT _ (Or.inl rfl)⟩
      (.cons ⟨e2, hT _ (Or.inl rfl), hT _ (Or.inr (Or.inl rfl))⟩
      (.cons ⟨e3, hT _ (Or.inr (Or.inl rfl)), hT _ (Or.inr (Or.inr (Or.inl rfl)))⟩
      (.cons ⟨e4, hT _ (Or.inr (Or.inr (Or.inl rfl))), hT _ (Or.inr (Or.inr (Or.inr rfl)))⟩
      (.nil _))))
  exact ⟨_, ⟨_, _, ⟨false, rfl⟩, run_append hr1 hr2⟩, rfl, rfl, rfl⟩

/-- The shipped loop (`cfgUringShipped`, a capped wait) meets the spec: every
worker is done within `bound P` and `shutdown` / `drain` return within
`mBound`, and a drain with `D > bound P` detaches nobody. -/
theorem fixed_meets_spec (P : Params) (dr : Option Nat) (n : Nat) (s : TS)
    (hr : (ltsH (cfgUringShipped dr) (Hyp P (cfgUringShipped dr)) n).Reachable s) {t0 : Nat}
    (hs : s.stop = some t0) :
    (t0 + bound P < s.now → ∀ w ∈ s.ws, w.pc = .done) ∧
    (t0 + mBound P (cfgUringShipped dr) n < s.now → ∃ t, s.m = .fin t) ∧
    (∀ D, dr = some D → bound P < D → (∀ t, s.m ≠ .wait t) → ∀ b ∈ s.snap, b = true) :=
  ⟨worker_done_by P _ n s hr hs, teardown_done_by P _ n s hr hs,
    fun D hD hB hm => drain_joins_all P (cfgUringShipped dr) n D hD hB s hr hm⟩

end Flare.Bugs.CONC_07
