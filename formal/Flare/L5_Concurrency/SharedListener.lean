import Flare.Core.LTS

/-!
# Shared-listener mode: who may still use the listener fd number

With `FLARE_REUSEPORT_WORKERS=0` (`flare/runtime/scheduler.mojo:407-409`)
`Scheduler.start` binds one listener (`bind_shared`, :457-474), heap-stores
the `TcpListener` and hands the bare fd number to every worker. Each worker
(`flare/http/_server_reactor_epoll.mojo:110-266`, `is_shared = True`)

* registers the number once with `register_exclusive` (:155-156), then
* loops `while not load_stop_flag(...)`: one `reactor.poll`, then for every
  event of the returned batch either runs a connection step (where the
  handler runs, for as long as it takes) or, for token 0, calls
  `_accept_loop_fd(listener_fd, ...)` (:184-193), which `accept`s on the
  number until `EAGAIN`.

So a worker touches the number at registration and at every listener event
of a batch it polled before observing the stop flag; a slow handler earlier
in the same batch delays that accept arbitrarily.

Teardown (`shutdown` :746-760, `drain` :778-901) starts with
`_signal_and_close_listener` (:655-668): store stop := True, then `close` the
number. `_free_resources` (:703-744) later frees the `TcpListener` (with
`fd := -1` so it is not closed twice). `drain` detaches workers that miss the
deadline; nothing protects the shared listener for them.

## Semantics

Interleaving semantics over: the workers' program counters, the stop flag,
the state of the listener's fd *number* (`Fd`: still the listener, closed,
or reused by an unrelated `open`/`socket`/`accept` of the process, which
the kernel does by handing out the lowest free number), and the drain
thread's program counter. The environment step `reuse` is that unrelated
allocation. A worker step that uses the number while it is not the listener
sets the ghost flag `stale`.

The batch structure is abstracted: `acc` is "the worker is past its stop
check and will use the number"; any delay (poll, handler) is just not
scheduling the worker. The drain wait loop is over-approximated by letting
the sweep detach any worker that has not returned (sound for safety).

Memory model: the stop flag is a single release/acquire location (see
`Flare.L5.Scheduler`); fd-table operations are atomic system calls, so the
interleaving of `close`, `reuse` and `accept` is sequentially consistent.
-/
namespace Flare.L5.SharedListener

/-- Worker program counter.
mirrors flare/http/_server_reactor_epoll.mojo:150-266 @59bda50 -/
inductive WPc where
  | reg    -- :155-156 `register_exclusive(listener_fd, ...)`
  | check  -- :163 `while not load_stop_flag(stopping_addr)`
  | acc    -- :184-193 `_accept_loop_fd(listener_fd, ...)` for a polled event
  | done   -- loop left; thread returns (the fd is never closed by the worker)
  deriving DecidableEq, Repr

structure W where
  pc : WPc
  joined : Bool
  detached : Bool
  deriving DecidableEq, Repr

/-- What the listener's fd number currently names. -/
inductive Fd where
  | lis | closed | other
  deriving DecidableEq, Repr

/-- Teardown thread.
mirrors flare/runtime/scheduler.mojo:746-760,815-901 @59bda50 -/
inductive MPc where
  | signal          -- `_signal_and_close_listener`
  | sweep (k : Nat) -- join worker k if it returned, else detach it (drain)
  | free            -- stuck-worker carve-out + `_free_resources`
  | fin
  deriving DecidableEq, Repr

structure St where
  ws : List W
  stop : Bool
  fd : Fd
  m : MPc
  stale : Bool
  deriving DecidableEq, Repr

/-- `hard`: `shutdown()` / `drain(timeout_ms <= 0)` (every worker joined;
the sweep waits). `fix`: the CONC-05 fix (no early close; close in
`_free_resources` only when no worker was detached, else leak). -/
structure Cfg where
  hard : Bool
  fix : Bool
  deriving DecidableEq, Repr

inductive Lbl where
  | w (i : Nat)
  | reuse
  | m
  deriving DecidableEq, Repr

def w0 : W := ⟨.reg, false, false⟩

/-- Right after `Scheduler.start` returned: listener bound, `n` workers
spawned, none registered yet. -/
def init (n : Nat) : St := ⟨List.replicate n w0, false, .lis, .signal, false⟩

/-- One worker step: the new worker and whether it used the fd number.
mirrors flare/http/_server_reactor_epoll.mojo:155-193 @59bda50 -/
def wStep (stop : Bool) (w : W) : Option (W × Bool) :=
  match w.pc with
  | .reg => some ({ w with pc := .check }, true)
  | .check => some ({ w with pc := if stop then .done else .acc }, false)
  | .acc => some ({ w with pc := .check }, true)
  | .done => none

/-- Storing the stop flag. Pre-fix (`fix = false`) `_signal_and_close_listener`
also closed the shared fd; shipped (`fix = true`) `_signal_stop` does not.
mirrors flare/runtime/scheduler.mojo:655-675 (fixed, CONC-05);
pre-fix: flare/runtime/scheduler.mojo:655-668 @59bda50 -/
def signalFd (c : Cfg) (fd : Fd) : Fd :=
  if c.fix then fd else if fd = .lis then .closed else fd

def anyDet (s : St) : Bool := s.ws.any (·.detached)

/-- Freeing the shared listener: closed once after the join, leaked when a
worker was detached (`fix = true`).
mirrors flare/runtime/scheduler.mojo:706-725,907-918 (fixed, CONC-05);
pre-fix: flare/runtime/scheduler.mojo:703-724,890-900 @59bda50 -/
def freeFd (c : Cfg) (s : St) : Fd :=
  if c.fix then (if anyDet s then s.fd else if s.fd = .lis then .closed else s.fd)
  else s.fd

/-- mirrors flare/runtime/scheduler.mojo:655-668,846-900 @59bda50 -/
def mStep (c : Cfg) (s : St) : Option St :=
  match s.m with
  | .signal => some { s with stop := true, fd := signalFd c s.fd, m := .sweep 0 }
  | .sweep k =>
    match s.ws[k]? with
    | none => some { s with m := .free }
    | some w =>
      if w.pc = .done then
        some { s with ws := s.ws.set k { w with joined := true }, m := .sweep (k + 1) }
      else if c.hard then none
      else some { s with ws := s.ws.set k { w with detached := true }, m := .sweep (k + 1) }
  | .free => some { s with fd := freeFd c s, m := .fin }
  | .fin => none

/-- mirrors flare/http/_server_reactor_epoll.mojo:155-193 and
flare/runtime/scheduler.mojo:655-668,846-900 @59bda50 -/
def step (c : Cfg) (s : St) : Lbl → Option St
  | .w i =>
    match s.ws[i]? with
    | none => none
    | some w =>
      (wStep s.stop w).map fun (w', u) =>
        { s with ws := s.ws.set i w', stale := s.stale || (u && s.fd != .lis) }
  | .reuse => if s.fd = .closed then some { s with fd := .other } else none
  | .m => mStep c s

def lts (c : Cfg) (n : Nat) : LTS St Lbl := LTS.ofFn (· = init n) (step c)

/-- Pre-fix `shutdown()` / `drain(timeout_ms <= 0)` (counterexamples). -/
def cfgShutdown : Cfg := ⟨true, false⟩
/-- Pre-fix `drain(timeout_ms > 0)` (counterexamples). -/
def cfgDrain : Cfg := ⟨false, false⟩
/-- The shipped teardown (CONC-05 fix); `hard` selects `shutdown` / hard drain. -/
def cfgFixed (hard : Bool) : Cfg := ⟨hard, true⟩

/-! ## Spec -/

/-- No worker registers or accepts on the number after it stopped naming
the listener (closed, or reused by an unrelated file). -/
def NoStaleUse (s : St) : Prop := s.stale = false

/-- The listener is closed once teardown finished, unless a worker was
detached (then it must stay open: that worker may still accept on it). -/
def ClosedAtEnd (s : St) : Prop := s.m = .fin → anyDet s = false → s.fd ≠ .lis

/-! ## Inductive invariant of the fixed teardown -/

def Inv (s : St) : Prop :=
  s.stale = false ∧
  (∀ (j : Nat) (w : W), s.ws[j]? = some w → w.joined = true → w.pc = .done) ∧
  (s.fd ≠ .lis → ∀ (j : Nat) (w : W), s.ws[j]? = some w → w.joined = true) ∧
  (∀ k, s.m = .sweep k → ∀ (j : Nat) (w : W), j < k → s.ws[j]? = some w → w.joined = true ∨ w.detached = true) ∧
  ((s.m = .free ∨ s.m = .fin) → ∀ (j : Nat) (w : W), s.ws[j]? = some w → w.joined = true ∨ w.detached = true) ∧
  (s.m = .signal → s.fd = .lis) ∧
  (s.m = .fin → anyDet s = true ∨ s.fd ≠ .lis)

theorem getElem?_set_cases {l : List W} {i j : Nat} {a x : W} (h : (l.set i a)[j]? = some x) :
    (i = j ∧ x = a ∧ i < l.length) ∨ (i ≠ j ∧ l[j]? = some x) := by
  rw [List.getElem?_set] at h
  by_cases hij : i = j
  · subst hij
    by_cases hl : i < l.length
    · simp [hl] at h; exact Or.inl ⟨rfl, h.symm, hl⟩
    · simp [hl] at h
  · simp [hij] at h; exact Or.inr ⟨hij, h⟩

theorem anyDet_false {s : St} (h : anyDet s = false) : ∀ (j : Nat) (w : W), s.ws[j]? = some w → w.detached = false := by
  intro j w hw
  have hm := List.mem_of_getElem? hw
  simp only [anyDet, List.any_eq_false] at h
  cases hd : w.detached
  · rfl
  · exact absurd hd (h w hm)

theorem anyDet_set_of {l : List W} {i : Nat} {w a : W} (hi : l[i]? = some w)
    (hd : a.detached = w.detached) : (l.set i a).any (·.detached) = l.any (·.detached) := by
  have hlt : i < l.length := by
    rcases Nat.lt_or_ge i l.length with h | h
    · exact h
    · rw [List.getElem?_eq_none h] at hi; cases hi
  have hw : l[i] = w := by simpa [List.getElem?_eq_getElem hlt] using hi
  apply Bool.eq_iff_iff.mpr
  simp only [List.any_eq_true, List.mem_iff_getElem]
  constructor
  · rintro ⟨x, ⟨j, hj, rfl⟩, hx⟩
    rw [List.length_set] at hj
    by_cases hij : i = j
    · subst hij; refine ⟨l[i], ⟨i, hlt, rfl⟩, ?_⟩; simp at hx; rw [hw, ← hd]; exact hx
    · exact ⟨l[j], ⟨j, hj, rfl⟩, by simpa [List.getElem_set, hij] using hx⟩
  · rintro ⟨x, ⟨j, hj, rfl⟩, hx⟩
    by_cases hij : i = j
    · subst hij; refine ⟨a, ⟨i, by simpa using hlt, by simp⟩, ?_⟩; rw [hd, ← hw]; exact hx
    · exact ⟨(l.set i a)[j]'(by simpa using hj), ⟨j, by simpa using hj, rfl⟩,
        by simpa [List.getElem_set, hij] using hx⟩

theorem inv_init (n : Nat) : Inv (init n) := by
  refine ⟨rfl, ?_, ?_, ?_, ?_, fun _ => rfl, ?_⟩
  · intro j w hw hj
    simp only [init, List.getElem?_replicate] at hw
    split at hw
    · simp only [Option.some.injEq] at hw; subst hw; cases hj
    · cases hw
  · intro h; exact absurd rfl h
  · intro k hk; cases hk
  · intro h; rcases h with h | h <;> cases h
  · intro h; cases h

theorem inv_step (hard : Bool) (s s' : St) (l : Lbl) (I : Inv s)
    (h : step (cfgFixed hard) s l = some s') : Inv s' := by
  obtain ⟨i1, i2, i3, i4, i5, i6, i7⟩ := I
  cases l with
  | w i =>
    simp only [step] at h
    split at h
    · cases h
    · rename_i w hi
      cases hs : wStep s.stop w with
      | none => simp [hs] at h
      | some p =>
        obtain ⟨w', u⟩ := p
        simp only [hs, Option.map_some, Option.some.injEq] at h
        subst h
        have hpc : w.pc ≠ .done := by intro hd; simp [wStep, hd] at hs
        have hj : w.joined = false := by
          cases hjj : w.joined
          · rfl
          · exact absurd (i2 i w hi hjj) hpc
        have hfd : s.fd = .lis := by
          cases hf : s.fd with
          | lis => rfl
          | _ => have := i3 (by rw [hf]; decide) i w hi; rw [hj] at this; cases this
        have e : w'.joined = w.joined ∧ w'.detached = w.detached := by
          unfold wStep at hs; split at hs <;> simp at hs <;> obtain ⟨rfl, -⟩ := hs <;> simp
        refine ⟨by simp [i1, hfd], ?_, fun h' => absurd hfd h', ?_, ?_, i6, ?_⟩
        · intro j x hx hxj
          rcases getElem?_set_cases hx with ⟨rfl, rfl, -⟩ | ⟨-, hx⟩
          · rw [e.1, hj] at hxj; cases hxj
          · exact i2 j x hx hxj
        · intro k hk j x hjk hx
          rcases getElem?_set_cases hx with ⟨rfl, rfl, -⟩ | ⟨-, hx⟩
          · rw [e.1, e.2]; exact i4 k hk _ w hjk hi
          · exact i4 k hk j x hjk hx
        · intro hm j x hx
          rcases getElem?_set_cases hx with ⟨rfl, rfl, -⟩ | ⟨-, hx⟩
          · rw [e.1, e.2]; exact i5 hm _ w hi
          · exact i5 hm j x hx
        · intro hm
          have : (s.ws.set i w').any (·.detached) = s.ws.any (·.detached) := anyDet_set_of hi e.2
          simp only [anyDet] at i7 ⊢
          rw [this]; exact i7 hm
  | reuse =>
    simp only [step] at h
    split at h
    · rename_i hc
      simp only [Option.some.injEq] at h; subst h
      have hne : s.fd ≠ .lis := by rw [hc]; decide
      exact ⟨i1, i2, fun _ => i3 hne, i4, i5, fun hm => absurd (i6 hm) hne,
        fun hm => (i7 hm).imp id (fun _ => (by decide : Fd.other ≠ Fd.lis))⟩
    · cases h
  | m =>
    simp only [step, mStep] at h
    cases hm : s.m with
    | signal =>
      simp only [hm, Option.some.injEq] at h; subst h
      have hfd := i6 hm
      refine ⟨i1, i2, ?_, ?_, ?_, ?_, ?_⟩
      · intro hne; simp [signalFd, cfgFixed, hfd] at hne
      · intro k hk j x hjk; simp at hk; omega
      · intro h'; rcases h' with h' | h' <;> cases h'
      · intro h'; cases h'
      · intro h'; cases h'
    | sweep k =>
      simp only [hm] at h
      split at h
      · rename_i hk
        simp only [Option.some.injEq] at h; subst h
        refine ⟨i1, i2, i3, ?_, ?_, ?_, ?_⟩
        · intro k' hk'; cases hk'
        · intro _ j x hx
          have hlen : k ≥ s.ws.length := List.getElem?_eq_none_iff.mp hk
          have hj : j < s.ws.length := by
            rcases Nat.lt_or_ge j s.ws.length with h' | h'
            · exact h'
            · rw [List.getElem?_eq_none h'] at hx; cases hx
          exact i4 k hm j x (by omega) hx
        · intro h'; cases h'
        · intro h'; cases h'
      · rename_i w hk
        split at h
        · rename_i hd
          simp only [Option.some.injEq] at h; subst h
          refine ⟨i1, ?_, ?_, ?_, ?_, ?_, ?_⟩
          · intro j x hx hxj
            rcases getElem?_set_cases hx with ⟨rfl, rfl, -⟩ | ⟨-, hx⟩
            · exact hd
            · exact i2 j x hx hxj
          · intro hne j x hx
            rcases getElem?_set_cases hx with ⟨rfl, rfl, -⟩ | ⟨-, hx⟩
            · rfl
            · exact i3 hne j x hx
          · intro k' hk' j x hjk hx
            simp only [MPc.sweep.injEq] at hk'; subst hk'
            rcases getElem?_set_cases hx with ⟨rfl, rfl, -⟩ | ⟨hne, hx⟩
            · exact Or.inl rfl
            · exact i4 k hm j x (by omega) hx
          · intro h'; rcases h' with h' | h' <;> cases h'
          · intro h'; cases h'
          · intro h'; cases h'
        · split at h
          · cases h
          · simp only [Option.some.injEq] at h; subst h
            rename_i hd _
            have hj : w.joined = false := by
              cases hjj : w.joined
              · rfl
              · exact absurd (i2 k w hk hjj) hd
            refine ⟨i1, ?_, ?_, ?_, ?_, ?_, ?_⟩
            · intro j x hx hxj
              rcases getElem?_set_cases hx with ⟨rfl, rfl, -⟩ | ⟨-, hx⟩
              · simp [hj] at hxj
              · exact i2 j x hx hxj
            · intro hne j x hx
              have := i3 hne k w hk; rw [hj] at this; cases this
            · intro k' hk' j x hjk hx
              simp only [MPc.sweep.injEq] at hk'; subst hk'
              rcases getElem?_set_cases hx with ⟨rfl, rfl, -⟩ | ⟨hne, hx⟩
              · exact Or.inr rfl
              · exact i4 k hm j x (by omega) hx
            · intro h'; rcases h' with h' | h' <;> cases h'
            · intro h'; cases h'
            · intro h'; cases h'
    | free =>
      simp only [hm, Option.some.injEq] at h; subst h
      have hdec := i5 (Or.inl hm)
      refine ⟨i1, i2, ?_, ?_, ?_, ?_, ?_⟩
      · intro hne j x hx
        simp only [freeFd, cfgFixed, if_true] at hne
        split at hne
        · exact i3 hne j x hx
        · rename_i had
          rcases hdec j x hx with h' | h'
          · exact h'
          · have := anyDet_false (Bool.eq_false_iff.mpr had) j x hx; rw [h'] at this; cases this
      · intro k' hk'; cases hk'
      · intro _; exact hdec
      · intro h'; cases h'
      · intro _
        show anyDet s = true ∨ freeFd (cfgFixed hard) s ≠ .lis
        simp only [freeFd, cfgFixed, if_true]
        cases had : anyDet s
        · right; simp only [Bool.false_eq_true, if_false]; split <;> simp_all
        · left; rfl
    | fin => simp [hm] at h

theorem inv_inductive (hard : Bool) (n : Nat) : (lts (cfgFixed hard) n).Inductive Inv where
  init := by rintro s rfl; exact inv_init n
  step := fun s l s' hi hs => inv_step hard s s' l hi hs

/-! ## Headline properties -/

/-- Fixed teardown, `shutdown` or `drain`, any number of workers, any
interleaving with unrelated fd allocations: no worker ever registers or
accepts on the listener's number after it stopped naming the listener. -/
theorem fixed_noStale (hard : Bool) (n : Nat) (s : St)
    (h : (lts (cfgFixed hard) n).Reachable s) : NoStaleUse s :=
  ((inv_inductive hard n).reachable s h).1

/-- …and the listener is not leaked when every worker was joined. -/
theorem fixed_closedAtEnd (hard : Bool) (n : Nat) (s : St)
    (h : (lts (cfgFixed hard) n).Reachable s) : ClosedAtEnd s := by
  intro hm hd
  rcases ((inv_inductive hard n).reachable s h).2.2.2.2.2.2 hm with h' | h'
  · rw [hd] at h'; cases h'
  · exact h'

/-- Without the early close, a worker still exits on the stop flag: once
`stop` is set its next loop check leaves the loop, and from `acc` it reaches
that check in one step (the 100 ms poll cap, `_reactor/lifecycle.mojo:31-47`,
bounds the time to that check when no event arrives). -/
theorem stop_exits (w : W) (hw : w.pc = WPc.check ∨ w.pc = WPc.acc) :
    (wStep true w).map (·.1.pc) = some WPc.done ∨
      ((wStep true w).bind (fun p => wStep true p.1)).map (·.1.pc) = some WPc.done := by
  rcases hw with hw | hw
  · left; simp [wStep, hw]
  · right; simp [wStep, hw]

/-! ## Traces -/

def exec (c : Cfg) : St → List Lbl → Option St
  | s, [] => some s
  | s, l :: ls => (step c s l).bind fun s' => exec c s' ls

theorem run_of_exec (c : Cfg) (n : Nat) :
    ∀ (s : St) (ls : List Lbl) (s' : St), exec c s ls = some s' → (lts c n).Run s ls s'
  | s, [], s', h => by simp [exec] at h; subst h; exact .nil _
  | s, l :: ls, s', h => by
    simp only [exec, Option.bind_eq_some_iff] at h
    obtain ⟨s₁, h₁, h₂⟩ := h
    exact .cons h₁ (run_of_exec c n s₁ ls s' h₂)

theorem reachable_of_exec (c : Cfg) (n : Nat) (ls : List Lbl) (s : St)
    (h : exec c (init n) ls = some s) : (lts c n).Reachable s :=
  ⟨_, ls, rfl, run_of_exec c n _ ls s h⟩

end Flare.L5.SharedListener
