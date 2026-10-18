import Flare.L5_Concurrency.SharedListener

/-!
# The io_uring buffer-ring worker and the shared listener

`HttpFrontend.run_worker` (`flare/http/frontend.mojo:135-183`) runs
`run_uring_bufring_reactor_loop_shared` (`flare/http/_server_reactor_uring.mojo:784-998`)
when io_uring is available, `config.use_bufring` is set, TLS is off and the
worker has no extra listeners. The same frontend tells the scheduler
`requires_per_worker_listener()` (:114-133) under the same conditions except
the extra listeners, and `Scheduler.start` then pre-binds per-worker
`SO_REUSEPORT` listeners (`flare/runtime/scheduler.mojo:388-430,511-521`), so
the worker never gets the shared fd. Both sides call `use_uring_backend()`
(`flare/runtime/uring_reactor.mojo:953-979`), which re-reads
`FLARE_DISABLE_IO_URING` and re-probes `io_uring_setup` on every call
(`flare/runtime/io_uring.mojo:513-536`, uncached).

So the shared-listener mode never runs the io_uring loop as long as the two
probes agree (`uring_never_shared`). They can disagree (`probe_skew_shared`):
a transient `io_uring_setup` failure on the scheduler thread (`EMFILE`,
`ENOMEM`) or a change to the environment variable between `start` and the
worker's first call; with `FLARE_REUSEPORT_WORKERS=0` the worker then runs
the io_uring loop on the shared fd.

For that case the io_uring worker is modelled on `Flare.L5.SharedListener`'s
state: it uses the fd number once, when it arms the multishot accept
(`arm_listener_multishot(listener_fd)`, :843), before its first stop check,
and never again: later accepts are completions of the armed request, which
holds its own reference to the socket. `sim_step` is a forward simulation
into the epoll model in which every use of the number is matched, so the
teardown's safety carries over (`uring_fixed_noStale`,
`uring_fixed_closedAtEnd`).
-/
namespace Flare.L5.UringShared

open Flare.L5.SharedListener

/-- mirrors flare/http/frontend.mojo#HttpFrontend.requires_per_worker_listener sha=0619b91262d6 at=59bda50f -/
def requiresPerWorker (linux probe bufring : Bool) (tls : Nat) : Bool :=
  linux && probe && bufring && tls == 0

/-- mirrors flare/http/frontend.mojo#HttpFrontend.run_worker sha=a464347a1707 at=0a183352 -/
def uringDispatch (linux probe bufring : Bool) (tls extras : Nat) : Bool :=
  linux && probe && bufring && tls == 0 && extras == 0

/-- mirrors flare/runtime/scheduler.mojo#Scheduler.start sha=a1f17c56964f at=0a183352 -/
def prebind (demands reuseport : Bool) (extras : Nat) : Bool :=
  demands || reuseport || decide (0 < extras)

/-- With the same probe result on both threads, a worker that runs the
io_uring loop was given a per-worker listener, never the shared one. -/
theorem uring_never_shared (linux probe bufring reuse : Bool) (tls extras : Nat)
    (h : uringDispatch linux probe bufring tls extras = true) :
    prebind (requiresPerWorker linux probe bufring tls) reuse extras = true := by
  simp only [uringDispatch, Bool.and_eq_true] at h
  obtain ⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, -⟩ := h
  simp [prebind, requiresPerWorker, h1, h2, h3, h4]

/-- The scheduler thread's probe fails, the worker's succeeds,
`FLARE_REUSEPORT_WORKERS=0`, one address: shared listener, io_uring loop. -/
theorem probe_skew_shared :
    prebind (requiresPerWorker true false true 0) false 0 = false ∧
      uringDispatch true true true 0 0 = true := by decide

/-- The io_uring worker on the shared-listener state: the number is used by
the arm only.
mirrors flare/http/_server_reactor_uring.mojo#run_uring_bufring_reactor_loop_shared sha=3b4da4a6d678 at=0a183352 -/
def uwStep (stop : Bool) (w : W) : Option (W × Bool) :=
  match w.pc with
  | .reg => some ({ w with pc := .check }, true)
  | .check => some ({ w with pc := if stop then .done else .acc }, false)
  | .acc => some ({ w with pc := .check }, false)
  | .done => none

/-- mirrors flare/http/_server_reactor_uring.mojo#run_uring_bufring_reactor_loop_shared sha=3b4da4a6d678 at=30fc5e99 and
flare/runtime/scheduler.mojo#Scheduler._signal_stop+Scheduler.drain sha=0d9bc4a3ee5b at=30fc5e99 -/
def ustep (hard : Bool) (s : St) : Lbl → Option St
  | .w i =>
    match s.ws[i]? with
    | none => none
    | some w =>
      (uwStep s.stop w).map fun (w', u) =>
        { s with ws := s.ws.set i w', stale := s.stale || (u && s.fd != .lis) }
  | .reuse => if s.fd = .closed then some { s with fd := .other } else none
  | .m => mStep hard s

def ults (hard : Bool) (n : Nat) : LTS St Lbl := LTS.ofFn (· = init n) (ustep hard)

/-- Same state except that the epoll model may have more stale uses. -/
def R (u s : St) : Prop :=
  u.ws = s.ws ∧ u.stop = s.stop ∧ u.fd = s.fd ∧ u.m = s.m ∧ (u.stale = true → s.stale = true)

theorem uwStep_le {st : Bool} {w w' : W} {b : Bool} (h : uwStep st w = some (w', b)) :
    ∃ b', wStep st w = some (w', b') ∧ (b = true → b' = true) := by
  cases hpc : w.pc <;> simp only [uwStep, hpc, Option.some.injEq, Prod.mk.injEq, reduceCtorEq] at h <;>
    obtain ⟨rfl, rfl⟩ := h <;> simp [wStep, hpc]

theorem mStep_stale (hard : Bool) (s : St) (b : Bool) :
    mStep hard { s with stale := b } = (mStep hard s).map (fun x => { x with stale := b }) := by
  obtain ⟨ws, stop, fd, m, st⟩ := s
  cases m with
  | signal => rfl
  | sweep k =>
    simp only [mStep]
    cases ws[k]? with
    | none => rfl
    | some w =>
      simp only
      split
      · rfl
      · split <;> rfl
  | free => simp [mStep, freeFd, anyDet]
  | fin => rfl

theorem mStep_keeps_stale {hard : Bool} {s s' : St} (h : mStep hard s = some s') : s'.stale = s.stale := by
  unfold mStep at h
  split at h
  · simp only [Option.some.injEq] at h; subst h; rfl
  · split at h
    · simp only [Option.some.injEq] at h; subst h; rfl
    · split at h
      · simp only [Option.some.injEq] at h; subst h; rfl
      · split at h
        · cases h
        · simp only [Option.some.injEq] at h; subst h; rfl
  · simp only [Option.some.injEq] at h; subst h; rfl
  · cases h

theorem R_eq {u s : St} (h : R u s) : u = { s with stale := u.stale } := by
  obtain ⟨h1, h2, h3, h4, -⟩ := h
  obtain ⟨_, _, _, _, _⟩ := u
  obtain ⟨_, _, _, _, _⟩ := s
  simp only at h1 h2 h3 h4
  subst h1 h2 h3 h4
  rfl

/-- Forward simulation: every io_uring step is an epoll step with the same
label, and a stale use on the io_uring side is a stale use on the epoll side. -/
theorem sim_step (hard : Bool) {u s u' : St} {l : Lbl} (hR : R u s) (hu : ustep hard u l = some u') :
    ∃ s', step hard s l = some s' ∧ R u' s' := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := hR
  cases l with
  | w i =>
    simp only [ustep] at hu
    split at hu
    · cases hu
    · rename_i w hw
      cases hp : uwStep u.stop w with
      | none => simp [hp] at hu
      | some p =>
        obtain ⟨w', b⟩ := p
        simp only [hp, Option.map_some, Option.some.injEq] at hu; subst hu
        obtain ⟨b', hb', hbb⟩ := uwStep_le hp
        refine ⟨{ s with ws := s.ws.set i w', stale := s.stale || (b' && s.fd != .lis) }, ?_, ?_⟩
        · simp only [step, ← h1, hw, ← h2, hb', Option.map_some]
        · refine ⟨by simp [h1], h2, h3, h4, ?_⟩
          simp only [Bool.or_eq_true, Bool.and_eq_true]
          rintro (h | ⟨hb, hf⟩)
          · exact Or.inl (h5 h)
          · exact Or.inr ⟨hbb hb, by rw [← h3]; exact hf⟩
  | reuse =>
    simp only [ustep] at hu
    split at hu
    · rename_i hc
      simp only [Option.some.injEq] at hu; subst hu
      refine ⟨{ s with fd := .other }, ?_, h1, h2, rfl, h4, h5⟩
      simp only [step]; rw [← h3]; simp [hc]
    · cases hu
  | m =>
    simp only [ustep] at hu
    rw [R_eq ⟨h1, h2, h3, h4, h5⟩, mStep_stale] at hu
    cases hs : mStep hard s with
    | none => simp [hs] at hu
    | some s' =>
      simp only [hs, Option.map_some, Option.some.injEq] at hu; subst hu
      refine ⟨s', by simp only [step]; exact hs, rfl, rfl, rfl, rfl, ?_⟩
      intro hst
      rw [mStep_keeps_stale hs]; exact h5 hst

theorem sim_run (hard : Bool) (n : Nat) {u s u' : St} {ls : List Lbl} (hR : R u s)
    (hr : (ults hard n).Run u ls u') : ∃ s', (lts hard n).Run s ls s' ∧ R u' s' := by
  induction hr generalizing s with
  | nil => exact ⟨s, .nil _, hR⟩
  | cons hst _ ih =>
    obtain ⟨s₁, h₁, hR₁⟩ := sim_step hard hR hst
    obtain ⟨s', hr', hR'⟩ := ih hR₁
    exact ⟨s', .cons h₁ hr', hR'⟩

theorem sim_reachable (hard : Bool) (n : Nat) {u : St} (h : (ults hard n).Reachable u) :
    ∃ s, (lts hard n).Reachable s ∧ R u s := by
  obtain ⟨u₀, ls, rfl, hr⟩ := h
  obtain ⟨s, hr', hR⟩ := sim_run hard n ⟨rfl, rfl, rfl, rfl, id⟩ hr
  exact ⟨s, ⟨_, ls, rfl, hr'⟩, hR⟩

/-- An io_uring worker on the shared fd never arms on the number after it
stopped naming the listener. -/
theorem uring_fixed_noStale (hard : Bool) (n : Nat) (u : St)
    (h : (ults hard n).Reachable u) : NoStaleUse u := by
  obtain ⟨s, hs, hR⟩ := sim_reachable _ n h
  have := noStale hard n s hs
  simp only [NoStaleUse] at this ⊢
  cases hu : u.stale
  · rfl
  · rw [hR.2.2.2.2 hu] at this; cases this

theorem uring_fixed_closedAtEnd (hard : Bool) (n : Nat) (u : St)
    (h : (ults hard n).Reachable u) : ClosedAtEnd u := by
  obtain ⟨s, hs, ⟨h1, -, h3, h4, -⟩⟩ := sim_reachable _ n h
  intro hm hd
  have := closedAtEnd hard n s hs
  simp only [anyDet] at hd this
  rw [h3]; rw [h4] at hm; rw [h1] at hd
  exact this hm hd

end Flare.L5.UringShared
