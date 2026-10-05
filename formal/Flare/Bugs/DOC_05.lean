/-!
# DOC-05: `serve_cancellable`, `serve_view` and `serve_static` silently ignore extra listeners

Status: resolved. The three methods now call the new
`HttpServer._reject_extra_listeners` (`flare/http/server.mojo`) and raise when
`bind` was given several addresses; regression tests
`tests/http/test_multi_listener.mojo`
`test_serve_cancellable_rejects_extra_listeners`,
`test_serve_view_rejects_extra_listeners` and
`test_serve_static_rejects_extra_listeners`. `entry` below is the shipped
model; `entryOld` is the pre-fix behaviour the counterexample is about.

* flare file (pre-fix): `flare/http/server.mojo` @59bda50. `bind(List[SocketAddr])`
  (262-346) stores every address after the first in `_extra_listener_fds`.
  `_reject_tls_with_extra_listeners` (1009-1026) raises only when `_tls_ctx`
  is set. `serve_cancellable` (1433-1444), `serve_view` (1475-1486) and
  `serve_static` (1523-1528 and the loop after it) call it, then run a reactor
  loop over `self._listener` alone.
* Doc clause: `docs/features.md:80-82` "`serve_cancellable`, `serve_view` and
  `serve_static` now raise when a TLS context or extra listeners are bound,
  instead of silently ignoring both."
* What goes wrong: on a two-address server each of the three runs, serves the
  first address, and never accepts on the second (connections sit in the
  kernel backlog unanswered).
* Fix (`entry`): also raise when `_extra_listener_fds` is non-empty.
-/
namespace Flare.Bugs.DOC_05

/-- What the entry points look at: a TLS context, and how many extra
listeners `bind` left in `_extra_listener_fds`. -/
structure Server where
  tls : Bool
  extras : Nat
  deriving DecidableEq, Repr

/-- `raises`, or runs a loop that accepts on the listed listeners (0 is the
primary, `i + 1` the `i`-th extra). -/
inductive Outcome
  | raises
  | runs (accepts : List Nat)
  deriving DecidableEq, Repr

/-- The three entry points before the fix: only a TLS context is rejected.
mirrors flare/http/server.mojo:1009-1026,1433-1444,1475-1486,1523-1539 @59bda50 -/
def entryOld (s : Server) : Outcome :=
  if s.tls then .raises else .runs [0]

/-- The doc's promise: raise when a TLS context or extra listeners are bound. -/
def Spec (e : Server → Outcome) : Prop :=
  ∀ s, (s.tls = true ∨ s.extras > 0) → e s = .raises

/-- Weaker, and what "silently ignoring" means: a loop that runs accepts on
every bound listener. -/
def NoSilentIgnore (e : Server → Outcome) : Prop :=
  ∀ s l, e s = .runs l → ∀ i, i ≤ s.extras → i ∈ l

/-- The shipped entry points: a TLS context (the inline check) or extra
listeners (`_reject_extra_listeners`) raise.
mirrors flare/http/server.mojo:1014-1043,1407-1470,1480-1517,1522-1580 (fixed, DOC-05) -/
def entry (s : Server) : Outcome :=
  if s.tls || decide (s.extras > 0) then .raises else .runs [0]

/-- The repro's server: two cleartext addresses. -/
def twoAddrs : Server := { tls := false, extras := 1 }

theorem bug : entryOld twoAddrs = .runs [0] := rfl

theorem counterexample : ¬ Spec entryOld ∧ ¬ NoSilentIgnore entryOld := by
  refine ⟨fun h => ?_, fun h => ?_⟩
  · have := h twoAddrs (Or.inr (by decide))
    rw [bug] at this
    cases this
  · have := h twoAddrs [0] bug 1 (by decide)
    simp at this

theorem fixed : Spec entry ∧ NoSilentIgnore entry := by
  refine ⟨fun s h => ?_, fun s l h i hi => ?_⟩
  · rcases h with h | h <;> simp [entry, h]
  · unfold entry at h
    split at h
    · cases h
    · rename_i hc
      cases h
      have : s.extras = 0 := by simp at hc; omega
      simp; omega

end Flare.Bugs.DOC_05
