import Flare.L2_Machine.Blocking

/-!
# RT-06: the `MAX_POOL_SIZE` thread cap is never enforced on macOS arm64

flare/runtime/blocking.mojo `_pool_try_acquire` / `_pool_release` (pre-fix lines 177-206).

Status: resolved. `_pool_sem_open` passes six dummy register arguments before
`mode` and `value` on macOS, so they land in the stack slots the variadic
callee reads; `sem_open` succeeds and the cap is enforced (tests:
tests/runtime/test_block_in_pool.mojo::test_pool_cap_is_exactly_max_pool_size
and ::test_pool_cap_enforced_and_recovers). The counterexample below stays
true of the pre-fix platform behaviour (`sem_open` failing on every call),
which the model takes as the input `openOk = false`.

Spec (comment at :116-122): at most `MAX_POOL_SIZE` (32) pool threads run
at once; the 33rd concurrent `block_in_pool` / `resolve_async` raises
"pool saturated".

What goes wrong: `sem_open(name, O_CREAT, mode, value)` is variadic. On
Apple arm64 variadic arguments are passed on the stack, but
`external_call` passes them in registers, so `sem_open` reads a garbage
initial value and fails (EINVAL, observed on every call). The acquire is
fail-open, so every `_pool_try_acquire` returns `True` and no cap exists.

The model takes "`sem_open` fails" as the environment input `openOk =
false` on every step (the platform fact is outside Lean; the repro
observes it). Once `sem_open` works, the cap holds
(`Flare.L2.Blocking.paired_cap_invariant`).

Repro: formal/repro/RT-06_pool_cap_not_enforced_macos.mojo (PLATFORM macos;
now prints OK on the host).
-/
namespace Flare.Bugs.RT_06
open Flare.L2.Blocking

def acquireN : Nat → Sem → Sem × Bool
  | 0, s => (s, true)
  | n + 1, s =>
    let r := tryAcquireOld false s
    let r' := acquireN n r.1
    (r'.1, r.2 && r'.2)

/-- **Counterexample** (pre-fix fail-open acquire `tryAcquireOld`, with every
`sem_open` failing as on macOS arm64): when every `sem_open` fails, `n` acquires all
succeed and `n` slots are held, for every `n` (in particular 40 > 32). -/
theorem persistentFailOpen_unbounded (n : Nat) (s : Sem) :
    (acquireN n s).2 = true ∧ (acquireN n s).1.held = s.held + n := by
  induction n generalizing s with
  | zero => simp [acquireN]
  | succ n ih =>
    simp only [acquireN, tryAcquireOld, Bool.not_false, if_true]
    obtain ⟨h1, h2⟩ := ih { s with held := s.held + 1 }
    refine ⟨by simp [h1], ?_⟩
    rw [h2]; dsimp only; omega

theorem forty_slots : (acquireN 40 Sem.init).1.held = 40 ∧ MAX_POOL_SIZE < 40 :=
  ⟨by simpa [Sem.init] using (persistentFailOpen_unbounded 40 Sem.init).2, by decide⟩

/-- **Fix meets spec**: with `sem_open` working (shipped since the ABI fix), the cap is
`count + held = 32`, so at most 32 slots are held. -/
theorem fixed_cap (ops : List Op) (hok : ∀ op ∈ ops, op.ok = true) :
    (run Sem.init ops).held ≤ MAX_POOL_SIZE :=
  (paired_cap_invariant ops hok Sem.init (by decide)).2

end Flare.Bugs.RT_06
