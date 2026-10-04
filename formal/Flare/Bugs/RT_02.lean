import Flare.L2_Machine.WriteLoop

/-!
# RT-02: `writev_buf_all` returns normally after a short write

flare/runtime/iovec.mojo:340-341: `if sent <= 0: return`. `writev_buf`
already raises on `-1`, so this branch is `writev` returning 0 with
bytes still queued, and the caller is told everything was written.
Spec: a normal return means every byte was written.
Severity low (latent): Linux/macOS never return 0 from `writev` on a
socket with a non-empty iovec.
Repro: formal/repro/RT-02_writev_all_silent_short_write.mojo, by fault
injection (an interposed `writev`; DYLD_INSERT_LIBRARIES on macOS,
LD_PRELOAD on Linux): a normal return with 0 of 100 bytes written.
-/
namespace Flare.Bugs.RT_02
open Flare.L2.WriteLoop

/-- Spec: a normal return means every byte was written. -/
def Spec (r : Res × VState) : Prop := r.1 = .done 0 → r.2.remaining ≤ 0

def s0 : VState := { first := 0, rest := [3, 2], remaining := 5 }

/-- Counterexample: a POSIX-legal oracle returning 0 makes the loop return
normally with 5 bytes unsent. -/
theorem writev_silent_short_write :
    Weak zeroOracle ∧ ¬ Spec (writevAll zeroOracle 10 0 s0) := by
  refine ⟨zeroOracle_weak, ?_⟩
  unfold Spec; native_decide

/-- Fixed loop: a 0 return raises.
mirrors flare/runtime/iovec.mojo:312-361 @59bda50 (with the minimal fix) -/
def writevAllFixed (o : Nat → Nat → Int) : Nat → Nat → VState → Res × VState
  | 0, _, s => (if s.remaining > 0 then .outOfFuel 0 else .done 0, s)
  | fuel + 1, k, s =>
    if s.remaining > 0 then
      let r := o k (sum s.rest)
      if r ≤ 0 then (.err, s)
      else
        let c := consume r.toNat s.rest
        writevAllFixed o fuel (k + 1)
          ⟨s.first + c.1, c.2, s.remaining - r⟩
    else (.done 0, s)

/-- The fixed loop meets the spec for every oracle (no contract needed). -/
theorem writevAllFixed_spec (o : Nat → Nat → Int) :
    ∀ fuel k s, Spec (writevAllFixed o fuel k s) := by
  intro fuel
  induction fuel with
  | zero =>
    intro k s h
    simp only [writevAllFixed] at h ⊢
    split at h <;> simp_all <;> omega
  | succ f ih =>
    intro k s
    simp only [writevAllFixed, Spec]
    by_cases hp : s.remaining > 0
    · rw [if_pos hp]
      by_cases hr : o k (sum s.rest) ≤ 0
      · simp [hr]
      · simp only [hr, if_false]; exact ih _ _
    · rw [if_neg hp]; intro _; simp only; omega

end Flare.Bugs.RT_02
