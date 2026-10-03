/-!
# Trust base: environment assumptions

Facts about libc / the kernel that the models depend on. They are **not**
`axiom`s: each is a `Prop`-valued definition that theorems take as an
explicit hypothesis, so `#print axioms` stays clean and every dependency is
visible in theorem signatures.
-/
namespace Flare.Assumptions

/-- `recv(2)`/`read(2)` into a buffer of capacity `cap` returns `-1` (error)
or a count in `0..cap`. -/
def RecvContract (cap : Nat) (ret : Int) : Prop := ret = -1 ∨ (0 ≤ ret ∧ ret ≤ cap)

/-- `send(2)` on a blocking stream socket with `len > 0` bytes returns `-1`
or `1..len`. POSIX does *not* guarantee `ret ≠ 0`; flare's `write_all`
needs that stronger fact (see `Flare.Bugs.B08`). -/
def SendContractStrong (len : Nat) (ret : Int) : Prop :=
  ret = -1 ∨ (1 ≤ ret ∧ ret ≤ len)

/-- The weaker, POSIX-faithful contract: `0` is permitted. -/
def SendContract (len : Nat) (ret : Int) : Prop :=
  ret = -1 ∨ (0 ≤ ret ∧ ret ≤ len)

/-- Monotonic clock: successive readings never decrease. -/
def MonotoneClock (ts : List Nat) : Prop := List.Pairwise (· ≤ ·) ts

end Flare.Assumptions
