import Flare.L2_Machine.BufferPool

/-!
# RT-05: `BufferPool.acquire` can return less capacity than requested

flare/runtime/buffer_pool.mojo `acquire` / `release` (pre-fix lines 297-364).

Status: resolved. `release` now drops a handle whose `bytes.capacity()` is
below its class capacity (tests: tests/runtime/test_buffer_pool.mojo::
test_pool_release_drops_handle_with_shrunk_capacity,
::test_pool_release_drops_forged_undersized_handle,
::test_pool_release_keeps_grown_handle). The counterexample below is about the
pre-fix `releaseOld`.

Spec (`acquire` docstring): returns "A reset-empty `BufferHandle` with
capacity ≥ `min_capacity`".

What goes wrong: `BufferHandle.bytes` is a public `List`. `release`
recycles a handle by its `class_index` tag alone, so a caller that
replaced or shrank `bytes` puts an undersized buffer into the bucket, and
the next `acquire` of that class returns it. Appends still grow the list
(a reallocation), so this is memory-unsafe only for code that writes
through `unsafe_ptr()` trusting the contract. `BufferPool` is not wired
into the server yet (module docstring).

Repro: formal/repro/RT-05_buffer_pool_capacity_contract.mojo (now prints OK).
-/
namespace Flare.Bugs.RT_05
open Flare.L2.BufferPool

/-- **Counterexample** (pre-fix `releaseOld`): `acquire(60000)`, replace `bytes` with an empty list
(capacity 0), `release`, `acquire(60000)` again: capacity 0. -/
theorem acquire_after_shrunk_release :
    let p0 := Pool.new 8
    let r1 := acquire p0 60000
    let p2 := releaseOld r1.1 { r1.2 with cap := 0 }
    (acquire p2 60000).2.cap = 0 := by
  decide

/-- **Shipped code meets spec**: since `release` drops handles whose capacity is below
their class's, then after any history of acquires and releases of
arbitrary (mutated or forged) handles, `acquire n` returns capacity `≥ n`. -/
theorem release_preserves_capacity (c : Nat) (ops : List Op) (n : Nat) :
    n ≤ (acquire (run (Pool.new c) ops) n).2.cap :=
  Flare.L2.BufferPool.release_preserves_capacity c ops n

end Flare.Bugs.RT_05
