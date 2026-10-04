# PLATFORM: any
"""RT-05: BufferPool.acquire can return a handle with less capacity than
requested.

Lean: Flare.Bugs.RT_05.acquire_after_shrunk_release (counterexample) and
Flare.Bugs.RT_05.releaseFixed_preserves_capacity (fix meets spec).
flare/runtime/buffer_pool.mojo:297-364 @59bda50.

Expected (docstring of acquire): "A reset-empty BufferHandle with
capacity >= min_capacity."
Actual: BufferHandle.bytes is a public List. release() recycles a handle
by its class_index tag alone, so a caller that replaced or shrank
bytes before releasing puts an undersized buffer into the 64 KiB
bucket, and the next acquire(60000) returns it. Appends still grow the
List, so this costs a reallocation; it becomes memory-unsafe only for
code that writes through unsafe_ptr() trusting the contract. BufferPool
is not yet wired into the server (module docstring), so severity is low.

Minimal fix: in release(), drop the handle unless
handle.bytes.capacity() >= _capacity_for_class(idx).
"""

from flare.runtime import BufferPool


def main() raises:
    var pool = BufferPool()
    var h = pool.acquire(60000)
    h.bytes = List[UInt8]()  # public field: capacity is now 0
    pool.release(h^)
    var h2 = pool.acquire(60000)
    if h2.bytes.capacity() < 60000:
        print(
            "BUG REPRODUCED: acquire(60000) returned a handle with capacity",
            h2.bytes.capacity(),
        )
        raise Error("RT-05")
    print("OK: acquire(60000) capacity", h2.bytes.capacity())
