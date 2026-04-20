"""Fuzz harness: runtime primitives used by the multicore scheduler.

Exercises the pthread + CPU pinning + SO_REUSEPORT primitives that
back ``flare.runtime.scheduler.Scheduler`` with random inputs:

- ``ThreadHandle.spawn`` + ``ThreadHandle.join`` round-trips.
- ``ThreadHandle.pin_to_cpu`` with a random CPU index modulo
  ``num_cpus()``.
- ``bind_reuseport`` with a random backlog.

Expected behaviour: no crashes, no leaked fds, no panics.

Note on scope: this harness deliberately does NOT import
``flare.runtime.scheduler``. The scheduler's rollback/shutdown path
uses ``external_call["free", ...]`` inside a ``Scheduler[H]``-parametric
method; under the fuzz-environment compile that external_call
conflicts with mozz's own ``free`` declaration at MLIR lowering
time. Exercising the primitives directly covers the bulk of the
scheduler's failure modes (join semantics, pinning edge cases,
listener bind timing) without triggering the build conflict. A
full ``Scheduler.shutdown`` fuzz is scheduled for v0.4.1 after the
Mojo compiler resolves the declaration conflict.

Run:
    pixi run --environment fuzz fuzz-scheduler-shutdown
"""

from mozz import fuzz, FuzzConfig
from flare.runtime._thread import (
    ThreadHandle,
    num_cpus,
    current_thread_id,
    _OpaquePtr,
)
from flare.runtime.reuseport import bind_reuseport
from flare.net import SocketAddr


@always_inline
def _null_arg() -> _OpaquePtr:
    return _OpaquePtr(unsafe_from_address=0)


def _increment(arg: _OpaquePtr) -> _OpaquePtr:
    """Increment the int at ``arg`` and return NULL."""
    if arg:
        var p = arg.bitcast[Int]()
        p[] = p[] + 1
    return _OpaquePtr(unsafe_from_address=0)


def target(data: List[UInt8]) raises:
    """Fuzz target: spawn+join worker, CPU-pin to random core, bind
    reuseport with random backlog. Any exception is a bug.
    """
    if len(data) == 0:
        return

    # Stage 1: spawn + join, with optional pinning.
    var h = ThreadHandle.spawn[_increment](_null_arg())
    var cpu = Int(data[0]) % max(1, num_cpus())
    try:
        h.pin_to_cpu(cpu)
    except:
        pass
    h.join()

    # Stage 2: bind_reuseport with a random backlog in [1, 4096].
    var backlog = 1
    if len(data) > 1:
        backlog = 1 + (Int(data[1]) * Int(data[1]) % 4096)
    var l = bind_reuseport(SocketAddr.localhost(0), backlog=backlog)
    if l.local_addr().port == 0:
        raise Error("assertion failed: bind_reuseport returned port 0")


def main() raises:
    print("=" * 60)
    print("fuzz_scheduler_shutdown.mojo — runtime primitives")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()

    def _b1(a: Int) -> List[UInt8]:
        var out = List[UInt8]()
        out.append(UInt8(a))
        return out^

    def _b2(a: Int, b: Int) -> List[UInt8]:
        var out = List[UInt8]()
        out.append(UInt8(a))
        out.append(UInt8(b))
        return out^

    seeds.append(_b1(0))
    seeds.append(_b2(0, 0))
    seeds.append(_b2(1, 1))
    seeds.append(_b2(7, 128))
    seeds.append(_b2(255, 255))

    fuzz(
        target,
        FuzzConfig(
            max_runs=10_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/scheduler_shutdown",
            max_input_len=4,
        ),
        seeds,
    )
