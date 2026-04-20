"""Example 17 - multicore Scheduler (type + lifecycle walk-through).

Demonstrates the multicore primitives landed in v0.4.0:

- ``num_cpus()`` from ``flare.runtime._thread``
- ``ThreadHandle.spawn`` + ``join``
- ``bind_reuseport`` (the helper the Scheduler uses internally)

Running a full ``HttpServer.serve_multicore`` loop blocks until
shutdown from another thread, which is not something the test
runner can script without a threading helper. So this example
walks through the pieces that the Scheduler composes and prints
them. The end-to-end multicore throughput numbers live in
``benchmark/`` (``pixi run --environment bench bench-vs-baseline-quick``).

Run:
    pixi run example-multicore
"""

from flare.runtime._thread import (
    ThreadHandle,
    num_cpus,
    current_thread_id,
    _OpaquePtr,
)
from flare.runtime.reuseport import bind_reuseport
from flare.net import SocketAddr


def _print_tid(arg: _OpaquePtr) -> _OpaquePtr:
    """Thread entry that writes pthread_self into its arg."""
    if arg:
        var p = arg.bitcast[UInt64]()
        p[] = current_thread_id()
    return _OpaquePtr(unsafe_from_address=0)


def main() raises:
    print("=" * 60)
    print("flare example 17 - multicore primitives walk-through")
    print("=" * 60)

    var cpus = num_cpus()
    print("  num_cpus        :", cpus)
    print("  main thread tid :", current_thread_id())

    # Spawn 3 workers; each records its pthread_self tid back into
    # a caller-side slot. The main thread joins them in order.
    var t1 = UInt64(0)
    var t2 = UInt64(0)
    var t3 = UInt64(0)

    def _ptr(ref v: UInt64) -> _OpaquePtr:
        var addr = Int(UnsafePointer[UInt64, _](to=v))
        return _OpaquePtr(unsafe_from_address=addr)

    var h1 = ThreadHandle.spawn[_print_tid](_ptr(t1))
    var h2 = ThreadHandle.spawn[_print_tid](_ptr(t2))
    var h3 = ThreadHandle.spawn[_print_tid](_ptr(t3))
    h1.join()
    h2.join()
    h3.join()
    print("  worker 1 tid    :", t1)
    print("  worker 2 tid    :", t2)
    print("  worker 3 tid    :", t3)

    # Bind three REUSEPORT listeners on the same port. The kernel
    # would load-balance accepted connections across them; a real
    # multicore server replaces `HttpServer.serve(handler)` with
    # `HttpServer.serve_multicore[Handler](handler, num_workers=N)`
    # and gets this pattern automatically.
    var l1 = bind_reuseport(SocketAddr.localhost(0))
    var port = l1.local_addr().port
    var l2 = bind_reuseport(SocketAddr.localhost(port))
    var l3 = bind_reuseport(SocketAddr.localhost(port))
    print("  shared port     :", port)
    print(
        "  listeners on port:",
        l1.local_addr().port,
        l2.local_addr().port,
        l3.local_addr().port,
    )

    print()
    print("OK.")
