# PLATFORM: any
# RESOLVED: APP-41 fixed on fix/formal-findings
"""APP-41: CircuitBreaker measures the cooldown from the *start* of the
failing request, so a failure slower than cooldown_ms opens the breaker
already expired and the next call goes straight to the inner handler.

Lean: Flare.Bugs.APP_41.slow_failure_skips_cooldown (counterexample),
Flare.Bugs.APP_41.fixed_cooldown_respected (fix meets spec);
model Flare.L4.CircuitBreaker.step.
flare/http/reliability.mojo:449, 463, 468, 435-440 @59bda50
(`now` is read once on entry and passed to `_record_failure(now)`,
which stores it as the opened-at timestamp).

Spec (docstring, reliability.mojo:404-411): after failure_threshold
consecutive failures the breaker opens and every call fast-fails with
503 for cooldown_ms.

Scenario: failure_threshold=1, cooldown_ms=100, the inner handler takes
150 ms and returns 500 (a slow upstream timeout, the case breakers exist
for; with the default cooldown_ms=5000, any upstream that fails after
more than 5 s defeats the breaker the same way).

Expected: the call right after the tripping failure gets 503 and the
inner handler is not invoked.
Before the fix: opened-at is 150 ms in the past when the breaker opens, so
`now - opened < cooldown_ns` is already false; the second call is let
through as a half-open probe and the inner handler runs again.

Minimal fix: stamp the opening with the time the failure is recorded:
`self._record_failure(Int64(perf_counter_ns()))` at both call sites.
"""

from std.memory.alloc import unsafe_alloc
from std.memory import Pointer
from std.time import perf_counter_ns

from flare.http.handler import Handler
from flare.http.reliability import CircuitBreaker
from flare.http.request import Request
from flare.http.response import Response


struct SlowFail(Copyable, Handler):
    """Busy-waits 150 ms, counts the call, returns 500."""

    var calls: Int

    def __init__(out self, calls: Int):
        self.calls = calls

    def serve(self, req: Request) raises -> Response:
        var p = Pointer[Int, MutUntrackedOrigin](unsafe_from_address=self.calls)
        p[] = p[] + 1
        var t0 = perf_counter_ns()
        while perf_counter_ns() - t0 < 150_000_000:
            pass
        return Response(status=500, reason=String("Internal Server Error"))


def main() raises:
    var cell = unsafe_alloc[Int](1)
    cell.unsafe_write(0)
    var cb = CircuitBreaker(
        SlowFail(Int(cell)), failure_threshold=1, cooldown_ms=100
    )
    var req = Request(method=String("GET"), url=String("/"))
    var s1 = cb.serve(req).status  # trips the breaker after 150 ms
    var s2 = cb.serve(req).status  # issued immediately after the trip
    var calls = cell[]
    if s2 != 503 or calls != 1:
        print(
            "BUG REPRODUCED: call right after the trip returned",
            s2,
            "and the inner handler ran",
            calls,
            "times (expected 503, 1 call); first status",
            s1,
        )
        raise Error("APP-41")
    print(
        "OK: breaker fast-failed with 503 during cooldown; inner calls", calls
    )
