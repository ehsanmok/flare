# PLATFORM: any
# RESOLVED: APP-42 fixed on fix/formal-findings
"""APP-42: CircuitBreaker lets every request through while HALF_OPEN,
so with worker copies sharing the cell any number of requests reach the
failing upstream during the single-probe window.

Lean: Flare.Bugs.APP_42.halfopen_admits_two (counterexample),
Flare.Bugs.APP_42.fixed_halfopen_one_probe (fix meets spec);
model Flare.L4.CircuitBreaker.step.
flare/http/reliability.mojo:450-460 @59bda50 (serve only tests
`state == _CB_OPEN`; a HALF_OPEN state falls through to the inner call).

Spec (docstring, reliability.mojo:31-34, 409-411): "fast-fail for
cooldown_ms before letting one probe through"; "The first call after
cooldown is a probe (half-open)". While that probe is in flight other
calls must fast-fail.

Scenario: two worker copies share one breaker cell (exactly what the
module docstring describes: copies share the leaked cell). Worker 1's
call is the probe; while it is in flight, worker 2 receives a request.
To make the interleaving deterministic, worker 1's inner handler issues
worker 2's request itself (this is the moment "probe in flight").

Expected: worker 2 gets 503 and its inner handler is not invoked.
Before the fix: worker 2 sees HALF_OPEN, treats it like CLOSED, and its inner
handler runs (status 200).

Minimal fix: in serve, fast-fail when the state is HALF_OPEN:
    if state == _CB_HALF_OPEN:
        return Response(status=503, reason=String("Service Unavailable"))
(and claim the OPEN -> HALF_OPEN transition with a compare_exchange so
two workers that both observe an expired OPEN cannot both probe).
"""

from std.memory.alloc import unsafe_alloc
from std.memory import Pointer
from std.time import perf_counter_ns

from flare.http.handler import Handler
from flare.http.reliability import CircuitBreaker
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok


struct CountingOk(Copyable, Handler):
    var calls: Int

    def __init__(out self, calls: Int):
        self.calls = calls

    def serve(self, req: Request) raises -> Response:
        var p = Pointer[Int, MutUntrackedOrigin](unsafe_from_address=self.calls)
        p[] = p[] + 1
        return ok(String("ok"))


struct ProbeInner(Copyable, Handler):
    """Worker 1's upstream. Phase 0: fail (trips the breaker).
    Phase 1: while this probe is in flight, worker 2 serves a request;
    its status is stored in slot 1, then the probe succeeds."""

    var w2: CircuitBreaker[CountingOk]
    var state: Int  # [0] phase, [1] worker-2 status

    def __init__(out self, var w2: CircuitBreaker[CountingOk], state: Int):
        self.w2 = w2^
        self.state = state

    def serve(self, req: Request) raises -> Response:
        var p = Pointer[Int, MutUntrackedOrigin](unsafe_from_address=self.state)
        if p[] == 0:
            return Response(status=500, reason=String("Internal Server Error"))
        var q = Pointer[Int, MutUntrackedOrigin](
            unsafe_from_address=self.state + 8
        )
        q[] = self.w2.serve(req).status
        return ok(String("probe ok"))


def main() raises:
    var calls = unsafe_alloc[Int](1)
    calls.unsafe_write(0)
    var st = unsafe_alloc[Int](2)
    st.unsafe_write(0)
    st.unsafe_offset(1).unsafe_write(0)
    var w2 = CircuitBreaker(
        CountingOk(Int(calls)), failure_threshold=1, cooldown_ms=50
    )
    var w1 = CircuitBreaker(
        ProbeInner(w2.copy(), Int(st)), failure_threshold=1, cooldown_ms=50
    )
    w1._cell = w2._cell  # worker copies share one cell
    var req = Request(method=String("GET"), url=String("/"))
    var s1 = w1.serve(req).status  # 500: breaker opens
    var t0 = perf_counter_ns()
    while perf_counter_ns() - t0 < 80_000_000:  # wait out the cooldown
        pass
    st[] = 1
    var s_probe = w1.serve(req).status  # the probe; worker 2 runs inside
    var s_w2 = st.unsafe_offset(1)[]
    if s_w2 != 503 or calls[] != 0:
        print(
            "BUG REPRODUCED: while worker 1's probe was in flight (HALF_OPEN),"
            " worker 2 got",
            s_w2,
            "and its upstream ran",
            calls[],
            "time(s); expected 503 and 0. trip status",
            s1,
            "probe status",
            s_probe,
        )
        raise Error("APP-42")
    print("OK: second request fast-failed with 503 while the probe was in flight")
