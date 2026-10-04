# PLATFORM: any
"""APP-40: RateLimit refill product elapsed_ns * rate_per_sec wraps Int64
after a long idle period, so a full bucket rejects requests with 429.

Lean: Flare.Bugs.APP_40.full_bucket_rejected_after_idle (counterexample),
Flare.Bugs.APP_40.implFixed_refines_spec (fix meets spec);
model Flare.L4.RateLimit.step.
flare/http/reliability.mojo:369-374 @59bda50
(`var refill = (elapsed * rate) // 1_000_000`).

Wrap threshold: elapsed_ns > (2^63 - 1) // rate_per_sec, i.e.
  rate 1_000_000/s -> 9_223 s idle (2.56 h)
  rate   100_000/s -> 25.6 h
  rate    10_000/s -> 10.7 days
  rate     1_000/s -> 106.7 days

Scenario: RateLimit(rate_per_sec=1_000_000) whose bucket is full and
whose last refill was 9_300 s ago (no request for 2.58 h). The repro
reproduces that idle gap by writing the last-refill slot of the
middleware's own state cell (slot 1, "last-refill ns"), which is the
state the middleware is in after its last request 9_300 s earlier;
everything else is the unmodified RateLimit.serve.

Expected: the bucket is full, so the request is admitted (200).
Actual: elapsed * rate = 9.3e18 > 2^63 - 1 wraps to about -9.15e18,
refill is about -9.15e12 milli-tokens, new_tokens goes negative and the
request is rejected with 429. The negative token count is stored, and
`last` is not advanced, so every later request in the next ~2.5 h makes
it more negative (a multi-hour self-inflicted outage).

Minimal fix: clamp elapsed to the time needed to fill the bucket before
multiplying, e.g. after `if elapsed < 0: elapsed = 0` add
    var max_elapsed = (Int64(self.burst) * 1000 * 1_000_000) // rate + 1
    if elapsed > max_elapsed:
        elapsed = max_elapsed
"""

from std.time import perf_counter_ns

from flare.http.handler import Handler
from flare.http.reliability import RateLimit, _cell_get, _cell_set
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok


struct OkHandler(Copyable, Defaultable, Handler):
    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        return ok(String("ok"))


def main() raises:
    var rl = RateLimit(OkHandler(), rate_per_sec=1_000_000)
    var idle_ns = Int64(9_300) * 1_000_000_000
    # Bucket is full (constructor set it to burst * 1000); pretend the
    # last refill happened idle_ns ago.
    _cell_set(rl._cell, 1, Int64(perf_counter_ns()) - idle_ns)
    var req = Request(method=String("GET"), url=String("/"))
    var status = rl.serve(req).status
    var tokens = _cell_get(rl._cell, 0)
    if status != 200:
        print(
            "BUG REPRODUCED: full bucket after 9300 s idle at rate 1e6/s"
            " returned",
            status,
            "; stored milli-tokens now",
            tokens,
        )
        raise Error("APP-40")
    print("OK: request admitted after 9300 s idle; milli-tokens", tokens)
