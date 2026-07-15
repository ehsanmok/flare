"""Reliability middleware — Retry / PostHocDeadline / RateLimit /
CircuitBreaker.

Shows how to wrap a handler with production-grade reliability
primitives:

- ``Retry[Inner]`` re-invokes the inner handler up to
  ``RetryPolicy.max_attempts`` times when it returns a 5xx
  response. Idempotent methods (GET / HEAD / OPTIONS / TRACE /
  PUT / DELETE — RFC 9110 §9.2.2) retry by default; non-idempotent
  methods (POST / PATCH / CONNECT) pass through once unless
  ``RetryPolicy.retry_only_idempotent`` is set to ``False``.
  Optional binary exponential backoff with full jitter
  (``initial_backoff_ms`` > 0) spaces attempts.

- ``PostHocDeadline[Inner]`` runs the inner handler **to
  completion**, measures the elapsed wall-clock time after it
  returns, and replaces the response with a sanitised 504
  Gateway Timeout when the budget was exceeded. The middleware
  does **not** preempt the inner handler -- a runaway handler
  ties up the worker for its full natural duration and the
  504 only suppresses the response. The reactor-cooperative
  cancel-cell flip lands in a later commit. Available at the
  package root as ``PostHocDeadline``; the ``Timeout`` symbol
  remains bound to ``flare.net.error.Timeout`` (the I/O timeout
  error type).

- ``RateLimit[Inner]`` is a token-bucket admission gate: it admits up
  to ``rate_per_sec`` requests/second with a ``burst`` depth, and
  short-circuits with ``429 Too Many Requests`` once the bucket is
  empty (the inner handler is never invoked on a rejected request).

- ``CircuitBreaker[Inner]`` opens after ``failure_threshold``
  consecutive failures (a 5xx response or a raised exception),
  fast-failing with ``503`` for ``cooldown_ms`` before letting a
  single probe through (half-open); a success closes it again.

Pure construction — no live network. Run:

    pixi run example-reliability
"""

from flare.http import Handler, Request, Response
from flare.http.reliability import (
    CircuitBreaker,
    PostHocDeadline,
    RateLimit,
    Retry,
    RetryPolicy,
)


@fieldwise_init
struct OkHandler(Copyable, Defaultable, Handler, Movable):
    """Always returns 200 OK — fast-path for both middlewares."""

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8](String("hello").as_bytes())
        resp.headers.set("Content-Length", String(len(resp.body)))
        return resp^


@fieldwise_init
struct FlakyHandler(Copyable, Defaultable, Handler, Movable):
    """Always returns 503 — used to demonstrate retry exhaustion."""

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        return Response(status=503, reason=String("Service Unavailable"))


def main() raises:
    print("=== flare Example: Reliability middleware ===")
    print()

    # 1. Fast path through Retry: the inner returns 200 on the
    # first attempt, so Retry never re-invokes it.
    var fast = Retry(
        OkHandler(),
        RetryPolicy(
            max_attempts=3,
            retry_only_idempotent=True,
            initial_backoff_ms=0,
            backoff_multiplier=2,
            max_backoff_ms=2_000,
        ),
    )
    var req = Request(method=String("GET"), url=String("/"))
    var resp = fast.serve(req)
    print("Retry / fast path  status:", resp.status)

    # 2. Retry exhausts max_attempts on a perpetually-flaky inner
    # and surfaces the last 5xx. POSTs would *not* retry under
    # the default policy; we flip retry_only_idempotent off to
    # force a retry here just for illustration.
    var flaky = Retry(
        FlakyHandler(),
        RetryPolicy(
            max_attempts=2,
            retry_only_idempotent=False,
            initial_backoff_ms=0,
            backoff_multiplier=2,
            max_backoff_ms=2_000,
        ),
    )
    var resp2 = flaky.serve(req)
    print("Retry / exhausted   status:", resp2.status)

    # 3. Retry with binary exponential backoff + full jitter:
    # 5 ms initial, 2x multiplier, 20 ms cap. The actual sleep
    # is drawn from [0, capped] before each retry. Three GETs
    # against a flaky inner will sleep at most 5+10 = 15 ms total
    # before surfacing the 503.
    var jittered = Retry(
        FlakyHandler(),
        RetryPolicy(
            max_attempts=3,
            retry_only_idempotent=True,
            initial_backoff_ms=5,
            backoff_multiplier=2,
            max_backoff_ms=20,
        ),
    )
    var resp_jit = jittered.serve(req)
    print("Retry / jittered    status:", resp_jit.status)

    # 4. PostHocDeadline disabled-by-zero-budget sentinel: a budget
    # of 0 ms is the explicit "no time allowed" knob — every call
    # surfaces as a 504 without invoking the inner handler.
    var bounded = PostHocDeadline(OkHandler(), budget_ms=0)
    var resp3 = bounded.serve(req)
    print("PostHocDeadline / 0ms       status:", resp3.status)

    # 5. PostHocDeadline with a generous budget: the inner runs and
    # the 200 passes through unchanged.
    var bounded_ok = PostHocDeadline(OkHandler(), budget_ms=30_000)
    var resp4 = bounded_ok.serve(req)
    print("PostHocDeadline / 30s       status:", resp4.status)

    # 6. RateLimit token bucket: rate 1/s, burst 2. Two rapid requests
    # drain the bucket (200, 200); the third is rejected with 429
    # without ever reaching the inner handler.
    var limited = RateLimit(OkHandler(), rate_per_sec=1, burst=2)
    print("RateLimit / req 1   status:", limited.serve(req).status)
    print("RateLimit / req 2   status:", limited.serve(req).status)
    print("RateLimit / req 3   status:", limited.serve(req).status)

    # 7. CircuitBreaker: opens after 2 consecutive 5xx. The first two
    # calls hit the flaky inner (503, 503) and trip the breaker; the
    # third fast-fails with 503 during the cooldown without invoking
    # the inner.
    var breaker = CircuitBreaker(
        FlakyHandler(), failure_threshold=2, cooldown_ms=60_000
    )
    print("CircuitBreaker / call 1  status:", breaker.serve(req).status)
    print("CircuitBreaker / call 2  status:", breaker.serve(req).status)
    print("CircuitBreaker / open    status:", breaker.serve(req).status)
