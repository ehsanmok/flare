"""Reliability middleware: ``Retry`` / ``PostHocDeadline`` /
``RateLimit`` / ``CircuitBreaker`` policies.

A reliability middleware wraps an inner ``Handler`` and adds a
policy that improves the chance the call succeeds in the face of
transient failures (transient upstream 5xx, slow handlers, etc).

- :class:`Retry[Inner]` — re-invoke the inner handler when it
  raises or returns a 5xx response, up to ``max_attempts`` times.
  Caller-tunable retry set (any 5xx by default; bounded to GET /
  HEAD / OPTIONS / TRACE / PUT / DELETE -- the RFC 9110 §9.2.2
  idempotent set -- by passing ``retry_only_idempotent=True``).
  Optional exponential backoff with full jitter spaces attempts.
- :class:`PostHocDeadline[Inner]` — bound the wall-clock time the
  inner handler may consume **measured after it returns**: the
  middleware records the entry timestamp, runs the inner handler
  to completion, then compares elapsed time against the budget
  and replaces the response with a 504 if the budget was
  exceeded. **It does not preempt the inner handler** -- Mojo
  cannot preempt synchronous code (see ``flare/http/cancel.mojo``),
  so a genuinely runaway synchronous handler runs to completion on
  its worker; reactor-enforced cancellation exists only at the
  peer-FIN, shutdown, and streaming-edge boundaries, not inside a
  synchronous handler body. This is the K2 model limit.
- :class:`RateLimit[Inner]` — token-bucket admission control:
  reject with ``429 Too Many Requests`` once the per-second rate
  (with burst) is exceeded. State is a leaked, atomic heap cell
  shared across worker copies (ponytail: process-lifetime leak of
  one small cell per middleware instance; the atomics keep it
  race-free, so N workers enforce an approximate shared rate).
- :class:`CircuitBreaker[Inner]` — trip to ``503`` after
  ``failure_threshold`` consecutive failures (5xx or raise), then
  fast-fail for ``cooldown_ms`` before letting one probe through.
  Same leaked-atomic-cell state model as ``RateLimit``.

Each middleware is generic over its inner ``Handler`` so the
chain stays monomorphised -- no virtual dispatch.
"""

from std.atomic import Atomic, Ordering
from std.memory import UnsafePointer, alloc
from std.time import perf_counter_ns
from std.random import random_ui64

from ..runtime._libc_time import libc_nanosleep_ms
from .handler import Handler
from .request import Request
from .response import Response


# ── Shared atomic-cell helpers (leaked, process-lifetime) ────────────────
def _alloc_cell(n: Int) -> Int:
    """Allocate an ``n``-slot ``Int`` cell zeroed; return its address.

    Leaked on purpose: the middleware structs are ``Copyable`` and a
    default copy shares the address, so freeing on ``__del__`` would
    double-free across worker copies. One small cell per middleware
    instance (created once at setup) is a negligible, bounded leak.
    """
    var p = alloc[Int](n)
    for i in range(n):
        (p + i).init_pointee_copy(0)
    return Int(p)


@always_inline
def _cell_get(addr: Int, i: Int) -> Int64:
    var p = UnsafePointer[Int, MutUntrackedOrigin](unsafe_from_address=addr)
    var slot = (p + i).bitcast[Scalar[DType.int64]]()
    return Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](slot)


@always_inline
def _cell_set(addr: Int, i: Int, v: Int64):
    var p = UnsafePointer[Int, MutUntrackedOrigin](unsafe_from_address=addr)
    var slot = (p + i).bitcast[Scalar[DType.int64]]()
    Atomic[DType.int64].store[ordering=Ordering.RELEASE](slot, v)


@fieldwise_init
struct RetryPolicy(Copyable, Defaultable, Movable):
    """Tunable retry policy.

    - ``max_attempts``: total number of inner-handler invocations
      (so ``max_attempts=3`` means 1 initial + 2 retries).
    - ``retry_only_idempotent``: when True, retries are gated on
      the request method being one of GET / HEAD / OPTIONS / TRACE
      / PUT / DELETE (the RFC 9110 §9.2.2 idempotent set). When
      False, every 5xx triggers a retry regardless of method.
    - ``initial_backoff_ms``: when > 0, sleep this many milliseconds
      before retry attempt #2. Each subsequent attempt scales the
      backoff by ``backoff_multiplier`` (capped at
      ``max_backoff_ms``). The actual sleep is "full jitter" --
      a uniform random draw in ``[0, capped_backoff_ms]`` -- which
      is the AWS-recommended default for retry storms (see
      <https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/>).
      ``0`` (the default) disables sleeps and matches the previous
      "tight loop" behaviour.
    - ``backoff_multiplier``: per-attempt scaling factor. Defaults
      to ``2`` (binary exponential backoff: 100ms -> 200ms ->
      400ms -> ...).
    - ``max_backoff_ms``: cap on the un-jittered backoff before
      ``random_ui64`` draws the actual sleep. Defaults to
      ``2_000`` (2 s); set to a small value to keep tail latency
      bounded.

    Defaults: ``max_attempts=3``, ``retry_only_idempotent=True``,
    ``initial_backoff_ms=0`` (no sleep), ``backoff_multiplier=2``,
    ``max_backoff_ms=2_000``.
    """

    var max_attempts: Int
    var retry_only_idempotent: Bool
    var initial_backoff_ms: Int
    var backoff_multiplier: Int
    var max_backoff_ms: Int

    def __init__(out self):
        self.max_attempts = 3
        self.retry_only_idempotent = True
        self.initial_backoff_ms = 0
        self.backoff_multiplier = 2
        self.max_backoff_ms = 2_000


def _is_idempotent_method(method: String) -> Bool:
    """Return True if ``method`` is in the RFC 9110 §9.2.2 idempotent
    set: GET, HEAD, OPTIONS, TRACE, PUT, DELETE.

    PUT and DELETE are idempotent at the protocol level even
    though they have observable side effects: re-applying them
    yields the same final resource state. Including them here
    matches RFC 9110 verbatim; callers that consider their PUT /
    DELETE handlers unsafe to re-invoke can flip
    ``retry_only_idempotent=False`` and gate retries with their
    own logic.
    """
    return (
        method == String("GET")
        or method == String("HEAD")
        or method == String("OPTIONS")
        or method == String("TRACE")
        or method == String("PUT")
        or method == String("DELETE")
    )


def _backoff_sleep_ms(policy: RetryPolicy, attempt: Int) -> Int:
    """Compute the jittered sleep budget for retry ``attempt``.

    ``attempt`` is the upcoming attempt index (1-based) **after**
    the failure that triggered the retry; the sleep precedes the
    next ``inner.serve`` call. Returns ``0`` when backoff is
    disabled (``initial_backoff_ms <= 0``) or the policy is
    misconfigured.

    The schedule is binary exponential by default
    (``backoff_multiplier=2``): the un-jittered budget for
    attempt N (counting from N=2 = first retry) is
    ``initial_backoff_ms * multiplier ** (N - 2)`` capped at
    ``max_backoff_ms``. The returned value is then drawn
    uniformly from ``[0, capped]`` ("full jitter").
    """
    if policy.initial_backoff_ms <= 0 or attempt <= 1:
        return 0
    var capped = policy.initial_backoff_ms
    var i = 2
    while i < attempt:
        var next = capped * policy.backoff_multiplier
        if policy.max_backoff_ms > 0 and next > policy.max_backoff_ms:
            capped = policy.max_backoff_ms
            break
        capped = next
        i += 1
    if policy.max_backoff_ms > 0 and capped > policy.max_backoff_ms:
        capped = policy.max_backoff_ms
    if capped <= 0:
        return 0
    return Int(random_ui64(0, UInt64(capped)))


struct Retry[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Retry the inner handler on transient failure.

    A response with status >= 500 triggers a retry; a raised
    exception is also treated as a transient failure (the
    inner handler re-runs from scratch). The last attempt's
    outcome (response or exception) is propagated unchanged when
    all attempts are exhausted.

    By default the middleware does NOT sleep between attempts and
    retries fire as fast as the inner handler returns. Set
    ``RetryPolicy.initial_backoff_ms`` to enable binary
    exponential backoff with full jitter (the AWS-recommended
    default for retry storms): the sleep before retry N is drawn
    uniformly from ``[0, min(initial_backoff_ms * 2 ** (N - 2),
    max_backoff_ms)]``. ``RateLimit[Inner]`` composed inside
    ``Retry`` remains the canonical way to express richer
    pacing policies.
    """

    var inner: Self.Inner
    var policy: RetryPolicy

    def __init__(out self):
        self.inner = Self.Inner()
        self.policy = RetryPolicy()

    def __init__(
        out self, var inner: Self.Inner, var policy: RetryPolicy = RetryPolicy()
    ):
        self.inner = inner^
        self.policy = policy^

    def serve(self, req: Request) raises -> Response:
        # Pre-flight: if the request method is non-idempotent and
        # the policy gates retries on idempotency, fall through to
        # a single serve() (no retry attempt at all).
        var allow_retry = True
        if self.policy.retry_only_idempotent and not _is_idempotent_method(
            req.method
        ):
            allow_retry = False
        if not allow_retry or self.policy.max_attempts <= 1:
            return self.inner.serve(req).lower()
        var attempt = 0
        var last_err: String = String("")
        var last_raised = False
        while attempt < self.policy.max_attempts:
            attempt += 1
            try:
                var resp = self.inner.serve(req).lower()
                if resp.status < 500 or attempt == self.policy.max_attempts:
                    return resp^
                # 5xx and we still have attempts: jittered sleep
                # before the next attempt (no-op when backoff is
                # disabled).
                var nap = _backoff_sleep_ms(self.policy, attempt + 1)
                if nap > 0:
                    _ = libc_nanosleep_ms(nap)
            except e:
                last_err = String(e)
                last_raised = True
                if attempt == self.policy.max_attempts:
                    break
                var nap = _backoff_sleep_ms(self.policy, attempt + 1)
                if nap > 0:
                    _ = libc_nanosleep_ms(nap)
        if last_raised:
            raise Error(last_err)
        # Should be unreachable: the only way out without a
        # response is via the raise branch above.
        return self.inner.serve(req).lower()


struct PostHocDeadline[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Post-hoc wall-clock deadline check.

    The middleware records the entry timestamp, runs the inner
    handler **to completion**, and compares elapsed time against
    ``budget_ms`` after serve() returns. If the budget was
    exceeded, the response is replaced with a 504 Gateway
    Timeout; otherwise the inner response passes through
    unchanged.

    The check is post-hoc by design -- it does **not** preempt
    the inner handler. A genuinely runaway handler still ties
    up the worker for the full natural duration; the 504 only
    suppresses its response. Tight cancel-cell wiring (the
    reactor flips a Cancel cell that the inner handler observes
    and short-circuits on) requires reactor cooperation and
    lands in a later commit.

    For codec-style sans-I/O handlers and the common case where
    misbehaving inners simply return slightly late, this
    primitive is enough: handlers that genuinely overrun
    surface as 504 to the client, and an external operator
    monitor sees both the elapsed time and the substituted
    status. ``budget_ms <= 0`` is the explicit "always trip"
    sentinel and bypasses the inner handler entirely.
    """

    var inner: Self.Inner
    var budget_ms: Int

    def __init__(out self):
        self.inner = Self.Inner()
        self.budget_ms = 30_000

    def __init__(out self, var inner: Self.Inner, budget_ms: Int = 30_000):
        self.inner = inner^
        self.budget_ms = budget_ms

    def serve(self, req: Request) raises -> Response:
        # ``budget_ms <= 0`` means "no time allowed at all": the
        # request is rejected before invoking the inner handler.
        # This keeps the contract intuitive for callers that flip
        # the budget through configuration (a zero budget is the
        # explicit "disabled" sentinel) and avoids the rounding
        # artifact where a sub-millisecond handler would otherwise
        # pass the elapsed > 0 check on a very fast host.
        if self.budget_ms <= 0:
            return Response(status=504, reason=String("Gateway Timeout"))
        var start = perf_counter_ns()
        var resp = self.inner.serve(req).lower()
        var elapsed_ms = (perf_counter_ns() - start) // 1_000_000
        if elapsed_ms > UInt(self.budget_ms):
            return Response(status=504, reason=String("Gateway Timeout"))
        return resp^


struct RateLimit[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Token-bucket rate limiter.

    Admits up to ``rate_per_sec`` requests per second with a bucket
    depth of ``burst`` (defaults to ``rate_per_sec``). Once the
    bucket is empty the middleware short-circuits with ``429 Too
    Many Requests`` without invoking the inner handler.

    ``rate_per_sec <= 0`` disables the limiter (pass-through). The
    bucket lives in a leaked atomic cell (see module docstring):
    worker copies share it, so the enforced rate is approximately
    global rather than strictly per-worker.
    """

    var inner: Self.Inner
    var rate_per_sec: Int
    var burst: Int
    var _cell: Int
    """Leaked 2-slot cell: [0] = milli-tokens, [1] = last-refill ns."""

    def __init__(out self):
        self.inner = Self.Inner()
        self.rate_per_sec = 0
        self.burst = 0
        self._cell = _alloc_cell(2)

    def __init__(
        out self, var inner: Self.Inner, rate_per_sec: Int, burst: Int = 0
    ):
        self.inner = inner^
        self.rate_per_sec = rate_per_sec
        self.burst = burst if burst > 0 else rate_per_sec
        self._cell = _alloc_cell(2)
        if self.rate_per_sec > 0:
            _cell_set(self._cell, 0, Int64(self.burst) * 1000)
            _cell_set(self._cell, 1, Int64(perf_counter_ns()))

    def serve(self, req: Request) raises -> Response:
        if self.rate_per_sec <= 0:
            return self.inner.serve(req).lower()
        var now = Int64(perf_counter_ns())
        var last = _cell_get(self._cell, 1)
        var tokens = _cell_get(self._cell, 0)
        var elapsed = now - last
        if elapsed < 0:
            elapsed = 0
        # milli-tokens accrued: elapsed_ns * rate / 1e6 (1 token = 1000 milli).
        var refill = (elapsed * Int64(self.rate_per_sec)) // 1_000_000
        var cap = Int64(self.burst) * 1000
        var new_tokens = tokens + refill
        if new_tokens > cap:
            new_tokens = cap
        var allow = new_tokens >= 1000
        if allow:
            new_tokens -= 1000
        _cell_set(self._cell, 0, new_tokens)
        _cell_set(self._cell, 1, now)
        if not allow:
            return Response(status=429, reason=String("Too Many Requests"))
        return self.inner.serve(req).lower()


# CircuitBreaker states.
comptime _CB_CLOSED: Int64 = 0
comptime _CB_OPEN: Int64 = 1
comptime _CB_HALF_OPEN: Int64 = 2


struct CircuitBreaker[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Trip open after consecutive failures, fast-fail during cooldown.

    Counts consecutive failures (a raised exception or a ``>= 500``
    response). After ``failure_threshold`` in a row the breaker
    opens: every call fast-fails with ``503 Service Unavailable``
    for ``cooldown_ms``. The first call after cooldown is a probe
    (half-open); success closes the breaker, another failure
    re-opens it.

    ``failure_threshold <= 0`` disables the breaker (pass-through).
    State lives in a leaked atomic cell (see module docstring).
    """

    var inner: Self.Inner
    var failure_threshold: Int
    var cooldown_ms: Int
    var _cell: Int
    """Leaked 3-slot cell: [0] = state, [1] = consecutive fails,
    [2] = opened-at ns."""

    def __init__(out self):
        self.inner = Self.Inner()
        self.failure_threshold = 0
        self.cooldown_ms = 0
        self._cell = _alloc_cell(3)

    def __init__(
        out self,
        var inner: Self.Inner,
        failure_threshold: Int,
        cooldown_ms: Int = 5_000,
    ):
        self.inner = inner^
        self.failure_threshold = failure_threshold
        self.cooldown_ms = cooldown_ms
        self._cell = _alloc_cell(3)

    def _record_failure(self, now: Int64):
        var fails = _cell_get(self._cell, 1) + 1
        _cell_set(self._cell, 1, fails)
        if fails >= Int64(self.failure_threshold):
            _cell_set(self._cell, 0, _CB_OPEN)
            _cell_set(self._cell, 2, now)

    def _record_success(self):
        _cell_set(self._cell, 1, 0)
        _cell_set(self._cell, 0, _CB_CLOSED)

    def serve(self, req: Request) raises -> Response:
        if self.failure_threshold <= 0:
            return self.inner.serve(req).lower()
        var now = Int64(perf_counter_ns())
        var state = _cell_get(self._cell, 0)
        if state == _CB_OPEN:
            var opened = _cell_get(self._cell, 2)
            var cooldown_ns = Int64(self.cooldown_ms) * 1_000_000
            if now - opened < cooldown_ns:
                return Response(
                    status=503, reason=String("Service Unavailable")
                )
            # Cooldown elapsed: let one probe through (half-open).
            _cell_set(self._cell, 0, _CB_HALF_OPEN)
        try:
            var resp = self.inner.serve(req).lower()
            if resp.status >= 500:
                self._record_failure(now)
            else:
                self._record_success()
            return resp^
        except e:
            self._record_failure(now)
            raise e^
