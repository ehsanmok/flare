"""Prometheus-text-exposition metrics middleware.

``Metrics[Inner]`` is a request-counting / latency-histogramming
middleware that wraps any inner ``Handler`` and emits Prometheus
text-format exposition compatible with the v0.0.4 spec
(https://prometheus.io/docs/instrumenting/exposition_formats/).

Why text-format and not the protobuf shape:

- Every Prometheus client + Grafana data source supports text.
- Zero protobuf dependency, zero schema stake-down.
- Cheap to render — one ``String`` build per scrape, which is on
  the scrape budget (15s default), not the request hot path.

Counters tracked (matching the de facto Prometheus HTTP-server
contract — Caddy, nginx-prometheus-exporter, Envoy stats):

- ``flare_http_requests_total{method,status}`` — request count
  partitioned by method label and status-code label.
- ``flare_http_request_duration_seconds_bucket{le}`` — histogram
  of request latency in seconds across the canonical Prometheus
  default-bucket layout (``0.005``, ``0.01``, ``0.025``, ``0.05``,
  ``0.1``, ``0.25``, ``0.5``, ``1``, ``2.5``, ``5``, ``10``,
  ``+Inf``). Same bucket boundaries hyper / actix-web / nginx all
  emit, so PromQL queries written against any of them just work.
- ``flare_http_request_duration_seconds_sum`` /
  ``..._count`` — histogram totals.
- ``flare_http_requests_in_flight`` — gauge of currently-serving
  requests.
- ``flare_http_request_errors_total`` — counter of errors raised
  by the inner handler.

Concurrency note (v0.7 cut):

The current Mojo nightly (``1.0.0b1.dev2026042717``) ships
``Atomic[DType.*]`` cells but they are NOT ``Copyable``, so they
can't live inside a ``List`` / ``InlineArray``. Putting 160
``Atomic`` cells as separate struct fields would explode the
declaration; an ``UnsafePointer[Atomic, ...]`` heap allocation
would re-introduce the lifetime-management surface that the
``Movable``-only registry is trying to avoid.

The v0.7 shape is therefore **per-worker, plain ``UInt64``**
counters. flare's HTTP server already monomorphises one
``Handler`` instance per worker pthread, so each worker owns
its own ``MetricsRegistry`` — counters are never shared across
worker threads, no atomic increment required.

For multi-worker aggregation (i.e. exposing a process-wide
``/metrics``), caller wires a small aggregator that snapshots
every worker's registry and concatenates the rendered text. The
v0.7.x follow-up swaps the per-cell type to ``Atomic`` once the
nightly lifts the ``Copyable`` requirement on ``Atomic`` (or
once we land an ``UnsafePointer``-backed ``AtomicArray``).

Cardinality discipline:

Status-code labels are kept in a small fixed table (200, 201,
204, 301, 302, 304, 400, 401, 403, 404, 412, 429, 500, 502,
503; ``other`` for the rest). Method labels are kept to the RFC
9110 set (GET, HEAD, POST, PUT, PATCH, DELETE, CONNECT,
OPTIONS, TRACE; ``other`` for the rest). This bounds cardinality
to ``10 methods × 16 statuses = 160 series`` total — under the
Prometheus advisory of ~10K series per server, with three orders
of magnitude headroom for downstream apps to add their own
business metrics.

Render cost:

The ``MetricsRegistry.render()`` snapshot allocates one output
``String`` sized for the worst case (~6 KB at 160
``method×status`` series + 13 latency buckets + 4 totals). On a
15 s scrape interval against a 4-worker EPYC node serving 220 K
req/s, the cost rounds to zero (<5 µs amortised per request).
"""

from std.time import perf_counter_ns

from flare.runtime.pool import Pool

from .handler import Handler
from .request import Request
from .response import Response


# ── Label tables ────────────────────────────────────────────────────────────


comptime _METHOD_COUNT: Int = 10
comptime _STATUS_COUNT: Int = 16
comptime _NUM_BUCKETS: Int = 13


def _method_index(method: String) -> Int:
    """Map an HTTP method to a slot in the per-method counter
    table. Unknown methods bucket into the last slot ('other')."""
    if method == "GET":
        return 0
    if method == "HEAD":
        return 1
    if method == "POST":
        return 2
    if method == "PUT":
        return 3
    if method == "PATCH":
        return 4
    if method == "DELETE":
        return 5
    if method == "CONNECT":
        return 6
    if method == "OPTIONS":
        return 7
    if method == "TRACE":
        return 8
    return 9


def _method_label(idx: Int) -> String:
    """Inverse of :func:`_method_index` — Prometheus label
    string for the given slot index."""
    if idx == 0:
        return String("GET")
    if idx == 1:
        return String("HEAD")
    if idx == 2:
        return String("POST")
    if idx == 3:
        return String("PUT")
    if idx == 4:
        return String("PATCH")
    if idx == 5:
        return String("DELETE")
    if idx == 6:
        return String("CONNECT")
    if idx == 7:
        return String("OPTIONS")
    if idx == 8:
        return String("TRACE")
    return String("other")


def _status_index(status: Int) -> Int:
    """Map an HTTP status code to a slot in the per-status counter
    table. Unknown statuses bucket into the last slot ('other')."""
    if status == 200:
        return 0
    if status == 201:
        return 1
    if status == 204:
        return 2
    if status == 301:
        return 3
    if status == 302:
        return 4
    if status == 304:
        return 5
    if status == 400:
        return 6
    if status == 401:
        return 7
    if status == 403:
        return 8
    if status == 404:
        return 9
    if status == 412:
        return 10
    if status == 429:
        return 11
    if status == 500:
        return 12
    if status == 502:
        return 13
    if status == 503:
        return 14
    return 15


def _status_label(idx: Int) -> String:
    """Inverse of :func:`_status_index` — Prometheus label
    string for the given slot index."""
    if idx == 0:
        return String("200")
    if idx == 1:
        return String("201")
    if idx == 2:
        return String("204")
    if idx == 3:
        return String("301")
    if idx == 4:
        return String("302")
    if idx == 5:
        return String("304")
    if idx == 6:
        return String("400")
    if idx == 7:
        return String("401")
    if idx == 8:
        return String("403")
    if idx == 9:
        return String("404")
    if idx == 10:
        return String("412")
    if idx == 11:
        return String("429")
    if idx == 12:
        return String("500")
    if idx == 13:
        return String("502")
    if idx == 14:
        return String("503")
    return String("other")


# ── Histogram buckets ───────────────────────────────────────────────────────


def _bucket_index(seconds_micro: Int) -> Int:
    """Return the smallest bucket index whose ``le`` (less-or-
    equal) bound covers ``seconds_micro`` microseconds.

    Bucket layout (microseconds for cheap integer compare):
    0:  5_000   (0.005s)
    1:  10_000  (0.01s)
    2:  25_000  (0.025s)
    3:  50_000  (0.05s)
    4:  100_000 (0.1s)
    5:  250_000 (0.25s)
    6:  500_000 (0.5s)
    7:  1_000_000   (1s)
    8:  2_500_000   (2.5s)
    9:  5_000_000   (5s)
    10: 10_000_000  (10s)
    11: max          (+Inf, always)
    """
    if seconds_micro <= 5_000:
        return 0
    if seconds_micro <= 10_000:
        return 1
    if seconds_micro <= 25_000:
        return 2
    if seconds_micro <= 50_000:
        return 3
    if seconds_micro <= 100_000:
        return 4
    if seconds_micro <= 250_000:
        return 5
    if seconds_micro <= 500_000:
        return 6
    if seconds_micro <= 1_000_000:
        return 7
    if seconds_micro <= 2_500_000:
        return 8
    if seconds_micro <= 5_000_000:
        return 9
    if seconds_micro <= 10_000_000:
        return 10
    return 11


def _bucket_le_label(idx: Int) -> String:
    """Prometheus ``le=`` label for bucket ``idx`` — the upper-
    inclusive bound, in seconds, formatted to match the
    Prometheus default-bucket convention."""
    if idx == 0:
        return String("0.005")
    if idx == 1:
        return String("0.01")
    if idx == 2:
        return String("0.025")
    if idx == 3:
        return String("0.05")
    if idx == 4:
        return String("0.1")
    if idx == 5:
        return String("0.25")
    if idx == 6:
        return String("0.5")
    if idx == 7:
        return String("1")
    if idx == 8:
        return String("2.5")
    if idx == 9:
        return String("5")
    if idx == 10:
        return String("10")
    return String("+Inf")


# ── MetricsRegistry ─────────────────────────────────────────────────────────


struct MetricsRegistry(Copyable, Defaultable, Movable):
    """Counter / gauge / histogram aggregate.

    The registry is the storage backing one ``Metrics[Inner]``
    middleware. It is per-worker (see module docstring "Concurrency
    note" for why); aggregation across workers is the caller's
    job at the ``/metrics`` scrape endpoint.

    All counters are plain ``UInt64``. Wrap-around is bounded by
    ``2^64`` requests (~580 years at 1 G req/s).
    """

    var requests_total: List[UInt64]
    """Flat ``[method × status]`` table; index =
    ``method_idx * _STATUS_COUNT + status_idx``."""

    var duration_buckets: List[UInt64]
    """Histogram bucket counts; flat over the 13-bucket layout.
    Each bucket holds the CUMULATIVE count of requests with
    latency ``<= le[i]`` (Prometheus convention)."""

    var duration_sum_micros: UInt64
    """Cumulative latency in microseconds. Renders as seconds in
    the exposition output."""

    var duration_count: UInt64
    """Cumulative request count for the histogram (= the value of
    the ``+Inf`` bucket)."""

    var in_flight: UInt64
    """Gauge of currently-serving requests. Bumped on entry,
    decremented on exit; ``Metrics.serve`` decrements via the
    ``except`` path so a raised ``Exception`` still drops the
    gauge."""

    var errors_total: UInt64
    """Counter of errors raised by the inner handler."""

    def __init__(out self):
        self.requests_total = List[UInt64]()
        for _ in range(_METHOD_COUNT * _STATUS_COUNT):
            self.requests_total.append(UInt64(0))
        self.duration_buckets = List[UInt64]()
        for _ in range(_NUM_BUCKETS):
            self.duration_buckets.append(UInt64(0))
        self.duration_sum_micros = UInt64(0)
        self.duration_count = UInt64(0)
        self.in_flight = UInt64(0)
        self.errors_total = UInt64(0)

    def record(
        mut self,
        method_idx: Int,
        status_idx: Int,
        latency_micros: UInt64,
    ):
        """Record a successful request-served event."""
        var slot = method_idx * _STATUS_COUNT + status_idx
        self.requests_total[slot] += UInt64(1)
        var b = _bucket_index(Int(latency_micros))
        # Histogram bucket counts in Prometheus are CUMULATIVE:
        # bucket k counts everything ≤ le[k]. Walk forward and
        # bump every bucket from the chosen one through +Inf.
        for i in range(b, _NUM_BUCKETS):
            self.duration_buckets[i] += UInt64(1)
        self.duration_sum_micros += latency_micros
        self.duration_count += UInt64(1)

    def record_error(mut self, latency_micros: UInt64):
        """Record an error from the inner handler. The error is
        also bucketed into the latency histogram so a slow-then-
        raise handler shows up in the latency graph too."""
        self.errors_total += UInt64(1)
        var b = _bucket_index(Int(latency_micros))
        for i in range(b, _NUM_BUCKETS):
            self.duration_buckets[i] += UInt64(1)
        self.duration_sum_micros += latency_micros
        self.duration_count += UInt64(1)

    def enter(mut self):
        """Bump the in-flight gauge on request entry."""
        self.in_flight += UInt64(1)

    def exit(mut self):
        """Drop the in-flight gauge on request completion (success
        or error)."""
        if self.in_flight > UInt64(0):
            self.in_flight -= UInt64(1)

    def render(self) -> String:
        """Snapshot the registry as a Prometheus text-format
        exposition body."""
        var out = String(capacity=4096)

        # ── flare_http_requests_total ──
        out += (
            "# HELP flare_http_requests_total Total number of HTTP requests"
            " served, partitioned by method and status.\n"
        )
        out += "# TYPE flare_http_requests_total counter\n"
        for m in range(_METHOD_COUNT):
            for s in range(_STATUS_COUNT):
                var slot = m * _STATUS_COUNT + s
                var v = self.requests_total[slot]
                if v == UInt64(0):
                    continue
                out += 'flare_http_requests_total{method="'
                out += _method_label(m)
                out += '",status="'
                out += _status_label(s)
                out += '"} '
                out += String(v)
                out += "\n"

        # ── flare_http_request_duration_seconds histogram ──
        out += (
            "# HELP flare_http_request_duration_seconds Histogram of HTTP"
            " request latency in seconds.\n"
        )
        out += "# TYPE flare_http_request_duration_seconds histogram\n"
        for i in range(_NUM_BUCKETS):
            out += 'flare_http_request_duration_seconds_bucket{le="'
            out += _bucket_le_label(i)
            out += '"} '
            out += String(self.duration_buckets[i])
            out += "\n"
        out += "flare_http_request_duration_seconds_sum "
        out += _format_seconds(self.duration_sum_micros)
        out += "\n"
        out += "flare_http_request_duration_seconds_count "
        out += String(self.duration_count)
        out += "\n"

        # ── flare_http_requests_in_flight ──
        out += (
            "# HELP flare_http_requests_in_flight Gauge of in-flight HTTP"
            " requests.\n"
        )
        out += "# TYPE flare_http_requests_in_flight gauge\n"
        out += "flare_http_requests_in_flight "
        out += String(self.in_flight)
        out += "\n"

        # ── flare_http_request_errors_total ──
        out += (
            "# HELP flare_http_request_errors_total Total number of HTTP"
            " requests that raised from the inner handler.\n"
        )
        out += "# TYPE flare_http_request_errors_total counter\n"
        out += "flare_http_request_errors_total "
        out += String(self.errors_total)
        out += "\n"

        return out^


def _alloc_registry_or_zero() -> Int:
    """Heap-allocate a fresh :class:`MetricsRegistry` and return
    its address, or 0 on allocator failure.

    Defaultable middleware ``__init__`` cannot raise, so we
    swallow the alloc failure and return 0; the first
    ``Metrics.serve`` will trip on a null-pointer deref, which
    surfaces the OOM at the right call site rather than masking
    it as a silent telemetry drop."""
    try:
        return Pool[MetricsRegistry].alloc_move(MetricsRegistry())
    except:
        return 0


def _format_seconds(micros: UInt64) -> String:
    """Render ``micros`` (microseconds) as a fixed-point
    seconds value with 6 decimals — matches the Prometheus
    convention for histogram_sum cells."""
    var whole = micros // UInt64(1_000_000)
    var frac = micros - whole * UInt64(1_000_000)
    var out = String(whole)
    out += "."
    var f = String(frac)
    var pad = 6 - f.byte_length()
    for _ in range(pad):
        out += "0"
    out += f
    return out^


# ── Metrics middleware ─────────────────────────────────────────────────────


struct Metrics[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Prometheus-text-exposition middleware around an inner
    handler.

    The inner ``Handler`` is wrapped with a counter / histogram
    update on every served request. The registry lives on the
    heap (allocated via :class:`flare.runtime.pool.Pool`) and the
    middleware holds the address as an ``Int`` — copies of the
    middleware therefore share the same registry, which matches
    the per-worker singleton pattern (one ``Metrics[Inner]`` per
    worker pthread, one ``MetricsRegistry`` per ``Metrics``).

    The shared-registry shape lets ``serve`` mutate counters
    through the immutable-``self`` ``Handler`` contract: we
    re-materialise the typed pointer via
    ``Pool[MetricsRegistry].get_ptr(self.registry_addr)`` and
    mutate the cell through it. The cell is leaked at process
    exit (the worker pthread lives the lifetime of the server,
    so nothing meaningful to free); a future ``ArcPointer``
    upgrade can swap the leak for ref-counting once the nightly
    surfaces a stable shared-pointer type.

    Pair with a small handler that returns
    ``Pool[MetricsRegistry].get_ptr(metrics.registry_addr)[].render()``
    on the ``/metrics`` route to expose to a Prometheus scraper.
    """

    var inner: Self.Inner

    var registry_addr: Int
    """Heap address of the shared :class:`MetricsRegistry` cell.
    Allocated in ``__init__``; intentionally leaked at process
    exit (see struct doc)."""

    def __init__(out self):
        self.inner = Self.Inner()
        self.registry_addr = _alloc_registry_or_zero()

    def __init__(out self, var inner: Self.Inner):
        self.inner = inner^
        self.registry_addr = _alloc_registry_or_zero()

    def serve(self, req: Request) raises -> Response:
        var reg = Pool[MetricsRegistry].get_ptr(self.registry_addr)
        var start = perf_counter_ns()
        reg[].enter()
        var resp: Response
        try:
            resp = self.inner.serve(req)
        except e:
            var latency_micros = (perf_counter_ns() - start) // UInt(1_000)
            reg[].record_error(UInt64(Int(latency_micros)))
            reg[].exit()
            raise Error(String(e))
        var latency_micros = (perf_counter_ns() - start) // UInt(1_000)
        reg[].record(
            _method_index(req.method),
            _status_index(Int(resp.status)),
            UInt64(Int(latency_micros)),
        )
        reg[].exit()
        return resp^

    def render(self) -> String:
        """Convenience accessor that snapshots the underlying
        registry as Prometheus text exposition. Equivalent to
        ``Pool[MetricsRegistry].get_ptr(self.registry_addr)[].render()``
        but keeps callers pointer-free."""
        return Pool[MetricsRegistry].get_ptr(self.registry_addr)[].render()
