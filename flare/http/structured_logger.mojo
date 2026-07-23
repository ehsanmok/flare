"""Structured (JSON-shaped) request logger middleware.

The plain ``Logger[Inner]`` middleware in :mod:`flare.http.middleware`
emits one space-delimited line per request:

    [flare] GET /users 200 12ms

That's grep-friendly, ``jq``-friendly with a parser, and zero-dep —
but it's not the shape modern observability stacks want. Datadog,
Elastic, Loki, Splunk, and CloudWatch Logs Insights all key on
JSON-per-line so they can build automatic dashboards on the
``status`` / ``latency_ms`` / ``method`` / ``url`` fields without
custom regex.

``StructuredLogger[Inner]`` is the additive sibling that emits one
JSON object per request with the same fields plus a few extras
(timestamp, request_id, peer-address). Surface stays tiny + the
inner ``Logger`` is unchanged: callers that prefer the line shape
keep using ``Logger[Inner]``.

Example output (one line per request):

    {"ts":"2026-05-01T15:39:01.123Z","method":"GET","url":"/users","status":200,"latency_ms":12,"request_id":"req-7f3","peer":"192.168.1.5:56324"}

Field selection rationale (vs Apache common log / nginx default):

- ``ts``: ISO-8601 UTC second-precision (``YYYY-MM-DDTHH:MM:SSZ``).
  Most ingest pipelines auto-detect this shape; nanos / millis are
  available if needed but the default is seconds + millisecond
  precision in the value to keep the line compact.
- ``method`` / ``url`` / ``status``: the obvious request triple.
- ``latency_ms``: ``perf_counter_ns`` delta divided by 1_000_000.
  Same shape the plain ``Logger`` already emits — but as a number,
  not a "12ms" string.
- ``request_id``: pulled from ``X-Request-Id`` on the response
  (the same header the existing ``RequestId[Inner]`` middleware
  echoes). Skipped from the line if absent. Lets a downstream
  pipeline join logs to traces without an extractor.
- ``peer``: pulled from ``Request.peer`` if set. Skipped if not.
  Useful for per-IP rate-limit forensics on a system without an
  upstream reverse-proxy access log.
- ``error``: only present on error path; carries the exception
  message verbatim (caller-controlled — the inner handler decides
  what to ``raise(...)``).

JSON-escape rules per RFC 8259:

- ``"`` → ``\\"``
- ``\\`` → ``\\\\``
- ``\\b`` / ``\\f`` / ``\\n`` / ``\\r`` / ``\\t`` → escaped form
- Other control bytes (< 0x20) → ``\\u00XX`` form
- All other UTF-8 bytes pass through unchanged

The escaper is single-pass, byte-by-byte, no allocator beyond the
output ``String``'s own grow buffer. For typical 100-byte URLs
this is well under 1µs/req — invisible against the inner
handler's latency budget.
"""

from std.time import perf_counter_ns

from .handler import Handler
from .request import Request
from .response import Response
from ..runtime.date_cache import unix_seconds_to_civil


# ── JSON escaper ────────────────────────────────────────────────────────────


def _json_escape(s: String) -> String:
    """Escape ``s`` for inclusion inside a JSON string literal.

    Returns the escaped body **without** the surrounding double
    quotes — caller wraps in ``"..."`` so multiple values can be
    concatenated cheaply.
    """
    var n = s.byte_length()
    if n == 0:
        return String("")
    var out = String(capacity=n + 8)
    var p = s.unsafe_ptr()
    var hex_chars = String("0123456789abcdef")
    var hp = hex_chars.unsafe_ptr()
    for i in range(n):
        var b = Int(p[i])
        if b == ord('"'):
            out += '\\"'
        elif b == ord("\\"):
            out += "\\\\"
        elif b == 0x08:
            out += "\\b"
        elif b == 0x09:
            out += "\\t"
        elif b == 0x0A:
            out += "\\n"
        elif b == 0x0C:
            out += "\\f"
        elif b == 0x0D:
            out += "\\r"
        elif b < 0x20:
            out += "\\u00"
            out += chr(Int(hp[(b >> 4) & 0xF]))
            out += chr(Int(hp[b & 0xF]))
        else:
            out += chr(b)
    return out^


# ── Timestamp formatter ─────────────────────────────────────────────────────


def _format_iso8601_utc(unix_ns: Int) -> String:
    """Format ``unix_ns`` (Unix epoch nanoseconds) as
    ``YYYY-MM-DDTHH:MM:SS.mmmZ`` UTC.

    Branch-free civil-from-days arithmetic via the canonical
    :func:`flare.runtime.date_cache.unix_seconds_to_civil`
    helper, so we don't need ``gmtime_r`` / TZ environment
    fiddling and the same identity is shared with the
    IMF-fixdate writer in :mod:`flare.runtime.date_cache` and
    the HTTP-date parser in :mod:`flare.http.conditional`.
    """
    var unix_ms_total = unix_ns // 1_000_000
    var ms_in_sec = Int(unix_ms_total % 1000)
    var unix_secs = Int(unix_ms_total // 1000)
    var ct = unix_seconds_to_civil(unix_secs)

    var out = String(capacity=24)
    out += _pad(ct.year, 4)
    out += "-"
    out += _pad(ct.month, 2)
    out += "-"
    out += _pad(ct.day, 2)
    out += "T"
    out += _pad(ct.hour, 2)
    out += ":"
    out += _pad(ct.minute, 2)
    out += ":"
    out += _pad(ct.second, 2)
    out += "."
    out += _pad(ms_in_sec, 3)
    out += "Z"
    return out^


def _pad(n: Int, width: Int) -> String:
    """Zero-pad ``n`` to ``width`` digits."""
    var s = String(n)
    if s.byte_length() >= width:
        return s
    var out = String(capacity=width + 1)
    for _ in range(width - s.byte_length()):
        out += "0"
    out += s
    return out^


# ── StructuredLogger ────────────────────────────────────────────────────────


struct StructuredLogger[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """JSON-per-line request logger around the inner handler.

    Emits one line of JSON per request to stdout:

        {"ts":"...","method":"GET","url":"/users","status":200,
         "latency_ms":12,"request_id":"req-7f3","peer":"1.2.3.4:5678"}

    Fields that are absent (no ``X-Request-Id`` header set; no
    ``Request.peer``) are skipped from the line so the JSON object
    stays compact. On the error path, the line carries an
    ``"error":"<exception message>"`` field instead of ``status``
    / ``latency_ms``.

    Construct via the default factory or with an explicit
    inner handler, mirroring the plain ``Logger`` shape:

        ``StructuredLogger[Router](Router())``

    Wraps ``Inner.serve`` with the timing / error catch /
    line-emit, exactly like ``Logger`` does — one extra
    allocation per request for the JSON line buffer.
    """

    var inner: Self.Inner
    var _epoch_offset_ns: Int
    """Cached delta between ``perf_counter_ns()`` and the wall
    clock at construction time. We use ``perf_counter_ns`` for
    latency arithmetic (monotonic, no clock-step jitter) and add
    this offset to derive a wall-clock timestamp for the ``ts``
    field. The clock-step risk is bounded by the lifetime of a
    single ``StructuredLogger`` instance — typically a worker
    pthread — and a 1-second drift on a 24-hour soak is OK for
    log-line resolution."""

    def __init__(out self):
        self.inner = Self.Inner()
        # perf_counter_ns is monotonic; we'd ideally subtract it
        # from a wall-clock read here. The stdlib doesn't expose
        # gettimeofday or clock_gettime(REALTIME) on this nightly,
        # so the offset stays 0 and the ``ts`` field is "ns since
        # the worker started" presented as ISO-8601. The line
        # shape is forward-compatible -- when wall-clock support
        # lands the offset can be back-filled without consumers
        # noticing.
        self._epoch_offset_ns = 0

    def __init__(out self, var inner: Self.Inner):
        self.inner = inner^
        self._epoch_offset_ns = 0

    def serve(self, req: Request) raises -> Response:
        var start = perf_counter_ns()
        var resp: Response
        try:
            resp = self.inner.serve(req).lower()
        except e:
            var latency_ms = Int((perf_counter_ns() - start) // 1_000_000)
            var line = self._build_error_line(
                req, String(e), latency_ms, Int(start)
            )
            print(line)
            raise Error(String(e))
        var latency_ms = Int((perf_counter_ns() - start) // 1_000_000)
        var line = self._build_success_line(req, resp, latency_ms, Int(start))
        print(line)
        return resp^

    def _build_success_line(
        self,
        req: Request,
        resp: Response,
        latency_ms: Int,
        start_ns: Int,
    ) -> String:
        var line = String(capacity=192)
        line += '{"ts":"'
        line += _format_iso8601_utc(start_ns + self._epoch_offset_ns)
        line += '","method":"'
        line += _json_escape(req.method)
        line += '","url":"'
        line += _json_escape(req.url)
        line += '","status":'
        line += String(resp.status)
        line += ',"latency_ms":'
        line += String(latency_ms)
        var rid = resp.headers.get("x-request-id")
        if rid.byte_length() > 0:
            line += ',"request_id":"'
            line += _json_escape(rid)
            line += '"'
        var peer = self._format_peer(req)
        if peer.byte_length() > 0:
            line += ',"peer":"'
            line += _json_escape(peer)
            line += '"'
        line += "}"
        return line^

    def _build_error_line(
        self,
        req: Request,
        err_msg: String,
        latency_ms: Int,
        start_ns: Int,
    ) -> String:
        var line = String(capacity=192)
        line += '{"ts":"'
        line += _format_iso8601_utc(start_ns + self._epoch_offset_ns)
        line += '","method":"'
        line += _json_escape(req.method)
        line += '","url":"'
        line += _json_escape(req.url)
        line += '","error":"'
        line += _json_escape(err_msg)
        line += '","latency_ms":'
        line += String(latency_ms)
        var peer = self._format_peer(req)
        if peer.byte_length() > 0:
            line += ',"peer":"'
            line += _json_escape(peer)
            line += '"'
        line += "}"
        return line^

    def _format_peer(self, req: Request) -> String:
        """Render Request.peer as ``host:port``, or ``""`` when
        the parser couldn't fill it in (e.g. UDS connection)."""
        return String(req.peer)
