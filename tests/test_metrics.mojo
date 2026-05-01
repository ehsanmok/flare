"""Tests for :mod:`flare.http.metrics`.

Coverage:

1. Method / status / bucket index → label round-trip is bijective
   on the documented domain.
2. ``MetricsRegistry.record`` updates the right slot, bumps the
   right histogram bucket cumulatively (= prometheus contract),
   and the latency total tracks the sum.
3. ``MetricsRegistry.record_error`` increments errors_total, still
   bumps latency histogram (so a slow-then-raise is visible).
4. ``MetricsRegistry.enter`` / ``exit`` move the in-flight gauge
   atomically against a 0 floor.
5. ``MetricsRegistry.render`` produces parseable Prometheus text
   exposition with the right HELP / TYPE preludes and skips
   zero-count rows for the cardinality-bounded ``requests_total``
   matrix.
6. ``Metrics[Inner].serve`` returns the inner response on the
   success path with the right counter / histogram increments.
7. ``Metrics[Inner].serve`` re-raises on the error path, drops
   in-flight, bumps errors_total.
8. Default histogram bucket layout matches the Prometheus
   default-bucket spec (hyper / actix-web parity).
9. ``_format_seconds`` zero-pads sub-second microsecond values
   correctly (no missing leading zeros after the decimal).
"""

from std.testing import TestSuite, assert_equal, assert_true

from flare.http.handler import Handler
from flare.http.metrics import (
    Metrics,
    MetricsRegistry,
    _bucket_index,
    _bucket_le_label,
    _format_seconds,
    _method_index,
    _method_label,
    _status_index,
    _status_label,
)
from flare.http.request import Request
from flare.http.response import Response
from flare.runtime.pool import Pool


# ── Index tables ──────────────────────────────────────────────────────────


def test_method_index_known_methods() raises:
    assert_equal(_method_index(String("GET")), 0)
    assert_equal(_method_index(String("HEAD")), 1)
    assert_equal(_method_index(String("POST")), 2)
    assert_equal(_method_index(String("PUT")), 3)
    assert_equal(_method_index(String("PATCH")), 4)
    assert_equal(_method_index(String("DELETE")), 5)
    assert_equal(_method_index(String("CONNECT")), 6)
    assert_equal(_method_index(String("OPTIONS")), 7)
    assert_equal(_method_index(String("TRACE")), 8)


def test_method_index_unknown_falls_to_other() raises:
    assert_equal(_method_index(String("PROPFIND")), 9)
    assert_equal(_method_index(String("get")), 9)  # case-sensitive
    assert_equal(_method_label(9), String("other"))


def test_status_index_known_codes() raises:
    assert_equal(_status_index(200), 0)
    assert_equal(_status_index(204), 2)
    assert_equal(_status_index(412), 10)
    assert_equal(_status_index(503), 14)


def test_status_index_unknown_falls_to_other() raises:
    assert_equal(_status_index(418), 15)
    assert_equal(_status_index(99), 15)
    assert_equal(_status_label(15), String("other"))


def test_method_label_round_trip() raises:
    """Every index 0..9 round-trips through label → index."""
    for i in range(10):
        var label = _method_label(i)
        if label != String("other"):
            assert_equal(_method_index(label), i)


def test_status_label_round_trip() raises:
    """Every index 0..15 round-trips through label → index."""
    for i in range(16):
        var label = _status_label(i)
        if label != String("other"):
            assert_equal(_status_index(Int(label)), i)


# ── Bucket table ──────────────────────────────────────────────────────────


def test_bucket_index_layout() raises:
    """Verify default Prometheus bucket layout (hyper / actix-web
    parity)."""
    assert_equal(_bucket_index(1_000), 0)  # 0.001s ≤ 0.005s
    assert_equal(_bucket_index(5_000), 0)
    assert_equal(_bucket_index(5_001), 1)
    assert_equal(_bucket_index(10_000), 1)
    assert_equal(_bucket_index(25_000), 2)
    assert_equal(_bucket_index(100_000), 4)
    assert_equal(_bucket_index(10_000_000), 10)
    assert_equal(_bucket_index(11_000_000), 11)  # +Inf
    assert_equal(_bucket_index(99_999_999_999), 11)


def test_bucket_le_label_strings() raises:
    assert_equal(_bucket_le_label(0), String("0.005"))
    assert_equal(_bucket_le_label(7), String("1"))
    assert_equal(_bucket_le_label(11), String("+Inf"))


# ── _format_seconds ───────────────────────────────────────────────────────


def test_format_seconds_zero() raises:
    assert_equal(_format_seconds(UInt64(0)), String("0.000000"))


def test_format_seconds_under_one_second() raises:
    """123 µs → 0.000123 — must zero-pad after the decimal."""
    assert_equal(_format_seconds(UInt64(123)), String("0.000123"))


def test_format_seconds_over_one_second() raises:
    """1_234_567 µs → 1.234567 (no extra leading zero)."""
    assert_equal(_format_seconds(UInt64(1_234_567)), String("1.234567"))


def test_format_seconds_exact_seconds() raises:
    """12_000_000 µs → 12.000000 (full zero pad)."""
    assert_equal(_format_seconds(UInt64(12_000_000)), String("12.000000"))


# ── MetricsRegistry ───────────────────────────────────────────────────────


def test_registry_default_zero() raises:
    var r = MetricsRegistry()
    assert_equal(Int(r.duration_count), 0)
    assert_equal(Int(r.duration_sum_micros), 0)
    assert_equal(Int(r.in_flight), 0)
    assert_equal(Int(r.errors_total), 0)


def test_registry_record_increments_method_status_slot() raises:
    var r = MetricsRegistry()
    r.record(0, 0, UInt64(7_500))  # GET 200, 7.5 ms
    var slot = 0 * 16 + 0
    assert_equal(Int(r.requests_total[slot]), 1)
    assert_equal(Int(r.duration_count), 1)
    assert_equal(Int(r.duration_sum_micros), 7500)


def test_registry_record_bumps_cumulative_buckets() raises:
    """A 7.5 ms request bumps every bucket from le=0.01 onward."""
    var r = MetricsRegistry()
    r.record(0, 0, UInt64(7_500))
    # bucket 0 (≤5ms): 0; bucket 1 (≤10ms): 1; ... +Inf: 1
    assert_equal(Int(r.duration_buckets[0]), 0)
    for i in range(1, 13):
        assert_equal(Int(r.duration_buckets[i]), 1)


def test_registry_record_two_requests_aggregate() raises:
    var r = MetricsRegistry()
    r.record(0, 0, UInt64(3_000))  # 3ms → all buckets including bucket 0
    r.record(0, 0, UInt64(7_500))  # 7.5ms → buckets 1..+Inf
    assert_equal(Int(r.requests_total[0]), 2)
    assert_equal(Int(r.duration_buckets[0]), 1)  # only the 3ms one
    assert_equal(Int(r.duration_buckets[1]), 2)  # both
    assert_equal(Int(r.duration_buckets[12]), 2)  # +Inf has both
    assert_equal(Int(r.duration_sum_micros), 10_500)


def test_registry_record_error_bumps_errors_and_histogram() raises:
    var r = MetricsRegistry()
    r.record_error(UInt64(50_000))
    assert_equal(Int(r.errors_total), 1)
    assert_equal(Int(r.duration_count), 1)


def test_registry_in_flight_gauge_floor_at_zero() raises:
    var r = MetricsRegistry()
    r.enter()
    r.enter()
    assert_equal(Int(r.in_flight), 2)
    r.exit()
    assert_equal(Int(r.in_flight), 1)
    r.exit()
    assert_equal(Int(r.in_flight), 0)
    # exit on empty registry must not underflow to UInt64::MAX
    r.exit()
    assert_equal(Int(r.in_flight), 0)


# ── render() ──────────────────────────────────────────────────────────────


def test_render_emits_help_and_type_preludes() raises:
    var r = MetricsRegistry()
    var s = r.render()
    assert_true("# HELP flare_http_requests_total" in s)
    assert_true("# TYPE flare_http_requests_total counter" in s)
    assert_true("# HELP flare_http_request_duration_seconds" in s)
    assert_true("# TYPE flare_http_request_duration_seconds histogram" in s)
    assert_true("# HELP flare_http_requests_in_flight" in s)
    assert_true("# TYPE flare_http_requests_in_flight gauge" in s)
    assert_true("# HELP flare_http_request_errors_total" in s)
    assert_true("# TYPE flare_http_request_errors_total counter" in s)


def test_render_skips_zero_count_request_rows() raises:
    """A fresh registry has 160 zero-count cells; render() must
    skip every one to keep the exposition compact."""
    var r = MetricsRegistry()
    var s = r.render()
    assert_true('flare_http_requests_total{method="GET",status="200"}' not in s)


def test_render_emits_recorded_request_row() raises:
    var r = MetricsRegistry()
    r.record(_method_index(String("POST")), _status_index(201), UInt64(15_000))
    var s = r.render()
    assert_true('flare_http_requests_total{method="POST",status="201"} 1' in s)


def test_render_includes_all_thirteen_histogram_buckets() raises:
    var r = MetricsRegistry()
    var s = r.render()
    assert_true('le="0.005"' in s)
    assert_true('le="0.01"' in s)
    assert_true('le="0.025"' in s)
    assert_true('le="0.05"' in s)
    assert_true('le="0.1"' in s)
    assert_true('le="0.25"' in s)
    assert_true('le="0.5"' in s)
    assert_true('le="1"' in s)
    assert_true('le="2.5"' in s)
    assert_true('le="5"' in s)
    assert_true('le="10"' in s)
    assert_true('le="+Inf"' in s)


def test_render_includes_in_flight_value() raises:
    var r = MetricsRegistry()
    r.enter()
    r.enter()
    var s = r.render()
    assert_true("flare_http_requests_in_flight 2\n" in s)


# ── Metrics[Inner] middleware ─────────────────────────────────────────────


struct _OK200(Copyable, Defaultable, Handler, Movable):
    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        return Response(status=200)


struct _Created201(Copyable, Defaultable, Handler, Movable):
    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        return Response(status=201)


struct _Boom(Copyable, Defaultable, Handler, Movable):
    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        raise Error("inner-boom")


def test_metrics_serve_records_success() raises:
    var m = Metrics[_OK200]()
    var req = Request(method=String("GET"), url=String("/x"))
    var resp = m.serve(req)
    var reg = Pool[MetricsRegistry].get_ptr(m.registry_addr)
    assert_equal(resp.status, 200)
    assert_equal(Int(reg[].duration_count), 1)
    assert_equal(Int(reg[].errors_total), 0)
    assert_equal(Int(reg[].in_flight), 0)
    var slot = _method_index(String("GET")) * 16 + _status_index(200)
    assert_equal(Int(reg[].requests_total[slot]), 1)


def test_metrics_serve_records_201_with_post() raises:
    var m = Metrics[_Created201]()
    var req = Request(method=String("POST"), url=String("/x"))
    var _resp = m.serve(req)
    var reg = Pool[MetricsRegistry].get_ptr(m.registry_addr)
    var slot = _method_index(String("POST")) * 16 + _status_index(201)
    assert_equal(Int(reg[].requests_total[slot]), 1)


def test_metrics_serve_re_raises_and_records_error() raises:
    var m = Metrics[_Boom]()
    var req = Request(method=String("GET"), url=String("/x"))
    var raised = False
    try:
        var _u = m.serve(req)
    except:
        raised = True
    var reg = Pool[MetricsRegistry].get_ptr(m.registry_addr)
    assert_true(raised)
    assert_equal(Int(reg[].errors_total), 1)
    assert_equal(Int(reg[].in_flight), 0)
    assert_equal(Int(reg[].duration_count), 1)


def test_metrics_render_helper_matches_registry_render() raises:
    """``Metrics.render()`` snapshots the same underlying
    registry as a direct ``Pool[MetricsRegistry].get_ptr`` call."""
    var m = Metrics[_OK200]()
    var req = Request(method=String("GET"), url=String("/x"))
    var _r = m.serve(req)
    var via_helper = m.render()
    var via_pool = Pool[MetricsRegistry].get_ptr(m.registry_addr)[].render()
    assert_equal(via_helper, via_pool)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
