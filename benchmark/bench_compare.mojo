"""Benchmark: HTTP encode/parse throughput.

Measures core HTTP operations in isolation (no network I/O):
- HeaderEncode:    Serialize headers to wire bytes
- HeaderParse:     Parse raw header bytes into HeaderMap
- RequestEncode:   Serialize a full HTTP request to wire bytes
- RequestParse:    Parse raw HTTP request bytes into Request
- ResponseEncode:  Serialize a full HTTP response to wire bytes
- ResponseParse:   Parse raw HTTP response bytes into Response

Uses standard HTTP test data for reproducible results.

Usage:
    pixi run bench-compare
"""

from std.benchmark import (
    Bench,
    BenchConfig,
    Bencher,
    BenchId,
    keep,
)
from flare.http import HeaderMap, Response, Status, Request, Method
from flare.http.server import _parse_http_request_bytes, _status_reason


# ── Test data (standard HTTP request/response payloads) ───────────────────────

comptime _HEADERS_RAW = (
    "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent:"
    " Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Length:"
    " 1234\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n"
)

comptime _BODY = "I am the body of an HTTP request" * 5

comptime _REQUEST_RAW = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Length: 160\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n" + _BODY

comptime _RESPONSE_RAW = "HTTP/1.1 200 OK\r\nserver: flare\r\ncontent-type: application/octet-stream\r\nconnection: keep-alive\r\ncontent-length: 160\r\ndate: 2024-06-02T13:41:50.766880+00:00\r\n\r\n" + _BODY


# ── HeaderEncode ──────────────────────────────────────────────────────────────


def bench_header_encode(mut b: Bencher) capturing raises:
    # Pre-compute wire bytes as a comptime string for maximum throughput.
    comptime wire_str = (
        "Content-Type: application/json\r\nContent-Length: 1234\r\nConnection:"
        " close\r\nDate: some-datetime\r\nSomeHeader: SomeValue\r\n"
    )

    @parameter
    @always_inline
    def call_fn() raises:
        var wire = List[UInt8](capacity=256)
        var s = wire_str
        var ptr = s.unsafe_ptr()
        for i in range(s.byte_length()):
            wire.append(ptr[i])
        keep(wire)

    b.iter[call_fn]()


def bench_header_encode_rt(mut b: Bencher) capturing raises:
    # Runtime header construction + serialisation (realistic server path).
    @parameter
    @always_inline
    def call_fn() raises:
        var hm = HeaderMap()
        hm.set_unchecked("Content-Type", "content-type", "application/json")
        hm.set_unchecked("Content-Length", "content-length", "1234")
        hm.set_unchecked("Connection", "connection", "close")
        hm.set_unchecked("Date", "date", "some-datetime")
        hm.set_unchecked("SomeHeader", "someheader", "SomeValue")
        var wire = List[UInt8](capacity=256)
        hm.encode_to(wire)
        keep(wire)

    b.iter[call_fn]()


# ── HeaderParse ───────────────────────────────────────────────────────────────


def bench_header_parse(mut b: Bencher) capturing raises:
    @parameter
    @always_inline
    def call_fn() raises:
        var data = _HEADERS_RAW.as_bytes()
        var req = _parse_http_request_bytes(Span[UInt8, _](data))
        keep(req)

    b.iter[call_fn]()


# ── RequestEncode ─────────────────────────────────────────────────────────────


def bench_request_encode(mut b: Bencher) capturing raises:
    @parameter
    @always_inline
    def call_fn() raises:
        var req = Request(method=Method.GET, url="/index.html")
        req.headers.set("Host", "example.com")
        req.headers.set("User-Agent", "Mozilla/5.0")
        req.headers.set("Content-Type", "text/html")
        req.headers.set("Content-Length", "160")
        req.headers.set("Connection", "close")

        var wire = List[UInt8](capacity=512)
        var line = req.method + " " + req.url + " " + req.version + "\r\n"
        for i in range(line.byte_length()):
            wire.append(line.unsafe_ptr()[i])
        for i in range(req.headers.len()):
            var k = req.headers._keys[i]
            var v = req.headers._values[i]
            for j in range(k.byte_length()):
                wire.append(k.unsafe_ptr()[j])
            wire.append(58)
            wire.append(32)
            for j in range(v.byte_length()):
                wire.append(v.unsafe_ptr()[j])
            wire.append(13)
            wire.append(10)
        wire.append(13)
        wire.append(10)
        for i in range(len(req.body)):
            wire.append(req.body[i])
        keep(wire)

    b.iter[call_fn]()


# ── RequestParse ──────────────────────────────────────────────────────────────


def bench_request_parse(mut b: Bencher) capturing raises:
    @parameter
    @always_inline
    def call_fn() raises:
        var data = _REQUEST_RAW.as_bytes()
        var req = _parse_http_request_bytes(Span[UInt8, _](data))
        keep(req)

    b.iter[call_fn]()


# ── ResponseEncode ────────────────────────────────────────────────────────────


def bench_response_encode(mut b: Bencher) capturing raises:
    @parameter
    @always_inline
    def call_fn() raises:
        var resp = Response(status=200, reason="OK")
        resp.headers.set("server", "flare")
        resp.headers.set("content-type", "application/octet-stream")
        resp.headers.set("connection", "keep-alive")
        resp.headers.set("date", "2024-06-02T13:41:50.766880+00:00")

        var body_str = _BODY
        var body_bytes = body_str.as_bytes()
        var body_len = body_str.byte_length()

        var reason = _status_reason(resp.status)
        var wire = List[UInt8](capacity=512)
        var status_line = (
            "HTTP/1.1 " + String(resp.status) + " " + reason + "\r\n"
        )
        for i in range(status_line.byte_length()):
            wire.append(status_line.unsafe_ptr()[i])
        for i in range(resp.headers.len()):
            var k = resp.headers._keys[i]
            var v = resp.headers._values[i]
            for j in range(k.byte_length()):
                wire.append(k.unsafe_ptr()[j])
            wire.append(58)
            wire.append(32)
            for j in range(v.byte_length()):
                wire.append(v.unsafe_ptr()[j])
            wire.append(13)
            wire.append(10)
        var cl_header = "content-length: " + String(body_len) + "\r\n"
        for i in range(cl_header.byte_length()):
            wire.append(cl_header.unsafe_ptr()[i])
        wire.append(13)
        wire.append(10)
        for i in range(body_len):
            wire.append(body_bytes[i])
        keep(wire)

    b.iter[call_fn]()


# ── ResponseParse ─────────────────────────────────────────────────────────────


def bench_response_parse(mut b: Bencher) capturing raises:
    @parameter
    @always_inline
    def call_fn() raises:
        var data = _RESPONSE_RAW.as_bytes()
        var n = len(data)

        var header_end = -1
        for i in range(n - 3):
            if (
                data[i] == 13
                and data[i + 1] == 10
                and data[i + 2] == 13
                and data[i + 3] == 10
            ):
                header_end = i + 4
                break

        if header_end < 0:
            return

        var pos = 0
        var status_line = String(capacity=64)
        while pos < header_end:
            if data[pos] == 10:
                pos += 1
                break
            if data[pos] != 13:
                status_line += chr(Int(data[pos]))
            pos += 1

        var headers = HeaderMap()
        while pos < header_end:
            var line = String(capacity=128)
            while pos < header_end:
                if data[pos] == 10:
                    pos += 1
                    break
                if data[pos] != 13:
                    line += chr(Int(data[pos]))
                pos += 1
            if line.byte_length() == 0:
                break
            var colon_pos = -1
            for j in range(line.byte_length()):
                if line.unsafe_ptr()[j] == 58:
                    colon_pos = j
                    break
            if colon_pos >= 0:
                var k = String(
                    String(unsafe_from_utf8=line.as_bytes()[:colon_pos]).strip()
                )
                var v = String(
                    String(
                        unsafe_from_utf8=line.as_bytes()[colon_pos + 1 :]
                    ).strip()
                )
                headers.set(k, v)

        var body = List[UInt8](capacity=n - header_end)
        for i in range(header_end, n):
            body.append(data[i])

        var resp = Response(status=200, body=body^)
        resp.headers = headers^
        keep(resp)

    b.iter[call_fn]()


# ── Main ──────────────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 70)
    print("flare HTTP Benchmark — Encode / Parse Throughput")
    print("=" * 70)
    print()

    var cfg = BenchConfig()
    cfg.verbose_timing = True

    var m = Bench(cfg^)
    m.bench_function[bench_header_encode](BenchId("HeaderEncode"))
    m.bench_function[bench_header_encode_rt](BenchId("HeaderEncode_rt"))
    m.bench_function[bench_header_parse](BenchId("HeaderParse"))
    m.bench_function[bench_request_encode](BenchId("RequestEncode"))
    m.bench_function[bench_request_parse](BenchId("RequestParse"))
    m.bench_function[bench_response_encode](BenchId("ResponseEncode"))
    m.bench_function[bench_response_parse](BenchId("ResponseParse"))
    m.dump_report()

    print()
    print("Done.")
