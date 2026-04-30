"""Tests for ``flare.http.cors`` (— track G).

Covers:

- ``CorsConfig.permissive`` defaults.
- Origin allowlist (string match + ``*`` wildcard).
- Preflight (``OPTIONS`` + ``Access-Control-Request-Method``)
  short-circuits with the right headers.
- Simple request gets ``Access-Control-Allow-Origin`` attached.
- Disallowed origin -> inner handler runs without CORS headers.
- Disallowed origin + preflight -> 403.
- ``allow_credentials=True`` echoes the request origin (not ``*``).
- ``exposed_headers`` are attached.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.http import (
    Cors,
    CorsConfig,
    Handler,
    Method,
    Request,
    Response,
)


@fieldwise_init
struct _Echo(Copyable, Defaultable, Handler, Movable):
    var _p: UInt8

    def __init__(out self):
        self._p = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8]("ok".as_bytes())
        return resp^


def test_permissive_config() raises:
    var c = CorsConfig.permissive()
    assert_true(len(c.allowed_origins) >= 1)
    assert_equal(c.allowed_origins[0], "*")


def test_simple_request_attaches_origin() raises:
    var cfg = CorsConfig.permissive()
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", "https://example.com")
    var resp = mw.serve(req)
    assert_equal(resp.headers.get("access-control-allow-origin"), "*")


def test_specific_origin_echoed() raises:
    var cfg = CorsConfig()
    cfg.allowed_origins.append("https://app.example.com")
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", "https://app.example.com")
    var resp = mw.serve(req)
    assert_equal(
        resp.headers.get("access-control-allow-origin"),
        "https://app.example.com",
    )


def test_disallowed_origin_passes_through_no_cors() raises:
    var cfg = CorsConfig()
    cfg.allowed_origins.append("https://app.example.com")
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", "https://evil.example.com")
    var resp = mw.serve(req)
    assert_equal(resp.status, 200)
    assert_false(resp.headers.contains("access-control-allow-origin"))


def test_preflight_disallowed_returns_403() raises:
    var cfg = CorsConfig()
    cfg.allowed_origins.append("https://app.example.com")
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.OPTIONS, url="/api")
    req.headers.set("Origin", "https://evil.example.com")
    req.headers.set("Access-Control-Request-Method", "POST")
    var resp = mw.serve(req)
    assert_equal(resp.status, 403)


def test_preflight_allowed_returns_204_with_headers() raises:
    var cfg = CorsConfig.permissive()
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.OPTIONS, url="/api")
    req.headers.set("Origin", "https://app.example.com")
    req.headers.set("Access-Control-Request-Method", "POST")
    req.headers.set("Access-Control-Request-Headers", "X-Custom")
    var resp = mw.serve(req)
    assert_equal(resp.status, 204)
    assert_true(resp.headers.contains("access-control-allow-origin"))
    assert_true(resp.headers.contains("access-control-allow-methods"))
    assert_equal(resp.headers.get("access-control-allow-headers"), "X-Custom")
    assert_true(resp.headers.contains("access-control-max-age"))


def test_credentials_disables_wildcard() raises:
    var cfg = CorsConfig()
    cfg.allowed_origins.append("*")
    cfg.allow_credentials = True
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", "https://app.example.com")
    var resp = mw.serve(req)
    assert_false(
        Bool(resp.headers.contains("access-control-allow-origin"))
        and resp.headers.get("access-control-allow-origin") == "*"
    )


def test_exposed_headers_attached() raises:
    var cfg = CorsConfig.permissive()
    cfg.exposed_headers.append("X-Total-Count")
    cfg.exposed_headers.append("ETag")
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", "https://example.com")
    var resp = mw.serve(req)
    assert_equal(
        resp.headers.get("access-control-expose-headers"),
        "X-Total-Count, ETag",
    )


def test_no_origin_passes_through() raises:
    var cfg = CorsConfig()
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.GET, url="/api")
    var resp = mw.serve(req)
    assert_equal(resp.status, 200)
    assert_false(resp.headers.contains("access-control-allow-origin"))


def main() raises:
    test_permissive_config()
    test_simple_request_attaches_origin()
    test_specific_origin_echoed()
    test_disallowed_origin_passes_through_no_cors()
    test_preflight_disallowed_returns_403()
    test_preflight_allowed_returns_204_with_headers()
    test_credentials_disables_wildcard()
    test_exposed_headers_attached()
    test_no_origin_passes_through()
    print("test_cors: 9 passed")
