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
struct _Echo(Copyable, Defaultable, Handler):
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


def _acao_with_credentials(
    origins: List[String], origin: String
) raises -> String:
    var cfg = CorsConfig()
    cfg.allow_credentials = True
    for o in origins:
        cfg.allowed_origins.append(o)
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", origin)
    return mw.serve(req).headers.get("access-control-allow-origin")


def test_credentials_allowlist_is_order_independent() raises:
    """APP-21: with credentials a ``*`` entry authorises nothing but must not
    hide a listed origin that comes after it."""
    var good = String("https://app.example.com")
    assert_equal(_acao_with_credentials(["*", good], good), good)
    assert_equal(_acao_with_credentials([good, "*"], good), good)
    assert_equal(_acao_with_credentials(["a", "*", good], good), good)
    # An unlisted origin is still rejected in both orders (``*`` cannot
    # authorise a credentialed request).
    assert_equal(_acao_with_credentials(["*", good], "https://evil"), "")
    assert_equal(_acao_with_credentials([good, "*"], "https://evil"), "")


def test_wildcard_without_credentials_still_first_match() raises:
    """APP-21: without credentials ``*`` still allows any origin, whatever
    the order."""
    var cfg = CorsConfig()
    cfg.allowed_origins.append("*")
    cfg.allowed_origins.append("https://app.example.com")
    var mw = Cors(_Echo(), cfg)
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", "https://other.example")
    var resp = mw.serve(req)
    assert_equal(
        resp.headers.get("access-control-allow-origin"),
        "https://other.example",
    )


def _vary_origin_count(resp: Response) raises -> Int:
    var n = 0
    for v in resp.headers.get_all("vary"):
        if v == "Origin":
            n += 1
    return n


def _allowlist_cors() raises -> CorsConfig:
    var cfg = CorsConfig()
    cfg.allowed_origins.append("https://a.example")
    cfg.allowed_origins.append("https://b.example")
    return cfg^


def test_vary_origin_on_response_without_origin() raises:
    """APP-22: the ACAO value depends on ``Origin``, so the response to a
    request with no ``Origin`` carries ``Vary: Origin`` too."""
    var mw = Cors(_Echo(), _allowlist_cors())
    var resp = mw.serve(Request(method=Method.GET, url="/api"))
    assert_equal(resp.status, 200)
    assert_false(resp.headers.contains("access-control-allow-origin"))
    assert_equal(_vary_origin_count(resp), 1)


def test_vary_origin_on_rejected_origin_and_preflight() raises:
    """APP-22: rejected simple requests and rejected preflights (403) carry
    ``Vary: Origin`` as well."""
    var mw = Cors(_Echo(), _allowlist_cors())
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", "https://evil.example")
    var resp = mw.serve(req)
    assert_false(resp.headers.contains("access-control-allow-origin"))
    assert_equal(_vary_origin_count(resp), 1)

    var pre = Request(method=Method.OPTIONS, url="/api")
    pre.headers.set("Origin", "https://evil.example")
    pre.headers.set("Access-Control-Request-Method", "GET")
    var presp = mw.serve(pre)
    assert_equal(presp.status, 403)
    assert_equal(_vary_origin_count(presp), 1)


def test_vary_origin_single_on_allowed_and_not_duplicated() raises:
    """APP-22: stamped responses still carry exactly one ``Vary: Origin``."""
    var mw = Cors(_Echo(), _allowlist_cors())
    var req = Request(method=Method.GET, url="/api")
    req.headers.set("Origin", "https://a.example")
    var resp = mw.serve(req)
    assert_equal(
        resp.headers.get("access-control-allow-origin"), "https://a.example"
    )
    assert_equal(_vary_origin_count(resp), 1)

    var pre = Request(method=Method.OPTIONS, url="/api")
    pre.headers.set("Origin", "https://b.example")
    pre.headers.set("Access-Control-Request-Method", "GET")
    var presp = mw.serve(pre)
    assert_equal(presp.status, 204)
    assert_equal(_vary_origin_count(presp), 1)


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
    test_credentials_allowlist_is_order_independent()
    test_wildcard_without_credentials_still_first_match()
    test_vary_origin_on_response_without_origin()
    test_vary_origin_on_rejected_origin_and_preflight()
    test_vary_origin_single_on_allowed_and_not_duplicated()
    test_exposed_headers_attached()
    test_no_origin_passes_through()
    print("test_cors: 14 passed")
