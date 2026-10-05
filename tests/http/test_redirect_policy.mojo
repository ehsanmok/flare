"""Tests for :mod:`flare.http.redirect_policy`.

Covers all three modes (FOLLOW_ALL, SAME_ORIGIN_ONLY, DENY), the
hop cap, the 301/302/303 method-degrade path, the 307/308 method-
preserve path, the same-origin Authorization-forwarding default,
the cross-origin auth-forwarding opt-in, and the Location resolver
(absolute, origin-relative, dir-relative)."""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

from flare.http import Request, Response
from flare.http.redirect_policy import (
    RedirectAction,
    RedirectDecision,
    RedirectMode,
    RedirectPolicy,
)


# ── Default / FOLLOW_ALL ──────────────────────────────────────────────────


def test_default_policy_is_follow_all_max_10() raises:
    var p = RedirectPolicy()
    assert_equal(p.mode, RedirectMode.FOLLOW_ALL)
    assert_equal(p.max_redirects, 10)
    assert_false(p.forward_auth_cross_origin)


def test_follow_all_follows_same_origin_get() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://api.example.com/old",
        "GET",
        302,
        "/new",
        0,
    )
    assert_equal(d.action, RedirectAction.FOLLOW)
    assert_equal(d.next_method, "GET")
    assert_equal(d.next_url, "https://api.example.com:443/new")
    assert_false(d.next_body_dropped)
    assert_true(d.forward_authorization)


def test_follow_all_follows_cross_origin_get() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://a.example.com/x",
        "GET",
        302,
        "https://b.example.com/y",
        0,
    )
    assert_equal(d.action, RedirectAction.FOLLOW)
    # Cross-origin: Authorization MUST NOT be forwarded by default.
    assert_false(d.forward_authorization)


# ── 301/302/303 method degrade ───────────────────────────────────────────


def test_303_post_degrades_to_get_and_drops_body() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://api.example.com/submit",
        "POST",
        303,
        "/result",
        0,
    )
    assert_equal(d.next_method, "GET")
    assert_true(d.next_body_dropped)


def test_302_put_degrades_to_get_and_drops_body() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://api.example.com/x",
        "PUT",
        302,
        "/y",
        0,
    )
    assert_equal(d.next_method, "GET")
    assert_true(d.next_body_dropped)


# ── 307/308 method preserve ──────────────────────────────────────────────


def test_307_preserves_method_and_body() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://api.example.com/submit",
        "POST",
        307,
        "/new-submit",
        0,
    )
    assert_equal(d.next_method, "POST")
    assert_false(d.next_body_dropped)


def test_308_preserves_method_and_body() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://api.example.com/x",
        "DELETE",
        308,
        "/y",
        0,
    )
    assert_equal(d.next_method, "DELETE")
    assert_false(d.next_body_dropped)


# ── Hops cap ──────────────────────────────────────────────────────────────


def test_max_redirects_cap_returns_stop() raises:
    var p = RedirectPolicy.follow_all(max_redirects=3)
    var d = p.decide(
        "https://api.example.com/x",
        "GET",
        302,
        "/y",
        3,  # already at the cap
    )
    assert_equal(d.action, RedirectAction.STOP)


# ── SAME_ORIGIN_ONLY ─────────────────────────────────────────────────────


def test_same_origin_follows_same_host() raises:
    var p = RedirectPolicy.same_origin_only()
    var d = p.decide(
        "https://api.example.com/x",
        "GET",
        302,
        "/y",
        0,
    )
    assert_equal(d.action, RedirectAction.FOLLOW)
    assert_true(d.forward_authorization)


def test_same_origin_rejects_cross_host() raises:
    var p = RedirectPolicy.same_origin_only()
    var d = p.decide(
        "https://a.example.com/x",
        "GET",
        302,
        "https://b.example.com/y",
        0,
    )
    assert_equal(d.action, RedirectAction.REJECT)


def test_same_origin_rejects_cross_scheme() raises:
    """HTTPS → HTTP is treated as cross-origin (different scheme
    means different security context)."""
    var p = RedirectPolicy.same_origin_only()
    var d = p.decide(
        "https://api.example.com/x",
        "GET",
        302,
        "http://api.example.com/y",
        0,
    )
    assert_equal(d.action, RedirectAction.REJECT)


def test_same_origin_rejects_cross_port() raises:
    var p = RedirectPolicy.same_origin_only()
    var d = p.decide(
        "https://api.example.com:443/x",
        "GET",
        302,
        "https://api.example.com:8443/y",
        0,
    )
    assert_equal(d.action, RedirectAction.REJECT)


# ── DENY ──────────────────────────────────────────────────────────────────


def test_deny_never_follows() raises:
    var p = RedirectPolicy.deny()
    var d = p.decide(
        "https://api.example.com/x",
        "GET",
        302,
        "/y",
        0,
    )
    assert_equal(d.action, RedirectAction.STOP)


# ── Empty Location ───────────────────────────────────────────────────────


def test_empty_location_returns_stop() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://api.example.com/x",
        "GET",
        302,
        "",
        0,
    )
    assert_equal(d.action, RedirectAction.STOP)


# ── Auth forwarding opt-in ───────────────────────────────────────────────


def test_auth_forwarding_opt_in_for_cross_origin() raises:
    var p = RedirectPolicy(
        max_redirects=10,
        mode=RedirectMode.FOLLOW_ALL,
        forward_auth_cross_origin=True,
    )
    var d = p.decide(
        "https://a.example.com/x",
        "GET",
        302,
        "https://b.example.com/y",
        0,
    )
    assert_equal(d.action, RedirectAction.FOLLOW)
    assert_true(d.forward_authorization)


# ── Location resolver edge cases ─────────────────────────────────────────


def test_absolute_https_location_passes_through() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://a.example.com/x",
        "GET",
        302,
        "https://b.example.com/y",
        0,
    )
    assert_equal(d.next_url, "https://b.example.com/y")


def test_absolute_http_location_resolves() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "http://a.example.com/x",
        "GET",
        302,
        "http://b.example.com/y",
        0,
    )
    assert_equal(d.next_url, "http://b.example.com/y")


def test_origin_relative_location_resolves_against_base_origin() raises:
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://api.example.com/old",
        "GET",
        302,
        "/new",
        0,
    )
    assert_equal(d.next_url, "https://api.example.com:443/new")


def test_network_path_location_replaces_the_authority() raises:
    """``//host/path`` (RFC 3986 §4.2) keeps only the base scheme; it was
    appended to the current origin as if it were an absolute path."""
    var p = RedirectPolicy.follow_all()
    var d = p.decide(
        "https://api.example.com/a",
        "GET",
        302,
        "//cdn.example.net/img",
        0,
    )
    assert_equal(d.action, RedirectAction.FOLLOW)
    assert_equal(d.next_url, "https://cdn.example.net/img")
    assert_false(d.forward_authorization)


def test_network_path_location_is_cross_origin_for_same_origin_only() raises:
    var p = RedirectPolicy.same_origin_only()
    var d = p.decide(
        "https://api.example.com/a",
        "GET",
        302,
        "//cdn.example.net/img",
        0,
    )
    assert_equal(d.action, RedirectAction.REJECT)
    # A network-path reference naming the same host stays same-origin.
    var same = p.decide(
        "https://api.example.com/a",
        "GET",
        302,
        "//api.example.com/b?x=1",
        0,
    )
    assert_equal(same.action, RedirectAction.FOLLOW)
    assert_equal(same.next_url, "https://api.example.com/b?x=1")


# ── Caller credentials stay with the origin they were meant for ────────────


def _bounce(req: Request) raises -> Response:
    from flare.http import redirect

    return redirect(req.headers.get("x-next"))


def _echo_creds(req: Request) raises -> Response:
    from flare.http import ok

    return ok(
        "cookie=["
        + req.headers.get("cookie")
        + "] proxy=["
        + req.headers.get("proxy-authorization")
        + "]"
    )


def test_cross_origin_redirect_drops_caller_cookie_and_proxy_auth() raises:
    from flare.http import HttpClient, HttpServer
    from flare.net import SocketAddr
    from flare.testing import fork_server, kill_forked_server

    var a = HttpServer.bind(SocketAddr.localhost(0))
    var a_port = Int(a.local_addr().port)
    var b = HttpServer.bind(SocketAddr.localhost(0))
    var b_port = Int(b.local_addr().port)
    var pa = fork_server(a^, _bounce)
    var pb = fork_server(b^, _echo_creds)
    var got: String
    try:
        var req = Request(
            method="GET", url="http://127.0.0.1:" + String(a_port) + "/"
        )
        req.headers.set("Cookie", "sid=secret")
        req.headers.set("Proxy-Authorization", "Basic c2VjcmV0")
        req.headers.set(
            "X-Next", "http://127.0.0.1:" + String(b_port) + "/landing"
        )
        got = HttpClient().send(req^).text()
    except e:
        got = String(e)
    kill_forked_server(pa)
    kill_forked_server(pb)
    assert_equal(got, "cookie=[] proxy=[]")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
