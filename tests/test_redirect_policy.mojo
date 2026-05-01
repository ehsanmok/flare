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
    """https → http is treated as cross-origin (different scheme
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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
