"""Unit tests for the interior-mutable client cookie store.

Exercises :class:`flare.http._client.cookie_store.CookieStore` in
isolation (no network): the empty/no-op handle, record + replay,
multi-cookie ordering, the RFC 6265 ``Max-Age=0`` delete directive,
and same-name overwrite.
"""

from std.testing import assert_equal, assert_true

from flare.http._client.cookie_store import CookieStore

comptime _U = "https://app.example.com/"


def test_disabled_is_noop() raises:
    var s = CookieStore.disabled()
    assert_true(not s.enabled())
    s.record_set_cookie("sid=abc", _U)  # no-op on the empty handle
    assert_equal(s.count(), 0)
    assert_equal(s.request_header(_U), "")


def test_record_and_replay() raises:
    var s = CookieStore.new()
    assert_true(s.enabled())
    s.record_set_cookie("sid=abc123; Path=/; HttpOnly", _U)
    assert_equal(s.count(), 1)
    assert_equal(s.request_header(_U), "sid=abc123")
    s.free()


def test_multiple_cookies_replay_in_order() raises:
    var s = CookieStore.new()
    s.record_set_cookie("a=1; Path=/", _U)
    s.record_set_cookie("b=2; Path=/", _U)
    assert_equal(s.count(), 2)
    assert_equal(s.request_header(_U), "a=1; b=2")
    s.free()


def test_max_age_zero_deletes() raises:
    var s = CookieStore.new()
    s.record_set_cookie("sid=abc; Max-Age=3600", _U)
    assert_equal(s.count(), 1)
    s.record_set_cookie("sid=abc; Max-Age=0", _U)  # RFC 6265 delete directive
    assert_equal(s.count(), 0)
    assert_equal(s.request_header(_U), "")
    s.free()


def test_overwrite_same_name() raises:
    var s = CookieStore.new()
    s.record_set_cookie("sid=old", _U)
    s.record_set_cookie("sid=new", _U)
    assert_equal(s.count(), 1)
    assert_equal(s.request_header(_U), "sid=new")
    s.free()


def test_unparseable_set_cookie_ignored() raises:
    var s = CookieStore.new()
    s.record_set_cookie("", _U)  # empty name -> ignored
    assert_equal(s.count(), 0)
    s.free()


# ── RFC 6265 scoping: domain, path, Secure ─────────────────────────────────


def test_host_only_cookie_is_not_sent_to_another_host() raises:
    var s = CookieStore.new()
    s.record_set_cookie("sid=a", "https://api.example.com/login")
    assert_equal(s.request_header("https://api.example.com/x"), "sid=a")
    assert_equal(s.request_header("https://evil.com/x"), "")
    assert_equal(s.request_header("https://www.example.com/x"), "")
    s.free()


def test_domain_cookie_covers_subdomains_only() raises:
    var s = CookieStore.new()
    s.record_set_cookie("t=1; Domain=.example.com", "https://api.example.com/")
    assert_equal(s.request_header("https://www.example.com/"), "t=1")
    assert_equal(s.request_header("https://example.com/"), "t=1")
    assert_equal(s.request_header("https://notexample.com/"), "")
    s.free()


def test_cookie_for_a_foreign_domain_is_refused() raises:
    """evil.com cannot plant a cookie for api.example.com."""
    var s = CookieStore.new()
    s.record_set_cookie("sid=attacker; Domain=example.com", "https://evil.com/")
    assert_equal(s.count(), 0)
    s.free()


def test_secure_cookie_needs_https_both_ways() raises:
    var s = CookieStore.new()
    s.record_set_cookie("s=1; Secure", "http://app.example.com/")
    assert_equal(s.count(), 0)
    s.record_set_cookie("s=1; Secure", "https://app.example.com/")
    assert_equal(s.request_header("http://app.example.com/"), "")
    assert_equal(s.request_header("https://app.example.com/"), "s=1")
    s.free()


def test_path_scoping() raises:
    var s = CookieStore.new()
    s.record_set_cookie("p=1; Path=/admin", "https://app.example.com/")
    assert_equal(s.request_header("https://app.example.com/admin/users"), "p=1")
    assert_equal(s.request_header("https://app.example.com/administrator"), "")
    assert_equal(s.request_header("https://app.example.com/"), "")
    s.free()


def main() raises:
    test_disabled_is_noop()
    test_record_and_replay()
    test_multiple_cookies_replay_in_order()
    test_max_age_zero_deletes()
    test_overwrite_same_name()
    test_unparseable_set_cookie_ignored()
    test_host_only_cookie_is_not_sent_to_another_host()
    test_domain_cookie_covers_subdomains_only()
    test_cookie_for_a_foreign_domain_is_refused()
    test_secure_cookie_needs_https_both_ways()
    test_path_scoping()
    print("test_cookie_store: 11 passed")
