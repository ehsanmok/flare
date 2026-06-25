"""Unit tests for the interior-mutable client cookie store (W1).

Exercises :class:`flare.http._client.cookie_store.CookieStore` in
isolation (no network): the empty/no-op handle, record + replay,
multi-cookie ordering, the RFC 6265 ``Max-Age=0`` delete directive,
and same-name overwrite.
"""

from std.testing import assert_equal, assert_true

from flare.http._client.cookie_store import CookieStore


def test_disabled_is_noop() raises:
    var s = CookieStore.disabled()
    assert_true(not s.enabled())
    s.record_set_cookie("sid=abc")  # no-op on the empty handle
    assert_equal(s.count(), 0)
    assert_equal(s.request_header(), "")


def test_record_and_replay() raises:
    var s = CookieStore.new()
    assert_true(s.enabled())
    s.record_set_cookie("sid=abc123; Path=/; HttpOnly")
    assert_equal(s.count(), 1)
    assert_equal(s.request_header(), "sid=abc123")
    s.free()


def test_multiple_cookies_replay_in_order() raises:
    var s = CookieStore.new()
    s.record_set_cookie("a=1; Path=/")
    s.record_set_cookie("b=2; Path=/")
    assert_equal(s.count(), 2)
    assert_equal(s.request_header(), "a=1; b=2")
    s.free()


def test_max_age_zero_deletes() raises:
    var s = CookieStore.new()
    s.record_set_cookie("sid=abc; Max-Age=3600")
    assert_equal(s.count(), 1)
    s.record_set_cookie("sid=abc; Max-Age=0")  # RFC 6265 delete directive
    assert_equal(s.count(), 0)
    assert_equal(s.request_header(), "")
    s.free()


def test_overwrite_same_name() raises:
    var s = CookieStore.new()
    s.record_set_cookie("sid=old")
    s.record_set_cookie("sid=new")
    assert_equal(s.count(), 1)
    assert_equal(s.request_header(), "sid=new")
    s.free()


def test_unparseable_set_cookie_ignored() raises:
    var s = CookieStore.new()
    s.record_set_cookie("")  # empty name -> ignored
    assert_equal(s.count(), 0)
    s.free()


def main() raises:
    test_disabled_is_noop()
    test_record_and_replay()
    test_multiple_cookies_replay_in_order()
    test_max_age_zero_deletes()
    test_overwrite_same_name()
    test_unparseable_set_cookie_ignored()
    print("test_cookie_store: 6 passed")
