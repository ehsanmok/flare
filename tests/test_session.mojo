"""Tests for ``flare.http.session`` (— track E).

Covers:

- ``signed_cookie_encode`` + ``signed_cookie_decode`` round-trip.
- Tampered MAC rejected.
- Tampered payload rejected.
- Multi-key decode (key rotation).
- Wrong key rejected.
- Cookie missing separator rejected.
- ``CookieSessionStore``: encode -> attach to request -> load -> match;
  short key rejected.
- ``InMemorySessionStore``: insert + load + remove + reload after
  remove.
- ``StringSessionCodec`` round-trip.
"""

from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.crypto import hmac_sha256
from flare.http import (
    CookieSessionStore,
    InMemorySessionStore,
    Method,
    Request,
    Session,
    SessionCodec,
    StringSessionCodec,
    signed_cookie_decode,
    signed_cookie_decode_keys,
    signed_cookie_encode,
)


def _bytes(s: String) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def _make_key(seed: String) raises -> List[UInt8]:
    return hmac_sha256(_bytes(seed), _bytes("flare-session-test"))


def test_signed_cookie_roundtrip() raises:
    var key = _make_key("k1")
    var payload = _bytes("hello")
    var cookie = signed_cookie_encode(payload, key)
    var got = signed_cookie_decode(cookie, key)
    assert_equal(len(got), 5)
    for i in range(5):
        assert_equal(Int(got[i]), Int(payload[i]))


def test_tampered_mac_rejected() raises:
    var key = _make_key("k1")
    var cookie = signed_cookie_encode(_bytes("hello"), key)
    var dot = -1
    for i in range(cookie.byte_length()):
        if cookie.unsafe_ptr()[i] == 46:
            dot = i
            break
    assert_true(dot > 0)
    var bad = String(unsafe_from_utf8=cookie.as_bytes()[: dot + 1])
    bad += "AAAA"
    with assert_raises():
        _ = signed_cookie_decode(bad, key)


def test_tampered_payload_rejected() raises:
    var key = _make_key("k1")
    var cookie = signed_cookie_encode(_bytes("admin"), key)
    var bad = String("XXXX") + cookie
    with assert_raises():
        _ = signed_cookie_decode(bad, key)


def test_wrong_key_rejected() raises:
    var k1 = _make_key("k1")
    var k2 = _make_key("k2")
    var cookie = signed_cookie_encode(_bytes("payload"), k1)
    with assert_raises():
        _ = signed_cookie_decode(cookie, k2)


def test_missing_separator_rejected() raises:
    var key = _make_key("k1")
    with assert_raises():
        _ = signed_cookie_decode("nopayload", key)


def test_decode_keys_rotation() raises:
    var k_old = _make_key("k_old")
    var k_new = _make_key("k_new")
    var cookie = signed_cookie_encode(_bytes("pl"), k_old)
    var keys = List[List[UInt8]]()
    keys.append(k_new.copy())
    keys.append(k_old.copy())
    var got = signed_cookie_decode_keys(cookie, keys)
    assert_equal(len(got), 2)


def test_decode_keys_no_match_raises() raises:
    var k1 = _make_key("k1")
    var k2 = _make_key("k2")
    var cookie = signed_cookie_encode(_bytes("pl"), k1)
    var keys = List[List[UInt8]]()
    keys.append(k2.copy())
    with assert_raises():
        _ = signed_cookie_decode_keys(cookie, keys)


def test_decode_keys_empty_raises() raises:
    var keys = List[List[UInt8]]()
    with assert_raises():
        _ = signed_cookie_decode_keys("foo.bar", keys)


def test_cookie_store_encode_load() raises:
    var key = _make_key("session")
    var store = CookieSessionStore(key=key, cookie_name="sid")
    var enc = store.encode("alice")
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Cookie", String("sid=") + enc)
    var s = store.load(req)
    assert_true(s.present)
    assert_equal(s.value, "alice")


def test_cookie_store_missing_returns_empty() raises:
    var store = CookieSessionStore(key=_make_key("k"))
    var req = Request(method=Method.GET, url="/")
    var s = store.load(req)
    assert_false(s.present)


def test_cookie_store_short_key_raises() raises:
    var bad_key = List[UInt8](length=8, fill=UInt8(1))
    var store = CookieSessionStore(key=bad_key)
    with assert_raises():
        _ = store.encode("oops")


def test_cookie_store_tampered_returns_empty() raises:
    var store = CookieSessionStore(key=_make_key("k"))
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Cookie", "flare_session=garbage")
    var s = store.load(req)
    assert_false(s.present)


def test_in_memory_store_insert_load() raises:
    var store = InMemorySessionStore(key=_make_key("k"))
    store.insert("sid-1", "alice")
    var enc = store.encode_id("sid-1")
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Cookie", String("flare_session=") + enc)
    var s = store.load(req)
    assert_true(s.present)
    assert_equal(s.value, "alice")


def test_in_memory_store_remove() raises:
    var store = InMemorySessionStore(key=_make_key("k"))
    store.insert("sid-1", "alice")
    var enc = store.encode_id("sid-1")
    assert_true(store.remove("sid-1"))
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Cookie", String("flare_session=") + enc)
    var s = store.load(req)
    assert_false(s.present)


def test_string_codec_roundtrip() raises:
    var enc = StringSessionCodec.encode("hello")
    assert_equal(len(enc), 5)
    var dec = StringSessionCodec.decode(enc)
    assert_equal(dec, "hello")


def main() raises:
    test_signed_cookie_roundtrip()
    test_tampered_mac_rejected()
    test_tampered_payload_rejected()
    test_wrong_key_rejected()
    test_missing_separator_rejected()
    test_decode_keys_rotation()
    test_decode_keys_no_match_raises()
    test_decode_keys_empty_raises()
    test_cookie_store_encode_load()
    test_cookie_store_missing_returns_empty()
    test_cookie_store_short_key_raises()
    test_cookie_store_tampered_returns_empty()
    test_in_memory_store_insert_load()
    test_in_memory_store_remove()
    test_string_codec_roundtrip()
    print("test_session: 15 passed")
