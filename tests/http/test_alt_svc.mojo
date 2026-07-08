"""Alt-Svc parser + per-origin cache + h3 wire policy.

Covers the RFC 7838 parser (single + multi advert, params, quoted
authority, same-host shorthand, ``clear``, malformed-skip), the
per-origin cache (record / fresh / expired / clear eviction), and
the pure :func:`decide_h3_wire` policy table.
"""

from std.collections import List
from std.testing import assert_equal, assert_false, assert_true

from flare.http._client.alt_svc import (
    AltSvcCache,
    H3WireChoice,
    decide_h3_wire,
    parse_alt_svc,
)


def test_parse_single_h3() raises:
    var p = parse_alt_svc(String('h3=":443"; ma=86400'))
    assert_false(p.cleared)
    assert_equal(len(p.entries), 1)
    assert_equal(p.entries[0].protocol, String("h3"))
    assert_equal(p.entries[0].host, String(""))
    assert_equal(Int(p.entries[0].port), 443)
    assert_equal(Int(p.entries[0].max_age), 86400)


def test_parse_multi_advert() raises:
    var p = parse_alt_svc(String('h3=":443"; ma=3600, h2=":443"; ma=7200'))
    assert_equal(len(p.entries), 2)
    assert_equal(p.entries[0].protocol, String("h3"))
    assert_equal(p.entries[1].protocol, String("h2"))
    assert_equal(Int(p.entries[1].max_age), 7200)


def test_parse_explicit_host() raises:
    var p = parse_alt_svc(String('h3="alt.example.net:8443"'))
    assert_equal(len(p.entries), 1)
    assert_equal(p.entries[0].host, String("alt.example.net"))
    assert_equal(Int(p.entries[0].port), 8443)
    # default max-age when ma omitted (RFC 7838 §3.1)
    assert_equal(Int(p.entries[0].max_age), 86400)


def test_parse_clear() raises:
    var p = parse_alt_svc(String("clear"))
    assert_true(p.cleared)
    assert_equal(len(p.entries), 0)


def test_parse_skips_malformed() raises:
    # First alt-value has no '=', must be skipped; second is valid.
    var p = parse_alt_svc(String('garbage, h3=":443"'))
    assert_equal(len(p.entries), 1)
    assert_equal(p.entries[0].protocol, String("h3"))


def test_cache_record_and_fresh() raises:
    var c = AltSvcCache.new()
    c.record(String("example.com:443"), String('h3=":443"; ma=100'), UInt64(0))
    assert_true(c.has_fresh_h3(String("example.com:443"), UInt64(50)))
    var ep = c.h3_endpoint(String("example.com:443"), UInt64(50))
    assert_true(Bool(ep))
    assert_equal(ep.value()[0], String("example.com"))
    assert_equal(Int(ep.value()[1]), 443)


def test_cache_expiry() raises:
    var c = AltSvcCache.new()
    c.record(String("example.com:443"), String('h3=":443"; ma=100'), UInt64(0))
    assert_false(c.has_fresh_h3(String("example.com:443"), UInt64(100)))
    assert_false(c.has_fresh_h3(String("example.com:443"), UInt64(200)))


def test_cache_clear_evicts() raises:
    var c = AltSvcCache.new()
    c.record(String("example.com:443"), String('h3=":443"; ma=100'), UInt64(0))
    assert_true(c.has_fresh_h3(String("example.com:443"), UInt64(10)))
    c.record(String("example.com:443"), String("clear"), UInt64(20))
    assert_false(c.has_fresh_h3(String("example.com:443"), UInt64(30)))


def test_cache_ignores_non_h3() raises:
    var c = AltSvcCache.new()
    c.record(String("example.com:443"), String('h2=":443"; ma=100'), UInt64(0))
    assert_false(c.has_fresh_h3(String("example.com:443"), UInt64(10)))


def test_decide_policy_table() raises:
    # https + prefer -> h3
    assert_equal(
        decide_h3_wire(String("https"), True, False, True),
        H3WireChoice.HTTP_3,
    )
    # https + cached advert -> h3
    assert_equal(
        decide_h3_wire(String("https"), False, True, True),
        H3WireChoice.HTTP_3,
    )
    # https, no pref/advert -> lower
    assert_equal(
        decide_h3_wire(String("https"), False, False, True),
        H3WireChoice.HTTP_2_OR_LOWER,
    )
    # cleartext never h3
    assert_equal(
        decide_h3_wire(String("http"), True, True, True),
        H3WireChoice.HTTP_2_OR_LOWER,
    )
    # quic unavailable never h3
    assert_equal(
        decide_h3_wire(String("https"), True, True, False),
        H3WireChoice.HTTP_2_OR_LOWER,
    )


def main() raises:
    test_parse_single_h3()
    test_parse_multi_advert()
    test_parse_explicit_host()
    test_parse_clear()
    test_parse_skips_malformed()
    test_cache_record_and_fresh()
    test_cache_expiry()
    test_cache_clear_evicts()
    test_cache_ignores_non_h3()
    test_decide_policy_table()
    print("test_alt_svc: 10 passed")
