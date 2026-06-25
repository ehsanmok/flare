"""H3C-3: HttpClient HTTP/3 discovery + wire-policy surface.

Exercises the transparent-upgrade decision surface on
:class:`flare.http.HttpClient`: the ``prefer_h3`` knob (the
constructor kwarg or the :meth:`with_prefer_h3` builder), the
``Alt-Svc`` discovery cache
(:meth:`record_alt_svc`), and the per-request decision
(:meth:`h3_wire_choice`). No network I/O -- the policy is pure over
the client's cached state.
"""

from std.testing import assert_equal

from flare.http._client.alt_svc import H3WireChoice
from flare.http.client import HttpClient


def test_default_no_h3() raises:
    var c = HttpClient()
    assert_equal(
        c.h3_wire_choice(String("https"), String("example.com"), UInt16(443)),
        H3WireChoice.HTTP_2_OR_LOWER,
    )


def test_prefer_h3_knob() raises:
    var c = HttpClient().with_prefer_h3()
    assert_equal(
        c.h3_wire_choice(String("https"), String("example.com"), UInt16(443)),
        H3WireChoice.HTTP_3,
    )
    # cleartext is never h3 even with the knob on
    assert_equal(
        c.h3_wire_choice(String("http"), String("example.com"), UInt16(80)),
        H3WireChoice.HTTP_2_OR_LOWER,
    )


def test_prefer_h3_ctor_kwarg() raises:
    # The constructor kwarg is the ergonomic equivalent of the
    # with_prefer_h3() builder (mirrors prefer_h2c): same wire choice,
    # cleartext still never rides h3.
    var c = HttpClient(String("https://example.com"), prefer_h3=True)
    assert_equal(
        c.h3_wire_choice(String("https"), String("example.com"), UInt16(443)),
        H3WireChoice.HTTP_3,
    )
    assert_equal(
        c.h3_wire_choice(String("http"), String("example.com"), UInt16(80)),
        H3WireChoice.HTTP_2_OR_LOWER,
    )


def test_alt_svc_advert_upgrades() raises:
    var c = HttpClient()
    c.record_alt_svc(String("example.com:443"), String('h3=":443"; ma=3600'))
    assert_equal(
        c.h3_wire_choice(String("https"), String("example.com"), UInt16(443)),
        H3WireChoice.HTTP_3,
    )
    # a different origin is unaffected
    assert_equal(
        c.h3_wire_choice(String("https"), String("other.com"), UInt16(443)),
        H3WireChoice.HTTP_2_OR_LOWER,
    )


def test_alt_svc_clear_evicts() raises:
    var c = HttpClient()
    c.record_alt_svc(String("example.com:443"), String('h3=":443"; ma=3600'))
    c.record_alt_svc(String("example.com:443"), String("clear"))
    assert_equal(
        c.h3_wire_choice(String("https"), String("example.com"), UInt16(443)),
        H3WireChoice.HTTP_2_OR_LOWER,
    )


def main() raises:
    test_default_no_h3()
    test_prefer_h3_knob()
    test_prefer_h3_ctor_kwarg()
    test_alt_svc_advert_upgrades()
    test_alt_svc_clear_evicts()
    print("test_client_h3_policy: 5 passed")
