"""Unit tests for the client-side 0-RTT safety gate.

The 0-RTT replay hazard (RFC 9001 sec 9.2) means an attacker can
re-send a captured early-data flight, so the client must only ever let
an *idempotent* request ride 0-RTT. These tests pin the gate
(:func:`flare.http3.is_idempotent_method`) and the outcome carrier
(:class:`flare.http3.Http3ZeroRttOutcome`) that
:meth:`Http3ClientConnection.fetch_0rtt` returns.

The end-to-end emission path is covered by the H3 client e2e harness;
here we lock down the security-critical classification in isolation so
a future edit cannot silently make POST 0-RTT-eligible.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.http3 import Http3ZeroRttOutcome, is_idempotent_method
from flare.http3.response_reader import Http3Response
from flare.qpack import QpackHeader


def _empty_response() -> Http3Response:
    return Http3Response(
        200, List[QpackHeader](), List[UInt8](), List[QpackHeader]()
    )


def test_idempotent_methods_eligible() raises:
    assert_true(is_idempotent_method(String("GET")))
    assert_true(is_idempotent_method(String("HEAD")))
    assert_true(is_idempotent_method(String("OPTIONS")))
    assert_true(is_idempotent_method(String("PUT")))
    assert_true(is_idempotent_method(String("DELETE")))
    assert_true(is_idempotent_method(String("TRACE")))


def test_non_idempotent_methods_excluded() raises:
    # A replay could double a side effect: never 0-RTT-eligible.
    assert_false(is_idempotent_method(String("POST")))
    assert_false(is_idempotent_method(String("PATCH")))
    assert_false(is_idempotent_method(String("CONNECT")))


def test_method_classification_case_insensitive() raises:
    assert_true(is_idempotent_method(String("get")))
    assert_true(is_idempotent_method(String("Get")))
    assert_false(is_idempotent_method(String("post")))


def test_outcome_carrier_fields() raises:
    var accepted = Http3ZeroRttOutcome(
        _empty_response(), used_0rtt=True, replayed=False
    )
    assert_true(accepted.used_0rtt)
    assert_false(accepted.replayed)

    var rejected = Http3ZeroRttOutcome(
        _empty_response(), used_0rtt=False, replayed=True
    )
    assert_false(rejected.used_0rtt)
    assert_true(rejected.replayed)


def main() raises:
    test_idempotent_methods_eligible()
    test_non_idempotent_methods_excluded()
    test_method_classification_case_insensitive()
    test_outcome_carrier_fields()
    print("test_h3_0rtt_gate: 4 passed")
