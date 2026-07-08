"""Unit tests for the ALPN dispatcher (``flare.http.alpn_dispatch``
scaffold).

Pins the pure decision functions that map an ALPN-negotiation
outcome to a :data:`WireProtocol` codepoint. The reactor-side
integration (mounting one ``Handler`` across h1 + h2c + h2 + h3
listeners simultaneously) ships in a focused follow-up; these
tests cover the choice that follow-up consults.
"""

from std.testing import assert_equal

from flare.http.alpn_dispatch import (
    ALPN_HTTP_1_1,
    ALPN_HTTP_2,
    ALPN_HTTP_3,
    WireProtocol,
    dispatch_alpn,
    dispatch_h2c_upgrade,
    negotiate_alpn,
    wire_protocol_name,
)


def test_wire_protocol_codepoints() raises:
    """Stable codepoints so the reactor's dispatch switch is
    monomorphic + log strings carry a fixed integer."""
    assert_equal(WireProtocol.UNKNOWN, 0)
    assert_equal(WireProtocol.HTTP_1_1, 1)
    assert_equal(WireProtocol.H2C, 2)
    assert_equal(WireProtocol.HTTP_2, 3)
    assert_equal(WireProtocol.HTTP_3, 4)


def test_dispatch_alpn_empty_falls_back_to_h1() raises:
    """Empty ALPN means the TLS handshake didn't advertise one
    (TLS 1.2 server with no ALPN extension); the server falls
    back to HTTP/1.1."""
    assert_equal(dispatch_alpn(String("")), WireProtocol.HTTP_1_1)


def test_dispatch_alpn_known_identifiers() raises:
    """The three canonical ALPN identifiers map to their wire
    codepoints exactly."""
    assert_equal(dispatch_alpn(ALPN_HTTP_1_1), WireProtocol.HTTP_1_1)
    assert_equal(dispatch_alpn(ALPN_HTTP_2), WireProtocol.HTTP_2)
    assert_equal(dispatch_alpn(ALPN_HTTP_3), WireProtocol.HTTP_3)


def test_dispatch_alpn_unknown_identifier() raises:
    """An unknown identifier maps to UNKNOWN; the reactor MUST
    close the connection with the no_application_protocol TLS
    alert (RFC 7301 §3.2)."""
    assert_equal(
        dispatch_alpn(String("h1.5-experimental")),
        WireProtocol.UNKNOWN,
    )


def test_dispatch_alpn_is_case_sensitive() raises:
    """ALPN identifiers are ASCII-case-sensitive per RFC 7301.
    Capitalised input is treated as unknown."""
    assert_equal(dispatch_alpn(String("H2")), WireProtocol.UNKNOWN)
    assert_equal(dispatch_alpn(String("HTTP/1.1")), WireProtocol.UNKNOWN)


def test_dispatch_h2c_upgrade() raises:
    """When the h1 parser sees ``Upgrade: h2c``, the wire upgrades
    to h2c; otherwise the connection stays on HTTP/1.1."""
    assert_equal(dispatch_h2c_upgrade(True), WireProtocol.H2C)
    assert_equal(dispatch_h2c_upgrade(False), WireProtocol.HTTP_1_1)


def test_negotiate_alpn_server_preference_wins() raises:
    """RFC 7301 §3.2: server preference order wins. Walking the
    server's list picks ``h2`` over ``http/1.1`` even though the
    client advertised both."""
    var client = List[String]()
    client.append(ALPN_HTTP_1_1)
    client.append(ALPN_HTTP_2)
    var server = List[String]()
    server.append(ALPN_HTTP_2)
    server.append(ALPN_HTTP_1_1)
    var pick = negotiate_alpn(client, server)
    assert_equal(pick, ALPN_HTTP_2)


def test_negotiate_alpn_h3_preferred_for_quic() raises:
    """When the server is bound on both UDP (QUIC) and TCP and
    advertises ``[h3, h2, http/1.1]``, a client that lists all
    three picks h3."""
    var client = List[String]()
    client.append(ALPN_HTTP_1_1)
    client.append(ALPN_HTTP_2)
    client.append(ALPN_HTTP_3)
    var server = List[String]()
    server.append(ALPN_HTTP_3)
    server.append(ALPN_HTTP_2)
    server.append(ALPN_HTTP_1_1)
    var pick = negotiate_alpn(client, server)
    assert_equal(pick, ALPN_HTTP_3)


def test_negotiate_alpn_no_overlap_returns_empty() raises:
    """When the client and server share no protocol identifier,
    negotiate returns the empty string and the caller must
    surface a TLS no_application_protocol alert."""
    var client = List[String]()
    client.append(String("h1.5-experimental"))
    var server = List[String]()
    server.append(ALPN_HTTP_2)
    server.append(ALPN_HTTP_1_1)
    var pick = negotiate_alpn(client, server)
    assert_equal(pick, String(""))


def test_negotiate_alpn_empty_inputs() raises:
    """Both lists empty -> empty result; the TLS layer never
    reached negotiation (no ALPN extension on either side)."""
    var client = List[String]()
    var server = List[String]()
    var pick = negotiate_alpn(client, server)
    assert_equal(pick, String(""))


def test_wire_protocol_name() raises:
    """The string form of every wire codepoint is stable for
    structured logs + metrics labels."""
    assert_equal(wire_protocol_name(WireProtocol.HTTP_1_1), String("HTTP/1.1"))
    assert_equal(wire_protocol_name(WireProtocol.H2C), String("h2c"))
    assert_equal(wire_protocol_name(WireProtocol.HTTP_2), String("HTTP/2"))
    assert_equal(wire_protocol_name(WireProtocol.HTTP_3), String("HTTP/3"))
    assert_equal(wire_protocol_name(WireProtocol.UNKNOWN), String("unknown"))
    assert_equal(wire_protocol_name(9999), String("unknown"))


def main() raises:
    test_wire_protocol_codepoints()
    test_dispatch_alpn_empty_falls_back_to_h1()
    test_dispatch_alpn_known_identifiers()
    test_dispatch_alpn_unknown_identifier()
    test_dispatch_alpn_is_case_sensitive()
    test_dispatch_h2c_upgrade()
    test_negotiate_alpn_server_preference_wins()
    test_negotiate_alpn_h3_preferred_for_quic()
    test_negotiate_alpn_no_overlap_returns_empty()
    test_negotiate_alpn_empty_inputs()
    test_wire_protocol_name()
    print("test_alpn_dispatch: 11 passed")
