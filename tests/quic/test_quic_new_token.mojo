"""NEW_TOKEN (RFC 9000 sec 8.1.3).

With address validation on, every connection paid a Retry round trip,
even from a client the server had just validated: no token was ever
issued, and the client could not present one. Now the server issues a
NEW_TOKEN token bound to the client's IP, a later connection presenting
it skips the Retry, and one that does not validate gets a Retry.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.quic.client import QuicClientConnection
from flare.quic.frame import NewTokenFrame, encode_new_token
from flare.quic.packet import ConnectionId
from flare.quic.retry import (
    mint_new_token,
    mint_retry_token,
    validate_new_token,
    validate_retry_token,
)
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import empty_events, handle_frame_buf, new_connection
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _b(s: String) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def test_token_is_bound_to_ip_age_and_kind() raises:
    var key = List[UInt8](length=32, fill=5)
    var t = mint_new_token(key, _b("10.0.0.1"), 1_000)
    assert_true(validate_new_token(key, t, _b("10.0.0.1"), 2_000, 10_000))
    assert_false(validate_new_token(key, t, _b("10.0.0.2"), 2_000, 10_000))
    assert_false(validate_new_token(key, t, _b("10.0.0.1"), 20_000, 10_000))
    var r = mint_retry_token(
        key, _b("10.0.0.1:5"), ConnectionId(bytes=_b("abcd")), 1_000
    )
    assert_false(validate_new_token(key, r, _b("10.0.0.1"), 2_000, 10_000))
    assert_false(
        Bool(validate_retry_token(key, t, _b("10.0.0.1"), 2_000, 10_000))
    )


def test_server_refuses_new_token() raises:
    var conn = new_connection(is_server=True)
    var f = List[UInt8]()
    encode_new_token(NewTokenFrame(_b("tok")), f)
    var events = empty_events()
    var raised = False
    try:
        _ = handle_frame_buf(conn, Span[UInt8, _](f), UInt64(0), events)
    except:
        raised = True
    assert_true(raised, "a client may not send NEW_TOKEN (sec 19.7)")


def _connect(
    mut listener: QuicListener, token: List[UInt8]
) raises -> QuicClientConnection:
    var alpn = List[String]()
    alpn.append(String("h3"))
    var quic = QuicClientConnection.start(
        listener.local_addr(),
        RustlsQuicConnector(Path(_FIXDIR + "ca.pem").read_text(), alpn^),
        String("localhost"),
        token=token,
    )
    for _ in range(60):
        _ = listener.tick(timeout_ms=10)
        _ = listener.drain_all_egress()
        _ = quic.poll(timeout_ms=10)
        if quic.is_established() and len(quic.address_token()) > 0:
            break
    assert_true(quic.is_established(), "handshake")
    return quic^


def test_a_returning_client_skips_the_retry() raises:
    var alpn = List[String]()
    alpn.append(String("h3"))
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.require_address_validation = True
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = alpn^
    var listener = QuicListener.bind(cfg^)
    var first = _connect(listener, List[UInt8]())
    assert_true(first.retried, "a first visit is validated by Retry")
    var token = first.address_token()
    assert_equal(len(token), 41)
    var again = _connect(listener, token)
    assert_false(again.retried, "the token spared the Retry")
    token[20] ^= 1
    var forged = _connect(listener, token)
    assert_true(forged.retried, "a token that does not validate gets a Retry")
    first.close()
    again.close()
    forged.close()
    listener.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
