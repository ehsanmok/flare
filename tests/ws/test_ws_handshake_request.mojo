"""The standalone WebSocket server checks the whole opening handshake (WS-05).

RFC 6455 sec 4.2.1: the request is a ``GET`` over HTTP/1.1 with an
``Upgrade`` field containing ``websocket``, a ``Connection`` field with the
token ``upgrade``, a ``Sec-WebSocket-Key`` that is base64 of 16 bytes and a
``Sec-WebSocket-Version`` of 13; sec 11.3.1 / 11.3.5 allow the key and
version fields once. Sec 4.2.2 point 4: another version gets 426 with the
version the server speaks. Only the Upgrade value and a non-empty key used
to be checked, with ``Connection`` matched as a substring.

The reactor applies the same rule through ``_ws_handshake_problem``
(WS-07, tests/http/test_server_ws_upgrade.mojo).
"""

from std.testing import assert_equal, assert_false, assert_true, TestSuite

from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.ws import WsConnection
from flare.ws.server import (
    _WsUpgradeRequest,
    _handle_ws_connection,
    _parse_ws_upgrade_bytes,
    _read_upgrade_request,
    _ws_handshake_problem,
)

comptime _KEY = "dGhlIHNhbXBsZSBub25jZQ=="


def _request(
    method: String = "GET",
    version: String = "HTTP/1.1",
    upgrade: String = "Upgrade: websocket\r\n",
    connection: String = "Connection: Upgrade\r\n",
    key: String = "Sec-WebSocket-Key: " + _KEY + "\r\n",
    ws_version: String = "Sec-WebSocket-Version: 13\r\n",
) -> String:
    return (
        method
        + " /chat "
        + version
        + "\r\nHost: localhost\r\n"
        + upgrade
        + connection
        + key
        + ws_version
        + "\r\n"
    )


def _parses(raw: String) -> Bool:
    var b = List[UInt8](raw.as_bytes())
    try:
        _ = _parse_ws_upgrade_bytes(Span[UInt8, _](b))
        return True
    except:
        return False


def _why(raw: String) -> String:
    var b = List[UInt8](raw.as_bytes())
    try:
        _ = _parse_ws_upgrade_bytes(Span[UInt8, _](b))
    except e:
        return String(e)
    return ""


def test_rfc_example_request_is_accepted() raises:
    assert_true(_parses(_request()))
    var b = List[UInt8](_request().as_bytes())
    var up = _parse_ws_upgrade_bytes(Span[UInt8, _](b))
    assert_equal(up.key, _KEY)


def test_valid_variants_are_accepted() raises:
    # Field names and tokens are case-insensitive; Connection is a list.
    assert_true(
        _parses(
            _request(
                upgrade="UPGRADE: WebSocket\r\n",
                connection="connection: keep-alive, UPGRADE\r\n",
            )
        )
    )
    # Upgrade is a list too.
    assert_true(_parses(_request(upgrade="Upgrade: foo, websocket\r\n")))
    # Base64 of 16 bytes without padding is still base64 of 16 bytes.
    assert_true(
        _parses(_request(key="Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ\r\n"))
    )


def test_non_get_and_http10_are_refused() raises:
    assert_false(_parses(_request(method="POST")))
    assert_false(_parses(_request(version="HTTP/1.0")))
    assert_false(_parses(_request(version="HTTP/1.2")))


def test_connection_is_matched_as_a_token_not_a_substring() raises:
    assert_false(_parses(_request(connection="Connection: noupgrade\r\n")))
    assert_false(_parses(_request(connection="Connection: upgrades\r\n")))
    assert_false(_parses(_request(connection="Connection: keep-alive\r\n")))
    assert_true(
        _parses(_request(connection="Connection: keep-alive,upgrade\r\n"))
    )


def test_key_must_be_base64_of_16_bytes() raises:
    assert_false(_parses(_request(key="Sec-WebSocket-Key: x\r\n")))
    assert_false(_parses(_request(key="Sec-WebSocket-Key: \r\n")))
    # 15 and 17 bytes of base64.
    assert_false(
        _parses(_request(key="Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAA\r\n"))
    )
    assert_false(
        _parses(
            _request(key="Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAAAAAA==\r\n")
        )
    )
    assert_false(
        _parses(_request(key="Sec-WebSocket-Key: not base64 at all!!\r\n"))
    )
    assert_false(_parses(_request(key="")))


def test_key_and_version_fields_may_appear_once() raises:
    var other = "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n"
    assert_false(
        _parses(_request(key="Sec-WebSocket-Key: " + _KEY + "\r\n" + other))
    )
    assert_false(
        _parses(
            _request(
                ws_version=(
                    "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13\r\n"
                )
            )
        )
    )


def test_version_must_be_13() raises:
    assert_false(_parses(_request(ws_version="")))
    assert_false(_parses(_request(ws_version="Sec-WebSocket-Version: 8\r\n")))
    assert_false(_parses(_request(ws_version="Sec-WebSocket-Version: 130\r\n")))
    assert_true(_parses(_request(ws_version="Sec-WebSocket-Version:  13 \r\n")))
    assert_true(
        "unsupported Sec-WebSocket-Version"
        in _why(_request(ws_version="Sec-WebSocket-Version: 8\r\n"))
    )


def test_shared_rule_is_a_pure_function_of_the_fields() raises:
    """The reactor calls this with ``HeaderMap`` values (WS-07)."""
    var up = List[String]()
    up.append("websocket")
    var cn = List[String]()
    cn.append("keep-alive, Upgrade")
    var ks = List[String]()
    ks.append(_KEY)
    var vs = List[String]()
    vs.append("13")
    assert_equal(_ws_handshake_problem("GET", "HTTP/1.1", up, cn, ks, vs), "")
    assert_true(_ws_handshake_problem("POST", "HTTP/1.1", up, cn, ks, vs) != "")
    var bad_cn = List[String]()
    bad_cn.append("noupgrade")
    assert_true(
        _ws_handshake_problem("GET", "HTTP/1.1", up, bad_cn, ks, vs) != ""
    )


def _rejection(raw: String) raises -> String:
    """Feed ``raw`` to the real connection path; return what the client sees."""
    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(SocketAddr.localhost(ln.local_addr().port))
    client.set_recv_timeout(3000)
    var server = ln.accept()
    ln.close()
    client.write_all(raw.as_bytes())
    var peer = server.peer_addr()

    def never(mut conn: WsConnection) raises -> None:
        raise Error("handler must not run for a refused handshake")

    _handle_ws_connection(server^, peer, never)
    var got = List[UInt8]()
    var buf = List[UInt8](capacity=1024)
    buf.resize(1024, 0)
    while True:
        var n = client.read(buf.unsafe_ptr(), 1024)
        if n <= 0:
            break
        for i in range(n):
            got.append(buf[i])
    return String(unsafe_from_utf8=Span[UInt8, _](got))


def test_unsupported_version_gets_426_and_other_refusals_400() raises:
    var v8 = _rejection(_request(ws_version="Sec-WebSocket-Version: 8\r\n"))
    assert_true(v8.startswith("HTTP/1.1 426"), v8)
    assert_true("Sec-WebSocket-Version: 13" in v8, v8)
    var bad_key = _rejection(_request(key="Sec-WebSocket-Key: x\r\n"))
    assert_true(bad_key.startswith("HTTP/1.1 400"), bad_key)
    var post = _rejection(_request(method="POST"))
    assert_true(post.startswith("HTTP/1.1 400"), post)
    assert_false("101" in post)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
