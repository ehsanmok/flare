"""``WsClient.connect`` checks the whole 101 (WS-04).

RFC 6455 sec 4.1: the client MUST fail the connection unless the response
has ``Upgrade: websocket``, a ``Connection`` field with the ``upgrade``
token and the right ``Sec-WebSocket-Accept``, and names no subprotocol or
extension that the request did not offer. The request offers the caller's
subprotocols (issue #49) and the client exposes the one the server picked.

Each case forks a raw server on an ephemeral loopback port that answers
the upgrade request with a scripted 101.
"""

from std.testing import assert_equal, assert_false, assert_true, TestSuite

from flare.net import SocketAddr
from flare.tcp import TcpListener
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.tls import TlsConfig
from flare.ws import WsAutoClient, WsAutoClientConfig
from flare.ws.client import WsClient, _UpgradeResponse, _subprotocol_header
from flare.ws.server import _compute_accept_srv

comptime _GOOD = "Upgrade: websocket\r\nConnection: Upgrade\r\n"
comptime _ECHO = "{echo}"
"""``fields`` marker: select the first offered subprotocol."""


def _serve(var lis: TcpListener, fields: String, good_accept: Bool):
    """Child: read the request, answer 101 with ``fields`` + the accept."""
    try:
        var s = lis.accept()
        var got = List[UInt8]()
        var tmp = List[UInt8](capacity=4096)
        tmp.resize(4096, 0)
        while True:
            var n = s.read(tmp.unsafe_ptr(), 4096)
            if n == 0:
                break
            for i in range(n):
                got.append(tmp[i])
            var done = False
            for i in range(3, len(got)):
                if (
                    got[i - 3] == 13
                    and got[i - 2] == 10
                    and got[i - 1] == 13
                    and got[i] == 10
                ):
                    done = True
            if done:
                break
        var req = String(unsafe_from_utf8=Span[UInt8, _](got))
        var key = String("")
        var offered = String("")
        for line in req.split("\r\n"):
            var l = String(line)
            if l.lower().startswith("sec-websocket-key:"):
                key = String(String(l[byte=18:]).strip())
            if l.lower().startswith("sec-websocket-protocol:"):
                offered = String(String(l[byte=23:]).strip())
        var hdrs = fields
        if hdrs == _ECHO:
            hdrs = String(_GOOD)
            if offered.byte_length() > 0:
                hdrs += (
                    "Sec-WebSocket-Protocol: "
                    + String(String(offered.split(",")[0]).strip())
                    + "\r\n"
                )
        var accept = _compute_accept_srv(key)
        if not good_accept:
            accept = "AAAAAAAAAAAAAAAAAAAAAAAAAAA="
        var resp = (
            String("HTTP/1.1 101 Switching Protocols\r\n")
            + hdrs
            + "Sec-WebSocket-Accept: "
            + accept
            + "\r\n\r\n"
        )
        s.write_all(resp.as_bytes())
        usleep(2_000_000)
        _ = s^
    except:
        pass
    exit()


def _connect(
    fields: String,
    good_accept: Bool = True,
    offered: List[String] = List[String](),
    auto: Bool = False,
) raises -> String:
    """ "connected" (plus ":<subprotocol>" when one was offered), or the
    error text the client raised."""
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var pid = fork()
    if pid == 0:
        _serve(lis^, fields, good_accept)
    var url = "ws://127.0.0.1:" + String(Int(port)) + "/"
    var out: String
    try:
        var picked: String
        if auto:
            var cfg = WsAutoClientConfig()
            cfg.url = url
            cfg.subprotocols = offered.copy()
            var a = WsAutoClient(cfg^)
            a.connect()
            picked = a.subprotocol
        else:
            var c = WsClient.connect(url, TlsConfig(), offered)
            picked = c.subprotocol
            _ = c^
        out = "connected"
        if len(offered) > 0:
            out += ":" + picked
    except e:
        out = String(e)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    return out


def test_complete_101_connects() raises:
    assert_equal(_connect(_GOOD), "connected")


def test_field_names_and_values_are_case_insensitive() raises:
    assert_equal(
        _connect("UPGRADE: WebSocket\r\nconnection: keep-alive, UPGRADE\r\n"),
        "connected",
    )


def test_101_without_upgrade_is_refused() raises:
    var err = _connect("Connection: Upgrade\r\n")
    assert_true("Upgrade: websocket" in err, err)


def test_101_with_another_upgrade_protocol_is_refused() raises:
    var err = _connect("Upgrade: h2c\r\nConnection: Upgrade\r\n")
    assert_true("Upgrade: websocket" in err, err)


def test_101_without_connection_upgrade_is_refused() raises:
    var err = _connect("Upgrade: websocket\r\n")
    assert_true("Connection" in err, err)
    var err2 = _connect("Upgrade: websocket\r\nConnection: keep-alive\r\n")
    assert_true("Connection" in err2, err2)


def test_101_with_an_unrequested_subprotocol_is_refused() raises:
    var err = _connect(_GOOD + "Sec-WebSocket-Protocol: chat\r\n")
    assert_true("subprotocol" in err, err)


def test_offered_subprotocol_is_sent_and_selected() raises:
    var offered: List[String] = [String("rex.control.v1"), String("b")]
    assert_equal(_connect(_ECHO, offered=offered), "connected:rex.control.v1")


def test_autoclient_offers_config_subprotocols() raises:
    var offered: List[String] = [String("rex.control.v1")]
    assert_equal(
        _connect(_ECHO, offered=offered, auto=True),
        "connected:rex.control.v1",
    )


def test_server_may_select_no_subprotocol() raises:
    assert_equal(_connect(_GOOD, offered=[String("a")]), "connected:")


def test_101_selecting_an_unoffered_subprotocol_is_refused() raises:
    var err = _connect(
        _GOOD + "Sec-WebSocket-Protocol: b\r\n", offered=[String("a")]
    )
    assert_true("subprotocol" in err, err)


def test_101_selecting_a_list_or_repeated_field_is_refused() raises:
    var offered: List[String] = [String("a"), String("b")]
    var err = _connect(
        _GOOD + "Sec-WebSocket-Protocol: a, b\r\n", offered=offered
    )
    assert_true("subprotocol" in err, err)
    var err2 = _connect(
        _GOOD + "Sec-WebSocket-Protocol: a\r\nSec-WebSocket-Protocol: a\r\n",
        offered=offered,
    )
    assert_true("subprotocol" in err2, err2)


def test_invalid_subprotocol_candidates_are_refused() raises:
    assert_equal(_subprotocol_header(List[String]()), "")
    assert_equal(_subprotocol_header([String("a"), String("b.v1")]), "a, b.v1")
    var bads: List[List[String]] = [
        [String("")],
        [String("a b")],
        [String("a\r\nX-Evil: 1")],
        [String("a,b")],
        [String("a"), String("a")],
    ]
    for bad in bads:
        var raised = False
        try:
            _ = _subprotocol_header(bad)
        except:
            raised = True
        assert_true(raised)
    # Refused before any I/O: nothing listens on port 1.
    var err: String
    try:
        _ = WsClient.connect("ws://127.0.0.1:1/", TlsConfig(), [String("a b")])
        err = "connected"
    except e:
        err = String(e)
    assert_true("not a token" in err, err)


def test_selected_protocol_matches_offer_exactly() raises:
    var r = _UpgradeResponse()
    r.observe("sec-websocket-protocol", "Chat")
    var raised = False
    try:
        _ = r.selected_protocol([String("chat")])
    except:
        raised = True
    assert_true(raised)
    assert_equal(r.selected_protocol([String("x"), String("Chat")]), "Chat")


def test_101_with_an_unrequested_extension_is_refused() raises:
    var err = _connect(
        _GOOD + "Sec-WebSocket-Extensions: permessage-deflate\r\n"
    )
    assert_true("extension" in err, err)


def test_101_with_a_wrong_accept_is_still_refused() raises:
    var err = _connect(_GOOD, False)
    assert_true("Sec-WebSocket-Accept mismatch" in err, err)


def test_upgrade_response_records_fields() raises:
    var r = _UpgradeResponse()
    r.observe("upgrade", "websocket")
    r.observe("connection", "keep-alive, upgrade")
    r.observe("sec-websocket-accept", "abc")
    assert_equal(r.verify("abc", List[String]()), "")
    # Only the exact token counts: "upgrades" or "websocket2" do not.
    var bad = _UpgradeResponse()
    bad.observe("upgrade", "websocket2")
    bad.observe("connection", "upgrades")
    bad.observe("sec-websocket-accept", "abc")
    assert_false(bad.upgrade_websocket)
    assert_false(bad.connection_upgrade)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
