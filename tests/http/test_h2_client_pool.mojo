"""``HttpClient`` reuses one HTTP/2 connection per origin.

Every h2 request (h2c prior knowledge, and ALPN h2 over TLS) used to
dial a fresh connection, handshake, and GOAWAY it after one response;
the gRPC client inherited that. The server echoes the client's source
port, so sequential requests on a pooled connection report one port.
"""

from std.testing import TestSuite, assert_equal, assert_true

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import IpAddr, SocketAddr
from flare.testing import fork_server, kill_forked_server
from flare.tls import TlsConfig


def _port_echo(req: Request) raises -> Response:
    var r = ok(String(req.peer.port))
    if req.url.endswith("/big"):
        r.body = List[UInt8](length=200_000, fill=UInt8(0x62))
    return r^


def _alpn_h2() -> List[String]:
    var a = List[String]()
    a.append("h2")
    a.append("http/1.1")
    return a^


def test_h2c_requests_share_one_connection() raises:
    var srv = HttpServer.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var port = srv.local_addr().port
    var pid = fork_server(srv^, _port_echo)
    var client = HttpClient(prefer_h2c=True)
    var url = String("http://127.0.0.1:") + String(port) + "/"
    var first = client.get(url).text()
    var same = 0
    for _ in range(9):
        if client.get(url).text() == first:
            same += 1
    # A 200 KB body ten times over: the connection's receive window is
    # replenished, so a pooled connection does not stall.
    var big = 0
    for _ in range(10):
        big += len(client.get(url + "big").body)
    kill_forked_server(pid)
    assert_equal(same, 9, "requests were spread over new connections")
    assert_equal(big, 2_000_000)


def test_h2_over_tls_requests_share_one_connection() raises:
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        "tests/certs/server.crt",
        "tests/certs/server.key",
        alpn=_alpn_h2(),
    )
    var port = srv.local_addr().port
    var pid = fork_server(srv^, _port_echo)
    var client = HttpClient(TlsConfig(ca_bundle="tests/certs/ca.crt"))
    var url = String("https://localhost:") + String(port) + "/"
    var first = client.get(url).text()
    var same = 0
    for _ in range(9):
        if client.get(url).text() == first:
            same += 1
    kill_forked_server(pid)
    assert_equal(same, 9)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
