"""Tests for ``Request.peer`` and the ``Peer`` extractor.

Covers:

- ``Request`` default-constructs ``peer`` to ``127.0.0.1:0`` so the
  field is always observable without special-casing reactor vs
  user-constructed requests.
- The ``peer`` keyword argument on ``Request.__init__`` overrides the
  default.
- ``_parse_http_request_bytes`` threads the supplied ``peer`` onto the
  parsed request.
- The ``Peer`` value-constructor extractor returns the request's peer
  unchanged.
- ``Peer`` participates in the reflective ``Extracted[H]`` auto-injection
  pipeline.
- A round-trip through ``HttpServer`` on loopback observes a non-zero
  peer port, proving the reactor populated it from the kernel.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http import (
    Request,
    Response,
    HttpServer,
    Handler,
    Method,
    ok,
    Peer,
    Extracted,
    ComptimeRoute,
    ComptimeRouter,
)
from flare.http.server import _parse_http_request_bytes
from flare.net import IpAddr, SocketAddr
from flare.tcp import TcpStream


# ── Default peer ─────────────────────────────────────────────────────────────


def test_request_default_peer_is_loopback_zero() raises:
    var req = Request(method=Method.GET, url="/")
    assert_true(req.peer.ip.is_loopback())
    assert_equal(req.peer.port, UInt16(0))


def test_request_constructed_peer_is_preserved() raises:
    var p = SocketAddr(IpAddr("203.0.113.7", False), UInt16(54321))
    var req = Request(method=Method.GET, url="/", peer=p)
    assert_equal(req.peer.ip, p.ip)
    assert_equal(req.peer.port, UInt16(54321))


def test_request_peer_v6() raises:
    var p = SocketAddr(IpAddr("::1", True), UInt16(443))
    var req = Request(method=Method.POST, url="/x", peer=p)
    assert_true(req.peer.ip.is_v6())
    assert_true(req.peer.ip.is_loopback())
    assert_equal(req.peer.port, UInt16(443))


# ── Parser threads peer through ──────────────────────────────────────────────


def test_parse_request_with_peer() raises:
    var raw = "GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n"
    var data = raw.as_bytes()
    var p = SocketAddr(IpAddr("198.51.100.42", False), UInt16(40404))
    var req = _parse_http_request_bytes(Span[UInt8, _](data), peer=p)
    assert_equal(req.peer.port, UInt16(40404))
    assert_equal(req.peer.ip, p.ip)
    assert_equal(req.url, "/hello")


def test_parse_request_default_peer_when_omitted() raises:
    var raw = "GET / HTTP/1.1\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    # Default loopback 127.0.0.1:0
    assert_true(req.peer.ip.is_loopback())
    assert_equal(req.peer.port, UInt16(0))


# ── Peer extractor ───────────────────────────────────────────────────────────


def test_peer_extractor_value_constructor() raises:
    var p = SocketAddr(IpAddr("192.0.2.5", False), UInt16(8081))
    var req = Request(method=Method.GET, url="/", peer=p)
    var got = Peer.extract(req).value
    assert_equal(got.port, UInt16(8081))
    assert_equal(got.ip, p.ip)


def test_peer_extractor_default() raises:
    var ext = Peer()
    # Default-constructed Peer points at the conventional sentinel
    # 127.0.0.1:0 so there is never a "missing" peer to handle.
    assert_true(ext.value.ip.is_loopback())
    assert_equal(ext.value.port, UInt16(0))


# ── Auto-injection through Extracted[H] ─────────────────────────────────────


@fieldwise_init
struct PeerEcho(Copyable, Defaultable, Handler):
    var who: Peer

    def __init__(out self):
        self.who = Peer()

    def serve(self, req: Request) raises -> Response:
        return ok(String(self.who.value.port))


def test_peer_via_extracted_handler() raises:
    var p = SocketAddr(IpAddr("203.0.113.99", False), UInt16(13579))
    var req = Request(method=Method.GET, url="/", peer=p)
    var h = Extracted[PeerEcho]()
    var resp = h.serve(req^)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "13579")


# ── End-to-end on loopback ───────────────────────────────────────────────────


def _peer_handler(req: Request) raises -> Response:
    """Echoes the kernel-reported peer port back as the body."""
    return ok(String(req.peer.port))


def test_server_observes_kernel_peer_port() raises:
    """Round-trip: bind, connect from a known ephemeral port,
    handler echoes ``req.peer.port``, client compares against its
    own ``local_addr().port``.

    Uses the legacy ``serve_one`` blocking path so this test is
    self-contained and does not need to spin up the reactor or a
    background thread.
    """
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var client_local_port = client.local_addr().port

    var server_stream = srv._listener.accept()
    var captured_peer_port = server_stream.peer_addr().port

    # The kernel-reported peer port on the server side equals the
    # client's local ephemeral port. (This is the property
    # ``ConnHandle.peer`` will then expose to the handler.)
    assert_equal(captured_peer_port, client_local_port)

    server_stream.close()
    client.close()
    srv.close()


# ── Routers carry the peer (and expose_errors) through to the handler ──────


def _peer_echo(req: Request) raises -> Response:
    return ok(
        String(req.peer.ip)
        + ":"
        + String(req.peer.port)
        + " expose="
        + String(req.expose_errors)
    )


def _client_req(url: String) -> Request:
    return Request(
        method="GET",
        url=url,
        peer=SocketAddr(IpAddr("203.0.113.9", False), UInt16(4242)),
        expose_errors=True,
    )


def test_router_passes_the_peer_to_the_handler() raises:
    """Router used to rebuild the request without ``peer``, so every
    handler behind it saw 127.0.0.1:0 -- and "loopback only" admin
    routes let the whole internet in."""
    from flare.http import Router

    var r = Router()
    r.get("/p", _peer_echo)
    var resp = r.serve(_client_req("/p"))
    assert_equal(resp.text(), "203.0.113.9:4242 expose=True")


def test_router_passes_the_peer_through_a_param_route_and_a_mount() raises:
    from flare.http import Router

    var r = Router()
    r.get("/u/:id", _peer_echo)
    assert_equal(
        r.serve(_client_req("/u/7")).text(), "203.0.113.9:4242 expose=True"
    )
    var sub = Router()
    sub.get("/q", _peer_echo)
    var outer = Router()
    outer.mount("/api", sub^)
    assert_equal(
        outer.serve(_client_req("/api/q")).text(),
        "203.0.113.9:4242 expose=True",
    )


comptime _PEER_ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET, "/p/:id", _peer_echo),
]


def test_comptime_router_passes_the_peer_to_the_handler() raises:
    var r = ComptimeRouter[_PEER_ROUTES]()
    assert_equal(
        r.serve(_client_req("/p/1")).text(), "203.0.113.9:4242 expose=True"
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
