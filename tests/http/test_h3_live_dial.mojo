"""Live HttpClient HTTP/3 dial over loopback QUIC.

Proves the transparent h3 dial path wired into
:meth:`flare.http.HttpClient._do_request`: a ``prefer_http3`` client
issuing ``get`` / ``post`` against an ``https://`` origin actually
opens a real QUIC connection, drives an HTTP/3 request/response, and
lowers the result back to a normal :class:`flare.http.Response` -- the
caller never sees the wire.

Harness: the parent binds a real :class:`flare.quic.server.QuicListener`
on a loopback UDP port (fixture ``localhost`` leaf cert + ``h3`` ALPN),
``fork()``s a child that runs a tick + dispatch serve loop, and the
parent dials it through :class:`HttpClient` configured to trust the
fixture CA. The host MUST be ``localhost`` (the leaf SAN) so cert
verification passes; ``resolve("localhost")`` maps to 127.0.0.1.

A final assertion covers the Alt-Svc upgrade: a client WITHOUT
``prefer_http3`` that has recorded an ``Alt-Svc: h3`` advert for an origin
flips :meth:`HttpClient.http3_wire_choice` to ``HTTP_3`` -- the auto-record
store path that makes a second request to that origin upgrade.

Note: public-Internet HTTP/3 is not exercised in CI; the fork + fixture
CA loopback covers the dial wiring deterministically.
"""

from std.pathlib import Path
from std.testing import assert_equal, assert_true

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

from flare.http import HttpClient, Request, Response, ok
from flare.http._client.alt_svc import Http3WireChoice
from flare.http.handler import Handler
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import TlsConfig


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _read_file(path: String) raises -> String:
    return Path(path).read_text()


def _h3_alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _bind_server() raises -> QuicListener:
    var cert = _read_file(_FIXDIR + "cert.pem")
    var key = _read_file(_FIXDIR + "key.pem")
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = cert^
    cfg.rustls_config.private_key_pem = key^
    cfg.rustls_config.alpn_protocols = _h3_alpn()
    return QuicListener.bind(cfg^)


@fieldwise_init
struct _EchoOrOk(Copyable, Handler, Movable):
    """200 handler: echoes a non-empty request body, else 'ok'."""

    def serve(self, req: Request) raises -> Response:
        if len(req.body) > 0:
            var resp = ok(String(""))
            resp.body = req.body.copy()
            return resp^
        return ok(String("ok"))


def _serve_forever(mut server: QuicListener):
    """Child-side serve loop: tick the listener and dispatch any
    completed H3 streams through the handler until the parent kills
    the process."""
    var handler = _EchoOrOk()
    while True:
        try:
            _ = server.tick(timeout_ms=50)
            for slot in range(server.connection_count()):
                var ready = server.take_http3_completed_streams(slot)
                for i in range(len(ready)):
                    var sid = ready[i]
                    var req = server.take_http3_request(slot, sid)
                    var resp = handler.serve(req^)
                    server.emit_http3_response(slot, sid, resp^)
        except:
            return


def _client() raises -> HttpClient:
    var cfg = TlsConfig(ca_bundle=_FIXDIR + "ca.pem")
    return HttpClient(cfg).with_prefer_http3()


def test_live_h3_get() raises:
    var server = _bind_server()
    var port = UInt16(server.local_addr().port)

    var pid = fork()
    if pid == 0:
        _serve_forever(server)
        exit()
    usleep(300000)

    var url = (
        String("https://localhost:") + String(Int(port)) + String("/hello")
    )
    var got_status = -1
    var got_body = String("")
    var raised = False
    try:
        with _client() as c:
            var r = c.get(url)
            got_status = r.status
            got_body = r.text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "HttpClient h3 GET raised over loopback QUIC")
    assert_equal(got_status, 200)
    assert_equal(got_body, String("ok"))


def test_live_h3_post_echo() raises:
    var server = _bind_server()
    var port = UInt16(server.local_addr().port)

    var pid = fork()
    if pid == 0:
        _serve_forever(server)
        exit()
    usleep(300000)

    var url = String("https://localhost:") + String(Int(port)) + String("/echo")
    var got_status = -1
    var got_body = String("")
    var raised = False
    try:
        with _client() as c:
            var r = c.post(url, String("flare-live-h3"))
            got_status = r.status
            got_body = r.text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "HttpClient h3 POST raised over loopback QUIC")
    assert_equal(got_status, 200)
    assert_equal(got_body, String("flare-live-h3"))


def test_alt_svc_auto_upgrade() raises:
    """A client without prefer_http3 that has seen an Alt-Svc h3 advert
    for an origin upgrades the NEXT request to HTTP/3 (the auto-record
    store flips http3_wire_choice)."""
    with HttpClient() as c:
        # Before any advert: cleartext-equivalent decision stays h2/h1.
        assert_equal(
            c.http3_wire_choice(
                "https", String("api.example.com"), UInt16(443)
            ),
            Http3WireChoice.HTTP_2_OR_LOWER,
        )
        c.record_alt_svc(
            String("api.example.com:443"), String('h3=":443"; ma=3600')
        )
        assert_equal(
            c.http3_wire_choice(
                "https", String("api.example.com"), UInt16(443)
            ),
            Http3WireChoice.HTTP_3,
        )


def main() raises:
    test_live_h3_get()
    test_live_h3_post_echo()
    test_alt_svc_auto_upgrade()
    print("test_h3_live_dial: 3 passed")
