"""HttpClient HTTP/3 connection reuse (pooling).

Proves the QUIC connection pool wired into
:meth:`flare.http.HttpClient._send_http3`: two sequential ``https://``
requests to the same origin reuse one established QUIC connection
instead of re-handshaking. The client exposes :meth:`quic_dials` (the
pool's miss counter) and :meth:`quic_idle_count`; after two GETs the
dial count must be 1 (handshake once) and one connection must be idle
in the pool.

Harness mirrors ``test_h3_live_dial.mojo``: the parent binds a real
QuicListener on loopback, forks a tick + dispatch serve loop, and the
parent drives a fixture-CA-trusting HttpClient.
"""

from std.pathlib import Path
from std.testing import assert_equal, assert_true

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

from flare.http import HttpClient, Request, Response, ok
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
struct _OkHandler(Copyable, Handler, Movable):
    def serve(self, req: Request) raises -> Response:
        return ok(String("ok"))


def _serve_forever(mut server: QuicListener):
    var handler = _OkHandler()
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


def test_two_gets_reuse_one_connection() raises:
    var server = _bind_server()
    var port = UInt16(server.local_addr().port)

    var pid = fork()
    if pid == 0:
        _serve_forever(server)
        exit()
    usleep(300000)

    var base = String("https://localhost:") + String(Int(port))
    var status1 = -1
    var status2 = -1
    var dials = -1
    var idle = -1
    var raised = False
    try:
        var cfg = TlsConfig(ca_bundle=_FIXDIR + "ca.pem")
        with HttpClient(cfg).with_prefer_http3() as c:
            var r1 = c.get(base + String("/one"))
            status1 = r1.status
            # After the first request the connection is back in the pool.
            assert_equal(c.quic_idle_count(), 1)
            var r2 = c.get(base + String("/two"))
            status2 = r2.status
            dials = c.quic_dials()
            idle = c.quic_idle_count()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "two sequential h3 GETs raised over loopback")
    assert_equal(status1, 200)
    assert_equal(status2, 200)
    assert_equal(dials, 1)  # handshake happened exactly once
    assert_equal(idle, 1)  # connection returned to the pool for reuse


def main() raises:
    test_two_gets_reuse_one_connection()
    print("test_h3_pool_reuse: 1 passed")
