"""End-to-end HTTP/3 client 0-RTT (EarlyData) send flight.

Drives the real :meth:`flare.h3.client.H3ClientConnection.fetch_0rtt`
against a real :class:`flare.quic.server.QuicListener` over loopback
QUIC, with the server run in a forked child process so the client's
internal poll loop has a live peer (mirrors
``tests/http/test_h3_live_dial.mojo``).

Two paths are covered:

* **Accept** -- one server with ``max_early_data_size > 0``. A first
  connection completes the handshake and absorbs the
  ``NewSessionTicket`` into the (in-process, parent-held) connector
  session store; a second connection opened with ``enable_0rtt=True``
  resumes, emits the GET in its first 0-RTT flight, the server accepts
  early data, and the response comes back. ``used_0rtt`` is True.
* **Reject / replay** -- the first connection's ticket (cached under
  ``localhost``) is presented to a *different* server process whose
  rustls ticket key cannot decrypt it. The server rejects early data
  and falls back to a full 1-RTT handshake; the client transparently
  replays the identical request at 1-RTT on the same stream, the
  response still arrives, ``used_0rtt`` is False and ``replayed`` True.

Reuses the 2-cert fixture chain from
``tests/tls/fixtures/rustls-quic-client/`` (CA + ``localhost`` leaf).
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

from flare.h3 import H3ClientConnection
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok
from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _read_file(path: String) raises -> String:
    return Path(path).read_text()


def _h3_alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _make_connector() raises -> RustlsQuicConnector:
    var ca = _read_file(_FIXDIR + "ca.pem")
    return RustlsQuicConnector(ca^, _h3_alpn())


def _bind_server() raises -> QuicListener:
    """Bind a loopback h3 listener that advertises 0-RTT in its issued
    tickets (stateful resumption), so a resumed client can ride
    EarlyData."""
    var cert = _read_file(_FIXDIR + "cert.pem")
    var key = _read_file(_FIXDIR + "key.pem")
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = cert^
    cfg.rustls_config.private_key_pem = key^
    cfg.rustls_config.alpn_protocols = _h3_alpn()
    cfg.rustls_config.max_early_data_size = UInt32(0xFFFF)
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
    """Child-side serve loop: tick + dispatch completed H3 streams
    until the parent kills the process."""
    var handler = _EchoOrOk()
    while True:
        try:
            _ = server.tick(timeout_ms=50)
            for slot in range(server.connection_count()):
                var ready = server.take_h3_completed_streams(slot)
                for i in range(len(ready)):
                    var sid = ready[i]
                    var req = server.take_h3_request(slot, sid)
                    var resp = handler.serve(req^)
                    server.emit_h3_response(slot, sid, resp^)
        except:
            return


def _elicit_ticket(
    mut connector: RustlsQuicConnector, addr: QuicListener
) raises:
    """Open a first connection against ``addr``, complete the handshake,
    and pump enough rounds to receive + cache the server's
    NewSessionTicket into the connector's in-process session store."""
    var c1 = QuicClientConnection.start(
        addr.local_addr(), connector, String("localhost")
    )
    for _ in range(60):
        _ = c1.poll(timeout_ms=50)
        if c1.is_established():
            break
    assert_true(c1.is_established(), "first connection must establish")
    # The server only drains its 1-RTT NewSessionTicket CRYPTO on a
    # client packet that does not itself feed crypto, so ping + poll.
    for _ in range(10):
        c1.keepalive()
        _ = c1.poll(timeout_ms=50)
    c1.close()


def test_0rtt_accept() raises:
    """A resumed GET rides 0-RTT and the server accepts early data."""
    var server = _bind_server()
    var pid = fork()
    if pid == 0:
        _serve_forever(server)
        exit()
    usleep(300000)

    var raised = False
    var status = -1
    var used_0rtt = False
    var replayed = True
    try:
        var connector = _make_connector()
        _elicit_ticket(connector, server)
        var c2 = QuicClientConnection.start(
            server.local_addr(),
            connector,
            String("localhost"),
            enable_0rtt=True,
        )
        assert_true(c2.early_data_ready(), "resumed connection has early keys")
        var h3 = H3ClientConnection(c2^)
        var outcome = h3.fetch_0rtt(
            String("GET"),
            String("https"),
            String("example.com"),
            String("/hello"),
            List[QpackHeader](),
            List[UInt8](),
            timeout_ms=100,
            max_polls=200,
        )
        status = outcome.response.status
        used_0rtt = outcome.used_0rtt
        replayed = outcome.replayed
        h3.close()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "0-RTT GET raised over loopback h3")
    assert_equal(status, 200)
    assert_true(used_0rtt, "server must accept early data on a resumed GET")
    assert_false(replayed, "accepted 0-RTT must not replay")


def test_0rtt_reject_replays() raises:
    """A ticket presented to a foreign server is rejected; the request
    transparently replays at 1-RTT and still completes."""
    var server_a = _bind_server()
    var pid_a = fork()
    if pid_a == 0:
        _serve_forever(server_a)
        exit()
    # A second, independent server process: its rustls ticket key cannot
    # decrypt server A's NewSessionTicket, so it rejects the PSK / early
    # data and does a full 1-RTT handshake.
    var server_b = _bind_server()
    var pid_b = fork()
    if pid_b == 0:
        _serve_forever(server_b)
        exit()
    usleep(300000)

    var raised = False
    var status = -1
    var used_0rtt = True
    var replayed = False
    try:
        var connector = _make_connector()
        # Cache server A's ticket under "localhost".
        _elicit_ticket(connector, server_a)
        # Resume (client derives early keys) but dial server B.
        var c2 = QuicClientConnection.start(
            server_b.local_addr(),
            connector,
            String("localhost"),
            enable_0rtt=True,
        )
        assert_true(
            c2.early_data_ready(),
            "client derives early keys from the cached ticket",
        )
        var h3 = H3ClientConnection(c2^)
        var outcome = h3.fetch_0rtt(
            String("GET"),
            String("https"),
            String("example.com"),
            String("/hello"),
            List[QpackHeader](),
            List[UInt8](),
            timeout_ms=100,
            max_polls=200,
        )
        status = outcome.response.status
        used_0rtt = outcome.used_0rtt
        replayed = outcome.replayed
        h3.close()
    except:
        raised = True

    _ = kill(pid_a, SIGKILL)
    _ = kill(pid_b, SIGKILL)
    waitpid(pid_a)
    waitpid(pid_b)
    assert_true(not raised, "rejected 0-RTT GET raised over loopback h3")
    assert_equal(status, 200)
    assert_false(used_0rtt, "foreign-ticket server must reject early data")
    assert_true(replayed, "rejected 0-RTT must replay at 1-RTT")


def main() raises:
    test_0rtt_accept()
    test_0rtt_reject_replays()
    print("test_h3_0rtt_e2e: 2 passed")
