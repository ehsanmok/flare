"""Happy-eyeballs h3-vs-h2 race coverage (plan item `happy-eyeballs`).

Two layers:

1. e2e win: a real loopback QUIC (h3) server + a ``prefer_h3``
   :class:`HttpClient` issuing an idempotent GET. The TLS branch of
   ``_do_request`` routes idempotent + h3-eligible requests through
   :func:`race_h3_h2_connect`, which spawns the h3 and h2/h1 *connect*
   legs on two OS threads. The h2/h1 leg fast-fails (no TCP listener on
   the QUIC port -> ECONNREFUSED), so h3 wins the connect race and the
   caller sends the request once on the pooled h3 connection, seeing a
   normal 200 Response.

2. orchestration unit cases: :func:`race_h3_h2_connect` is exercised
   directly with a synthetic ``thin`` connect leg so the win/fallback/
   both-fail picks are deterministic without a second TLS server:
     * both legs connect   -> RACE_H3 (h3 preferred),
     * h3 connect raises   -> RACE_H2 (transparent fallback, the point
                              of the race),
     * both connects raise -> RACE_NONE.

The scenario is carried in the ``url`` arg (the race hands the same url
to both legs); the synthetic leg branches on it and on ``is_h3``.

ASan note: the race joins both worker threads before reading either
result cell (pthread_join is a happens-before barrier) and frees all
heap cells after the join, so there is no leak or data race for ASan to
flag; this test is in the ASan inventory.
"""

from std.testing import assert_equal, assert_true

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

from flare.http import HttpClient, Request, Response, ok
from flare.http._client.h3_race import (
    RACE_H2,
    RACE_H3,
    RACE_NONE,
    race_h3_h2_connect,
)
from flare.http.handler import Handler
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import TlsConfig
from std.pathlib import Path


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
        return ok(String("h3-server"))


def _serve_forever(mut server: QuicListener):
    var handler = _OkHandler()
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


def _client() raises -> HttpClient:
    var cfg = TlsConfig(ca_bundle=_FIXDIR + "ca.pem")
    return HttpClient(cfg).with_prefer_h3()


def test_race_h3_wins_e2e() raises:
    """A live h3 origin: the threaded race returns h3's 200 while the
    h2/h1 leg fast-fails against the same port (no TCP listener)."""
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
    assert_true(not raised, "race h3 GET raised over loopback QUIC")
    assert_equal(got_status, 200)
    assert_equal(got_body, String("h3-server"))


def _synthetic_connect_leg(
    client_addr: Int,
    is_h3: Bool,
    url: String,
) raises -> Bool:
    """Deterministic stand-in for a real connect leg. The scenario is
    encoded in ``url``; each leg branches on ``is_h3``."""
    if is_h3:
        if url == "h3-dead" or url == "both-dead":
            raise Error("synthetic h3 down")
        return True
    if url == "both-dead":
        raise Error("synthetic h2 down")
    return True


def test_race_prefers_h3_when_both_ok() raises:
    var winner = race_h3_h2_connect(
        _synthetic_connect_leg, 0, String("both-ok")
    )
    assert_equal(winner, RACE_H3)


def test_race_falls_back_to_h2_when_h3_dead() raises:
    var winner = race_h3_h2_connect(
        _synthetic_connect_leg, 0, String("h3-dead")
    )
    assert_equal(winner, RACE_H2)


def test_race_none_when_both_dead() raises:
    var winner = race_h3_h2_connect(
        _synthetic_connect_leg, 0, String("both-dead")
    )
    assert_equal(winner, RACE_NONE)


def main() raises:
    test_race_h3_wins_e2e()
    print("OK test_race_h3_wins_e2e")
    test_race_prefers_h3_when_both_ok()
    print("OK test_race_prefers_h3_when_both_ok")
    test_race_falls_back_to_h2_when_h3_dead()
    print("OK test_race_falls_back_to_h2_when_h3_dead")
    test_race_none_when_both_dead()
    print("OK test_race_none_when_both_dead")
    print("test_h3_happy_eyeballs: 4 passed")
