"""Happy-eyeballs h3-vs-h2 race coverage (plan item `happy-eyeballs`).

Two layers:

1. e2e win: a real loopback QUIC (h3) server + a ``prefer_h3``
   :class:`HttpClient` issuing an idempotent GET. The TLS branch of
   ``_do_request`` routes idempotent + h3-eligible requests through
   :func:`race_h3_h2`, which spawns the h3 and h2/h1 legs on two OS
   threads. The h2/h1 leg fast-fails (no TCP listener on the QUIC
   port -> ECONNREFUSED), so h3 wins and the caller sees a normal 200
   Response. This drives the real threaded race over the wire.

2. orchestration unit cases: :func:`race_h3_h2` is exercised directly
   with a synthetic ``thin`` leg so the win/fallback/both-fail picks
   are deterministic without a second TLS server (there is no
   TLS-terminating h1+h2 fork harness yet):
     * both legs succeed   -> h3 response is preferred,
     * h3 leg raises       -> h2 response is used (transparent
                              fallback, the point of the race),
     * both legs raise     -> the combined error is raised.

The scenario is carried in the ``url`` arg (race_h3_h2 hands the same
url to both legs); the synthetic leg branches on it and on ``is_h3``.

ASan note: the race joins both worker threads before reading either
result cell (pthread_join is a happens-before barrier) and frees all
heap cells after the join, so there is no leak or data race for ASan to
flag; this test is in the ASan inventory.
"""

from std.testing import assert_equal, assert_true

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

from flare.http import HttpClient, Request, Response, ok
from flare.http._client.h3_race import race_h3_h2
from flare.http.handler import Handler
from flare.http.headers import HeaderMap
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


def _bytes(s: String) -> List[UInt8]:
    var b = List[UInt8]()
    for c in s.as_bytes():
        b.append(c)
    return b^


def _synthetic_leg(
    client_addr: Int,
    is_h3: Bool,
    url: String,
    method: String,
    headers: HeaderMap,
    body: List[UInt8],
    wire: String,
) raises -> Response:
    """Deterministic stand-in for a real protocol leg. The scenario is
    encoded in ``url``; each leg branches on ``is_h3``."""
    if is_h3:
        if url == "h3-dead" or url == "both-dead":
            raise Error("synthetic h3 down")
        return Response(200, String("OK"), _bytes(String("h3-won")))
    if url == "both-dead":
        raise Error("synthetic h2 down")
    return Response(200, String("OK"), _bytes(String("h2-won")))


def test_race_prefers_h3_when_both_ok() raises:
    var r = race_h3_h2(
        _synthetic_leg,
        0,
        String("both-ok"),
        String("GET"),
        HeaderMap(),
        List[UInt8](),
        String("h2"),
    )
    assert_equal(r.status, 200)
    assert_equal(r.text(), String("h3-won"))


def test_race_falls_back_to_h2_when_h3_dead() raises:
    var r = race_h3_h2(
        _synthetic_leg,
        0,
        String("h3-dead"),
        String("GET"),
        HeaderMap(),
        List[UInt8](),
        String("h2"),
    )
    assert_equal(r.status, 200)
    assert_equal(r.text(), String("h2-won"))


def test_race_raises_when_both_dead() raises:
    var raised = False
    try:
        _ = race_h3_h2(
            _synthetic_leg,
            0,
            String("both-dead"),
            String("GET"),
            HeaderMap(),
            List[UInt8](),
            String("h2"),
        )
    except:
        raised = True
    assert_true(raised, "race must raise when both legs fail")


def main() raises:
    test_race_h3_wins_e2e()
    print("OK test_race_h3_wins_e2e")
    test_race_prefers_h3_when_both_ok()
    print("OK test_race_prefers_h3_when_both_ok")
    test_race_falls_back_to_h2_when_h3_dead()
    print("OK test_race_falls_back_to_h2_when_h3_dead")
    test_race_raises_when_both_dead()
    print("OK test_race_raises_when_both_dead")
    print("test_h3_happy_eyeballs: 4 passed")
