"""SNI certificate selection and certificate hot-reload on ``bind_tls``.

The two fixture certificates are both for ``localhost`` but issued by
different CAs, so which one a client was served shows in which CA
verifies it.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_false, assert_true

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import IpAddr, SocketAddr
from flare.testing import fork_server, kill_forked_server
from flare.tls import TlsConfig, TlsServerConfig, TlsSniCert


comptime _A_CERT = "tests/certs/server.crt"
comptime _A_KEY = "tests/certs/server.key"
comptime _A_CA = "tests/certs/ca.crt"
comptime _B_CERT = "tests/tls/fixtures/rustls-quic-client/cert.pem"
comptime _B_KEY = "tests/tls/fixtures/rustls-quic-client/key.pem"
comptime _B_CA = "tests/tls/fixtures/rustls-quic-client/ca.pem"


def _hi(req: Request) raises -> Response:
    return ok("hi")


def _verifies(url: String, ca: String) -> Bool:
    try:
        var c = HttpClient(TlsConfig(ca_bundle=ca))
        return c.get(url).status == 200
    except:
        return False


def _addr() raises -> SocketAddr:
    return SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0))


def test_sni_picks_the_certificate() raises:
    var sni = List[TlsSniCert]()
    sni.append(TlsSniCert("LocalHost", _B_CERT, _B_KEY))
    var srv = HttpServer.bind_tls(
        _addr(), TlsServerConfig(_A_CERT, _A_KEY, sni_certs=sni^)
    )
    var port = String(srv.local_addr().port)
    var pid = fork_server(srv^, _hi)
    var by_name_b = _verifies("https://localhost:" + port + "/", _B_CA)
    var by_name_a = _verifies("https://localhost:" + port + "/", _A_CA)
    var no_sni_a = _verifies("https://127.0.0.1:" + port + "/", _A_CA)
    kill_forked_server(pid)
    assert_true(by_name_b, "SNI localhost is served the SNI certificate")
    assert_false(by_name_a)
    assert_true(no_sni_a, "no SNI gets the default certificate")


def test_reload_serves_the_new_files_and_survives_a_bad_pair() raises:
    var cert = Path("build/test_reload.crt")
    var key = Path("build/test_reload.key")
    cert.write_text(Path(_A_CERT).read_text())
    key.write_text(Path(_A_KEY).read_text())
    var srv = HttpServer.bind_tls(_addr(), String(cert), String(key))
    cert.write_text(Path(_B_CERT).read_text())
    key.write_text(Path(_B_KEY).read_text())
    srv.reload_tls()
    key.write_text(Path(_A_KEY).read_text())  # no longer matches the cert
    var raised = False
    try:
        srv.reload_tls()
    except:
        raised = True
    assert_true(raised, "a mismatched pair is refused")
    var port = String(srv.local_addr().port)
    var pid = fork_server(srv^, _hi)
    var new_cert = _verifies("https://localhost:" + port + "/", _B_CA)
    var old_cert = _verifies("https://localhost:" + port + "/", _A_CA)
    kill_forked_server(pid)
    assert_true(new_cert, "the reloaded certificate is served")
    assert_false(old_cert)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
