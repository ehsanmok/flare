"""``HttpServer.bind_tls`` from a ``TlsServerConfig``: the reactor's TLS
handshakes honour mTLS and the minimum protocol version. The cert/key
form could set neither, and ``min_protocol`` was not applied anywhere,
so a TLS 1.3-only acceptor still took TLS 1.2.
"""

from std.ffi import c_int, external_call
from std.testing import TestSuite, assert_false, assert_true

from flare.http import HttpServer, Request, Response, ok
from flare.net import IpAddr, SocketAddr
from flare.tls import TLS_PROTOCOL_TLS13, TlsConfig, TlsServerConfig, TlsStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _CRT: String = "tests/certs/server.crt"
comptime _KEY: String = "tests/certs/server.key"
comptime _CA: String = "tests/certs/ca.crt"


def _hello(req: Request) raises -> Response:
    return ok("hello")


def _serve(var tls: TlsServerConfig) raises -> Tuple[Int, UInt16]:
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)), tls^
    )
    var port = UInt16(srv.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(300000)
    return (pid, port)


def _stop(pid: Int):
    _ = kill(pid, SIGKILL)
    waitpid(pid)


def _get(port: UInt16, cfg: TlsConfig) -> Bool:
    """Whether a GET over TLS gets a 200."""
    try:
        var s = TlsStream.connect("localhost", port, cfg)
        var req = (
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        s.write_all(Span[UInt8, _](List[UInt8](req.as_bytes())))
        var buf = List[UInt8](length=512, fill=0)
        var n = s.read(buf.unsafe_ptr(), 512)
        s.close()
        return n > 12 and String(
            unsafe_from_utf8=Span[UInt8, _](buf)[:n]
        ).startswith("HTTP/1.1 200")
    except:
        return False


def _openssl_ok(port: UInt16, flag: String) -> Bool:
    var cmd = (
        "echo | openssl s_client "
        + flag
        + " -connect 127.0.0.1:"
        + String(port)
        + " -servername localhost >/dev/null 2>&1"
    )
    var c = cmd.copy()
    return external_call["system", c_int](c.as_c_string_span()) == 0


def test_min_protocol_tls13_refuses_tls12() raises:
    var t = _serve(TlsServerConfig(_CRT, _KEY, min_protocol=TLS_PROTOCOL_TLS13))
    var tls12 = _openssl_ok(t[1], "-tls1_2")
    var tls13 = _openssl_ok(t[1], "-tls1_3")
    _stop(t[0])
    assert_false(tls12, "a TLS 1.2 handshake was accepted")
    assert_true(tls13, "TLS 1.3 was refused")


def test_mtls_requires_a_client_certificate() raises:
    var t = _serve(
        TlsServerConfig(
            _CRT, _KEY, require_client_cert=True, client_ca_bundle=_CA
        )
    )
    var without = _get(t[1], TlsConfig(ca_bundle=_CA))
    var with_cert = _get(
        t[1], TlsConfig(ca_bundle=_CA, cert_file=_CRT, key_file=_KEY)
    )
    _stop(t[0])
    assert_false(without, "served a client with no certificate")
    assert_true(with_cert, "refused a client with a CA-signed certificate")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
