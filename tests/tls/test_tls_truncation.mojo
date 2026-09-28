"""A TLS response framed by the end of the stream must end in close_notify.

TLS signs the end of a stream with close_notify so that someone who can
reset the TCP connection cannot cut a message short and have it read as
complete. The blocking client read treated a peer that vanished without
one as a clean EOF, so a close-delimited body cut off mid-way came back
as a finished response.

The server here is a forked child that handshakes through
``TlsAcceptor.handshake_fd``, writes one response and exits without
``SSL_shutdown``: the TCP connection closes and no close_notify is sent.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http._client.parse import _read_http_response_tls
from flare.net import SocketAddr
from flare.tcp import TcpListener
from flare.tls import TlsAcceptor, TlsConfig, TlsServerConfig, TlsStream
from flare.tls._server_ffi import server_ssl_read_ex, server_ssl_write_ex
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _CRT: String = "tests/certs/server.crt"
comptime _KEY: String = "tests/certs/server.key"
comptime _CA: String = "tests/certs/ca.crt"


def _serve_once_without_close_notify(var lis: TcpListener, response: String):
    """Child side: one handshake, read the request head, write
    ``response``, then exit with the TCP connection still up so the
    kernel closes it with no TLS alert."""
    try:
        var stream = lis.accept()
        var acc = TlsAcceptor(TlsServerConfig(cert_file=_CRT, key_file=_KEY))
        var r = acc.handshake_fd(Int(stream._socket.fd))
        var got = List[UInt8]()
        for _ in range(200):
            _ = server_ssl_read_ex(acc._ctx, r[0], got, 4096)
            var done = False
            for i in range(3, len(got)):
                if got[i - 3] == 13 and got[i] == 10 and got[i - 1] == 13:
                    done = True
            if done:
                break
            usleep(5_000)
        var bytes = response.as_bytes()
        var off = 0
        while off < len(bytes):
            var n = server_ssl_write_ex(acc._ctx, r[0], bytes, off)
            if n <= 0:
                break
            off += n
        _ = stream^
    except:
        pass
    exit()


def _fetch(response: String) raises -> String:
    """Return the body the client read, or ``raised: <error>``."""
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var pid = fork()
    if pid == 0:
        _serve_once_without_close_notify(lis^, response)
    usleep(100_000)
    var out: String
    try:
        var s = TlsStream.connect("localhost", port, TlsConfig(ca_bundle=_CA))
        s.write_all(
            String("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()
        )
        var resp = _read_http_response_tls(s)
        out = resp.text()
        s.close()
    except e:
        out = "raised: " + String(e)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    return out^


def test_close_delimited_body_without_close_notify_is_refused() raises:
    var got = _fetch(
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfirst half of the"
    )
    assert_true(got.startswith("raised: "), "got: " + got)
    assert_true("close_notify" in got, "got: " + got)


def test_length_framed_body_without_close_notify_is_fine() raises:
    """A body that says how long it is does not depend on the close, so
    the missing alert changes nothing."""
    var got = _fetch(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    )
    assert_equal(got, "ok")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
