"""Streaming download over TLS: a stream cut without close_notify (H1-11).

A close-delimited body (no Content-Length, not chunked) is complete only
if the TLS stream ends with close_notify (RFC 8446 sec 6.1, RFC 9112
sec 8). ``HttpDownload`` read to end of stream and reported success for a
body cut short by a TCP reset. The raw TLS server below writes a response
and closes the socket without close_notify, so the client sees exactly
that reset. Ports are ephemeral; the server child is killed at the end.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http._client.download import HttpDownload
from flare.http._client.h2_transport import _H2Transport
from flare.net import SocketAddr
from flare.tcp import TcpListener
from flare.tls import TlsAcceptor, TlsConfig, TlsServerConfig, TlsStream
from flare.tls._server_ffi import server_ssl_read_ex, server_ssl_write_ex
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _CRT: String = "tests/certs/server.crt"
comptime _KEY: String = "tests/certs/server.key"
comptime _CA: String = "tests/certs/ca.crt"


def _serve_without_close_notify(var lis: TcpListener, resp: String):
    """Answer one request, then drop the TCP connection (no close_notify)."""
    try:
        var stream = lis.accept()
        var acc = TlsAcceptor(TlsServerConfig(cert_file=_CRT, key_file=_KEY))
        var r = acc.handshake_fd(Int(stream._socket.fd))
        var got = List[UInt8]()
        for _ in range(400):
            _ = server_ssl_read_ex(acc._ctx, r[0], got, 4096)
            var done = False
            for i in range(3, len(got)):
                if (
                    got[i - 3] == 13
                    and got[i - 2] == 10
                    and got[i - 1] == 13
                    and got[i] == 10
                ):
                    done = True
            if done:
                break
            usleep(5_000)
        var bytes = resp.as_bytes()
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


def _download(resp: String, mut verdict: String) raises -> Bool:
    """Fetch ``resp`` from a no-close_notify server through ``HttpDownload``.

    Returns True if the whole body was returned without an error;
    ``verdict`` carries the body or the error text.
    """
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var pid = fork()
    if pid == 0:
        _serve_without_close_notify(lis^, resp)
    var accepted = False
    try:
        var s = TlsStream.connect("localhost", port, TlsConfig(ca_bundle=_CA))
        s.write_all(
            String("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()
        )
        var t = _H2Transport.from_tls(s^)
        var dl = HttpDownload[_H2Transport](t^, "GET")
        var body = dl.read_all()
        verdict = String(unsafe_from_utf8=Span[UInt8, _](body))
        accepted = True
    except e:
        verdict = "raised: " + String(e)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    return accepted


def test_close_delimited_tls_body_without_close_notify_is_refused() raises:
    var verdict = String("")
    var accepted = _download(
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npartial", verdict
    )
    assert_true(
        not accepted,
        "a close-delimited body without close_notify was returned as complete: "
        + verdict,
    )
    assert_true("close_notify" in verdict, verdict)


def test_length_framed_tls_body_needs_no_close_notify() raises:
    """A Content-Length body is complete by its length; no close_notify."""
    var verdict = String("")
    var accepted = _download(
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nwhole!!", verdict
    )
    assert_true(accepted, verdict)
    assert_equal(verdict, "whole!!")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
