# PLATFORM: any
"""H1-11: the streaming download reader returns a close-delimited TLS body
cut short by a TCP reset (no close_notify) as complete.

Lean: Flare.Bugs.H1_11.counterexample (dlClose accepts an unclean end)
and Flare.L3.H1.ClientResponse.bufferedClose_safe (the fixed reader, the
same guard the buffered readers apply, never accepts one).
flare/http/_client/download.mojo:215-220 (`_read_close`: EOF sets
_done and returns end of body) with flare/http/_client/h2_transport.mojo
:68-83 (`read` passes the TLS 0 through without consulting
eof_was_unclean) @59bda50. Reached from HttpClient's streaming API
(flare/http/client.mojo:1778, 1812). The buffered readers refuse this
case (_refuse_truncated_tls, parse.mojo:665-683).

Expected (RFC 8446 §6.1, RFC 9112 §8): a body delimited by connection
close over TLS is complete only if the stream ends with close_notify;
otherwise the reader must raise.
Actual: read_all returns "partial" with no error.

Minimal fix: in _H2Transport.read, when the TLS read returns 0 and
`eof_was_unclean()` is true, raise NetworkError (or have
HttpDownload._read_close check it).
"""

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
comptime _RESP: String = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npartial"


def _serve_once_without_close_notify(var lis: TcpListener):
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
        var bytes = _RESP.as_bytes()
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


def main() raises:
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var pid = fork()
    if pid == 0:
        _serve_once_without_close_notify(lis^)
    usleep(100_000)
    var t: _H2Transport
    try:
        var s = TlsStream.connect("localhost", port, TlsConfig(ca_bundle=_CA))
        s.write_all(
            String("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()
        )
        t = _H2Transport.from_tls(s^)
    except e:
        _ = kill(pid, SIGKILL)
        waitpid(pid)
        print("inconclusive: TLS setup failed: " + String(e))
        raise Error("inconclusive")
    var verdict: String
    var accepted = False
    try:
        var dl = HttpDownload[_H2Transport](t^, "GET")
        var body = dl.read_all()
        var text = String(unsafe_from_utf8=Span[UInt8, _](body))
        verdict = "status=" + String(dl.status) + " body=" + text
        accepted = True
    except e:
        verdict = "raised: " + String(e)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    print(verdict)
    if accepted:
        print(
            "BUG REPRODUCED: close-delimited TLS body without close_notify"
            " returned as complete (" + verdict + ")"
        )
        raise Error("H1-11")
    print("OK: truncated TLS download refused (" + verdict + ")")
