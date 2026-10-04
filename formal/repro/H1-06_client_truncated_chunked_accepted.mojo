# PLATFORM: any
"""H1-06: the read-to-EOF client readers return a truncated chunked body as
complete, so a TLS reset without close_notify cuts a response short
undetected.

Lean: Flare.Bugs.H1_06.counterexample (the shipped decoder accepts
"5\\r\\nhel" although the scanner calls it incomplete) and
Flare.L3.H1.ClientChunked.cDecFixed_complete (fix meets spec: an accepted
body is a complete chunked message, decoded exactly).
flare/http/_client/parse.mojo:497-578 (_decode_chunked: `while pos < n`,
`end = min(pos + size, n)`, no check for the CRLF after the data or for
the last chunk) and 665-683 (_refuse_truncated_tls only guards the
close-delimited case; its docstring claims "a length or chunked body
already fails on a short read") @59bda50. Callers:
_read_http_response_tls/_tcp (flare/http/client.mojo:1283, 1445, 1495,
2505).

Expected (RFC 9112 §7.1, RFC 8446 §6.1): a chunked body is complete only
after the last-chunk and the empty line that ends the trailers; a
connection that ends earlier is an incomplete message and must raise.
Actual: "5\\r\\nhel" then EOF decodes to body "hel" with status 200.

Minimal fix: in _parse_http_response's chunked branch, raise unless
`scan_chunked_end(Span(raw), body_start, MAX_BUFFERED_RESPONSE_BYTES) >= 0`
before decoding.
"""

from flare.http._client.parse import (
    _parse_http_response,
    _read_http_response_tls,
)
from flare.net import SocketAddr
from flare.tcp import TcpListener
from flare.tls import TlsAcceptor, TlsConfig, TlsServerConfig, TlsStream
from flare.tls._server_ffi import server_ssl_read_ex, server_ssl_write_ex
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _CRT: String = "tests/certs/server.crt"
comptime _KEY: String = "tests/certs/server.key"
comptime _CA: String = "tests/certs/ca.crt"
comptime _RESP: String = (
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"
)


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


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
    # 1. The pure parser on the bytes a reset leaves behind.
    var pure: String
    try:
        var resp = _parse_http_response(_bytes(_RESP))
        pure = "accepted status=" + String(resp.status) + " body=" + resp.text()
    except e:
        pure = "raised: " + String(e)
    print("pure _parse_http_response:", pure)

    # 2. End to end: a TLS server that sends the cut response and then
    # drops the TCP connection without close_notify.
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var pid = fork()
    if pid == 0:
        _serve_once_without_close_notify(lis^)
    usleep(100_000)
    var tls: String
    var s: TlsStream
    try:
        s = TlsStream.connect("localhost", port, TlsConfig(ca_bundle=_CA))
        s.write_all(
            String("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()
        )
    except e:
        _ = kill(pid, SIGKILL)
        waitpid(pid)
        print("inconclusive: TLS setup failed: " + String(e))
        raise Error("inconclusive")
    try:
        var resp = _read_http_response_tls(s)
        tls = "accepted status=" + String(resp.status) + " body=" + resp.text()
    except e:
        tls = "raised: " + String(e)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    print("TLS _read_http_response_tls:", tls)

    if pure.startswith("accepted") or tls.startswith("accepted"):
        print(
            "BUG REPRODUCED: truncated chunked body returned as complete"
            " (pure: " + pure + "; TLS without close_notify: " + tls + ")"
        )
        raise Error("H1-06")
    print("OK: truncated chunked body refused (" + pure + "; " + tls + ")")
