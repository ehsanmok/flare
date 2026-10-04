# PLATFORM: any (loopback TCP + OpenSSL, forked server child; uses tests/certs)
"""DOC-08: server session tickets are on by default, and
`enable_session_tickets=False` does not turn resumption off.

Lean: Flare.Bugs.DOC_08.counterexample (counterexample) and
Flare.Bugs.DOC_08.fixed (fix meets spec).
flare/tls/acceptor.mojo:206 @59bda50 (`enable_session_tickets: Bool =
True`) and acceptor.mojo:364-365 (the flag only decides whether
`flare_ssl_ctx_enable_session_tickets` is called; False leaves the
SSL_CTX that `flare_ssl_ctx_new_server`, openssl_wrapper.cpp:526-557,
built, with OpenSSL's defaults: tickets on, server session cache on).

Doc claim: docs/features.md:572 "server-side ticket cache (opt-in via
`TlsServerConfig.enable_session_tickets`)".

Trace: a forked child serves four blocking handshakes with a one-byte
echo each: two on an acceptor with tickets on (control: the second must
resume the first, or the harness cannot tell), then two on a fresh
acceptor built with `enable_session_tickets=False`. The parent offers the
third connection's session on the fourth. Expected for an opt-in switch
that is off: no session, or a full handshake. Also checked: the default
value of the field.

Minimal fix: default `enable_session_tickets` to False, and when it is
False set SSL_OP_NO_TICKET, `SSL_CTX_set_num_tickets(ctx, 0)` and
`SSL_SESS_CACHE_OFF` on the SSL_CTX.
"""

from flare.net import SocketAddr
from flare.tcp import TcpListener
from flare.tls import TlsAcceptor, TlsConfig, TlsServerConfig, TlsStream
from flare.tls._server_ffi import (
    server_ssl_free,
    server_ssl_read_ex,
    server_ssl_write_ex,
)
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

comptime _CA = "tests/certs/ca.crt"
comptime _CRT = "tests/certs/server.crt"
comptime _KEY = "tests/certs/server.key"


def _serve_one(mut acc: TlsAcceptor, mut ln: TcpListener) raises:
    var s = ln.accept()
    var r = acc.handshake_fd(Int(s._socket.fd))
    var ssl = r[0]
    var buf = List[UInt8]()
    for _ in range(2000):
        var n = server_ssl_read_ex(acc._ctx, ssl, buf, 16)
        if n > 0:
            break
        if n == 0 or len(buf) > 0:
            break
        usleep(1000)
    if len(buf) > 0:
        _ = server_ssl_write_ex(acc._ctx, ssl, Span[UInt8, _](buf))
    usleep(50000)
    server_ssl_free(acc._ctx, ssl)
    s.close()


def _serve(mut ln: TcpListener) raises:
    var on = TlsAcceptor(TlsServerConfig(_CRT, _KEY, enable_session_tickets=True))
    _serve_one(on, ln)
    _serve_one(on, ln)
    var off = TlsAcceptor(
        TlsServerConfig(_CRT, _KEY, enable_session_tickets=False)
    )
    _serve_one(off, ln)
    _serve_one(off, ln)


def _round_trip(mut s: TlsStream) raises -> Bool:
    var msg = String("p")
    s.write_all(msg.as_bytes())
    var buf = List[UInt8](length=16, fill=0)
    var n = s.read(buf.unsafe_ptr(), 16)
    return n == 1 and buf[0] == 0x70


def main() raises:
    var default_on = TlsServerConfig(_CRT, _KEY).enable_session_tickets

    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(ln.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            _serve(ln)
        except:
            exit(7)
        exit(0)
    ln.close()
    usleep(150000)

    var verdict = String("")
    var off_session = False
    var off_resumed = False
    try:
        var cfg = TlsConfig(ca_bundle=_CA)
        var s1 = TlsStream.connect("localhost", port, cfg)
        var r1 = s1.was_session_reused()
        if not _round_trip(s1):
            verdict = "inconclusive: connection 1 echo failed"
        var sess1 = s1.session()
        var sess1_addr = sess1.session_addr()
        s1.close()
        if verdict == "" and sess1_addr == 0:
            verdict = "inconclusive: control acceptor issued no session"
        if verdict == "":
            var s2 = TlsStream.connect_resumed("localhost", port, cfg, sess1^)
            var r2 = s2.was_session_reused()
            _ = _round_trip(s2)
            s2.close()
            if r1 or not r2:
                verdict = "inconclusive: control failed (conn 1 reused " + String(
                    r1
                ) + ", conn 2 reused " + String(r2) + ")"
        if verdict == "":
            usleep(100000)
            var s3 = TlsStream.connect("localhost", port, cfg)
            if not _round_trip(s3):
                verdict = "inconclusive: connection 3 echo failed"
            var sess3 = s3.session()
            off_session = sess3.session_addr() != 0
            s3.close()
            if verdict == "" and off_session:
                usleep(100000)
                var s4 = TlsStream.connect_resumed(
                    "localhost", port, cfg, sess3^
                )
                off_resumed = s4.was_session_reused()
                _ = _round_trip(s4)
                s4.close()
    except e:
        if verdict == "":
            verdict = "inconclusive: client raised: " + String(e)
    _ = kill(pid, SIGKILL)
    waitpid(pid)

    if verdict != "":
        print(verdict)
        raise Error("setup")
    if default_on or off_resumed:
        print(
            "BUG REPRODUCED: TlsServerConfig default enable_session_tickets =",
            default_on,
            "; with enable_session_tickets=False the server still issued a",
            "session:",
            off_session,
            "and resumed it:",
            off_resumed,
        )
        raise Error("DOC-08")
    print(
        "OK: session tickets are off by default and",
        "enable_session_tickets=False gives a full handshake (session issued:",
        off_session,
        ")",
    )
