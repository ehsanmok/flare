# PLATFORM: any (loopback TCP + OpenSSL, forked server child; uses tests/certs)
"""DOC-07: `TlsAcceptor.reload()` swaps the certificate and key but keeps
the session-ticket key and session cache, so a ticket issued before the
reload still resumes after it.

Lean: Flare.Bugs.DOC_07.counterexample (counterexample) and
Flare.Bugs.DOC_07.fixed (fix meets spec).
flare/tls/acceptor.mojo:369-376 @59bda50 (`reload` calls
`ServerCtx.reload`, flare/tls/_server_ffi.mojo:272-276, which calls
`flare_ssl_ctx_reload`, flare/tls/ffi/openssl_wrapper.cpp:559+, which
installs a new chain and key on the same SSL_CTX). Tickets are on by
default (acceptor.mojo:206, `flare_ssl_ctx_enable_session_tickets`,
openssl_wrapper.cpp:489-516) and nothing ever sets new ticket keys or
flushes the session cache; the TlsServerConfig docstring says as much
(acceptor.mojo:175-182, "the acceptor does not auto-rotate").

Doc claim: docs/threat-model.md:59 (TLS session-ticket replay) "flare
emits new tickets on every handshake; the OpenSSL rotation key is part of
the TlsAcceptor and rotates with `reload`."

Trace: a forked child runs a TlsAcceptor (tests/certs/server.crt) and
serves three blocking handshakes with a one-byte echo each, calling
`reload()` (same files) between the second and the third. The parent:
connection 1 is a full handshake and captures its session; connection 2
resumes it (control: must be reused, or the harness cannot tell); it
captures connection 2's session; connection 3 offers that session after
the reload. Expected: connection 3 is a full handshake. Actual: it
resumes.

Minimal fix: in `TlsAcceptor.reload`, build a fresh acceptor (new
SSL_CTX, so new ticket keys and an empty session cache) from `config` and
replace `self` with it, instead of patching the chain into the old
context.
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


def _serve(mut ln: TcpListener) raises:
    var acc = TlsAcceptor(TlsServerConfig(_CRT, _KEY))
    for round in range(3):
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
        if round == 1:
            acc.reload()


def _round_trip(mut s: TlsStream) raises -> Bool:
    var msg = String("p")
    s.write_all(msg.as_bytes())
    var buf = List[UInt8](length=16, fill=0)
    var n = s.read(buf.unsafe_ptr(), 16)
    return n == 1 and buf[0] == 0x70


def main() raises:
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
    var r2 = False
    var r3 = False
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
            verdict = "inconclusive: no session captured on connection 1"
        if verdict == "":
            var s2 = TlsStream.connect_resumed("localhost", port, cfg, sess1^)
            r2 = s2.was_session_reused()
            _ = _round_trip(s2)
            var sess2 = s2.session()
            var sess2_addr = sess2.session_addr()
            s2.close()
            if r1 or not r2:
                verdict = "inconclusive: control failed (conn 1 reused " + String(
                    r1
                ) + ", conn 2 reused " + String(r2) + ")"
            elif sess2_addr == 0:
                verdict = "inconclusive: no session captured on connection 2"
            else:
                usleep(100000)
                var s3 = TlsStream.connect_resumed(
                    "localhost", port, cfg, sess2^
                )
                r3 = s3.was_session_reused()
                _ = _round_trip(s3)
                s3.close()
    except e:
        if verdict == "":
            verdict = "inconclusive: client raised: " + String(e)
    _ = kill(pid, SIGKILL)
    waitpid(pid)

    if verdict != "":
        print(verdict)
        raise Error("setup")
    if r3:
        print(
            "BUG REPRODUCED: a session ticket issued before",
            "TlsAcceptor.reload() still resumed after it (conn 2 reused:",
            r2,
            ", conn 3 after reload reused:",
            r3,
            "); the ticket key did not rotate",
        )
        raise Error("DOC-07")
    print("OK: after reload() the old ticket no longer resumes (full handshake)")
