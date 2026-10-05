"""``TlsAcceptor`` session tickets: rotation on ``reload()`` (DOC-07).

``docs/threat-model.md`` says the ticket key "is part of the TlsAcceptor and
rotates with ``reload``". A ticket (or cached session) issued before a
``reload()`` must therefore not resume after it, while tickets issued after
the reload resume as usual.

Each scenario forks a server child that runs one ``TlsAcceptor`` over a
loopback listener (ephemeral port) and serves three blocking handshakes with
a one-byte echo; the parent drives three client connections, each offering
the session captured on the one before.
"""

from std.testing import assert_equal, assert_false, assert_true, TestSuite

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


def _serve_round(mut acc: TlsAcceptor, mut ln: TcpListener) raises:
    """Accept one connection, echo one message, tear it down."""
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


def _serve_three(mut ln: TcpListener, reload_after_round: Int) raises:
    var acc = TlsAcceptor(TlsServerConfig(_CRT, _KEY))
    for round in range(3):
        _serve_round(acc, ln)
        if round == reload_after_round:
            acc.reload()


def _round_trip(mut s: TlsStream) raises -> Bool:
    var msg = String("p")
    s.write_all(msg.as_bytes())
    var buf = List[UInt8](length=16, fill=0)
    var n = s.read(buf.unsafe_ptr(), 16)
    return n == 1 and buf[0] == 0x70


def _resumption_chain(reload_after_round: Int) raises -> Tuple[Bool, Bool]:
    """Connect three times, each offering the previous connection's
    session. Returns ``(connection 2 reused, connection 3 reused)``; the
    server reloads after ``reload_after_round`` (-1 = never)."""
    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(ln.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            _serve_three(ln, reload_after_round)
        except:
            exit(7)
        exit(0)
    ln.close()
    usleep(150000)

    var failure = String("")
    var r2 = False
    var r3 = False
    try:
        var cfg = TlsConfig(ca_bundle=_CA)
        var s1 = TlsStream.connect("localhost", port, cfg)
        if s1.was_session_reused() or not _round_trip(s1):
            failure = "connection 1 was not a plain full handshake"
        var sess1 = s1.session()
        var addr1 = sess1.session_addr()
        s1.close()
        if failure == "" and addr1 == 0:
            failure = "no session captured on connection 1"
        if failure == "":
            var s2 = TlsStream.connect_resumed("localhost", port, cfg, sess1^)
            r2 = s2.was_session_reused()
            _ = _round_trip(s2)
            var sess2 = s2.session()
            var addr2 = sess2.session_addr()
            s2.close()
            if addr2 == 0:
                failure = "no session captured on connection 2"
            else:
                usleep(100000)
                var s3 = TlsStream.connect_resumed(
                    "localhost", port, cfg, sess2^
                )
                r3 = s3.was_session_reused()
                _ = _round_trip(s3)
                s3.close()
    except e:
        failure = "client raised: " + String(e)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    if failure != "":
        raise Error(failure)
    return (r2, r3)


def test_ticket_resumes_without_reload() raises:
    """Control: the harness can see a resumption (and the acceptor issues
    tickets), so the reload test below is not vacuous."""
    var r = _resumption_chain(-1)
    assert_true(r[0], "connection 2 should resume connection 1")
    assert_true(r[1], "connection 3 should resume connection 2")


def test_reload_rotates_the_ticket_key() raises:
    """DOC-07: a ticket issued before ``reload()`` no longer resumes
    after it."""
    var r = _resumption_chain(1)
    assert_true(r[0], "connection 2 should resume connection 1")
    assert_false(
        r[1], "a ticket issued before reload() must not resume after it"
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
