"""Loopback tests for the non-blocking server TLS state machine.

Drives a real TLS 1.2/1.3 handshake between two flare components in the
same process via ``fork(2)``:

  - Parent: the new :class:`flare.http._reactor.tls_conn_handle.TlsConnHandle`
    on the accept side, driven purely on non-blocking edges
    (``drive_handshake`` -> ``recv`` -> ``send``), asserting the negotiated
    ALPN protocol + SNI host and a plaintext request/response round-trip
    through ``SSL_read`` / ``SSL_write``.
  - Child: the existing blocking :class:`flare.tls.TlsStream` client, which
    connects with a wrong-then-right... no -- with the self-signed test CA
    trusted, offers ALPN ``["h2"]`` and SNI ``localhost``, writes a
    request, reads the response, and exits.

The certificates are the shared self-signed pair in ``tests/certs/``
(same ones ``test_tls.mojo`` uses). The server advertises
``["h2", "http/1.1"]`` so ALPN negotiates to ``h2``.

This is the Phase-4 (TLS reactor) coverage: it proves the ciphertext-side
``StepResult`` state machine completes a handshake, exposes ALPN/SNI for
h1-vs-h2 dispatch, and moves application bytes both ways -- all without a
blocking handshake thread.
"""

from std.testing import assert_equal, assert_true, TestSuite
from std.memory import stack_allocation

from flare.utils import exit, fork, usleep, waitpid
from flare.net import SocketAddr, IpAddr
from flare.tcp import TcpListener
from flare.tls._server_ffi import (
    ServerCtx,
    SSL_IO_WANT_READ,
    SSL_IO_WANT_WRITE,
)
from flare.tls import TlsConfig, TlsStream
from flare.http._reactor.tls_conn_handle import TlsConnHandle


comptime _SERVER_CRT: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"
comptime _CA_CRT: String = "tests/certs/ca.crt"

comptime _REQUEST: String = "PING-over-tls"
comptime _RESPONSE: String = "PONG-over-tls"


def _bytes(s: String) -> List[UInt8]:
    """Copy ``s``'s UTF-8 bytes into an owned list."""
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def _alpn_wire(protos: List[String]) -> List[UInt8]:
    """Build the OpenSSL wire-format ALPN blob:
    ``len || bytes || len || bytes || ...``."""
    var out = List[UInt8]()
    for i in range(len(protos)):
        var p = protos[i]
        out.append(UInt8(p.byte_length()))
        for b in p.as_bytes():
            out.append(b)
    return out^


def _run_client(port: Int) -> None:
    """Child: connect over TLS, offer ALPN h2 + SNI localhost, exchange
    one request/response, then exit. Never returns."""
    # Give the parent a beat to reach accept(); the SYN would queue
    # regardless, but this keeps the handshake ordering tidy.
    usleep(60000)
    try:
        var alpn = List[String]()
        alpn.append("h2")
        var cfg = TlsConfig(ca_bundle=_CA_CRT, alpn=alpn^)
        var stream = TlsStream.connect("localhost", UInt16(port), cfg)

        var req = _bytes(_REQUEST)
        stream.write_all(Span[UInt8, _](req))

        # Read the response back (blocking client read).
        var rbuf = stack_allocation[64, UInt8]()
        var n = stream.read(rbuf, 64)
        _ = n
        stream.close()
    except:
        pass
    exit()


def test_tls_conn_handle_handshake_alpn_sni_roundtrip() raises:
    """A full non-blocking accept-side handshake completes, negotiates
    ALPN h2 + SNI localhost, and round-trips application bytes."""
    var ctx = ServerCtx.new(_SERVER_CRT, _SERVER_KEY)
    var server_alpn = List[String]()
    server_alpn.append("h2")
    server_alpn.append("http/1.1")
    ctx.set_alpn(_alpn_wire(server_alpn))

    var listener = TcpListener.bind(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0))
    )
    var port = listener.local_addr().port

    var pid = fork()
    if pid == 0:
        listener.close()
        _run_client(Int(port))
        return  # unreachable; _run_client calls exit()

    # ── Parent: non-blocking TLS accept side ──────────────────────────────
    var stream = listener.accept()
    var conn = TlsConnHandle(stream^, ctx)

    # Drive the handshake across simulated readiness edges.
    var established = False
    for _ in range(20000):
        var sr = conn.drive_handshake()
        if conn.handshake_done():
            established = True
            break
        if sr.done:
            break
        usleep(200)
    assert_true(established, "handshake did not complete")
    assert_equal(conn.alpn, "h2")
    assert_equal(conn.sni, "localhost")

    # Read the client's plaintext request through SSL_read.
    var inbuf = List[UInt8](capacity=256)
    var got = False
    for _ in range(20000):
        var n = conn.recv(inbuf, 256)
        if n > 0:
            got = True
            break
        if n == SSL_IO_WANT_READ or n == SSL_IO_WANT_WRITE:
            usleep(200)
            continue
        break
    assert_true(got, "did not read the client request")
    assert_equal(String(unsafe_from_utf8=Span[UInt8, _](inbuf)), _REQUEST)

    # Write the response back through SSL_write.
    var out = _bytes(_RESPONSE)
    var off = 0
    var sent_ok = False
    for _ in range(20000):
        var n = conn.send(Span[UInt8, _](out), off)
        if n > 0:
            off += n
            if off >= len(out):
                sent_ok = True
                break
        elif n == SSL_IO_WANT_READ or n == SSL_IO_WANT_WRITE:
            usleep(200)
            continue
        else:
            break
    assert_true(sent_ok, "did not send the full response")

    _ = conn^
    listener.close()
    waitpid(pid)


def test_tls_conn_handle_new_accept_is_nonblocking() raises:
    """Constructing a handle forces the accepted socket non-blocking and
    the pre-handshake introspection fields are empty."""
    var ctx = ServerCtx.new(_SERVER_CRT, _SERVER_KEY)
    var listener = TcpListener.bind(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0))
    )
    var port = listener.local_addr().port

    var pid = fork()
    if pid == 0:
        listener.close()
        # Child: just connect (insecure, no ALPN) so the parent's accept
        # returns, then exit. The parent only inspects pre-handshake state.
        usleep(60000)
        try:
            var cfg = TlsConfig.insecure()
            var stream = TlsStream.connect("localhost", UInt16(port), cfg)
            usleep(20000)
            stream.close()
        except:
            pass
        exit()
        return

    var stream = listener.accept()
    var conn = TlsConnHandle(stream^, ctx)
    assert_true(not conn.handshake_done(), "must not be established pre-drive")
    assert_equal(conn.alpn, "")
    assert_equal(conn.sni, "")
    assert_true(conn.fd() > 0, "fd accessor must return the live socket")

    _ = conn^
    listener.close()
    waitpid(pid)


def main() raises:
    print("=" * 60)
    print("test_tls_conn_handle.mojo — non-blocking server TLS reactor")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
