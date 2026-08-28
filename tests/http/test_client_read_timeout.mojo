"""Tests for :meth:`flare.http.HttpClient.with_read_timeout`.

``timeout_ms`` only ever bounded ``connect(2)``. Once the connection was
up, a read could block forever -- which is exactly what a half-open
connection looks like from the client side: the request goes out, the
network drops, the peer never learns it should FIN, and ``recv`` waits
for bytes that will never arrive.

The silent-peer case is reproduced without a second process: a bound
``TcpListener`` that never calls ``accept`` still completes the TCP
handshake in the kernel's accept queue, so ``connect`` succeeds and the
request is written, and then nothing ever comes back. Without a read
timeout that request hangs; with one it raises.

TLS is covered separately, because it fails in two different places and
neither one is the cleartext path. Against the same never-accept
listener an ``https://`` dial never reaches a read at all -- it parks in
``SSL_connect``, which ``TlsStream.connect_timeout`` now bounds with the
client's ``timeout_ms``. Past the handshake, an expired ``SO_RCVTIMEO``
reaches OpenSSL as ``SSL_ERROR_WANT_READ`` rather than as ``EAGAIN``,
so ``TlsStream.read`` has to classify it or the caller gets a
``NetworkError`` with an empty reason instead of a ``Timeout``.
"""

from std.testing import assert_equal, assert_true

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import IpAddr, SocketAddr
from flare.tcp import TcpListener
from flare.testing import fork_server, kill_forked_server
from flare.tls import TlsConfig
from flare.utils import usleep

comptime _SERVER_CRT: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"
comptime _CA_CRT: String = "tests/certs/ca.crt"

comptime _STALL_US: Int = 3_000_000
"""How long the stalling handler sits on a request: ten times the read
timeout under test, so the timeout has nothing to race."""


def _hello(req: Request) raises -> Response:
    return ok("read-timeout-hello")


def _stall(req: Request) raises -> Response:
    """Accept, complete the TLS handshake, then send nothing for long
    enough that a 300 ms read timeout must fire first."""
    usleep(_STALL_US)
    return ok("too late")


def _url(port: Int) -> String:
    return String("http://127.0.0.1:") + String(port) + String("/")


def _https_url(port: Int) -> String:
    """``localhost``, not the literal IP: this one gets far enough to
    verify the certificate, and OpenSSL matches ``SSL_set1_host``
    against the DNS SANs, not the IP one."""
    return String("https://localhost:") + String(port) + String("/")


def _https_ip_url(port: Int) -> String:
    """No DNS round trip and no ``::1`` first attempt, so the dial lands
    on the never-accept listener directly. Nothing here reaches
    certificate verification, so the IP in SNI does not matter."""
    return String("https://127.0.0.1:") + String(port) + String("/")


def test_read_timeout_fires_on_silent_peer() raises:
    """A peer that accepts the connection but never answers must not
    hang the client once a read timeout is set.

    The failure is asserted by message, not merely by "something
    raised": the same shape passes trivially if the listener is gone
    and the dial is refused instead. listener is closed only
    *after* the request so it stays alive across it -- Mojo destroys a
    value at its last use, and closing the listener earlier turns this
    into a ConnectionRefused test.
    """
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = Int(listener.local_addr().port)

    var err = String("")
    try:
        with HttpClient().with_read_timeout(300) as c:
            _ = c.get(_url(port))
    except e:
        err = String(e)

    listener.close()
    assert_true(
        err.find("Timeout") >= 0,
        String("expected a read timeout, got: ") + err,
    )


def test_read_timeout_does_not_break_a_normal_request() raises:
    """A timeout generous enough for a live server must not fire: the
    bound is per-read inactivity, not a deadline on the request."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = Int(srv.local_addr().port)
    var pid = fork_server(srv^, _hello)

    var status = -1
    var body = String("")
    var raised = False
    try:
        with HttpClient().with_read_timeout(30_000) as c:
            var r = c.get(_url(port))
            status = r.status
            body = r.text()
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "round-trip with a read timeout raised")
    assert_equal(status, 200)
    assert_equal(body, "read-timeout-hello")


def test_read_timeout_applies_to_pooled_connections() raises:
    """``SO_RCVTIMEO`` is armed on the socket when it is dialled, so a
    connection that goes back into the keep-alive pool carries the
    timeout into its next request."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = Int(srv.local_addr().port)
    var pid = fork_server(srv^, _hello)

    var first = -1
    var second = -1
    var idle_between = -1
    var raised = False
    try:
        with HttpClient().with_pool().with_read_timeout(30_000) as c:
            first = c.get(_url(port)).status
            idle_between = c.idle_count()
            second = c.get(_url(port)).status
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "pooled round-trip with a read timeout raised")
    assert_equal(first, 200)
    assert_equal(second, 200)
    assert_equal(idle_between, 1)


def test_read_timeout_is_off_by_default() raises:
    """The default client is unchanged: no ``SO_RCVTIMEO`` is set, so
    behaviour matches every release before this one."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = Int(srv.local_addr().port)
    var pid = fork_server(srv^, _hello)

    var status = -1
    var raised = False
    try:
        with HttpClient() as c:
            status = c.get(_url(port)).status
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "default round-trip raised")
    assert_equal(status, 200)


def test_tls_handshake_timeout_fires_on_silent_peer() raises:
    """The ``https://`` sibling of
    :func:`test_read_timeout_fires_on_silent_peer`, and the case where
    the two wires differ.

    A read timeout cannot save this one: nothing reaches a read.
    ``connect(2)`` succeeds out of the listener's backlog, then
    ``SSL_connect`` writes a ClientHello and blocks waiting for a
    ServerHello that never comes. Before ``connect_timeout`` armed the
    socket for the handshake this hung until the process was killed,
    so the assertion here is really "it returns at all".

    ``timeout_ms``, not ``with_read_timeout``, is the knob: the
    handshake is part of connecting.
    """
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = Int(listener.local_addr().port)

    var err = String("")
    try:
        with HttpClient(TlsConfig(ca_bundle=_CA_CRT), timeout_ms=300) as c:
            _ = c.get(_https_ip_url(port))
    except e:
        err = String(e)

    listener.close()
    assert_true(
        err.find("Timeout") >= 0,
        String("expected a handshake timeout, got: ") + err,
    )


def test_read_timeout_fires_on_stalled_tls_response() raises:
    """Past the handshake, a stalled ``https://`` read raises
    ``Timeout`` just as a cleartext one does.

    It did not before: the blocking client path reads through
    ``flare_ssl_read``, and an expired ``SO_RCVTIMEO`` makes ``recv``
    return ``EAGAIN``, which ``SSL_read`` reports as
    ``SSL_ERROR_WANT_READ`` with an *empty* OpenSSL error queue. That
    surfaced as ``NetworkError("TLS read error: ")`` with nothing
    after the colon. The assertion is on the message for that reason
    -- "something raised" passed the whole time.

    The handler answers eventually, so this is a stalled read and not
    a dead peer: the 300 ms bound has to fire while the connection is
    still perfectly healthy.
    """
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
    )
    var port = Int(srv.local_addr().port)
    var pid = fork_server(srv^, _stall)

    var err = String("")
    try:
        with HttpClient(TlsConfig(ca_bundle=_CA_CRT)).with_read_timeout(
            300
        ) as c:
            _ = c.get(_https_url(port))
    except e:
        err = String(e)

    kill_forked_server(pid)
    assert_true(
        err.find("Timeout") >= 0,
        String("expected a TLS read timeout, got: ") + err,
    )


def main() raises:
    test_read_timeout_fires_on_silent_peer()
    test_read_timeout_does_not_break_a_normal_request()
    test_read_timeout_applies_to_pooled_connections()
    test_read_timeout_is_off_by_default()
    test_tls_handshake_timeout_fires_on_silent_peer()
    test_read_timeout_fires_on_stalled_tls_response()
    print("test_client_read_timeout: 6 passed")
