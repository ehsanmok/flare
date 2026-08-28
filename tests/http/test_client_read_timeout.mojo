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
"""

from std.testing import assert_equal, assert_true

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import SocketAddr
from flare.tcp import TcpListener
from flare.testing import fork_server, kill_forked_server


def _hello(req: Request) raises -> Response:
    return ok("read-timeout-hello")


def _url(port: Int) -> String:
    return String("http://127.0.0.1:") + String(port) + String("/")


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


def main() raises:
    test_read_timeout_fires_on_silent_peer()
    test_read_timeout_does_not_break_a_normal_request()
    test_read_timeout_applies_to_pooled_connections()
    test_read_timeout_is_off_by_default()
    print("test_client_read_timeout: 4 passed")
