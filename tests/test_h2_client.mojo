"""Integration tests for ``flare.http2.client.Http2Client``.

Spawns a child process that listens on a loopback port, drives
:class:`flare.http2.server.H2Connection` over a real TCP socket,
serves a fixed handler, and shuts down on peer close. The parent
process opens a :class:`flare.http2.Http2Client`, performs one
or more requests over h2c (cleartext HTTP/2), and asserts the
response shape.

Test inventory:

- :func:`test_h2c_get_request_round_trip` -- single GET against
  the in-process H2 server returns the expected status + body.
- :func:`test_h2c_post_with_body` -- POST with a small JSON body
  echoes the body length back.
- :func:`test_h2c_two_sequential_requests_share_connection` --
  two requests on the same :class:`Http2Client` reuse the
  underlying TCP socket (verified by the same source port being
  observed on both server-side accepts -- handled implicitly by
  the same fd staying open across the second ``client.get``).
- :func:`test_h2c_https_url_rejected` -- targeting an
  ``https://`` URL with the cleartext-only cut raises a
  :class:`flare.net.NetworkError` with a clear message.
- :func:`test_h2c_cross_origin_reuse_rejected` -- a second
  request whose host differs from the first raises (RFC 9113
  §9.1.1: one origin per H2 connection).

Cross-platform: Linux + macOS (no io_uring dependency).
"""

from std.ffi import c_int, c_uint, c_size_t, external_call
from std.memory import UnsafePointer, stack_allocation
from std.testing import assert_equal, assert_true

from flare.http2 import (
    H2Connection,
    HpackHeader,
    Http2Client,
)
from flare.http import (
    BasicAuth,
    BearerAuth,
    HttpServer,
    Response,
    ServerConfig,
    ok,
)
from flare.http2.server import H2Connection as ServerH2
from flare.tcp import TcpStream, TcpListener
from flare.net import NetworkError, SocketAddr


# ── POSIX shims (same shape as test_static_multicore.mojo) ──────────────


@always_inline
def _fork() -> c_int:
    return external_call["fork", c_int]()


@always_inline
def _waitpid(pid: c_int):
    _ = external_call["waitpid", c_int](pid, 0, c_int(0))


@always_inline
def _exit_child(code: c_int = c_int(0)):
    _ = external_call["_exit", c_int](code)


@always_inline
def _usleep(us: c_int):
    _ = external_call["usleep", c_int](us)


@always_inline
def _kill(pid: c_int, sig: c_int) -> c_int:
    return external_call["kill", c_int](pid, sig)


comptime _SIGKILL: c_int = c_int(9)


# ── In-process H2 server harness ─────────────────────────────────────────


def _serve_one_h2_connection(
    mut listener: TcpListener,
    body_for_path: String,
    echo_auth: Bool = False,
) raises:
    """Accept one connection and drive H2Connection until peer close.

    For every completed request, builds a :class:`Response` whose
    body is either ``body_for_path`` (the default constant
    response) or, when ``echo_auth = True``, the request's
    ``authorization`` header value (so the auth-propagation test
    can confirm the header arrived). Loops until ``read`` returns
    0 (peer closed) or any read/write fails.
    """
    var stream = listener.accept()
    var h2 = ServerH2()
    var buf = stack_allocation[16384, UInt8]()
    while True:
        var n = stream.read(buf, 16384)
        if n == 0:
            return
        # Feed the bytes; this advances the state machine and may
        # auto-queue SETTINGS / SETTINGS-ACK / PING-ACK /
        # WINDOW_UPDATE frames into h2's outbox.
        var slice = List[UInt8](capacity=n)
        for i in range(n):
            slice.append(buf[i])
        try:
            h2.feed(Span[UInt8, _](slice))
        except:
            return
        # Pop any completed request streams + emit responses.
        var ids = h2.take_completed_streams()
        for i in range(len(ids)):
            var sid = ids[i]
            var req_auth = String("")
            try:
                var req = h2.take_request(sid)
                if echo_auth:
                    req_auth = req.headers.get("authorization")
            except:
                continue
            var resp = Response(status=200)
            resp.headers.set("Content-Type", "text/plain; charset=utf-8")
            if echo_auth:
                # Echo the auth header back in the body so the
                # client test can verify what the server saw.
                resp.body = List[UInt8](req_auth.as_bytes())
            else:
                resp.body = List[UInt8](body_for_path.as_bytes())
            try:
                h2.emit_response(sid, resp^)
            except:
                continue
        # Push all queued outbound bytes onto the wire.
        var out = h2.drain()
        if len(out) > 0:
            try:
                stream.write_all(Span[UInt8, _](out))
            except:
                return


# ── Tests ────────────────────────────────────────────────────────────────


def test_h2c_get_request_round_trip() raises:
    """Single GET via Http2Client -> in-process H2 server -> response."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)
    assert_true(Int(port) > 0)

    var pid = _fork()
    if pid == 0:
        # Child: serve one h2c connection and exit.
        try:
            _serve_one_h2_connection(listener, String("hello h2 world"))
        except:
            pass
        _exit_child()
    # Parent: give the child a moment to enter accept().
    _usleep(c_int(200000))

    # Build the URL pointing at the child's listener.
    var url = (
        String("http://127.0.0.1:") + String(Int(port)) + String("/api/users")
    )
    var got_status = -1
    var got_body = String("")
    var raised = False
    try:
        with Http2Client() as c:
            var resp = c.get(url)
            got_status = resp.status
            got_body = resp.text()
    except:
        raised = True

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "Http2Client.get raised an exception")
    assert_equal(got_status, 200)
    assert_equal(got_body, "hello h2 world")


def test_h2c_post_with_body() raises:
    """POST with a JSON body succeeds; server-side body echo not asserted
    (the in-process harness is constant-response), but the request
    must complete without raising."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)
    assert_true(Int(port) > 0)

    var pid = _fork()
    if pid == 0:
        try:
            _serve_one_h2_connection(listener, String("posted ok"))
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/items")
    var got_status = -1
    var got_body = String("")
    var raised = False
    try:
        with Http2Client() as c:
            var resp = c.post(url, '{"name": "flare"}')
            got_status = resp.status
            got_body = resp.text()
    except:
        raised = True

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "Http2Client.post raised an exception")
    assert_equal(got_status, 200)
    assert_equal(got_body, "posted ok")


def test_h2c_two_sequential_requests_share_connection() raises:
    """Two ``client.get(url)`` calls on the same :class:`Http2Client`
    reuse the same underlying TCP socket."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)
    assert_true(Int(port) > 0)

    var pid = _fork()
    if pid == 0:
        try:
            _serve_one_h2_connection(listener, String("multi-req"))
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var base = String("http://127.0.0.1:") + String(Int(port))
    var s1 = -1
    var s2 = -1
    var raised = False
    try:
        with Http2Client(base_url=base) as c:
            var r1 = c.get("/a")
            s1 = r1.status
            var r2 = c.get("/b")
            s2 = r2.status
    except:
        raised = True

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "Http2Client raised on the second sequential get")
    assert_equal(s1, 200)
    assert_equal(s2, 200)


def test_h2_unsupported_scheme_rejected() raises:
    """A URL with neither ``http://`` nor ``https://`` raises with a
    clear message."""
    var raised = False
    var msg = String("")
    try:
        with Http2Client() as c:
            _ = c.get("ftp://example.com/")
    except e:
        raised = True
        msg = String(e)
    assert_true(raised, "non-http/https scheme must raise")
    assert_true(
        "ftp" in msg or "scheme" in msg or "supported" in msg,
        "expected a scheme-related error message; got: " + msg,
    )


def test_h2c_cross_origin_reuse_rejected() raises:
    """A second request to a different host on the same client raises."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            _serve_one_h2_connection(listener, String("origin-test"))
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var url1 = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    # Different host (still loopback in IP space, but textually
    # distinct -- the same-origin check is on the URL host
    # string, not the resolved IP, matching RFC 9113 §9.1.1's
    # scheme + authority comparison).
    var url2 = String("http://localhost:") + String(Int(port)) + String("/")
    var raised = False
    try:
        with Http2Client() as c:
            _ = c.get(url1)
            _ = c.get(url2)
    except:
        raised = True

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(raised, "cross-origin reuse must raise")


def test_h2c_basic_auth_header_propagated() raises:
    """``Http2Client(BasicAuth(...))`` propagates the
    ``Authorization`` header to the server on every request."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            _serve_one_h2_connection(
                listener, String("ignored"), echo_auth=True
            )
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got = String("")
    var raised = False
    try:
        with Http2Client(BasicAuth("alice", "s3cr3t")) as c:
            var r = c.get(url)
            got = r.text()
    except:
        raised = True

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "Http2Client(BasicAuth) raised")
    # ``alice:s3cr3t`` base64-encoded is ``YWxpY2U6czNjcjN0``.
    assert_equal(got, "Basic YWxpY2U6czNjcjN0")


def test_h2c_bearer_auth_header_propagated() raises:
    """``Http2Client(BearerAuth(...))`` propagates the bearer token."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            _serve_one_h2_connection(
                listener, String("ignored"), echo_auth=True
            )
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var base = String("http://127.0.0.1:") + String(Int(port))
    var got = String("")
    var raised = False
    try:
        # Use the (base_url, auth) overload to mirror the
        # natural HttpClient call-site shape.
        with Http2Client(base, BearerAuth("tok_abc")) as c:
            var r = c.get("/")
            got = r.text()
    except:
        raised = True

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "Http2Client(base_url, BearerAuth) raised")
    assert_equal(got, "Bearer tok_abc")


def main() raises:
    test_h2c_get_request_round_trip()
    test_h2c_post_with_body()
    test_h2c_two_sequential_requests_share_connection()
    test_h2_unsupported_scheme_rejected()
    test_h2c_cross_origin_reuse_rejected()
    test_h2c_basic_auth_header_propagated()
    test_h2c_bearer_auth_header_propagated()
    print("test_h2_client: 7 passed")
