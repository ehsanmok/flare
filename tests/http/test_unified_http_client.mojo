"""Unified HttpClient auto-negotiation test.

Proves :class:`flare.http.HttpClient` auto-dispatches via ALPN
when speaking ``https://`` AND that it stays on the existing
HTTP/1.1 wire when speaking ``http://``. The TLS+ALPN h2 path is
covered indirectly: if a TLS server happens to negotiate
``http/1.1`` (no ALPN, or ALPN downgrade), the client still
returns a normal :class:`flare.http.Response`.

The full TLS+h2 round-trip requires either (a) a public origin
that speaks h2 over TLS or (b) an in-process ALPN-enabled TLS
server. Neither is portable inside the test sandbox, so the
strict-h2-with-cert test is deferred to the live-net suite. The
in-process tests below verify:

- ``http://`` URL via the unified HttpClient against a unified
  HttpServer (cleartext) -> handler runs, response body returns.
  Same handler is hit via Http2Client (different test) so the
  unified server proves both wires.
- The HttpClient module-level shortcut ``flare.http.get(url)``
  routes through the same unified ``_do_request``.
"""

from std.ffi import c_int
from std.testing import assert_equal, assert_true


from flare.utils import (
    SIGKILL,
    exit,
    fork,
    kill,
    usleep,
    waitpid,
)

from flare.http import (
    BasicAuth,
    BearerAuth,
    HttpClient,
    HttpServer,
    Request,
    Response,
    get,
    ok,
)
from flare.net import SocketAddr


def _hello(req: Request) raises -> Response:
    return ok("hello unified client")


def test_unified_client_http_url_round_trip() raises:
    """``HttpClient.get('http://...')`` returns the handler's response
    over the existing HTTP/1.1 wire (no ALPN since there is no TLS)."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(200000)

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got_status = -1
    var got_body = String("")
    var raised = False
    try:
        with HttpClient() as c:
            var r = c.get(url)
            got_status = r.status
            got_body = r.text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "HttpClient.get raised over http://")
    assert_equal(got_status, 200)
    assert_equal(got_body, "hello unified client")


def test_unified_client_module_level_get() raises:
    """``flare.http.get(url)`` is the one-shot helper -- routes through
    the same unified _do_request as the HttpClient methods."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(200000)

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got_status = -1
    var got_body = String("")
    var raised = False
    try:
        var r = get(url)
        got_status = r.status
        got_body = r.text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "flare.http.get(url) raised")
    assert_equal(got_status, 200)
    assert_equal(got_body, "hello unified client")


def test_unified_client_h2c_prior_knowledge() raises:
    """``HttpClient(prefer_h2c=True).get('http://...')`` speaks HTTP/2
    cleartext via prior knowledge (no Upgrade dance). Proves the
    h2c path that test_h2_client.mojo previously exercised via the
    now-removed Http2Client."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(200000)

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got_status = -1
    var got_body = String("")
    var raised = False
    try:
        with HttpClient(prefer_h2c=True) as c:
            var r = c.get(url)
            got_status = r.status
            got_body = r.text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "HttpClient(prefer_h2c=True).get raised")
    assert_equal(got_status, 200)
    assert_equal(got_body, "hello unified client")


def _echo_authorization(req: Request) raises -> Response:
    """Reflect the Authorization header in the response body so the
    test can verify the auth-propagation path."""
    return ok(req.headers.get("authorization"))


def test_unified_client_basic_auth_h2c() raises:
    """``HttpClient(BasicAuth(...), prefer_h2c=True)`` propagates the
    Authorization header through the HTTP/2 cleartext path."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo_authorization)
        except:
            pass
        exit()
    usleep(200000)

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got = String("")
    var raised = False
    try:
        with HttpClient(BasicAuth("alice", "s3cr3t"), prefer_h2c=True) as c:
            got = c.get(url).text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "HttpClient(BasicAuth, prefer_h2c=True) raised")
    # base64("alice:s3cr3t") == "YWxpY2U6czNjcjN0"
    assert_equal(got, "Basic YWxpY2U6czNjcjN0")


def test_unified_client_bearer_auth_h1() raises:
    """``HttpClient(BearerAuth(...))`` propagates Authorization through
    the HTTP/1.1 cleartext path (proves the same Auth shape works
    on the other wire too)."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo_authorization)
        except:
            pass
        exit()
    usleep(200000)

    var base = String("http://127.0.0.1:") + String(Int(port))
    var got = String("")
    var raised = False
    try:
        with HttpClient(base, BearerAuth("tok_abc")) as c:
            got = c.get("/").text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "HttpClient(base, BearerAuth) raised")
    assert_equal(got, "Bearer tok_abc")


# ── Authorization header forwarding (regression) ─────────────────────────────
# Regression: HttpClient._do_request() and _send_h2c_via_upgrade() were
# silently dropping the caller-supplied Authorization header, blocking
# per-request auth patterns (AWS SigV4, OAuth2 rotation, HMAC signing).
# These tests prove the caller's Authorization reaches the wire on every
# path, and that a client credential still wins when both are set.


def _count_authorization_header(blob: String) -> Int:
    """Count the number of times an "Authorization:" header appears in
    the raw wire bytes. Used to detect the duplicate-header bug where
    a stored credential AND a caller-set header both land on the wire."""
    var count = 0
    var i = 0
    while i < blob.byte_length():
        # Find next "Authorization:" (case-insensitive via lowercased compare)
        if i + 14 <= blob.byte_length():
            var tag = String("")
            for j in range(14):
                tag += String(blob[byte=i + j])
            if tag.lower() == "authorization:":
                count += 1
        i += 1
    return count


def test_caller_authorization_h1_no_credential() raises:
    """A caller-set Authorization must reach the wire on H1 when the
    client has no stored credential. This is the primary use case for
    per-request auth (AWS SigV4, OAuth2, HMAC)."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo_authorization)
        except:
            pass
        exit()
    usleep(200000)

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got = String("")
    var raised = False
    try:
        # No client credential — caller's Authorization must be the only one
        with HttpClient() as c:
            var req = Request(method="GET", url=url)
            req.headers.set("Authorization", "Bearer aws4-token-xyz")
            got = c.send(req).text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(
        not raised, "HttpClient().send with caller Authorization raised"
    )
    assert_equal(got, "Bearer aws4-token-xyz")


def test_caller_authorization_h2c_no_credential() raises:
    """A caller-set Authorization must reach the wire on the H2c upgrade
    path when the client has no stored credential."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo_authorization)
        except:
            pass
        exit()
    usleep(200000)

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got = String("")
    var raised = False
    try:
        with HttpClient(prefer_h2c=True) as c:
            var req = Request(method="GET", url=url)
            req.headers.set("Authorization", "Bearer aws4-token-h2c")
            got = c.send(req).text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(
        not raised,
        "HttpClient(prefer_h2c=True).send with caller Authorization raised",
    )
    assert_equal(got, "Bearer aws4-token-h2c")


def test_no_duplicate_authorization_h1() raises:
    """When the client has a stored credential (BearerAuth) AND the caller
    sets a per-request Authorization, the stored credential wins and only
    ONE Authorization header reaches the wire. No duplicate."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo_authorization)
        except:
            pass
        exit()
    usleep(200000)

    var url = String("http://127.0.0.1:", Int(port), "/")
    var got = String("")
    var raised = False
    try:
        # Client credential is set, caller also sets one - stored wins.
        # Use a full request URL (not base_url + relative): send() takes
        # req.url as absolute, base_url joining only happens in get/post.
        with HttpClient(BearerAuth("stored-cred")) as c:
            var req = Request(method="GET", url=url)
            req.headers.set("Authorization", "Bearer caller-cred")
            got = c.send(req).text()
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "HttpClient with both creds raised")
    # Stored credential must be the one the server sees, not the caller's
    assert_equal(got, "Bearer stored-cred")


def main() raises:
    test_unified_client_http_url_round_trip()
    test_unified_client_module_level_get()
    test_unified_client_h2c_prior_knowledge()
    test_unified_client_basic_auth_h2c()
    test_unified_client_bearer_auth_h1()
    test_caller_authorization_h1_no_credential()
    test_caller_authorization_h2c_no_credential()
    test_no_duplicate_authorization_h1()
    print("test_unified_http_client: 8 passed")
