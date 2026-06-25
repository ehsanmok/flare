"""End-to-end tests for the wired HttpClient ergonomics (W1).

Drives :class:`flare.http.HttpClient` against a forked, path-routed
server and verifies the additive client UX:

* Redirect policy: ``follow_all`` lands on the target; ``deny`` surfaces
  the 3xx unfollowed; ``same_origin_only`` rejects a cross-origin hop.
* Auto-decompress: a ``Content-Encoding: gzip`` body is transparently
  decoded and the header stripped (and the opt-out keeps raw bytes).
* Cookie jar: a ``Set-Cookie`` is captured and replayed as a ``Cookie``
  request header on the next request.
* Retry: a flaky origin (503, 503, 200 via a file counter) recovers
  under ``with_retry``.

The routed handler keys on the request target (``req.url`` is the path
on the server side).
"""

from std.testing import assert_equal, assert_true

from flare.http import HttpClient, HttpServer, Request, Response
from flare.http import RedirectPolicy, RetryPolicy
from flare.http._server.responses import ok, redirect
from flare.http.encoding import compress_gzip
from flare.net import SocketAddr
from flare.testing import fork_server, kill_forked_server


# ponytail: fixed temp path for the flaky-origin counter; the test
# truncates it before forking. Single-writer (one forked child), so a
# fixed name is safe here. Upgrade path: a per-test unique temp name.
comptime _FLAKY_COUNTER = "/tmp/flare_client_ux_retry.cnt"


def _ux(req: Request) raises -> Response:
    var path = req.url
    if path.startswith("/redir-cross"):
        # Cross-origin (different port) absolute redirect target.
        return redirect("http://127.0.0.1:1/x", 302)
    if path.startswith("/redir"):
        return redirect("/landing", 302)
    if path.startswith("/landing"):
        return ok("landed")
    if path.startswith("/setcookie"):
        var resp = ok("set")
        resp.headers.set("Set-Cookie", "sid=abc123; Path=/")
        return resp^
    if path.startswith("/echo-cookie"):
        return ok(req.headers.get("Cookie"))
    if path.startswith("/gzip"):
        var raw = String("hello-decompressed-body").as_bytes()
        var gz = compress_gzip(Span[UInt8, _](raw))
        var resp = Response(200, "", gz^)
        resp.headers.set("Content-Encoding", "gzip")
        return resp^
    if path.startswith("/flaky"):
        var prior = 0
        try:
            with open(_FLAKY_COUNTER, "r") as f:
                prior = f.read().byte_length()
        except:
            pass
        var buf = String("")
        for _ in range(prior + 1):
            buf += "x"
        with open(_FLAKY_COUNTER, "w") as f:
            f.write(buf)
        if prior + 1 <= 2:
            return Response(503, "flaky", List[UInt8]())
        return ok("recovered")
    return ok("root")


def _base(port: UInt16) -> String:
    return String("http://127.0.0.1:") + String(Int(port))


def test_redirect_follow_all_lands() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _ux)

    var text = String("")
    var status = -1
    var raised = False
    try:
        with HttpClient() as c:
            var r = c.get(_base(port) + "/redir")
            status = r.status
            text = r.text()
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "follow_all redirect raised")
    assert_equal(status, 200)
    assert_equal(text, "landed")


def test_redirect_deny_surfaces_3xx() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _ux)

    var status = -1
    var location = String("")
    var raised = False
    try:
        with HttpClient().with_redirect_policy(RedirectPolicy.deny()) as c:
            var r = c.get(_base(port) + "/redir")
            status = r.status
            location = r.headers.get("Location")
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "deny redirect raised")
    assert_equal(status, 302)
    assert_equal(location, "/landing")


def test_redirect_same_origin_rejects_cross_origin() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _ux)

    var raised = False
    try:
        with HttpClient().with_redirect_policy(
            RedirectPolicy.same_origin_only()
        ) as c:
            _ = c.get(_base(port) + "/redir-cross")
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(raised, "cross-origin redirect should be rejected")


def test_auto_decompress_gzip() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _ux)

    var text = String("")
    var enc = String("?")
    var raised = False
    try:
        with HttpClient() as c:
            var r = c.get(_base(port) + "/gzip")
            text = r.text()
            enc = r.headers.get("Content-Encoding")
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "gzip auto-decompress raised")
    assert_equal(text, "hello-decompressed-body")
    assert_equal(enc, "")  # header stripped after decoding


def test_auto_decompress_opt_out_keeps_raw() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _ux)

    var enc = String("")
    var decoded_len = -1
    var raised = False
    try:
        with HttpClient(auto_decompress=False) as c:
            var r = c.get(_base(port) + "/gzip")
            enc = r.headers.get("Content-Encoding")
            decoded_len = len(r.body)
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "opt-out raised")
    assert_equal(enc, "gzip")  # header preserved, body still compressed
    assert_true(decoded_len > 0)


def test_cookie_jar_captures_and_replays() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _ux)

    var echoed = String("")
    var raised = False
    try:
        with HttpClient().with_cookies() as c:
            _ = c.get(_base(port) + "/setcookie")  # captures Set-Cookie
            var r = c.get(_base(port) + "/echo-cookie")  # replays Cookie
            echoed = r.text()
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "cookie round-trip raised")
    assert_equal(echoed, "sid=abc123")


def test_retry_recovers_flaky_origin() raises:
    # Truncate the flaky counter so the child starts at zero.
    with open(_FLAKY_COUNTER, "w") as f:
        f.write("")

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _ux)

    var status = -1
    var text = String("")
    var raised = False
    try:
        var pol = RetryPolicy()
        pol.max_attempts = 3
        with HttpClient().with_retry(pol) as c:
            var r = c.get(_base(port) + "/flaky")
            status = r.status
            text = r.text()
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "retry round-trip raised")
    assert_equal(status, 200)
    assert_equal(text, "recovered")


def main() raises:
    test_redirect_follow_all_lands()
    test_redirect_deny_surfaces_3xx()
    test_redirect_same_origin_rejects_cross_origin()
    test_auto_decompress_gzip()
    test_auto_decompress_opt_out_keeps_raw()
    test_cookie_jar_captures_and_replays()
    test_retry_recovers_flaky_origin()
    print("test_client_ux: 7 passed")
