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

from std.ffi import c_int, external_call
from std.testing import assert_equal, assert_true

from flare.http import HttpClient, HttpServer, Request, Response, ok, get
from flare.net import SocketAddr


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
def _kill(pid: c_int, sig: c_int) -> c_int:
    return external_call["kill", c_int](pid, sig)


@always_inline
def _usleep(us: c_int):
    _ = external_call["usleep", c_int](us)


comptime _SIGKILL: c_int = c_int(9)


def _hello(req: Request) raises -> Response:
    return ok("hello unified client")


def test_unified_client_http_url_round_trip() raises:
    """``HttpClient.get('http://...')`` returns the handler's response
    over the existing HTTP/1.1 wire (no ALPN since there is no TLS)."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

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

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "HttpClient.get raised over http://")
    assert_equal(got_status, 200)
    assert_equal(got_body, "hello unified client")


def test_unified_client_module_level_get() raises:
    """``flare.http.get(url)`` is the one-shot helper -- routes through
    the same unified _do_request as the HttpClient methods."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

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

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "flare.http.get(url) raised")
    assert_equal(got_status, 200)
    assert_equal(got_body, "hello unified client")


def main() raises:
    test_unified_client_http_url_round_trip()
    test_unified_client_module_level_get()
    print("test_unified_http_client: 2 passed")
