"""In-process test client for ``Handler`` implementations.

``TestClient[H]`` is a thin synthesise-request-call-handler-
return-response helper. It exists for the same reason
FastAPI's ``TestClient`` does: handler-level tests want to
exercise the request/response shape without the friction of a
real socket, a real reactor, or a real port assignment.

Usage::

    var client = TestClient(MyHandler())
    var resp = client.get("/users/42")
    assert_equal(resp.status, 200)

The client supports the seven standard HTTP methods (GET, POST,
PUT, PATCH, DELETE, HEAD, OPTIONS); each accepts an optional
body and optional headers, and returns the captured
``Response``.

The client does not run any middleware *for* the caller -- the
``handler`` passed in must already be the fully-composed stack
the test wants to exercise. Compose your middleware once at
construction time, then run as many requests through it as the
test needs.
"""

from std.collections import List
from std.memory import Span

from flare.http.handler import Handler
from flare.http.headers import HeaderMap
from flare.http.proto.ascii import ascii_lower
from flare.http.request import Request
from flare.http.response import Response
from flare.http2 import Http2Connection, Http2ClientConnection, HpackHeader
from flare.net import IpAddr, SocketAddr


struct TestClient[H: Handler](ImplicitlyDestructible, Movable):
    """Wraps a ``Handler`` and exposes per-method synth helpers.

    The handler is moved in at construction; subsequent calls
    take a borrow. Two helper shapes are available per method:
    a bare ``get(path)`` shape for cases where no body / no
    custom headers are needed, and a ``request(method, path,
    body, headers)`` shape for the full surface.
    """

    var handler: Self.H

    def __init__(out self, var handler: Self.H):
        self.handler = handler^

    def request(
        self,
        method: String,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        """Synth a ``Request`` from the arguments and run it
        through ``self.handler``. The peer address is fixed to
        ``127.0.0.1:0`` and ``expose_errors`` is True so
        handler-level errors surface in the body (a test-mode
        affordance; production runs default to False)."""
        var req = Request(
            method=method,
            url=path,
            body=body^,
            version=String("HTTP/1.1"),
            peer=SocketAddr(IpAddr("127.0.0.1", False), UInt16(0)),
            expose_errors=True,
        )
        req.headers = headers^
        return self.handler.serve(req)

    def get(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("GET"), path, headers=headers^)

    def head(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("HEAD"), path, headers=headers^)

    def options(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("OPTIONS"), path, headers=headers^)

    def post(
        self,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        return self.request(String("POST"), path, body=body^, headers=headers^)

    def put(
        self,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        return self.request(String("PUT"), path, body=body^, headers=headers^)

    def patch(
        self,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        return self.request(String("PATCH"), path, body=body^, headers=headers^)

    def delete(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("DELETE"), path, headers=headers^)


struct H2cTestClient[H: Handler](ImplicitlyDestructible, Movable):
    """In-process HTTP/2-cleartext (h2c) test client for a ``Handler``.

    Where :class:`TestClient` calls ``handler.serve`` on a synthesized
    :class:`Request` directly, :class:`H2cTestClient` drives the request
    through the *real* HTTP/2 stack -- the byte-level
    :class:`flare.http2.Http2ClientConnection` and
    :class:`flare.http2.Http2Connection` exchange frames in memory (preface,
    SETTINGS, HPACK-encoded HEADERS, DATA) so the h2 framing + HPACK
    request-assembly + response-encoding path gets coverage with no TLS,
    no socket, and no reactor. The handler runs server-side exactly as
    the live reactor invokes it.

    Usage::

        var client = H2cTestClient(MyHandler())
        var resp = client.get("/users/42")
        assert_equal(resp.status, 200)

    The handler is moved in at construction; each request spins up a
    fresh client + server driver pair so requests are independent (no
    shared HPACK dynamic-table state across calls).

    This does one request/response round per call over a fresh
    connection pair -- no multiplexing or connection reuse across calls,
    and request/response bodies must fit the default flow-control window
    (no WINDOW_UPDATE-gated body pumping here). That is plenty to cover
    the handler-facing h2 path; multi-stream / large-body coverage stays
    with the live reactor e2e tests."""

    var handler: Self.H

    def __init__(out self, var handler: Self.H):
        self.handler = handler^

    def request(
        self,
        method: String,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
        authority: String = String("testserver"),
    ) raises -> Response:
        """Drive one request through the in-process h2c client + server
        and return the :class:`Response` the handler produced.

        Builds the request on a fresh client driver, pumps the framed
        bytes into a fresh server driver, dispatches the assembled
        :class:`Request` to ``self.handler``, frames the response back,
        and decodes it on the client driver."""
        var client = Http2ClientConnection()
        var server = Http2Connection()
        var sid = client.next_stream_id()
        var extra = List[HpackHeader]()
        for i in range(len(headers._keys)):
            extra.append(
                HpackHeader(
                    ascii_lower(headers._keys[i]), headers._values[i].copy()
                )
            )
        client.send_request(
            sid,
            method,
            String("http"),
            authority,
            path,
            extra,
            Span[UInt8, _](body),
        )
        # Exchange frames until the response is ready. Two rounds suffice
        # for a single unmultiplexed request (round 1: request -> handler
        # -> response; round 2 drains any trailing SETTINGS ACK), but the
        # bounded loop tolerates an extra control-frame round.
        var ready = False
        for _ in range(8):
            server.feed(Span[UInt8, _](client.drain()))
            var done = server.take_completed_streams()
            for di in range(len(done)):
                var rid = done[di]
                var req = server.take_request(rid)
                var resp = self.handler.serve(req)
                server.emit_response(rid, resp^)
            client.feed(Span[UInt8, _](server.drain()))
            if client.response_ready(sid):
                ready = True
                break
        if not ready:
            raise Error(
                "h2c test client: handler produced no response for "
                + method
                + " "
                + path
            )
        var r = client.take_response(sid)
        var out = Response(r.status, String(""), r.body.copy())
        for i in range(len(r.headers)):
            out.headers.set(r.headers[i].name, r.headers[i].value)
        return out^

    def get(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("GET"), path, headers=headers^)

    def head(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("HEAD"), path, headers=headers^)

    def options(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("OPTIONS"), path, headers=headers^)

    def post(
        self,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        return self.request(String("POST"), path, body=body^, headers=headers^)

    def put(
        self,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        return self.request(String("PUT"), path, body=body^, headers=headers^)

    def patch(
        self,
        path: String,
        var body: List[UInt8] = List[UInt8](),
        var headers: HeaderMap = HeaderMap(),
    ) raises -> Response:
        return self.request(String("PATCH"), path, body=body^, headers=headers^)

    def delete(
        self, path: String, var headers: HeaderMap = HeaderMap()
    ) raises -> Response:
        return self.request(String("DELETE"), path, headers=headers^)
