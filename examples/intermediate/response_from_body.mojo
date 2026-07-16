"""Opt-in Response[B: Body] ergonomics: `response_from_body`.

`response_from_body[B: Body](body, status, reason)` lowers ANY `Body`
impl into the concrete `Response` returned by the normal `Handler` path
-- no generic `Response[B]` type (which would erase to `InlineBody` at
every router thunk boundary anyway), and no change to the hot-path
`Response`. A body that knows its length buffers (`Content-Length`); an
open-ended body streams (`Transfer-Encoding: chunked`) via the K1
`body_stream` path.

This forks a real `HttpServer`, hits both routes with the real
`HttpClient`, and prints the responses.

Run:
    pixi run example-response-from-body
"""

from std.collections import Optional

from flare.http import (
    Body,
    Cancel,
    ChunkedBody,
    ChunkSource,
    HttpClient,
    InlineBody,
    Request,
    Response,
    Router,
    response_from_body,
)
from flare.http.server import HttpServer
from flare.net import SocketAddr
from flare.testing import fork_server, kill_forked_server


struct _Lines(ChunkSource, Copyable, Movable):
    """Open-ended body: yields ``n`` ``line k\\n`` chunks (no fixed length)."""

    var i: Int
    var n: Int

    def __init__(out self, n: Int):
        self.i = 0
        self.n = n

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.i >= self.n:
            return Optional[List[UInt8]]()
        var s = "line " + String(self.i) + "\n"
        self.i += 1
        var out = List[UInt8]()
        for b in s.as_bytes():
            out.append(b)
        return Optional[List[UInt8]](out^)


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var bs = s.as_bytes()
    for i in range(len(bs)):
        out.append(bs[i])
    return out^


def buffered(req: Request) raises -> Response:
    # Known-length Body -> buffered Response (Content-Length framing).
    var body = InlineBody(_bytes("hello from a Body impl"))
    return response_from_body[InlineBody](body^, 200, "OK")


def streamed(req: Request) raises -> Response:
    # Open-ended Body -> chunk-streamed Response (body_stream / chunked).
    var body = ChunkedBody[_Lines](_Lines(3))
    return response_from_body[ChunkedBody[_Lines]](body^, 200, "OK")


def main() raises:
    print("=== flare response_from_body example ===")

    var r = Router()
    r.get("/buffered", buffered)
    r.get("/streamed", streamed)

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    print("[server] listening on 127.0.0.1:" + String(port))
    var pid = fork_server(srv^, r^)

    var base = "http://127.0.0.1:" + String(port)
    with HttpClient(base_url=base) as c:
        var b = c.get("/buffered")
        print("GET /buffered ->", b.status, "|", b.text())
        var s = c.get("/streamed")
        print("GET /streamed ->", s.status, "|", s.text())

    kill_forked_server(pid)
    print("=== done ===")
