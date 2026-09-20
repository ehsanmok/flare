"""Example -- HTTPS server with streaming, on the unified reactor.

`basic/tls.mojo` shows the TLS *client*; this is the server side. Flare
terminates TLS in-process and serves ordinary `Handler` / `Router` code
over the encrypted connection -- no reverse proxy required. The canonical
shape is one call to bind, one to serve::

    var srv = HttpServer.bind_tls(
        SocketAddr.localhost(8443),
        cert_file="server.crt",
        key_file="server.key",
        alpn=["h2", "http/1.1"],
    )
    srv.serve(router^, num_workers=4)

`bind_tls` loads the PEM cert/key into a server `SSL_CTX` and advertises
the given ALPN protocols. TLS is a property of the bind, not of serving,
so the serve call is the ordinary one: the handshake runs on the reactor
as its own connection kind, so many TLS connections are in flight at
once and `num_workers > 1` spreads them across cores. (`serve_tls` was
the v0.10 spelling of that line. It still works and goes away in 0.12.) When the handshake completes, the negotiated ALPN picks
the protocol -- `h2` gets an HTTP/2 connection, anything else gets
HTTP/1.1 -- and from there it is the same parsing and serialisation the
plaintext path uses, just through `SSL_read` / `SSL_write`.

Streaming composes for free: a handler that returns `stream_response(src)`
is emitted with `Transfer-Encoding: chunked` framing, pulled chunk by
chunk and written as ciphertext. The same handler streams byte-identically
on h1 (chunked), h2 (DATA frames), h3 (DATA frames), and https (chunked
over `SSL_write`) -- the wire is an implementation detail.

This demo is self-contained: it exercises the handler + streaming source
in-process (deterministic output), then binds a real HTTPS listener on an
ephemeral port using the repo's test cert to prove `bind_tls` loads the
cert and binds the socket. It does not enter the serve loop, which blocks.

Run:
    pixi run example-https
"""

from flare.prelude import *


def _index(req: Request) raises -> Response:
    """A plain buffered response -- served over TLS unchanged."""
    return ok("hello over TLS")


struct _LogTail(ChunkSource, Movable):
    """A tiny streaming source: emits a fixed set of log lines, one chunk
    each, then ends. A real tail would block on new lines instead."""

    var lines: List[String]
    var idx: Int

    def __init__(out self, var lines: List[String]):
        self.lines = lines^
        self.idx = 0

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.idx >= len(self.lines):
            return None
        var line = self.lines[self.idx]
        self.idx += 1
        var out = List[UInt8]()
        for b in line.as_bytes():
            out.append(b)
        return out^


def _logs(req: Request) raises -> Response:
    """A streaming response -- chunked over TLS, pulled lazily."""
    var lines = List[String]()
    lines.append("[log] boot\n")
    lines.append("[log] listening\n")
    lines.append("[log] request served\n")
    var resp = stream_response(_LogTail(lines^))
    resp.headers.set("content-type", "text/plain")
    return resp^


def _drain(var resp: Response) raises -> String:
    """Pull a streaming Response's body to a String, in-process."""
    var out = List[UInt8]()
    var box = resp.body_stream.take()
    var sentinel = Cancel.never()
    while True:
        var maybe = box.next(sentinel)
        if not maybe:
            break
        var chunk = maybe.value().copy()
        for i in range(len(chunk)):
            out.append(chunk[i])
    return String(unsafe_from_utf8=Span[UInt8, _](out))


def main() raises:
    print("=== flare Example: HTTPS server (TLS-terminated H1) ===")
    print()

    # 1) An ordinary buffered handler -- identical code to a plaintext
    #    server; TLS termination is transparent to the handler.
    print("[1] buffered handler over TLS:")
    var r = Router()
    r.get("/", _index)
    r.get("/logs", _logs)
    var buffered = _index(Request("GET", "/"))
    print("    GET /      ->", buffered.status, buffered.text())
    print()

    # 2) A streaming handler -- `stream_response` yields a chunked body
    #    that rides `SSL_write` on the wire. Drained here in-process so
    #    the demo is deterministic.
    print("[2] streaming handler (chunked over SSL_write):")
    var streamed = _logs(Request("GET", "/logs"))
    print("    GET /logs  is streaming:", Bool(streamed.body_stream))
    print("    drained body:")
    var body = _drain(streamed^)
    for line in body.splitlines():
        print("     ", line)
    print()

    # 3) The real bind: load the cert/key and bind an HTTPS listener on an
    #    ephemeral port, advertising h2 ahead of http/1.1 so a modern
    #    client negotiates HTTP/2 over the same socket. `serve(r^)`
    #    would then run the reactor (omitted here so the example exits).
    print("[3] HttpServer.bind_tls (real cert load + socket bind):")
    try:
        var alpn = List[String]()
        alpn.append("h2")
        alpn.append("http/1.1")
        var srv = HttpServer.bind_tls(
            SocketAddr.localhost(0),
            cert_file="tests/certs/server.crt",
            key_file="tests/certs/server.key",
            alpn=alpn^,
        )
        print("    bound HTTPS listener at", String(srv.local_addr()))
        print("    advertising ALPN: h2, http/1.1")
        print("    -> srv.serve(r^, num_workers=4) runs the reactor")
    except e:
        print("    (skipped live bind:", String(e), ")")

    print()
    print("=== Example complete ===")
