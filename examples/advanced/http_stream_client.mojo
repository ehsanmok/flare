"""Stream a response body without buffering it.

``get_streaming`` takes either scheme and follows whatever the
handshake settles on: HTTP/2 when ALPN says ``h2``, HTTP/1.1 otherwise,
and the same call works on ``http://``. The body arrives through
``read_chunk``, so a response larger than memory costs one buffer
rather than one allocation the size of the body.

Run:
    pixi run mojo -I . examples/advanced/http_stream_client.mojo

This example serves itself: it starts a local server in a forked child
so it needs no network. Point ``_URL`` at a real origin to watch
``protocol()`` report ``h2``.
"""

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import SocketAddr
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _BODY_CHUNKS: Int = 64
comptime _CHUNK_BYTES: Int = 1024


def _big(req: Request) raises -> Response:
    """Return 64 KiB so the read loop below runs more than once."""
    var body = String("")
    for _ in range(_BODY_CHUNKS):
        body += String("x") * _CHUNK_BYTES
    return ok(body)


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_big)
        except:
            pass
        exit()
    usleep(300000)

    var url = "http://127.0.0.1:" + String(port) + "/"
    var total = 0
    var pulls = 0
    var wire: String
    try:
        var c = HttpClient()
        var r = c.get_streaming(url)
        r.raise_for_status()
        wire = r.protocol()
        print("status:", r.status, "on", wire)
        print("content-type:", r.header("content-type"))

        # The loop that matters: pull until read_chunk returns empty.
        # Nothing here holds more than one chunk at a time.
        while True:
            var chunk = r.read_chunk(8192)
            if len(chunk) == 0:
                break
            total += len(chunk)
            pulls += 1
        r.close()
    except e:
        print("streaming failed:", e)

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    print("read", total, "bytes in", pulls, "pulls")
    if total != _BODY_CHUNKS * _CHUNK_BYTES:
        raise Error(
            "expected "
            + String(_BODY_CHUNKS * _CHUNK_BYTES)
            + " bytes, got "
            + String(total)
        )
    print("ok")
