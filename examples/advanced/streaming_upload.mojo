"""Upload a body larger than memory, one chunk at a time.

``send_chunked`` pulls from a ``ChunkSource`` and writes each chunk as
it arrives, so the body is never materialised. Two shapes:

- **Unknown length** -- the default. Framed with
  ``Transfer-Encoding: chunked``.
- **Known length** -- pass ``body_size``. Framed with
  ``Content-Length``, which is cheaper on the wire and lets the origin
  size its buffer up front.

A source that raises mid-body propagates *without* writing the chunked
terminator, so a truncated upload is never framed as a complete one.

Run:
    pixi run mojo -I . examples/advanced/streaming_upload.mojo
"""

from std.collections import Optional

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.net import SocketAddr
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _CHUNKS: Int = 16
comptime _CHUNK_BYTES: Int = 4096


struct CountingSource(ChunkSource, Movable):
    """Yields ``_CHUNKS`` fixed-size chunks and then stops.

    A real one would read a file, pull from a queue, or wrap a
    generator. The only contract is: return the next chunk, or ``None``
    when done, and honour ``cancel`` between chunks.
    """

    var remaining: Int

    def __init__(out self, count: Int):
        self.remaining = count

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.remaining <= 0:
            return Optional[List[UInt8]]()
        self.remaining -= 1
        var out = List[UInt8](capacity=_CHUNK_BYTES)
        for _ in range(_CHUNK_BYTES):
            out.append(97)
        return Optional[List[UInt8]](out^)


def _sink(req: Request) raises -> Response:
    """Report how many body bytes arrived."""
    return ok(String(len(req.body)))


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_sink)
        except:
            pass
        exit()
    usleep(300000)

    var url = "http://127.0.0.1:" + String(port) + "/upload"
    var total = _CHUNKS * _CHUNK_BYTES

    try:
        var c = HttpClient()

        # Known length: Content-Length framing, no per-chunk overhead.
        var src = CountingSource(_CHUNKS)
        var r = c.send_chunked(
            "POST", url, src, "application/octet-stream", body_size=total
        )
        print("known-length upload ->", r.status, "server saw", r.text())
    except e:
        print("upload failed:", e)

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    print("ok")
