"""A request body that keeps arriving after the handler has started.

With ``Http3Config.stream_request_bodies`` an HTTP/3 request is handed
to the handler on its HEADERS; the HTTP/3 driver appends the body to a
shared :class:`BodyPipe` as DATA arrives, and the handler reads it with
:meth:`flare.http.Request.body_stream`, a :trait:`ChunkSource` it can
put on its response (echo, transform, proxy) without blocking the loop.
"""

from std.memory import ArcPointer

from .body import ChunkSource
from .cancel import Cancel


struct BodyPipe(Movable):
    var data: List[UInt8]
    """Body bytes received and not yet read."""
    var done: Bool
    """The request ended (FIN) and everything is in :attr:`data`."""
    var failed: Bool
    """The request stream was reset or abandoned."""

    def __init__(out self, var data: List[UInt8], done: Bool):
        self.data = data^
        self.done = done
        self.failed = False


struct BodyPipeSource(ChunkSource):
    """Reads a :class:`BodyPipe`: data as it arrives, an empty chunk
    while there is none yet, ``None`` once the body has ended."""

    var pipe: ArcPointer[BodyPipe]

    def __init__(out self, pipe: ArcPointer[BodyPipe]):
        self.pipe = pipe

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self.pipe[].failed or cancel.cancelled():
            raise Error("request body aborted")
        if len(self.pipe[].data) > 0:
            var out = List[UInt8]()
            swap(out, self.pipe[].data)
            return out^
        if self.pipe[].done:
            return None
        return List[UInt8]()
