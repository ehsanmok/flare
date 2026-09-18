"""Coalesced streaming on the Handler path (v0.10).

The reactor used to pull exactly one chunk per writable edge, so an
N-chunk streaming response cost N trips through the event loop and N
sends. This drives a ``ConnHandle`` over a real loopback pair and counts
``on_writable`` calls: a 16-chunk response must complete in at most ONE
edge, not 16. The de-chunked body is asserted too, so a coalescing bug
that merges frames incorrectly fails here rather than on the wire.

The readable edge that dispatches the request is retried. A non-blocking
server socket can see the request bytes arrive late, and that is a
property of the loopback pair, not of the coalescing path being measured.
"""

from std.collections import Optional
from std.testing import assert_equal, assert_true

from flare.http._server_reactor_impl import (
    ConnHandle,
    STATE_READING,
)
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.handler import FnHandler
from flare.http.request import Request
from flare.http.response import Response, stream_response
from flare.http.server import ServerConfig
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.utils import usleep

comptime _CHUNKS: Int = 16
comptime _CHUNK_BYTES: Int = 256


struct _FixedChunks(ChunkSource, Movable):
    """Yields ``remaining`` chunks of ``_CHUNK_BYTES`` 'a's, then None."""

    var remaining: Int

    def __init__(out self, remaining: Int):
        self.remaining = remaining

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.remaining <= 0:
            return Optional[List[UInt8]]()
        self.remaining -= 1
        var out = List[UInt8](capacity=_CHUNK_BYTES)
        for _ in range(_CHUNK_BYTES):
            out.append(97)  # 'a'
        return Optional[List[UInt8]](out^)


def _stream_handler(req: Request) raises -> Response:
    return stream_response[_FixedChunks](_FixedChunks(_CHUNKS))


def _hex_to_int(s: String) -> Int:
    var acc = 0
    for i in range(s.byte_length()):
        var c = Int(s.unsafe_ptr()[i])
        var d = -1
        if c >= 48 and c <= 57:
            d = c - 48
        elif c >= 97 and c <= 102:
            d = c - 97 + 10
        if d < 0:
            break
        acc = acc * 16 + d
    return acc


def _dechunk(body: String) -> String:
    """De-chunk an RFC 9112 sec 7.1 body (ASCII payloads)."""
    var acc = String("")
    var i = 0
    var n = body.byte_length()
    var bytes = body.as_bytes()
    while i < n:
        var j = i
        while j + 1 < n and not (bytes[j] == 13 and bytes[j + 1] == 10):
            j += 1
        var size = _hex_to_int(String(unsafe_from_utf8=bytes[i:j]))
        i = j + 2
        if size == 0:
            break
        acc += String(unsafe_from_utf8=bytes[i : i + size])
        i += size + 2
    return acc^


def test_stream_coalescing() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    listener.close()

    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    cfg.write_timeout_ms = 0

    var ch = ConnHandle(server^)
    var req = String("GET /stream HTTP/1.1\r\nHost: t\r\n\r\n")
    _ = client.write(req.as_bytes())

    # Dispatch: builds the response and queues the chunked headers.
    #
    # Retried, because one readable edge is not guaranteed to dispatch.
    # The server socket is non-blocking, so if the request bytes written
    # above have not landed in its receive buffer yet, ``on_readable``
    # takes the incomplete-request path and returns with the handle still
    # in STATE_READING, having written nothing. That is a loopback timing
    # detail, not the behaviour under test.
    var h = FnHandler(_stream_handler)
    var reads = 0
    while ch.state == STATE_READING and reads < 64:
        reads += 1
        _ = ch.on_readable(h, cfg)
        if ch.state != STATE_READING:
            break
        usleep(2000)
    assert_true(
        ch.state != STATE_READING,
        "request never dispatched after " + String(reads) + " readable edge(s)",
    )

    # Drive writable edges until the stream finishes. The whole point of
    # the change under test is that this takes one pass, not _CHUNKS.
    var edges = 0
    while ch.state != STATE_READING and edges < 64:
        edges += 1
        var step = ch.on_writable(cfg)
        if step.done:
            break

    # A bound, not an equality: zero would mean the send buffer took the
    # whole 4 KB response inline during dispatch, which is better still.
    # What this guards is the regression -- before coalescing, an N-chunk
    # response cost N edges.
    assert_true(
        edges <= 1,
        String(_CHUNKS)
        + " chunks should cost at most 1 writable edge, took "
        + String(edges),
    )

    # The peer sees well-formed chunked framing and the exact payload.
    var acc = String("")
    var buf = List[UInt8](capacity=8192)
    buf.resize(8192, 0)
    while acc.find("0\r\n\r\n") == -1:
        var n = client.read(buf.unsafe_ptr(), 8192)
        if n <= 0:
            break
        acc += String(unsafe_from_utf8=Span[UInt8, _](buf)[0:n])

    assert_true(
        acc.find("Transfer-Encoding: chunked") != -1,
        "expected chunked framing",
    )
    var sep = acc.find("\r\n\r\n")
    assert_true(sep != -1, "no header terminator")
    var body = String(
        unsafe_from_utf8=acc.as_bytes()[sep + 4 : acc.byte_length()]
    )
    var decoded = _dechunk(body)
    assert_equal(decoded.byte_length(), _CHUNKS * _CHUNK_BYTES)
    for i in range(decoded.byte_length()):
        if decoded.unsafe_ptr()[i] != 97:
            raise Error("payload corrupted at byte " + String(i))

    client.close()
    print(
        "test_stream_coalescing: passed (",
        _CHUNKS,
        "chunks ->",
        edges,
        "edge(s))",
    )


def main() raises:
    test_stream_coalescing()
