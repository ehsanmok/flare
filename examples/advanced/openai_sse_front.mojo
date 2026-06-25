"""Example -- an OpenAI-shaped SSE front over a streaming token backend.

The design-0.9 payoff: a front that relays an upstream token stream to a
client as OpenAI ``chat.completion.chunk`` Server-Sent-Events, with
end-to-end watermark backpressure, in a handful of safe lines on top of
flare. The front names zero file descriptors, zero ``Span[UInt8, _]``,
zero ``Dict`` connection tables, and closes nothing by hand -- the
framework owns the reactor, the per-connection lifecycle, and the
upstream source's lifetime.

The composable pieces, all from ``flare``:

- ``StreamHandler`` / ``StreamConn`` -- the typed streaming server. The
  handler's fields are its shared state; the framework hands it a
  ``StreamConn`` per event.
- ``UpstreamChunkSource.connect(path)`` -- a chunk source dialed to a
  backend over a Unix socket; the framework watches its fd.
- ``conn.upstream().poll(cancel)`` -- pull one ready token chunk without
  blocking; ``conn.send(text)`` writes the shaped SSE frame downstream.
- watermark backpressure -- ``set_watermarks(hi, lo)`` makes the reactor
  stop reading the backend while the client is slow, so a slow consumer
  cannot force unbounded buffering.

Protocol shaping (the OpenAI SSE envelope) lives here in the example,
not in flare -- the library streams bytes; the application decides the
wire shape (per the design doc's "out of scope for flare").

The example forks a token-generator backend (FrameMux CHUNK frames with
gaps, like a real generator), forks the SSE front, then connects a plain
TCP client and prints the relayed ``data:`` frames.

Run:
    pixi run example-openai-sse-front
"""

from flare.http import (
    HttpServer,
    StreamConn,
    StreamHandler,
    UpstreamChunkSource,
)
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.uds import FrameMux, UnixListener, UnixStream
from flare.uds._libc import unlink_path
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


# ── SSE shaping helpers (the application's wire shape) ───────────────────────


def _push(mut buf: List[UInt8], s: String):
    """Append a String's UTF-8 bytes to ``buf`` (keeps the front
    Span-free at the call site)."""
    for b in s.as_bytes():
        buf.append(b)


def _sse_token_frame(token: List[UInt8]) -> List[UInt8]:
    """Wrap one upstream token as an OpenAI ``chat.completion.chunk``
    SSE frame: ``data: {json}\\n\\n``.

    ponytail: the token content is spliced into the JSON verbatim (no
    escaping). Sound here because the backend emits ASCII tokens; the
    upgrade path is a JSON string-escape pass if untrusted tokens flow.
    """
    var buf = List[UInt8]()
    _push(
        buf,
        String(
            'data: {"id":"chatcmpl-flare","object":"chat.completion.chunk",'
            '"created":0,"model":"flare-demo","choices":[{"index":0,'
            '"delta":{"content":"'
        ),
    )
    for b in token:
        buf.append(b)
    _push(buf, String('"},"finish_reason":null}]}\n\n'))
    return buf^


def _sse_done_frames() -> List[UInt8]:
    """The terminal frames: a ``finish_reason:"stop"`` chunk followed by
    the ``data: [DONE]`` sentinel."""
    var buf = List[UInt8]()
    _push(
        buf,
        String(
            'data: {"id":"chatcmpl-flare","object":"chat.completion.chunk",'
            '"created":0,"model":"flare-demo","choices":[{"index":0,'
            '"delta":{},"finish_reason":"stop"}]}\n\n'
        ),
    )
    _push(buf, String("data: [DONE]\n\n"))
    return buf^


# ── The front: shape upstream tokens into SSE with backpressure ──────────────


struct OpenAiSseFront(Movable, StreamHandler):
    """Relay a backend token stream to the client as OpenAI SSE chunks.

    Shared state is just the backend socket path. The per-connection
    upstream is framework-owned; the front polls it for ready tokens,
    shapes each into an SSE frame, and sends it with backpressure.
    """

    var backend_path: String

    def __init__(out self, backend_path: String):
        self.backend_path = backend_path

    def on_open(mut self, mut conn: StreamConn) raises:
        # Emit the SSE response head, then dial the backend and let the
        # framework own the source + watch its fd.
        conn.send(
            String(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: close\r\n\r\n"
            )
        )
        conn.attach_upstream(UpstreamChunkSource.connect(self.backend_path))
        # Pause the backend once 64 KiB is queued for a slow client,
        # resume at 16 KiB (hysteresis).
        conn.set_watermarks(hi=64 * 1024, lo=16 * 1024)

    def on_upstream(mut self, mut conn: StreamConn) raises:
        # Drain ready tokens into the client as SSE frames with
        # backpressure: stop at the high watermark (the reactor re-arms
        # upstream interest as the client drains), emit the DONE frames on
        # EOF, park on pending.
        var cancel = conn.cancel()
        while not conn.write_buffer_full():
            var p = conn.upstream().poll(cancel)
            if p.is_ready():
                conn.send(_sse_token_frame(p.take_chunk()))
            elif p.is_eof():
                conn.send(_sse_done_frames())
                conn.request_close()
                break
            else:
                break

    def on_writable(mut self, mut conn: StreamConn) raises:
        pass  # the framework drains conn's buffer

    def on_close(mut self, mut conn: StreamConn) raises:
        pass  # the framework closes the upstream source on teardown


# ── A toy token-generator backend over FrameMux ──────────────────────────────


def _run_backend(mut listener: UnixListener, n_tokens: Int) raises:
    """Accept one connection and emit ``n_tokens`` CHUNK frames with
    small gaps, then DONE -- the shape a generation backend produces."""
    var conn = listener.accept()
    var mux = FrameMux(conn^)
    for i in range(n_tokens):
        mux.send_chunk(1, ("token-" + String(i) + " ").as_bytes())
        mux.flush()
        usleep(20_000)  # gap between tokens; the front parks, no spin
    mux.done(1)
    mux.flush()
    usleep(200_000)


def _read_all(mut s: TcpStream) raises -> String:
    var out = List[UInt8]()
    var chunk = List[UInt8](capacity=4096)
    while True:
        chunk.resize(4096, 0)
        var n = s.read(chunk.unsafe_ptr(), 4096)
        if n == 0:
            break
        for i in range(n):
            out.append(chunk[i])
    return String(unsafe_from_utf8=Span[UInt8, _](out))


def main() raises:
    var n_tokens = 5
    var backend_path = String("/tmp/flare_openai_sse_backend.sock")
    _ = unlink_path(backend_path)

    print("[sse-front] starting token backend at", backend_path)
    var backend = UnixListener.bind_with_options(
        backend_path, cleanup_path=False
    )
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    print("[sse-front] front listening on 127.0.0.1:", port)

    var backend_pid = fork()
    if backend_pid == 0:
        try:
            _run_backend(backend, n_tokens)
        except:
            pass
        exit()

    usleep(150_000)

    var front_pid = fork()
    if front_pid == 0:
        try:
            srv.serve_streaming(OpenAiSseFront(backend_path))
        except:
            pass
        exit()

    usleep(200_000)

    print("[sse-front] client connecting; reading SSE stream...\n")
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var got = _read_all(client)
    client.close()

    _ = kill(front_pid, SIGKILL)
    waitpid(front_pid)
    _ = kill(backend_pid, SIGKILL)
    waitpid(backend_pid)
    _ = backend.local_path()
    _ = unlink_path(backend_path)

    print(got)
    print(
        "[sse-front] done -- shaped",
        n_tokens,
        "backend tokens into OpenAI SSE chunks with end-to-end backpressure.",
    )
