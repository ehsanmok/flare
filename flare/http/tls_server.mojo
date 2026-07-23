"""Synchronous HTTPS/1.1 serving on top of the non-blocking TLS primitive.

This is the Phase-4 ``serve_tls`` wiring: a self-contained, one-connection-
at-a-time HTTPS/1.1 server built on
:class:`flare.http._reactor.tls_conn_handle.TlsConnHandle`. It is
deliberately **additive** -- it does not touch the plaintext unified
reactor hot path. Each accepted connection runs the full
handshake -> request -> response cycle on the calling thread, driving the
ciphertext seams (``SSL_accept`` / ``SSL_read`` / ``SSL_write``) through
the reactor's own ``WANT_READ`` / ``WANT_WRITE`` sentinels and blocking
between edges with ``poll(2)``.

Streaming composes for free: a handler that returns a streaming
``Response`` (a ``body_stream`` chunk source) is emitted with
``Transfer-Encoding: chunked`` framing, pulled chunk-by-chunk and written
as ciphertext -- byte-identical framing to the plaintext h1 streaming
path, just through ``SSL_write``.

Scope / follow-ups (documented, not silently missing):

- **h1 only.** If ALPN negotiates ``h2`` the connection is closed cleanly
  rather than mis-framed; h2-over-TLS belongs on the multiplexed reactor
  path, which is the next integration step after this primitive lands.
- **One connection at a time.** This mirrors the original blocking
  ``HttpServer`` semantics (each connection handled in the calling
  thread). Reactor-multiplexed TLS (many concurrent TLS connections on
  one event loop) reuses this exact ``TlsConnHandle`` state machine and
  is the larger follow-up.
"""

from std.ffi import c_int, c_uint, external_call
from std.memory import UnsafePointer, stack_allocation

from flare.errors import map_handler_error
from flare.http.cancel import Cancel
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http.response_stream import (
    ChunkSourceBox,
    frame_chunk_into,
    frame_terminator_into,
)
from flare.http.server import (
    ServerConfig,
    _find_crlfcrlf,
    _parse_http_request_bytes,
    _scan_content_length,
)
from flare.runtime import DateCache

from ._reactor.keepalive_scan import (
    _compact_read_buf_drop_prefix,
    _compute_close_after,
)
from ._reactor.tls_conn_handle import TlsConnHandle
from ._reactor.write_path import (
    build_error_response,
    serialize_response_headers_chunked_into,
    serialize_response_into,
)

from flare.tls._server_ffi import SSL_IO_WANT_READ, SSL_IO_WANT_WRITE


# poll(2) event bits (identical on Linux and macOS).
comptime _POLLIN: Int16 = 0x0001
comptime _POLLOUT: Int16 = 0x0004


def _poll_wait(fd: c_int, want_write: Bool, timeout_ms: Int) -> None:
    """Block until ``fd`` is readable (or writable when ``want_write``),
    or until ``timeout_ms`` elapses. A best-effort readiness wait between
    ``WANT_*`` sentinels; errors and timeouts fall through so the caller
    simply retries the SSL op (which re-reports the sentinel)."""
    var pfd = stack_allocation[8, UInt8]()
    pfd.bitcast[Int32]()[0] = Int32(fd)
    (pfd + 4).bitcast[Int16]()[0] = _POLLOUT if want_write else _POLLIN
    (pfd + 6).bitcast[Int16]()[0] = Int16(0)
    _ = external_call["poll", c_int](pfd, c_uint(1), c_int(timeout_ms))


def _send_all_tls(mut conn: TlsConnHandle, buf: List[UInt8]) raises -> Bool:
    """Write all of ``buf`` through ``SSL_write``, blocking on ``poll``
    between partial writes. Returns ``False`` on a closed/fatal TLS
    error (caller should tear the connection down)."""
    var off = 0
    while off < len(buf):
        var n = conn.send(Span[UInt8, _](buf), off)
        if n > 0:
            off += n
        elif n == SSL_IO_WANT_READ or n == SSL_IO_WANT_WRITE:
            _poll_wait(conn.fd(), n == SSL_IO_WANT_WRITE, 30000)
        else:
            return False
    return True


def _stream_body_tls(mut conn: TlsConnHandle, var box: ChunkSourceBox) raises:
    """Pull ``box`` chunk-by-chunk, frame each as chunked, and write it as
    ciphertext; finish with the last-chunk terminator."""
    var cancel = Cancel.never()
    while True:
        var chunk_opt = box.next(cancel)
        if not chunk_opt:
            var term = List[UInt8]()
            frame_terminator_into(term)
            _ = _send_all_tls(conn, term)
            return
        var chunk = chunk_opt.value().copy()
        if len(chunk) == 0:
            continue
        var framed = List[UInt8]()
        frame_chunk_into(framed, chunk)
        if not _send_all_tls(conn, framed):
            return


def handle_tls_h1_connection[
    H: Handler
](mut conn: TlsConnHandle, config: ServerConfig, ref handler: H) raises:
    """Drive one TLS connection: handshake, then an HTTP/1.1
    request/response keep-alive loop, until the peer closes, an error
    occurs, or ``Connection: close`` is negotiated.

    All request parsing and response serialisation reuse the same
    helpers as the plaintext h1 path; only the byte transport differs
    (``SSL_read`` / ``SSL_write`` instead of ``recv`` / ``send``).
    """
    # ── Handshake ──────────────────────────────────────────────────────────
    while True:
        var sr = conn.drive_handshake()
        if conn.handshake_done():
            break
        if sr.done:
            return
        _poll_wait(conn.fd(), sr.want_write, config.idle_timeout_ms)

    # h2-over-TLS is not framed by this synchronous h1 path; close cleanly
    # rather than emit h1 bytes on an h2 connection. (See module docstring.)
    if conn.alpn == "h2":
        return

    var date_cache = DateCache()
    var read_buf = List[UInt8]()

    while True:
        # Accumulate one complete request.
        var headers_end = -1
        var body_total = -1
        while True:
            if headers_end < 0:
                var end = _find_crlfcrlf(read_buf, 0)
                if end >= 0:
                    headers_end = end
                    var content_length = _scan_content_length(
                        read_buf, headers_end
                    )
                    if content_length > config.max_body_size:
                        var er = build_error_response(413, "Content Too Large")
                        var wb = List[UInt8]()
                        serialize_response_into(wb, date_cache, er, False)
                        _ = _send_all_tls(conn, wb)
                        return
                    body_total = headers_end + content_length
            if headers_end >= 0 and len(read_buf) >= body_total:
                break
            if headers_end < 0 and len(read_buf) > config.max_header_size:
                var er = build_error_response(
                    431, "Request Header Fields Too Large"
                )
                var wb = List[UInt8]()
                serialize_response_into(wb, date_cache, er, False)
                _ = _send_all_tls(conn, wb)
                return
            var n = conn.recv(read_buf, 8192)
            if n > 0:
                continue
            if n == SSL_IO_WANT_READ or n == SSL_IO_WANT_WRITE:
                _poll_wait(
                    conn.fd(),
                    n == SSL_IO_WANT_WRITE,
                    config.idle_timeout_ms,
                )
                continue
            return  # clean EOF or fatal

        # Parse.
        var req: Request
        var close_after: Bool
        try:
            req = _parse_http_request_bytes(
                Span[UInt8, _](read_buf)[:body_total],
                config.max_header_size,
                config.max_body_size,
                config.max_uri_length,
                conn.peer,
                config.expose_error_messages,
            )
            close_after = _compute_close_after(req.headers, req.version)
        except:
            var er = build_error_response(400, "Bad Request")
            var wb = List[UInt8]()
            serialize_response_into(wb, date_cache, er, False)
            _ = _send_all_tls(conn, wb)
            return

        var expose_errors = req.expose_errors

        # Dispatch.
        var resp: Response
        try:
            resp = handler.serve(req^)
        except e:
            var mapped = map_handler_error(String(e), expose_errors)
            var er = build_error_response(mapped.status, mapped.reason)
            var wb = List[UInt8]()
            serialize_response_into(wb, date_cache, er, False)
            _ = _send_all_tls(conn, wb)
            return

        # Consume the request bytes from the buffer.
        if body_total > 0 and body_total <= len(read_buf):
            _compact_read_buf_drop_prefix(read_buf, body_total)

        # Serialise + send (buffered or chunked-streaming).
        if resp.body_stream:
            var box = resp.body_stream.take()
            var wb = List[UInt8]()
            serialize_response_headers_chunked_into(
                wb, date_cache, resp, not close_after
            )
            if not _send_all_tls(conn, wb):
                return
            _stream_body_tls(conn, box^)
        else:
            var wb = List[UInt8]()
            serialize_response_into(wb, date_cache, resp, not close_after)
            if not _send_all_tls(conn, wb):
                return

        if close_after:
            return
