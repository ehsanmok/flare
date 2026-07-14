"""Response serialisation helpers for the H1 reactor write path.

This module owns the byte-emitting half of the per-connection
state machine: turning a parsed :class:`flare.http.response.Response`
or a pre-encoded :class:`flare.http.static_response.StaticResponse`
into the HTTP/1.1 wire bytes that
:meth:`flare.http._reactor.conn_handle.ConnHandle.on_writable`
flushes to the socket.

Splitting the serialise-path helpers out of
:mod:`flare.http._reactor.conn_handle` keeps that module focused
on the connection state machine; the helpers here are pure
functions over the connection's ``write_buf`` and ``DateCache``
and only mutate those caller-supplied references.

The hot-path optimisations (response-side ``DateCache`` reuse,
single-allocation header skip predicates, bulk-copy body append)
match the byte-fast-path / keep-alive helpers in
:mod:`flare.http._reactor.keepalive_scan`.
"""

from std.collections import List
from std.memory import memcpy, UnsafePointer

from flare.http.response import Response
from flare.http.server import (
    _status_reason,
    _append_str,
)
from flare.http.static_response import StaticResponse
from flare.runtime import DateCache

from .keepalive_scan import (
    _is_connection,
    _is_content_length,
    _is_date,
    _is_transfer_encoding,
)


@always_inline
def _decimal_digits(n: Int) -> Int:
    """Number of ASCII digits in the non-negative decimal form of ``n``."""
    if n < 10:
        return 1
    var d = 1
    var x = n
    while x >= 10:
        x //= 10
        d += 1
    return d


@always_inline
def _put_str(mut buf: List[UInt8], off: Int, s: StringSlice) -> Int:
    """memcpy ``s`` into ``buf`` at ``off``; return the advanced offset.

    The caller is responsible for having sized ``buf`` to fit
    (``serialize_response_into`` computes the exact total up front).
    """
    var n = s.byte_length()
    if n > 0:
        memcpy(dest=buf.unsafe_ptr() + off, src=s.unsafe_ptr(), count=n)
    return off + n


@always_inline
def _put_int(mut buf: List[UInt8], off: Int, n: Int) -> Int:
    """Write the ASCII decimal form of non-negative ``n`` at ``off``.

    Writes digits most-significant first by computing the digit count
    and filling backwards from the end -- no temporary buffer, no
    allocation.
    """
    var p = buf.unsafe_ptr()
    if n == 0:
        p[off] = 48
        return off + 1
    var d = _decimal_digits(n)
    var end = off + d
    var k = end
    var x = n
    while x > 0:
        k -= 1
        p[k] = UInt8(48 + (x % 10))
        x //= 10
    return end


@always_inline
def _put_bytes(
    mut buf: List[UInt8], off: Int, src: UnsafePointer[UInt8, _], n: Int
) -> Int:
    """memcpy ``n`` bytes from ``src`` into ``buf`` at ``off``."""
    if n > 0:
        memcpy(dest=buf.unsafe_ptr() + off, src=src, count=n)
    return off + n


def serialize_static_into(
    mut write_buf: List[UInt8],
    mut write_pos: Int,
    resp: StaticResponse,
    keep_alive: Bool,
) -> None:
    """Queue a pre-encoded static response into ``write_buf``.

    Reuses the buffer's existing capacity across requests (same
    pattern as :func:`serialize_response_into`) and pulls either
    the keep-alive or close variant of the pre-encoded bytes
    depending on ``keep_alive``.
    """
    write_buf.clear()
    write_pos = 0
    # Pick the keep-alive or close variant by branch rather than via
    # a conditional expression. ``List[UInt8]`` is not
    # ``ImplicitlyCopyable`` under current Mojo, so binding the
    # selected variant to a single ``var`` would force an implicit
    # copy that the compiler now rejects. Splitting the branch
    # keeps both arms in pure borrow + ``unsafe_ptr()`` form and
    # avoids any copy at all.
    var n: Int
    if keep_alive:
        n = len(resp.keepalive_bytes)
    else:
        n = len(resp.close_bytes)
    if write_buf.capacity < n:
        write_buf.reserve(n)
    write_buf.resize(n, UInt8(0))
    if keep_alive:
        memcpy(
            dest=write_buf.unsafe_ptr(),
            src=resp.keepalive_bytes.unsafe_ptr(),
            count=n,
        )
    else:
        memcpy(
            dest=write_buf.unsafe_ptr(),
            src=resp.close_bytes.unsafe_ptr(),
            count=n,
        )


def serialize_response_into(
    mut write_buf: List[UInt8],
    mut date_cache: DateCache,
    resp: Response,
    keep_alive: Bool,
) -> None:
    """Serialise ``resp`` into ``write_buf`` ready to be sent.

    Reuses ``write_buf``'s allocated capacity across requests --
    callers clear the buffer after the previous response has been
    flushed, so the backing storage is idle when serialise starts.
    The ``Date`` header is emitted from the caller-supplied
    :class:`flare.runtime.DateCache` (RFC 9110 §6.6.1); any
    caller-supplied ``Date`` field on ``resp`` is dropped.
    """
    var reason = resp.reason
    if reason.byte_length() == 0:
        reason = _status_reason(resp.status)
    var body_len = len(resp.body)

    # Date: RFC 9110 §6.6.1, IMF-fixdate from the per-connection
    # DateCache. The cache calls clock_gettime + (re)formats only
    # when the wall-clock second has advanced; reads on the same
    # second return the cached buffer directly.
    date_cache.refresh()
    var date_bytes = date_cache.current_bytes()
    var date_len = len(date_bytes)

    # Compute the EXACT serialized length up front so the buffer is
    # sized in a single pass. The previous form issued ~10 separate
    # ``_append_str`` calls, each doing a ``resize(.,0)`` that
    # zero-filled its new tail (showing up as ``__memset_avx2`` on the
    # hot path) before the memcpy overwrote it. Sizing once and writing
    # through a raw cursor drops both the repeated resize overhead and
    # the redundant zero-fill -- the bytes emitted are identical.
    #
    # Fixed segment widths:
    #   "HTTP/1.1 " = 9, status digits, " " = 1, reason, "\r\n" = 2
    #   "Content-Length: " = 16, body_len digits, "\r\n" = 2
    #   "Date: " = 6, date_bytes, "\r\n" = 2
    #   "Connection: keep-alive\r\n" = 24  /  "Connection: close\r\n" = 19
    #   "\r\n" = 2 (header terminator), then body
    var total = 9 + _decimal_digits(resp.status) + 1 + reason.byte_length() + 2
    for i in range(resp.headers.len()):
        var k = resp.headers._keys[i]
        # Case-insensitive skip of Content-Length, Connection, and Date
        # without allocating a lowercased copy each header. Date is
        # always emitted by us from the per-connection DateCache
        # (RFC 9110 §6.6.1 mandates a single Date field-line).
        if _is_content_length(k) or _is_connection(k) or _is_date(k):
            continue
        total += k.byte_length() + 2 + resp.headers._values[i].byte_length() + 2
    total += 16 + _decimal_digits(body_len) + 2
    total += 6 + date_len + 2
    total += 24 if keep_alive else 19
    total += 2
    total += body_len

    write_buf.clear()
    write_buf.resize(unsafe_uninit_length=total)
    var off = 0

    off = _put_str(write_buf, off, "HTTP/1.1 ")
    off = _put_int(write_buf, off, resp.status)
    off = _put_str(write_buf, off, " ")
    off = _put_str(write_buf, off, reason)
    off = _put_str(write_buf, off, "\r\n")

    for i in range(resp.headers.len()):
        var k = resp.headers._keys[i]
        if _is_content_length(k) or _is_connection(k) or _is_date(k):
            continue
        off = _put_str(write_buf, off, k)
        off = _put_str(write_buf, off, ": ")
        off = _put_str(write_buf, off, resp.headers._values[i])
        off = _put_str(write_buf, off, "\r\n")

    off = _put_str(write_buf, off, "Content-Length: ")
    off = _put_int(write_buf, off, body_len)
    off = _put_str(write_buf, off, "\r\n")

    off = _put_str(write_buf, off, "Date: ")
    off = _put_bytes(write_buf, off, date_bytes.unsafe_ptr(), date_len)
    off = _put_str(write_buf, off, "\r\n")

    if keep_alive:
        off = _put_str(write_buf, off, "Connection: keep-alive\r\n")
    else:
        off = _put_str(write_buf, off, "Connection: close\r\n")

    off = _put_str(write_buf, off, "\r\n")

    if body_len > 0:
        _ = _put_bytes(write_buf, off, resp.body.unsafe_ptr(), body_len)


def serialize_response_headers_chunked_into(
    mut write_buf: List[UInt8],
    mut date_cache: DateCache,
    resp: Response,
    keep_alive: Bool,
) -> None:
    """Serialise ``resp``'s status line + headers with
    ``Transfer-Encoding: chunked`` framing (no ``Content-Length``, no
    body) into ``write_buf``.

    Used for the streaming-response path: the reactor emits these
    headers once, then frames each pulled chunk (see
    ``flare.http.response_stream``) on subsequent writable edges. Not
    on the plaintext hot path -- correctness over micro-optimisation,
    so it uses the append-based writer rather than the single-pass
    exact-size writer ``serialize_response_into`` uses.
    """
    var reason = resp.reason
    if reason.byte_length() == 0:
        reason = _status_reason(resp.status)
    date_cache.refresh()
    var date_bytes = date_cache.current_bytes()

    write_buf.clear()
    var wire = write_buf^
    _append_str(wire, "HTTP/1.1 ")
    _append_str(wire, String(resp.status))
    _append_str(wire, " ")
    _append_str(wire, reason)
    _append_str(wire, "\r\n")
    for i in range(resp.headers.len()):
        var k = resp.headers._keys[i]
        # Drop caller-supplied framing / hop headers -- we emit the
        # canonical Transfer-Encoding, Date, and Connection ourselves.
        if (
            _is_content_length(k)
            or _is_connection(k)
            or _is_date(k)
            or _is_transfer_encoding(k)
        ):
            continue
        _append_str(wire, k)
        _append_str(wire, ": ")
        _append_str(wire, resp.headers._values[i])
        _append_str(wire, "\r\n")
    _append_str(wire, "Transfer-Encoding: chunked\r\n")
    _append_str(wire, "Date: ")
    for i in range(len(date_bytes)):
        wire.append(date_bytes[i])
    _append_str(wire, "\r\n")
    if keep_alive:
        _append_str(wire, "Connection: keep-alive\r\n")
    else:
        _append_str(wire, "Connection: close\r\n")
    _append_str(wire, "\r\n")
    write_buf = wire^


def build_error_response(status: Int, reason: String) -> Response:
    """Build a minimal text/plain error response. The caller threads
    the result through :func:`serialize_response_into` to queue it
    onto the wire.
    """
    var body_str = String(status) + " " + reason
    var resp = Response(status=status, reason=reason)
    var body_bytes = body_str.as_bytes()
    for i in range(len(body_bytes)):
        resp.body.append(body_bytes[i])
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def queue_h2c_upgrade_101(mut write_buf: List[UInt8]) -> None:
    """Queue the ``101 Switching Protocols`` response for an h2c
    upgrade (RFC 7540 §3.2) into ``write_buf``. ``Connection: close``
    is intentionally omitted so the same TCP fd carries the
    subsequent HTTP/2 frames.
    """
    write_buf.clear()
    var wire = write_buf^
    _append_str(wire, "HTTP/1.1 101 Switching Protocols\r\n")
    _append_str(wire, "Connection: Upgrade\r\n")
    _append_str(wire, "Upgrade: h2c\r\n\r\n")
    write_buf = wire^
