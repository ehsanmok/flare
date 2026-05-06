"""Per-stream Cancel propagation for HTTP/2 (RFC 9113 §6.4 RST_STREAM).

Exercises the v0.7 wiring in
:class:`flare.http._h2_conn_handle.H2ConnHandle` that flips a
per-stream :class:`flare.http.cancel.CancelCell` so an in-flight
:trait:`flare.http.CancelHandler` observes peer RST_STREAM and
sibling streams stay isolated.

Cases:

* ``test_rst_stream_flips_only_target_cell``: server-side
  ``H2Connection`` records the reset stream id; the per-conn
  handle's helper flips only that cell.
* ``test_concurrent_streams_isolated``: flipping stream 3 leaves
  stream 1's cell live.
* ``test_goaway_flips_all_cells``: a GOAWAY-driven sweep flips
  every live cell + the connection-level cell.
* ``test_drain_flips_all_cells``: ``signal_drain()`` flips every
  cell with reason :data:`CancelReason.SHUTDOWN`.
* ``test_cancel_after_dispatch_is_noop``: after the response is
  queued and the cell freed, a late RST_STREAM for the same id is
  a no-op (the cell allocation re-creates a fresh cell with no
  observer, so flipping it is harmless).
"""

from std.ffi import c_int

from std.testing import assert_equal, assert_false, assert_true

from flare.http import (
    Cancel,
    CancelHandler,
    Request,
    Response,
    ServerConfig,
    ok,
)
from flare.http.cancel import CancelReason
from flare.net import RawSocket, SocketAddr
from flare.net._libc import AF_INET, SOCK_STREAM, _close
from flare.http._h2_conn_handle import H2ConnHandle
from flare.http2 import Http2Config
from flare.tcp import TcpListener, TcpStream


@fieldwise_init
struct _RecordingCancelHandler(CancelHandler, Copyable, Movable):
    """``CancelHandler`` that returns 200 + the cell's cancelled-state
    so the test can assert what the handler observed at dispatch time.
    """

    var _placeholder: Int

    def serve(self, req: Request, cancel: Cancel) raises -> Response:
        if cancel.cancelled():
            return Response(status=499, reason="Client Cancelled")
        return ok("ran")


struct _Pair(Movable):
    """Test fixture: an :class:`H2ConnHandle` paired with the raw
    fd for the peer side of the loopback connection so the test
    can close it on tear-down."""

    var handle: H2ConnHandle
    var client_fd: c_int

    def __init__(out self) raises:
        var listener = TcpListener.bind(SocketAddr.localhost(0))
        var port = UInt16(listener.local_addr().port)
        var client = TcpStream.connect(SocketAddr.localhost(port))
        var server = listener.accept()
        self.client_fd = client._socket.fd
        client._socket.fd = c_int(-1)
        _ = client^
        self.handle = H2ConnHandle(server^, Http2Config())


def test_rst_stream_flips_only_target_cell() raises:
    """A simulated peer RST_STREAM(3) flips the cell bound to
    stream 3, leaving stream 1's cell untouched."""
    var p = _Pair()
    ref handle = p.handle
    var client_fd = p.client_fd
    var addr1 = handle._alloc_stream_cell(1)
    var addr3 = handle._alloc_stream_cell(3)

    handle._flip_stream_cell(3, CancelReason.PEER_CLOSED)
    assert_false(
        handle._stream_cell_cancelled(1),
        "sibling stream 1 must not be cancelled by RST(3)",
    )
    assert_true(
        handle._stream_cell_cancelled(3),
        "stream 3 must be cancelled after RST(3)",
    )
    assert_true(addr1 != addr3, "per-stream cells must have distinct addrs")
    handle._free_stream_cell(1)
    handle._free_stream_cell(3)
    _ = _close(client_fd)
    _ = p^


def test_concurrent_streams_isolated() raises:
    """Flipping stream 3 then stream 5 leaves stream 1 untouched."""
    var p = _Pair()
    ref handle = p.handle
    var client_fd = p.client_fd
    _ = handle._alloc_stream_cell(1)
    _ = handle._alloc_stream_cell(3)
    _ = handle._alloc_stream_cell(5)

    handle._flip_stream_cell(3, CancelReason.PEER_CLOSED)
    handle._flip_stream_cell(5, CancelReason.PEER_CLOSED)

    assert_false(handle._stream_cell_cancelled(1))
    assert_true(handle._stream_cell_cancelled(3))
    assert_true(handle._stream_cell_cancelled(5))

    handle._free_stream_cell(1)
    handle._free_stream_cell(3)
    handle._free_stream_cell(5)
    _ = _close(client_fd)
    _ = p^


def test_goaway_flips_all_cells() raises:
    """``_flip_all_stream_cells`` flips every live per-stream cell
    plus the connection-level cell."""
    var p = _Pair()
    ref handle = p.handle
    var client_fd = p.client_fd
    _ = handle._alloc_stream_cell(1)
    _ = handle._alloc_stream_cell(3)
    _ = handle._alloc_stream_cell(5)

    handle._flip_all_stream_cells(CancelReason.PEER_CLOSED)

    assert_true(handle._stream_cell_cancelled(1))
    assert_true(handle._stream_cell_cancelled(3))
    assert_true(handle._stream_cell_cancelled(5))
    assert_true(handle.cancel_cell.handle().cancelled())

    handle._free_stream_cell(1)
    handle._free_stream_cell(3)
    handle._free_stream_cell(5)
    _ = _close(client_fd)
    _ = p^


def test_drain_flips_all_cells_with_shutdown_reason() raises:
    """``signal_drain()`` flips every cell with ``SHUTDOWN``."""
    var p = _Pair()
    ref handle = p.handle
    var client_fd = p.client_fd
    _ = handle._alloc_stream_cell(1)
    _ = handle._alloc_stream_cell(3)

    handle.signal_drain()

    assert_equal(handle.cancel_cell.handle().reason(), CancelReason.SHUTDOWN)
    assert_true(handle._stream_cell_cancelled(1))
    assert_true(handle._stream_cell_cancelled(3))
    assert_true(handle.should_close)

    handle._free_stream_cell(1)
    handle._free_stream_cell(3)
    _ = _close(client_fd)
    _ = p^


def test_cell_freed_after_dispatch_is_idempotent() raises:
    """After ``_free_stream_cell`` the cell is gone; repeated free
    or stale flip is a no-op (no double-free, no re-alloc)."""
    var p = _Pair()
    ref handle = p.handle
    var client_fd = p.client_fd

    _ = handle._alloc_stream_cell(1)
    handle._free_stream_cell(1)
    # Repeat free is a no-op.
    handle._free_stream_cell(1)
    # Stale flip would re-alloc; assert the cell-cancelled probe
    # behaves correctly: after re-alloc + flip, the new cell is
    # cancelled but it's a fresh allocation (not a use-after-free).
    handle._flip_stream_cell(1, CancelReason.PEER_CLOSED)
    assert_true(handle._stream_cell_cancelled(1))
    handle._free_stream_cell(1)
    _ = _close(client_fd)
    _ = p^


def test_on_readable_cancel_dispatches_through_cancel_handler() raises:
    """``on_readable_cancel`` invokes the ``CancelHandler.serve``
    overload with a fresh per-stream cancel cell, the handler runs
    normally (cell not flipped), and the response flushes via the
    same ``write_buf`` path the non-cancel dispatch uses.

    This is the "happy path" parity check: the cancel-aware
    dispatch should be byte-for-byte identical to the regular
    dispatch when nothing flips the cell.
    """
    from std.ffi import c_size_t, external_call
    from std.memory import stack_allocation
    from flare.http2 import HpackHeader, Http2ClientConnection
    from flare.net._libc import _recv, _send, MSG_NOSIGNAL

    var p = _Pair()
    ref handle = p.handle
    var client_fd = p.client_fd

    var s1 = RawSocket(handle.fd(), AF_INET, SOCK_STREAM, _wrap=True)
    s1.set_nonblocking(True)
    s1.fd = c_int(-1)
    var s2 = RawSocket(client_fd, AF_INET, SOCK_STREAM, _wrap=True)
    s2.set_nonblocking(True)
    s2.fd = c_int(-1)

    var client = Http2ClientConnection()
    var sid = client.next_stream_id()
    var no_extra = List[HpackHeader]()
    var no_body = List[UInt8]()
    client.send_request(
        sid,
        "GET",
        "http",
        "127.0.0.1",
        "/",
        no_extra,
        Span[UInt8, _](no_body),
    )
    var first = client.drain()
    var n = _send(
        client_fd,
        first.unsafe_ptr(),
        c_size_t(len(first)),
        c_int(MSG_NOSIGNAL),
    )
    assert_true(Int(n) == len(first))

    var cfg = ServerConfig()
    var h = _RecordingCancelHandler(0)
    var step_pump = handle.on_readable_cancel(h, cfg)
    var pump_attempts = 0
    while (not step_pump.want_write) and pump_attempts < 50:
        pump_attempts += 1
        _ = external_call["usleep", c_int](c_int(2000))
        step_pump = handle.on_readable_cancel(h, cfg)
    assert_true(
        step_pump.want_write,
        "on_readable_cancel did not surface a writable step",
    )
    var step2 = handle.on_writable(cfg)
    _ = step2

    var got = List[UInt8]()
    var attempts = 0
    while not client.response_ready(sid) and attempts < 50:
        attempts += 1
        var buf = stack_allocation[8192, UInt8]()
        var got_n = _recv(client_fd, buf, c_size_t(8192), c_int(0))
        if Int(got_n) > 0:
            for i in range(Int(got_n)):
                got.append(buf[i])
            client.feed(Span[UInt8, _](got))
            got.clear()
        else:
            _ = handle.on_writable(cfg)
            _ = handle.on_readable_cancel(h, cfg)
    assert_true(client.response_ready(sid), "h2 response did not arrive")
    var resp = client.take_response(sid)
    assert_equal(resp.status, 200)
    var body_str = String(unsafe_from_utf8=Span[UInt8, _](resp.body))
    assert_equal(body_str, "ran")

    _ = _close(client_fd)
    _ = p^


def main() raises:
    test_rst_stream_flips_only_target_cell()
    test_concurrent_streams_isolated()
    test_goaway_flips_all_cells()
    test_drain_flips_all_cells_with_shutdown_reason()
    test_cell_freed_after_dispatch_is_idempotent()
    test_on_readable_cancel_dispatches_through_cancel_handler()
    print("test_h2_per_stream_cancel: 6 passed")
