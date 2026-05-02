"""Tests for ``flare.runtime.iovec`` (Track B4).

End-to-end tests use a real TCP loopback pair to verify that
``writev(2)`` actually delivers the concatenated bytes to the
peer. Direct in-memory tests cover the iovec layout +
partial-write loop accounting.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.runtime import IoVecBuf, writev_buf_all
from flare.tcp import TcpListener, TcpStream
from flare.net import SocketAddr


# ── IoVecBuf layout tests ───────────────────────────────────────────────────


def test_iovec_size_for_returns_16_per_cell() raises:
    """C ``struct iovec`` is exactly 16 bytes on every 64-bit
    target this commit supports.
    """
    assert_equal(IoVecBuf.size_for(1), 16)
    assert_equal(IoVecBuf.size_for(3), 48)
    assert_equal(IoVecBuf.size_for(8), 128)
    assert_equal(IoVecBuf.size_for(0), 0)


def test_iovec_count_matches_constructor_arg() raises:
    var a = IoVecBuf(1)
    assert_equal(a.count(), 1)
    var b = IoVecBuf(7)
    assert_equal(b.count(), 7)


def test_iovec_set_then_read_back_round_trip() raises:
    """Set ``{ ptr, len }`` into every cell; read back via
    ``cell_ptr`` / ``cell_len`` and assert byte-identical
    round-trip.
    """
    var iov = IoVecBuf(3)
    iov.set(0, 0xCAFEBABE, 64)
    iov.set(1, 0xDEADBEEF, 1024)
    iov.set(2, 0x12345678, 0)
    assert_equal(iov.cell_ptr(0), 0xCAFEBABE)
    assert_equal(iov.cell_len(0), 64)
    assert_equal(iov.cell_ptr(1), 0xDEADBEEF)
    assert_equal(iov.cell_len(1), 1024)
    assert_equal(iov.cell_ptr(2), 0x12345678)
    assert_equal(iov.cell_len(2), 0)


def test_iovec_unset_cells_default_to_null_zero() raises:
    """Constructor must zero-init every cell so an unset cell
    behaves as ``{ NULL, 0 }`` (the writev kernel ABI treats
    those as "skip this cell" rather than "error").
    """
    var iov = IoVecBuf(4)
    for i in range(4):
        assert_equal(iov.cell_ptr(i), 0)
        assert_equal(iov.cell_len(i), 0)


def test_iovec_set_overwrites_previous_value() raises:
    var iov = IoVecBuf(1)
    iov.set(0, 100, 200)
    iov.set(0, 300, 400)
    assert_equal(iov.cell_ptr(0), 300)
    assert_equal(iov.cell_len(0), 400)


# ── End-to-end writev over a TCP loopback pair ──────────────────────────────


def test_writev_delivers_concatenated_bytes_to_peer() raises:
    """The classic HTTP-response shape: one writev with three
    cells (status line, header block, body) must deliver the
    concatenated bytes to the peer in order.
    """
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var addr = listener.local_addr()
    var client = TcpStream.connect(addr)
    var server_side = listener.accept()

    var part1 = String("HTTP/1.1 200 OK\r\n")
    var part2 = String("Content-Length: 11\r\nContent-Type: text/plain\r\n\r\n")
    var part3 = String("hello world")

    var iov = IoVecBuf(3)
    iov.set(0, Int(part1.unsafe_ptr()), part1.byte_length())
    iov.set(1, Int(part2.unsafe_ptr()), part2.byte_length())
    iov.set(2, Int(part3.unsafe_ptr()), part3.byte_length())

    var total = part1.byte_length() + part2.byte_length() + part3.byte_length()
    writev_buf_all(iov, Int(server_side._socket.fd), total)

    var buf = List[UInt8](capacity=total + 4)
    buf.resize(total + 4, 0)
    var n = client.read(buf.unsafe_ptr(), total)
    assert_equal(n, total)

    var expected = part1 + part2 + part3
    var ep = expected.as_bytes()
    for i in range(total):
        assert_equal(Int(buf.unsafe_ptr()[i]), Int(ep.unsafe_ptr()[i]))

    server_side.close()
    client.close()
    listener.close()


def test_writev_with_zero_length_cells_skips_them() raises:
    """``{ ptr, 0 }`` cells must be ignored by the kernel —
    common case after a partial write where ``writev_buf_all``
    has zeroed an already-consumed cell.
    """
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var addr = listener.local_addr()
    var client = TcpStream.connect(addr)
    var server_side = listener.accept()

    var data = String("ABCDEFG")

    var iov = IoVecBuf(5)
    # Cells 0, 2, 4 hold real data; cells 1, 3 are empty
    # placeholders.
    var p = Int(data.unsafe_ptr())
    iov.set(0, p, 1)
    iov.set(2, p + 1, 3)
    iov.set(4, p + 4, 3)

    writev_buf_all(iov, Int(server_side._socket.fd), 7)

    var buf = List[UInt8](capacity=10)
    buf.resize(10, 0)
    var n = client.read(buf.unsafe_ptr(), 7)
    assert_equal(n, 7)
    var dp = data.as_bytes()
    for i in range(7):
        assert_equal(Int(buf.unsafe_ptr()[i]), Int(dp.unsafe_ptr()[i]))

    server_side.close()
    client.close()
    listener.close()


def test_writev_single_cell_matches_send_semantics() raises:
    """A 1-cell writev should behave exactly like a single
    ``send(2)`` — used to sanity-check that the FFI ABI is
    correct on the host.
    """
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var addr = listener.local_addr()
    var client = TcpStream.connect(addr)
    var server_side = listener.accept()

    var data = String("hello, vectored world")
    var iov = IoVecBuf(1)
    iov.set(0, Int(data.unsafe_ptr()), data.byte_length())

    writev_buf_all(iov, Int(server_side._socket.fd), data.byte_length())

    var buf = List[UInt8](capacity=64)
    buf.resize(64, 0)
    var n = client.read(buf.unsafe_ptr(), data.byte_length())
    assert_equal(n, data.byte_length())
    var dp = data.as_bytes()
    for i in range(data.byte_length()):
        assert_equal(Int(buf.unsafe_ptr()[i]), Int(dp.unsafe_ptr()[i]))

    server_side.close()
    client.close()
    listener.close()


def test_writev_buf_all_zeroes_consumed_cells() raises:
    """After a complete write, every cell should be
    ``{ NULL, 0 }``  (so a follow-up writev call would be a
    no-op).
    """
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var addr = listener.local_addr()
    var client = TcpStream.connect(addr)
    var server_side = listener.accept()

    var part1 = String("foo")
    var part2 = String("bar")

    var iov = IoVecBuf(2)
    iov.set(0, Int(part1.unsafe_ptr()), part1.byte_length())
    iov.set(1, Int(part2.unsafe_ptr()), part2.byte_length())

    writev_buf_all(iov, Int(server_side._socket.fd), 6)

    # Drain the peer so the loopback fd is clean.
    var buf = List[UInt8](capacity=8)
    buf.resize(8, 0)
    var n = client.read(buf.unsafe_ptr(), 6)
    assert_equal(n, 6)

    # Both cells should be zeroed after the write.
    assert_equal(iov.cell_ptr(0), 0)
    assert_equal(iov.cell_len(0), 0)
    assert_equal(iov.cell_ptr(1), 0)
    assert_equal(iov.cell_len(1), 0)

    server_side.close()
    client.close()
    listener.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
