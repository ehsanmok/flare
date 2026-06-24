"""Coalesced small-frame writes for token bursts (v0.9 B7).

Streaming one token per chunk must not mean one syscall per token -- that
per-token round-trip is the dominant nTPOT tax on long outputs. flare
coalesces by appending every ``send`` into one contiguous out buffer and
flushing it in a single ``send(2)`` on the drain.

This microbench queues K small chunks into a ``StreamConn`` and drains
once, asserting via the write-syscall counter that K chunks cost ONE
syscall (not K), and that the peer receives every chunk in order.
"""

from std.testing import assert_equal, assert_true

from flare.http.streaming_server import StreamConn
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream


def main() raises:
    var lst = TcpListener.bind(SocketAddr.localhost(0))
    var port = lst.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var peer = lst.accept()
    var conn = StreamConn(client^, 1)

    var K = 64
    var expected = String("")
    for i in range(K):
        var tok = String("tok") + String(i) + ":"
        conn.send(tok.as_bytes())
        expected += tok

    # All K chunks are buffered (no syscalls issued by send itself).
    assert_equal(conn.write_syscalls(), 0)
    assert_equal(conn.pending_out(), expected.byte_length())

    # One drain flushes the whole burst in a single send(2).
    var done = conn.drain_nonblocking()
    assert_true(done, "expected the burst to flush fully")
    assert_equal(
        conn.write_syscalls(),
        1,
        "K chunks should cost 1 syscall, got " + String(conn.write_syscalls()),
    )

    # The peer receives every chunk, in order.
    var got = List[UInt8]()
    var chunk = List[UInt8](capacity=4096)
    var need = expected.byte_length()
    while len(got) < need:
        chunk.resize(4096, 0)
        var n = peer.read(chunk.unsafe_ptr(), 4096)
        if n == 0:
            break
        for i in range(n):
            got.append(chunk[i])
    var got_str = String(unsafe_from_utf8=Span[UInt8, _](got))
    assert_equal(got_str, expected)

    peer.close()
    # ``conn`` drops here -> client socket closed.
    print("test_write_coalescing: passed (", K, "chunks -> 1 syscall)")
