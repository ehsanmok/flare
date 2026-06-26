"""Tests for flare.udp.batch -- recvmmsg / sendmmsg / GSO.

Loopback (127.0.0.1) with OS-assigned ports. These syscalls are
Linux-only; on a non-Linux target or a kernel without the syscall the
helpers raise ``UdpBatchUnsupported`` and the relevant test is skipped
(the per-datagram fallback is exercised by ``test_udp.mojo``).
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.net import SocketAddr
from flare.udp import UdpSocket
from flare.udp.batch import (
    BatchReceiver,
    UdpBatchUnsupported,
    send_batch,
    send_segmented,
    udp_batch_supported,
)
from flare.utils import usleep


def _drain(mut rx: BatchReceiver, fd: Int, want: Int) raises -> Int:
    """Poll recvmmsg until ``want`` datagrams are seen or we give up.

    Loopback delivery is effectively synchronous but the kernel may
    split a burst across two ready notifications; retry a few times.
    """
    var total = 0
    for _ in range(50):
        var n = rx.recv(fd)
        total += n
        if total >= want:
            break
        usleep(2_000)
    return total


def test_recvmmsg_batch_round_trip() raises:
    if not udp_batch_supported():
        return
    var recv_sock = UdpSocket.bind(SocketAddr.localhost(0))
    var tx = UdpSocket.bind(SocketAddr.localhost(0))
    var port = recv_sock.local_addr().port
    var tx_port = tx.local_addr().port

    var count = 4
    for i in range(count):
        var d = List[UInt8]()
        d.append(UInt8(0xA0 + i))
        d.append(UInt8(i))
        _ = tx.send_to(Span[UInt8, _](d), SocketAddr.localhost(port))

    var rx = BatchReceiver(capacity=16, max_payload=1500)
    try:
        var got = _drain(rx, recv_sock.fd(), count)
        assert_equal(got, count, "recvmmsg should drain all datagrams")
        # The last recv call holds the final batch; re-verify message 0
        # by re-draining is racy, so assert on whatever the final batch
        # captured: every captured datagram is 2 bytes with a known
        # first byte in [0xA0, 0xA3].
        for i in range(rx.count()):
            var m = rx.message(i)
            assert_equal(len(m), 2, "each datagram is 2 bytes")
            assert_true(
                m[0] >= UInt8(0xA0) and m[0] <= UInt8(0xA3),
                "payload tag in range",
            )
            var who = rx.sender(i)
            assert_equal(who.port, tx_port, "sender port matches tx")
            assert_equal(String(who.ip), "127.0.0.1")
    except e:
        if String(e).startswith("UdpBatchUnsupported"):
            tx.close()
            recv_sock.close()
            return
        raise e^
    tx.close()
    recv_sock.close()


def test_sendmmsg_batch_round_trip() raises:
    if not udp_batch_supported():
        return
    var rx = UdpSocket.bind(SocketAddr.localhost(0))
    rx.set_recv_timeout(2000)
    var tx = UdpSocket.unbound()
    var port = rx.local_addr().port

    var payloads = List[List[UInt8]]()
    var addrs = List[SocketAddr]()
    var count = 3
    for i in range(count):
        var d = List[UInt8]()
        d.append(UInt8(0x50 + i))
        d.append(UInt8(0x60 + i))
        d.append(UInt8(0x70 + i))
        payloads.append(d^)
        addrs.append(SocketAddr.localhost(port))

    try:
        var sent = send_batch(tx.fd(), payloads, addrs)
        assert_equal(sent, count, "sendmmsg should accept all datagrams")
    except e:
        if String(e).startswith("UdpBatchUnsupported"):
            tx.close()
            rx.close()
            return
        raise e^

    var seen = 0
    for i in range(count):
        var buf = List[UInt8]()
        buf.resize(64, 0)
        var pair = rx.recv_from(Span[UInt8, _](buf))
        assert_equal(pair[0], 3, "each datagram is 3 bytes")
        assert_equal(buf[0], UInt8(0x50 + i), "first byte in send order")
        seen += 1
    assert_equal(seen, count)
    tx.close()
    rx.close()


def test_gso_segmented_send() raises:
    if not udp_batch_supported():
        return
    var rx = UdpSocket.bind(SocketAddr.localhost(0))
    rx.set_recv_timeout(2000)
    var tx = UdpSocket.unbound()
    var port = rx.local_addr().port

    var seg = 100
    var segments = 3
    var data = List[UInt8]()
    for i in range(seg * segments):
        data.append(UInt8(i & 0xFF))

    try:
        var n = send_segmented(
            tx.fd(), SocketAddr.localhost(port), Span[UInt8, _](data), seg
        )
        assert_equal(n, seg * segments, "GSO sendmsg accepts whole buffer")
    except e:
        if String(e).startswith("UdpBatchUnsupported"):
            # Kernel / loopback without UDP_SEGMENT: fallback path is
            # covered by per-datagram send_to elsewhere.
            tx.close()
            rx.close()
            return
        raise e^

    # The kernel slices the buffer into `segments` wire datagrams.
    var received = 0
    for _ in range(segments):
        var buf = List[UInt8]()
        buf.resize(seg + 16, 0)
        try:
            var pair = rx.recv_from(Span[UInt8, _](buf))
            assert_equal(pair[0], seg, "each GSO segment is seg_size bytes")
            received += 1
        except:
            break
    assert_equal(received, segments, "all GSO segments delivered")
    tx.close()
    rx.close()


def main() raises:
    print("=" * 60)
    print("test_udp_batch.mojo -- recvmmsg / sendmmsg / GSO")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
