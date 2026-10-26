"""The OS facts the Lean proofs take as hypotheses, checked on this OS.

``formal/Flare/Core/Assumptions.lean`` states what the models assume about
libc and the kernel, and the proofs (``WriteLoop``, ``ServerConfig``,
``CircuitBreaker``) hold only where those facts do. They are hypotheses,
so nothing in ``lake build`` checks them; this file calls the same
``send(2)`` / ``recv(2)`` / ``clock_gettime`` wrappers flare uses and
asserts each predicate on the results:

  RecvContract cap ret        ret = -1 or 0 <= ret <= cap
  SendContractStrong len ret  ret = -1 or 1 <= ret <= len   (blocking, len > 0)
  SendContract len ret        ret = -1 or 0 <= ret <= len
  MonotoneClock ts            successive readings never decrease
"""

from std.ffi import c_int, c_size_t
from std.testing import assert_true, TestSuite

from flare.net import SocketAddr
from flare.net._libc import MSG_DONTWAIT, MSG_NOSIGNAL, _recv, _send
from flare.runtime._libc_time import libc_usleep, monotonic_now_ms
from flare.tcp import TcpListener, TcpStream


def _recv_contract(cap: Int, ret: Int) -> Bool:
    return ret == -1 or (0 <= ret and ret <= cap)


def _send_contract(len: Int, ret: Int) -> Bool:
    return ret == -1 or (0 <= ret and ret <= len)


def _send_contract_strong(len: Int, ret: Int) -> Bool:
    return ret == -1 or (1 <= ret and ret <= len)


def _fill(n: Int) -> List[UInt8]:
    var b = List[UInt8]()
    b.resize(n, 0x61)
    return b^


def test_recv_contract() raises:
    """``recv`` into every capacity, below, at and above what is queued, on
    an empty non-blocking queue and at EOF, stays within ``0..cap`` or is
    ``-1``."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()
    var buf = _fill(4096)
    var payload = _fill(10)
    for cap in [1, 3, 10, 16, 4096]:
        c.write_all(Span(payload))
        var got = 0
        while got < 10:
            var ret = Int(
                _recv(s._socket.fd, buf.unsafe_ptr(), c_size_t(cap), c_int(0))
            )
            assert_true(
                _recv_contract(cap, ret), "recv returned " + String(ret)
            )
            assert_true(ret > 0, "recv must make progress on queued bytes")
            got += ret
    var empty = Int(
        _recv(s._socket.fd, buf.unsafe_ptr(), c_size_t(16), MSG_DONTWAIT)
    )
    assert_true(empty == -1, "empty non-blocking recv must be -1")
    c.shutdown_write()
    var eof = Int(_recv(s._socket.fd, buf.unsafe_ptr(), c_size_t(16), c_int(0)))
    assert_true(_recv_contract(16, eof) and eof == 0, "recv at EOF must be 0")
    c.close()
    s.close()
    l.close()


def test_send_contract_strong_blocking() raises:
    """A blocking ``send`` of ``len > 0`` bytes returns ``1..len``, never 0:
    the strong contract ``write_all`` relies on."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()
    var sink = _fill(8192)
    for n in [1, 7, 1500, 8192]:
        var data = _fill(n)
        var ret = Int(
            _send(c._socket.fd, data.unsafe_ptr(), c_size_t(n), MSG_NOSIGNAL)
        )
        assert_true(
            _send_contract_strong(n, ret), "send returned " + String(ret)
        )
        s.read_exact(sink.unsafe_ptr(), ret)
    c.close()
    s.close()
    l.close()


def test_send_contract_partial_and_full() raises:
    """``send`` on a non-blocking socket into a peer that never reads: partial writes and
    then ``-1`` (EAGAIN), every result within the POSIX contract."""
    var l = TcpListener.bind(SocketAddr.localhost(0))
    var c = TcpStream.connect(SocketAddr.localhost(l.local_addr().port))
    var s = l.accept()
    c._socket.set_nonblocking(True)
    var n = 1 << 18
    var data = _fill(n)
    var saw_full = False
    for _ in range(256):
        var ret = Int(
            _send(
                c._socket.fd,
                data.unsafe_ptr(),
                c_size_t(n),
                MSG_NOSIGNAL,
            )
        )
        assert_true(_send_contract(n, ret), "send returned " + String(ret))
        assert_true(ret != 0, "send of a non-empty buffer returned 0")
        if ret == -1:
            saw_full = True
            break
    assert_true(saw_full, "the socket buffer never filled; EAGAIN path not hit")
    c.close()
    s.close()
    l.close()


def test_monotone_clock() raises:
    """``monotonic_now_ms`` never decreases, and it advances: a clock stuck
    at a constant would satisfy the contract while breaking every deadline
    (the wrong ``CLOCK_MONOTONIC`` id on macOS did exactly that)."""
    var last = monotonic_now_ms()
    for _ in range(10000):
        var now = monotonic_now_ms()
        assert_true(now >= last, "monotonic clock went backwards")
        last = now
    var before = monotonic_now_ms()
    _ = libc_usleep(20_000)
    assert_true(
        monotonic_now_ms() - before >= 10, "monotonic clock did not advance"
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
