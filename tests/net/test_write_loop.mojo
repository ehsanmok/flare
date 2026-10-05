"""Tests for the shared ``write_all`` loop (``flare.net._write_loop``).

NET-02: ``TcpStream.write_all`` / ``UnixStream.write_all`` added the result
of ``send(2)`` to their progress counter without checking for ``0``. POSIX
lets ``send`` return ``0`` for a non-empty buffer; the loop then called
``send`` again forever. No supported kernel does this on a blocking stream
socket, so the loop is driven here through a scripted writer.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    TestSuite,
)

from std.memory import Layout, Pointer, alloc

from flare.net import NetworkError
from flare.net._write_loop import _ChunkWriter, write_all_chunks


comptime _LOG_SLOTS = 8


struct _ScriptedWriter(_ChunkWriter):
    """Returns the scripted byte counts in order; once the script is used up
    it raises ``Error("script exhausted")`` (so a livelocking loop ends).

    ``_ChunkWriter._write_chunk`` takes ``self`` immutably (the real streams
    are used through shared references), so the call log lives behind a
    heap pointer: ``state[0]`` is the number of calls so far and
    ``state[1 + i]`` the bytes offered on call ``i`` (first 8 calls).
    """

    var script: List[Int]
    var state: Pointer[Int, MutUntrackedOrigin]

    def __init__(out self, var script: List[Int]):
        self.script = script^
        var raw = alloc(Layout[Int](count=1 + _LOG_SLOTS)).unsafe_leak()
        self.state = Pointer[Int, MutUntrackedOrigin](
            unsafe_from_address=Int(raw)
        )
        for i in range(1 + _LOG_SLOTS):
            (self.state.unsafe_offset(i)).unsafe_write(0)

    def __deinit__(deinit self):
        self.state.unsafe_free()

    def count(self) -> Int:
        return self.state.unsafe_offset(0)[]

    def offered(self, i: Int) -> Int:
        return self.state.unsafe_offset(1 + i)[]

    def _write_chunk(self, data: Span[UInt8, _]) raises -> Int:
        var i = self.count()
        (self.state.unsafe_offset(0)).unsafe_write(i + 1)
        if i < _LOG_SLOTS:
            (self.state.unsafe_offset(1 + i)).unsafe_write(len(data))
        if i >= len(self.script):
            raise Error("script exhausted")
        var n = self.script[i]
        if n > len(data):
            n = len(data)
        return n


def _bytes(n: Int) -> List[UInt8]:
    return List[UInt8](length=n, fill=UInt8(0x41))


def test_write_all_completes_through_partial_writes() raises:
    var w = _ScriptedWriter([3, 4, 100])
    var data = _bytes(10)
    write_all_chunks(w, Span(data))
    # 3 + 4 + the remaining 3.
    assert_equal(w.count(), 3)
    assert_equal(w.offered(0), 10)
    assert_equal(w.offered(1), 7)
    assert_equal(w.offered(2), 3)


def test_write_all_empty_data_makes_no_call() raises:
    var w = _ScriptedWriter(List[Int]())
    var data = _bytes(0)
    write_all_chunks(w, Span(data))
    assert_equal(w.count(), 0)


def test_write_all_raises_when_send_returns_zero() raises:
    """NET-02: a 0 return with bytes remaining must raise, not spin."""
    # 1000 zero returns, then the script runs out (stands in for the EIO
    # that ended the livelock in the repro).
    var zeros = List[Int]()
    for _ in range(1000):
        zeros.append(0)
    var w = _ScriptedWriter(zeros^)
    var data = _bytes(100)
    var raised = False
    var msg = String("")
    try:
        write_all_chunks(w, Span(data))
    except e:
        raised = True
        msg = String(e)
    assert_true(raised)
    assert_equal(w.count(), 1)
    assert_true("returned 0" in msg)


def test_write_all_raises_after_partial_progress_then_zero() raises:
    var w = _ScriptedWriter([40, 0, 60])
    var data = _bytes(100)
    var raised = False
    var msg = String("")
    try:
        write_all_chunks(w, Span(data))
    except e:
        raised = True
        msg = String(e)
    assert_true(raised)
    assert_equal(w.count(), 2)
    assert_true("40/100" in msg)


def test_write_all_propagates_writer_errors() raises:
    var w = _ScriptedWriter([5])
    var data = _bytes(10)
    var msg = String("")
    try:
        write_all_chunks(w, Span(data))
    except e:
        msg = String(e)
    assert_equal(msg, String("script exhausted"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
