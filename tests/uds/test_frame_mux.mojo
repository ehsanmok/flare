"""Tests for the multiplexed framed transport (v0.9 B3).

Three layers, each isolated:

- the pure codec (``encode_frame`` / ``decode_frame``) round-trips;
- ``FrameDemux`` reassembles frames split/coalesced arbitrarily across
  feeds, keeps per-stream FIFO order, isolates streams, and rejects an
  oversize length as a protocol error;
- ``FrameMux`` multiplexes 1k logical streams over a single forked
  loopback ``UnixStream`` with correct per-stream echo (no reconnect).
"""

from std.testing import assert_equal, assert_true, assert_false

from flare.io import ByteReader, ByteWriter
from flare.uds import (
    Frame,
    FrameDemux,
    FrameKind,
    FrameMux,
    UnixListener,
    UnixStream,
    decode_frame,
    encode_frame,
)
from flare.uds._libc import unlink_path
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


# ── Pure codec ──────────────────────────────────────────────────────────────


def test_encode_decode_roundtrip() raises:
    var w = ByteWriter()
    var payload: List[UInt8] = [0x68, 0x69, 0x21]  # "hi!"
    encode_frame(w, 42, FrameKind.CHUNK, Span[UInt8, _](payload))
    var bytes = w.take()
    # 13-byte header + 3-byte payload.
    assert_equal(len(bytes), 16)
    var r = ByteReader(Span[UInt8, _](bytes))
    var f = decode_frame(r)
    assert_equal(Int(f.request_id), 42)
    assert_equal(Int(f.kind), Int(FrameKind.CHUNK))
    assert_equal(len(f.payload), 3)
    assert_equal(Int(f.payload[0]), 0x68)
    assert_equal(Int(f.payload[2]), 0x21)


def test_decode_short_buffer_raises() raises:
    var w = ByteWriter()
    var payload: List[UInt8] = [1, 2, 3, 4]
    encode_frame(w, 7, FrameKind.CHUNK, Span[UInt8, _](payload))
    var bytes = w.take()
    bytes.resize(len(bytes) - 1, 0)  # truncate last payload byte
    var r = ByteReader(Span[UInt8, _](bytes))
    var raised = False
    try:
        _ = decode_frame(r)
    except:
        raised = True
    assert_true(raised, "decode_frame must raise on a truncated frame")


# ── FrameDemux reassembly / routing ─────────────────────────────────────────


def _enc(mut w: ByteWriter, rid: UInt64, kind: UInt8, text: String) raises:
    encode_frame(w, rid, kind, text.as_bytes())


def test_demux_multiple_frames_one_feed() raises:
    var w = ByteWriter()
    _enc(w, 1, FrameKind.CHUNK, "a")
    _enc(w, 2, FrameKind.CHUNK, "bb")
    _enc(w, 1, FrameKind.CHUNK, "ccc")
    var bytes = w.take()

    var d = FrameDemux()
    d.feed(Span[UInt8, _](bytes))

    # Stream 1 keeps FIFO order: "a" then "ccc".
    assert_equal(d.pending(1), 2)
    assert_equal(d.pending(2), 1)
    var f1 = d.poll(1)
    assert_true(f1.__bool__())
    assert_equal(len(f1.value().payload), 1)
    var f2 = d.poll(1)
    assert_equal(len(f2.value().payload), 3)
    assert_false(d.poll(1).__bool__())  # drained
    # Stream 2 untouched by stream 1's draining (isolation).
    assert_equal(d.pending(2), 1)
    assert_equal(len(d.poll(2).value().payload), 2)


def test_demux_split_across_feeds() raises:
    var w = ByteWriter()
    _enc(w, 9, FrameKind.CHUNK, "hello world")
    var bytes = w.take()

    var d = FrameDemux()
    # Feed one byte at a time -- exercises header + payload split.
    for i in range(len(bytes)):
        var one = List[UInt8](capacity=1)
        one.append(bytes[i])
        d.feed(Span[UInt8, _](one))
        if i < len(bytes) - 1:
            assert_equal(d.pending(9), 0)  # nothing complete yet
    assert_equal(d.pending(9), 1)
    var f = d.poll(9)
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](f.value().payload)),
        "hello world",
    )


def test_demux_oversize_length_raises() raises:
    # Hand-craft a header whose u32 length is absurd.
    var w = ByteWriter()
    w.write_u32_be(UInt32(0xFFFFFFFF))
    w.write_u64_be(1)
    w.write_u8(FrameKind.CHUNK)
    var bytes = w.take()
    var d = FrameDemux()
    var raised = False
    try:
        d.feed(Span[UInt8, _](bytes))
    except:
        raised = True
    assert_true(raised, "demux must reject a payload above MAX_FRAME_PAYLOAD")


def test_demux_thousand_streams_isolated() raises:
    var w = ByteWriter()
    for rid in range(1, 1001):
        _enc(w, UInt64(rid), FrameKind.CHUNK, String(rid))
    var bytes = w.take()

    var d = FrameDemux()
    d.feed(Span[UInt8, _](bytes))
    for rid in range(1, 1001):
        assert_equal(d.pending(UInt64(rid)), 1)
        var f = d.poll(UInt64(rid))
        assert_equal(
            String(unsafe_from_utf8=Span[UInt8, _](f.value().payload)),
            String(rid),
        )


# ── FrameMux over a single forked loopback connection ────────────────────────


def main() raises:
    test_encode_decode_roundtrip()
    test_decode_short_buffer_raises()
    test_demux_multiple_frames_one_feed()
    test_demux_split_across_feeds()
    test_demux_oversize_length_raises()
    test_demux_thousand_streams_isolated()

    # ── Loopback multiplex: 1k streams, one connection, per-stream echo ──
    var N = 1000
    var path = String("/tmp/flare_framemux_test.sock")
    _ = unlink_path(path)
    # cleanup_path=False: the path lifecycle spans the fork (two
    # processes share the listening socket). With the default
    # cleanup_path=True the parent's listener destructor unlinks the
    # socket file before the parent connects -> ConnectionRefused. The
    # parent unlinks the path explicitly at the end instead.
    var listener = UnixListener.bind_with_options(path, cleanup_path=False)

    var pid = fork()
    if pid == 0:
        # Child: accept one connection, echo each CHUNK back on its id.
        try:
            var conn = listener.accept()
            var mux = FrameMux(conn^)
            var seen = 0
            while seen < N:
                var got = mux.pump()
                if got == 0:
                    break
                for rid in range(1, N + 1):
                    var f = mux.poll(UInt64(rid))
                    while f.__bool__():
                        var frame = f.value().copy()
                        mux.send_chunk(
                            UInt64(rid), Span[UInt8, _](frame.payload)
                        )
                        seen += 1
                        f = mux.poll(UInt64(rid))
            mux.flush()
            # Give the parent time to drain before the socket closes.
            usleep(200_000)
        except:
            pass
        exit()

    usleep(250_000)

    var conn = UnixStream.connect(path)
    var mux = FrameMux(conn^)
    for rid in range(1, N + 1):
        mux.send_chunk(UInt64(rid), String(rid).as_bytes())
    mux.flush()

    var done = List[Bool](capacity=N + 1)
    done.resize(N + 1, False)
    var collected = 0
    while collected < N:
        var got = mux.pump()
        if got == 0:
            break
        for rid in range(1, N + 1):
            if done[rid]:
                continue
            var f = mux.poll(UInt64(rid))
            if f.__bool__():
                var frame = f.value().copy()
                assert_equal(
                    String(unsafe_from_utf8=Span[UInt8, _](frame.payload)),
                    String(rid),
                )
                done[rid] = True
                collected += 1

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    _ = listener.local_path()  # keep the listener alive past the drain
    _ = unlink_path(path)  # parent owns path cleanup (cleanup_path=False)

    assert_equal(collected, N)
    print("test_frame_mux: all passed (6 unit + 1k-stream loopback)")
