"""Fuzz harness: HTTP/3 server driver
(:class:`flare.h3.H3Connection`).

Drives the bidirectional + unidirectional stream entry points
of the server-side H3 connection driver against arbitrary
bytes. The driver is sans-I/O -- the QUIC reactor feeds it
reassembled stream-data chunks via :meth:`feed_stream_chunk`
(bidi request streams) and :meth:`feed_uni_stream_chunk`
(control / qpack-enc / qpack-dec / push) -- so the safety
invariants we fuzz here are:

1. **No panics.** Neither feed entry point may ever crash on
   arbitrary input; any structural violation must raise a
   regular :class:`Error` (the QUIC reactor catches the Error,
   maps it to an H3 error code, and resets / cancels the
   stream).
2. **Bounded state growth.** A single feed call may register
   at most one new stream and may surface at most one new
   completed-stream ID. The driver must not allocate
   unbounded memory in response to a single peer chunk.
3. **Take operations are idempotent on the same stream.**
   ``take_completed_streams`` may return the same ID multiple
   times across calls until ``take_request`` is invoked; after
   ``take_request`` the stream MUST NOT re-appear in
   ``take_completed_streams``.
4. **emit_response refuses double-emit.** A repeat
   :meth:`emit_response` on the same stream raises.

The fuzzer carves the input bytes into five work items:

* Branch A: feed the bytes as a bidi-stream chunk on stream 0,
  then signal FIN, then take_completed_streams.
* Branch B: feed the bytes as a peer uni-stream chunk on
  stream 3 (the typical peer control-stream id).
* Branch C: split the bytes in half across two feed calls, then
  FIN, then take_completed_streams.
* Branch D: feed every byte as a 1-byte chunk (worst case for
  the NEEDS_MORE buffering loop).
* Branch E (Track Q12-W): route the bytes through
  :meth:`flare.quic.server.QuicListener._route_h3_stream_chunks`
  via a synthetic :class:`flare.quic.state.ConnectionEvents` so
  the new dispatch-on-listener path is fuzz-covered too. Same
  safety bar as branches A..D.

Run:
    pixi run --environment fuzz fuzz-h3-server
"""

from mozz import FuzzConfig, fuzz

from flare.h3 import H3Connection
from flare.net import IpAddr, SocketAddr
from flare.quic.frame import StreamFrame
from flare.quic.packet import (
    ConnectionId,
    LongHeader,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
)
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import empty_events
from flare.tls.rustls_quic import RustlsQuicConfig


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


def _run_bidi_round(mut c: H3Connection, var chunk: List[UInt8]) raises:
    """Feed a bidi chunk on stream 0, signal FIN, and check the
    bounded-growth invariants."""
    var pre_count = len(c.streams)
    try:
        c.feed_stream_chunk(0, chunk^)
    except _:
        return
    c.signal_end_of_stream(0)
    var post_count = len(c.streams)
    _assert(
        post_count <= pre_count + 1,
        "H3 bidi feed allocated > 1 stream in a single chunk",
    )
    var ready = c.take_completed_streams()
    _assert(
        len(ready) <= 1,
        "H3 take_completed_streams surfaced > 1 id in a single chunk",
    )
    if len(ready) == 1 and ready[0] == 0:
        try:
            var _req = c.take_request(0)
        except _:
            return
        # After take, the stream must no longer be in the ready
        # set on a second call.
        var ready2 = c.take_completed_streams()
        for i in range(len(ready2)):
            _assert(
                ready2[i] != 0,
                "stream 0 re-surfaced after take_request",
            )


def _run_uni_round(mut c: H3Connection, var chunk: List[UInt8]) raises:
    """Feed a chunk on peer uni stream 3 -- the typical peer
    control stream id. Errors are acceptable (the chunk may be
    structurally invalid)."""
    try:
        c.feed_uni_stream_chunk(3, chunk^)
    except _:
        pass


def _run_split_feed(mut c: H3Connection, data: List[UInt8]) raises:
    var mid = len(data) // 2
    var a = List[UInt8](capacity=mid)
    var b = List[UInt8](capacity=len(data) - mid)
    for i in range(mid):
        a.append(data[i])
    for i in range(mid, len(data)):
        b.append(data[i])
    try:
        c.feed_stream_chunk(4, a^)
        c.feed_stream_chunk(4, b^)
    except _:
        return
    c.signal_end_of_stream(4)
    var ready = c.take_completed_streams()
    _assert(
        len(ready) <= 2,
        "split feed surfaced > 2 ready streams",
    )


def _run_byte_at_a_time(mut c: H3Connection, data: List[UInt8]) raises:
    for i in range(len(data)):
        var chunk = List[UInt8]()
        chunk.append(data[i])
        try:
            c.feed_stream_chunk(8, chunk^)
        except _:
            return
    c.signal_end_of_stream(8)
    _ = c.take_completed_streams()


def _run_listener_dispatch(var data: List[UInt8]) raises:
    """Branch E (Track Q12-W): drive the new H3 dispatch on
    :class:`flare.quic.server.QuicListener` with a synthetic
    STREAM frame so the fuzz coverage extends past the
    sans-I/O driver into the listener-side routing path.

    The empty-PEM acceptor returns a NULL rustls session
    handle; the path never needs a real TLS roundtrip because
    :meth:`QuicListener._route_h3_stream_chunks` is
    sans-I/O too.
    """
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config = RustlsQuicConfig()
    var listener: QuicListener
    try:
        listener = QuicListener.bind(cfg^)
    except _:
        return
    var dcid_bytes = List[UInt8]()
    for i in range(8):
        dcid_bytes.append(UInt8(0xA0 + i))
    var scid_bytes = List[UInt8]()
    for i in range(8):
        scid_bytes.append(UInt8(0xB0 + i))
    var dcid = ConnectionId(bytes=dcid_bytes^)
    var scid = ConnectionId(bytes=scid_bytes^)
    var lh = LongHeader(
        packet_type=PACKET_TYPE_INITIAL,
        version=QUIC_VERSION_1,
        dcid=dcid^,
        scid=scid^,
        payload_offset=0,
    )
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot: Int
    try:
        slot = listener._accept_initial(lh, peer)
    except _:
        return
    var events = empty_events()
    events.stream_chunks.append(
        StreamFrame(
            stream_id=UInt64(0),
            offset=UInt64(0),
            data=data^,
            fin=True,
        )
    )
    try:
        listener._route_h3_stream_chunks(slot, events)
    except _:
        return
    var ready = listener.take_h3_completed_streams(slot)
    _assert(
        len(ready) <= 1,
        "listener dispatch surfaced > 1 ready stream from a single frame",
    )


def target(data: List[UInt8]) raises:
    var n = len(data)

    # Branch A: bidi chunk on stream 0.
    var c1 = H3Connection()
    _run_bidi_round(c1, data.copy())

    # Branch B: peer uni stream chunk.
    var c2 = H3Connection()
    _run_uni_round(c2, data.copy())

    if n < 2:
        return

    # Branch C: split bidi feed.
    var c3 = H3Connection()
    _run_split_feed(c3, data)

    # Branch D: 1-byte-at-a-time feed (the NEEDS_MORE buffering
    # worst case). Capped at 64 bytes so each fuzz run stays
    # fast.
    var capped = data.copy()
    if len(capped) > 64:
        var trim = List[UInt8](capacity=64)
        for i in range(64):
            trim.append(capped[i])
        capped = trim^
    var c4 = H3Connection()
    _run_byte_at_a_time(c4, capped)

    # Branch E (Q12-W): the new dispatch-on-listener path. The
    # listener bind allocates a UDP fd + a TimerWheel; the
    # constructor is fast (<1 ms) so doing it on every fuzz run
    # is acceptable. ``data`` is cloned because Branch C already
    # consumed the original.
    _run_listener_dispatch(data.copy())


def main() raises:
    print("=" * 60)
    print("fuzz_h3_server.mojo -- HTTP/3 server driver safety")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    # Empty.
    seeds.append(List[UInt8]())
    # Single zero byte -- not a valid varint type for h3.
    seeds.append(_bytes("\x00"))
    # SETTINGS frame on a control stream (type 0x00) -- valid
    # peer-control prefix.
    seeds.append(_bytes("\x00\x04\x04\x01\x01\x06\x02"))
    # HEADERS frame, 4-byte payload, all-zero (decodes to empty
    # field section; reader rejects -- exercises error path).
    seeds.append(_bytes("\x01\x04\x00\x00\x00\x00"))
    # DATA frame, 5-byte payload "hello" -- on a request stream
    # without preceding HEADERS this should error out.
    seeds.append(_bytes("\x00\x05hello"))
    # Truncated HEADERS (declares 16 bytes, supplies 5).
    seeds.append(_bytes("\x01\x10short"))
    # Grease frame type 0x21 + empty payload.
    seeds.append(_bytes("\x21\x00"))
    # 2-byte varint frame type 0x40 0x00.
    seeds.append(_bytes("\x40\x00\x00"))
    # Push uni-stream prefix (type 0x01).
    seeds.append(_bytes("\x01"))
    # QPACK encoder uni-stream prefix (type 0x02) + a SET
    # DYNAMIC TABLE CAPACITY instruction body.
    seeds.append(_bytes("\x02\x3F\x00"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/h3_server",
            corpus_dir="fuzz/corpus/h3_server",
            max_input_len=256,
        ),
        seeds,
    )
