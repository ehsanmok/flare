"""Fuzz harness: HTTP/2 RAPID-RESET (CVE-2023-44487).

Adversary opens streams with ``HEADERS`` and immediately sends
``RST_STREAM`` to close them, repeating fast enough to consume
server resources (HPACK dynamic table churn, stream-state slots,
HEADERS decode work) without ever paying for a body. This took
out a non-trivial fraction of public h2 traffic in October 2023.

Property checked: ``Connection.handle_frame`` does not panic on
any sequence of HEADERS / RST_STREAM / DATA / WINDOW_UPDATE frames
on stream ids the fuzzer can name. The state machine now enforces
a rapid-reset cap: past ``_RST_FLOOD_THRESHOLD`` inbound
RST_STREAMs it emits GOAWAY(ENHANCE_YOUR_CALM) once (the exact
threshold behavior is asserted in tests/http2/test_h2_state.mojo).
Shape bit 4 drives a cheap single-stream RST flood so the fuzzer
exercises that enforcement branch; the invariant here stays
no-panic.

Run:
    pixi run fuzz-h2-rapid-reset
"""

from mozz import fuzz, FuzzConfig

from flare.http2 import (
    Frame,
    FrameFlags,
    FrameType,
    Http2Connection,
    H2_PREFACE,
    HpackEncoder,
    HpackHeader,
    Http2Config,
    encode_frame,
)


def _preface() -> List[UInt8]:
    var b = String(H2_PREFACE).as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


def _build_headers_frame(
    mut enc: HpackEncoder, stream_id: Int, end_stream: Bool, path: String
) raises -> Frame:
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", path))
    hdrs.append(HpackHeader(":authority", "example.com"))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = stream_id
    var flags = FrameFlags.END_HEADERS()
    if end_stream:
        flags = flags | FrameFlags.END_STREAM()
    f.header.flags = FrameFlags(flags)
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    return f^


def _build_rst_stream_frame(stream_id: Int, error_code: Int) -> Frame:
    """RFC 9113 paragraph 6.4: RST_STREAM has a 4-byte payload (error code)."""
    var f = Frame()
    f.header.type = FrameType.RST_STREAM()
    f.header.stream_id = stream_id
    f.header.flags = FrameFlags(0)
    f.payload = List[UInt8]()
    f.payload.append(UInt8((error_code >> 24) & 0xFF))
    f.payload.append(UInt8((error_code >> 16) & 0xFF))
    f.payload.append(UInt8((error_code >> 8) & 0xFF))
    f.payload.append(UInt8(error_code & 0xFF))
    return f^


def _build_data_frame(stream_id: Int, end_stream: Bool, n: Int) -> Frame:
    var f = Frame()
    f.header.type = FrameType.DATA()
    f.header.stream_id = stream_id
    f.header.flags = FrameFlags(
        FrameFlags.END_STREAM()
    ) if end_stream else FrameFlags(0)
    f.payload = List[UInt8]()
    for _ in range(n):
        f.payload.append(UInt8(ord("x")))
    return f^


def target(data: List[UInt8]) raises:
    if len(data) < 4:
        return

    var c = Http2Connection.with_config(Http2Config())
    try:
        c.feed(Span[UInt8, _](_preface()))
        _ = c.drain()
    except:
        return

    # data[0] -> n_cycles (0..255 capped to 64 runtime; the harness
    #            still explores the no-panic property at large N).
    # data[1] -> attack-shape bits:
    #            bit 0: include END_STREAM on the HEADERS
    #            bit 1: send a DATA frame between HEADERS and RST_STREAM
    #            bit 2: alternate RST_STREAM error codes
    #            bit 3: target stream 0 with RST_STREAM (RFC violation)
    # data[2..]: per-cycle stream-id offset / payload chunk
    var n_cycles = Int(data[0])
    if n_cycles > 64:
        n_cycles = 64  # bound the wall-clock cost of one fuzz iter
    var shape = Int(data[1])
    var es = (shape & 0x01) != 0
    var with_data = (shape & 0x02) != 0
    var alt_codes = (shape & 0x04) != 0
    var rst_zero = (shape & 0x08) != 0
    var flood = (shape & 0x10) != 0

    # Cheap single-stream RST flood: open one stream, then blast
    # RST_STREAMs past the rapid-reset threshold to exercise the
    # GOAWAY(ENHANCE_YOUR_CALM) enforcement branch without paying a
    # HEADERS decode per reset. Invariant remains no-panic.
    if flood:
        var fenc = HpackEncoder()
        try:
            var of = _build_headers_frame(fenc, 1, False, "/flood")
            c.feed(Span[UInt8, _](encode_frame(of)))
            _ = c.drain()
            for _ in range(600):
                var rf = _build_rst_stream_frame(1, 0x8)
                c.feed(Span[UInt8, _](encode_frame(rf)))
                _ = c.drain()
        except:
            pass
        return

    var enc = HpackEncoder()
    var sid = 1  # Client streams MUST be odd (RFC 9113 paragraph 5.1.1)
    var cursor = 2

    for cycle in range(n_cycles):
        # HEADERS for this stream.
        try:
            var path = "/cycle" + String(cycle)
            var hf = _build_headers_frame(enc, sid, es, path)
            var hf_bytes = encode_frame(hf)
            c.feed(Span[UInt8, _](hf_bytes))
            _ = c.drain()
        except:
            return

        # Optional DATA frame.
        if with_data and not es:
            var n = 0
            if cursor < len(data):
                n = Int(data[cursor]) & 0x7  # 0..7 bytes
                cursor += 1
            try:
                var df = _build_data_frame(sid, False, n)
                var df_bytes = encode_frame(df)
                c.feed(Span[UInt8, _](df_bytes))
                _ = c.drain()
            except:
                pass

        # RST_STREAM: target the stream we just opened, or stream 0
        # (RFC violation -- harness asserts handler doesn't panic).
        var target_sid = sid
        if rst_zero:
            target_sid = 0
        var ec = 0x8  # CANCEL by default
        if alt_codes:
            ec = (cycle & 0xFF) % 0xD  # cycles through error codes 0..0xC
        try:
            var rf = _build_rst_stream_frame(target_sid, ec)
            var rf_bytes = encode_frame(rf)
            c.feed(Span[UInt8, _](rf_bytes))
            _ = c.drain()
        except:
            pass

        sid += 2  # next client stream id

    # After N cycles, fire one more HEADERS to verify the connection
    # is still serviceable (or has gracefully closed). Either is OK;
    # a panic / SIGSEGV is not.
    try:
        var hf = _build_headers_frame(enc, sid, True, "/probe")
        var hf_bytes = encode_frame(hf)
        c.feed(Span[UInt8, _](hf_bytes))
        _ = c.drain()
    except:
        pass


def main() raises:
    print("[mozz] fuzzing HTTP/2 RAPID-RESET state machine...")

    var seeds = List[List[UInt8]]()

    def _seed(*bytes: Int) -> List[UInt8]:
        var out = List[UInt8]()
        for i in range(len(bytes)):
            out.append(UInt8(bytes[i] & 0xFF))
        return out^

    # Empty.
    seeds.append(_seed(0, 0))
    # Single HEADERS+END_STREAM then RST_STREAM.
    seeds.append(_seed(1, 0x01))
    # 32 cycles of vanilla HEADERS-no-END_STREAM + RST_STREAM
    # (the canonical CVE-2023-44487 shape).
    seeds.append(_seed(32, 0x00))
    # 32 cycles of HEADERS+DATA+RST_STREAM (mid-body abort).
    seeds.append(_seed(32, 0x02, 4, 4, 4, 4))
    # 16 cycles, alternating error codes 0..C.
    seeds.append(_seed(16, 0x04))
    # RST_STREAM on stream 0 (RFC 9113 paragraph 6.4 violation).
    seeds.append(_seed(8, 0x08))
    # Single-stream RST flood past the rapid-reset threshold.
    seeds.append(_seed(1, 0x10))
    # Mix: HEADERS+DATA+RST_STREAM with alternating error codes.
    seeds.append(_seed(16, 0x06, 2, 2, 2, 2, 2, 2, 2, 2))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/h2_rapid_reset",
            corpus_dir="fuzz/corpus/h2_rapid_reset",
            max_input_len=128,
        ),
        seeds,
    )
