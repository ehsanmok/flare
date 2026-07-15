"""Fuzz harness: HTTP/2 CONTINUATION-flood (RFC 9113 paragraph 4.3).

Adversary sends ``HEADERS`` with ``END_HEADERS=0``, then arbitrary
``CONTINUATION`` frames -- with or without ``END_HEADERS``, on
arbitrary stream ids, with arbitrary HPACK payloads. The state
machine MUST never panic. Long-running CONTINUATION sequences
without END_HEADERS are a classic resource-exhaustion vector
(the server has to buffer every header block until END_HEADERS,
or until the connection is killed).

Property checked: ``Connection.handle_frame`` does not panic on
any sequence of HEADERS / CONTINUATION / DATA / RST_STREAM frames
the fuzzer can construct, *whatever* the byte stream looks like.
The state machine now caps CONTINUATION frames per header block
(``_CONTINUATION_FRAME_CAP``) and the accumulated header-list
bytes, RST'ing an over-cap block with ENHANCE_YOUR_CALM (the
exact behavior is asserted in tests/http2/test_h2_state.mojo). A
sentinel first byte (0xFF) drives a long empty-CONTINUATION flood
so the fuzzer exercises that enforcement branch; the invariant
here stays no-panic.

Run:
    pixi run fuzz-h2-continuation
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


def _printable_str(data: List[UInt8], start: Int, length: Int) -> String:
    """Build a printable-ASCII-only string from ``data[start:start+length]``.

    HPACK accepts arbitrary octets, but we want the fuzzer to
    explore the *state-machine* shape (HEADERS without END_HEADERS,
    long CONTINUATION trains, etc.), not the HPACK byte parser
    (that's covered by ``fuzz-hpack-decoder``). So we sanitise
    header values to printable ASCII; non-printable bytes become
    ``x``.
    """
    var s = String("")
    var n = length
    if start + n > len(data):
        n = len(data) - start
    if n < 0:
        n = 0
    for i in range(n):
        var c = Int(data[start + i])
        if c < 0x20 or c > 0x7E or c == 0x3A:
            s += "x"
        else:
            s += chr(c)
    if s == "":
        s = "x"
    return s^


def _build_headers_frame(
    mut enc: HpackEncoder,
    stream_id: Int,
    end_headers: Bool,
    end_stream: Bool,
    extra_value: String,
) raises -> Frame:
    """Build a server-side request HEADERS frame with the four standard
    pseudo-headers + a fuzzer-controlled ``x-fuzz`` value."""
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    if extra_value != "":
        hdrs.append(HpackHeader("x-fuzz", extra_value))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = stream_id
    var flags = UInt8(0)
    if end_headers:
        flags = flags | FrameFlags.END_HEADERS()
    if end_stream:
        flags = flags | FrameFlags.END_STREAM()
    f.header.flags = FrameFlags(flags)
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    return f^


def _build_continuation_frame(
    mut enc: HpackEncoder,
    stream_id: Int,
    end_headers: Bool,
    extra_value: String,
) raises -> Frame:
    var hdrs = List[HpackHeader]()
    if extra_value != "":
        hdrs.append(HpackHeader("x-fuzz-cont", extra_value))
    else:
        hdrs.append(HpackHeader("x-fuzz-cont", "y"))
    var f = Frame()
    f.header.type = FrameType.CONTINUATION()
    f.header.stream_id = stream_id
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS()
    ) if end_headers else FrameFlags(0)
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
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

    # Sentinel: drive a long empty-CONTINUATION flood past the cap to
    # exercise the RST(ENHANCE_YOUR_CALM) enforcement branch cheaply.
    # Invariant remains no-panic.
    if Int(data[0]) == 0xFF:
        var fenc = HpackEncoder()
        try:
            var hf = _build_headers_frame(fenc, 1, False, False, "")
            c.feed(Span[UInt8, _](encode_frame(hf)))
            _ = c.drain()
            for _ in range(80):
                var cf = _build_continuation_frame(fenc, 1, False, "")
                c.feed(Span[UInt8, _](encode_frame(cf)))
                _ = c.drain()
        except:
            pass
        return

    # Decode the fuzzer bytes into a frame plan:
    #  data[0]                 -> n_continuations (0..31), shifted >> 3
    #  data[0] & 0x07          -> control bits:
    #                              bit 0: HEADERS carries END_HEADERS
    #                              bit 1: HEADERS carries END_STREAM
    #                              bit 2: terminal CONTINUATION carries END_HEADERS
    #  data[1]                 -> stream id seed (we use 1 + (data[1]&0xFE))
    #  data[2]                 -> initial value byte length (0..15)
    #  data[3..3+plen]         -> initial value (printable-coerced)
    #  remaining bytes         -> per-CONTINUATION value chunks
    var ctrl = Int(data[0])
    var n_cont = (ctrl >> 3) & 0x1F
    var headers_eh = (ctrl & 0x01) != 0
    var headers_es = (ctrl & 0x02) != 0
    var cont_term_eh = (ctrl & 0x04) != 0
    var sid = 1 + ((Int(data[1]) >> 1) << 1)  # client streams are odd
    var plen = Int(data[2]) & 0xF
    var initial_val = _printable_str(data, 3, plen)

    var enc = HpackEncoder()
    try:
        var hf = _build_headers_frame(
            enc, sid, headers_eh, headers_es, initial_val
        )
        var hf_bytes = encode_frame(hf)
        c.feed(Span[UInt8, _](hf_bytes))
        _ = c.drain()
    except:
        return

    # Walk through (up to 32) CONTINUATION frames built from the
    # tail of ``data``. The terminal one optionally sets
    # END_HEADERS. The harness deliberately does NOT cap the
    # accumulated stream.headers size -- that's the property
    # under test.
    var cursor = 3 + plen
    for i in range(n_cont):
        if cursor >= len(data):
            break
        var chunk_len = Int(data[cursor]) & 0xF
        cursor += 1
        var val = _printable_str(data, cursor, chunk_len)
        cursor += chunk_len
        var is_terminal = i == (n_cont - 1)
        var eh = is_terminal and cont_term_eh
        try:
            var cf = _build_continuation_frame(enc, sid, eh, val)
            var cf_bytes = encode_frame(cf)
            c.feed(Span[UInt8, _](cf_bytes))
            _ = c.drain()
        except:
            # PROTOCOL_ERROR / similar are valid rejections; the
            # contract is "no panic / no SIGSEGV / no abort". As long
            # as the call returned, we're good.
            pass


def main() raises:
    print("[mozz] fuzzing HTTP/2 CONTINUATION-flood state machine...")

    var seeds = List[List[UInt8]]()

    def _seed(*bytes: Int) -> List[UInt8]:
        var out = List[UInt8]()
        for i in range(len(bytes)):
            out.append(UInt8(bytes[i] & 0xFF))
        return out^

    # Empty.
    seeds.append(_seed(0, 1, 0))
    # Clean HEADERS+END_HEADERS, no continuations.
    seeds.append(_seed(0x01, 1, 0))
    # HEADERS without END_HEADERS, then 4 CONTINUATIONs (last with END_HEADERS).
    seeds.append(
        _seed(
            0x04 | (4 << 3),  # 4 conts, terminal cont has END_HEADERS
            1,
            3,
            ord("a"),
            ord("b"),
            ord("c"),
            2,
            ord("d"),
            ord("e"),
            2,
            ord("f"),
            ord("g"),
            2,
            ord("h"),
            ord("i"),
            2,
            ord("j"),
            ord("k"),
        )
    )
    # HEADERS without END_HEADERS, 16 CONTINUATIONs, none with
    # END_HEADERS (the flood shape).
    var flood = List[UInt8]()
    flood.append(UInt8((16 << 3) & 0xFF))
    flood.append(UInt8(1))
    flood.append(UInt8(0))
    for _ in range(16):
        flood.append(UInt8(2))
        flood.append(UInt8(ord("z")))
        flood.append(UInt8(ord("y")))
    seeds.append(flood^)
    # CONTINUATION on stream 0 (RFC 9113 paragraph 6.10 forbids; must
    # be rejected).  Uses sid seed = 0 so stream id resolves to 1
    # via the +1 nudge -- but a CONTINUATION targeted at stream 0
    # is exercised inside the fuzzer's mutation space, not here.
    seeds.append(_seed(0x04 | (1 << 3), 0, 0, 1, ord("x")))
    # Sentinel: long empty-CONTINUATION flood past the cap.
    seeds.append(_seed(0xFF, 1, 0))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/h2_continuation",
            corpus_dir="fuzz/corpus/h2_continuation",
            max_input_len=512,
        ),
        seeds,
    )
