"""Fuzz harness: RFC 8441 Extended CONNECT inbound dispatch.

Drives :class:`flare.http2.H2Connection` (server-side) with
arbitrary HEADERS-frame payloads representing CONNECT requests
+ a fuzzer-controlled ``:protocol`` value (well-formed and
malformed). The contract: the parser MUST never panic; any
malformed pseudo-header combination must either (a) leave the
stream in a recoverable state or (b) raise a regular ``Error``
that the reactor catches and converts to ``RST_STREAM
(PROTOCOL_ERROR)``. A panic / SIGSEGV / hang is a fuzz failure.

Run:
    pixi run fuzz-extended-connect
"""

from mozz import fuzz, FuzzConfig

from flare.http2 import (
    Frame,
    FrameFlags,
    FrameType,
    H2Connection,
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


def _str_from_bytes(data: List[UInt8], start: Int, length: Int) -> String:
    """Build a Mojo String from a slice of fuzzer bytes, replacing
    NULs and non-printable controls so HPACK encoding stays valid.
    The point of the fuzzer is the *combination* of pseudo-headers,
    not raw byte exploration of HPACK encoding (covered by
    fuzz_h2_hpack)."""
    var s = String("")
    var n = length
    if start + n > len(data):
        n = len(data) - start
    if n < 0:
        n = 0
    for i in range(n):
        var c = Int(data[start + i])
        # Clamp to printable ASCII so HPACK doesn't reject.
        if (
            c < 0x20 or c > 0x7E or c == 0x3A
        ):  # also drop ':' since it'd collide with pseudo prefix
            s += "x"
        else:
            s += chr(c)
    if s == "":
        s = "x"
    return s^


def target(data: List[UInt8]) raises:
    if len(data) < 4:
        return

    # ENABLE_CONNECT_PROTOCOL flag byte: low bit decides whether
    # the H2Connection advertised RFC 8441 in its initial SETTINGS
    # (the server-side latch the fuzzer must explore both ways
    # of).
    var enable_connect = (Int(data[0]) & 1) != 0

    # Build the H2Connection.
    var cfg = Http2Config()
    cfg.enable_connect_protocol = enable_connect
    var c = H2Connection.with_config(cfg^)
    try:
        c.feed(Span[UInt8, _](_preface()))
        _ = c.drain()
    except:
        return

    # Pseudo-header construction. Parameterise:
    #  * which pseudo-headers are present (bitmap byte data[1])
    #  * whether :method is "CONNECT" (data[2] low bit)
    #  * the :protocol value (data[3..3+plen])
    #  * the :path value (rest)
    var present = Int(data[1])
    var method_is_connect = (Int(data[2]) & 1) != 0
    var plen = Int(data[3]) & 0xF  # 0..15 bytes
    var protocol_val = _str_from_bytes(data, 4, plen)
    var path_val = _str_from_bytes(data, 4 + plen, 8)

    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    if (present & 0x01) != 0:
        var method = "GET"
        if method_is_connect:
            method = "CONNECT"
        hdrs.append(HpackHeader(":method", method))
    if (present & 0x02) != 0:
        hdrs.append(HpackHeader(":scheme", "https"))
    if (present & 0x04) != 0:
        hdrs.append(HpackHeader(":path", path_val))
    if (present & 0x08) != 0:
        hdrs.append(HpackHeader(":authority", "example.com"))
    if (present & 0x10) != 0:
        hdrs.append(HpackHeader(":protocol", protocol_val))
    if (present & 0x20) != 0:
        hdrs.append(HpackHeader("sec-websocket-version", "13"))

    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    var flag_byte = Int(data[2])
    var flags = FrameFlags.END_HEADERS()
    if (flag_byte & 0x2) != 0:
        flags = flags | FrameFlags.END_STREAM()
    f.header.flags = FrameFlags(flags)
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))

    var hf_bytes = encode_frame(f)
    try:
        c.feed(Span[UInt8, _](hf_bytes))
        _ = c.drain()
    except:
        # Errors are fine; the contract is "no panic".
        pass


def main() raises:
    print("[mozz] fuzzing RFC 8441 Extended CONNECT dispatch...")

    var seeds = List[List[UInt8]]()

    def _seed(*bytes: Int) -> List[UInt8]:
        var out = List[UInt8]()
        for i in range(len(bytes)):
            out.append(UInt8(bytes[i] & 0xFF))
        return out^

    # Empty / short.
    seeds.append(_seed(0))
    # Vanilla CONNECT + websocket.
    var ws = List[UInt8]()
    ws.append(UInt8(1))  # enable_connect
    ws.append(UInt8(0x1F))  # all four pseudo + :protocol
    ws.append(UInt8(0x1))  # method = CONNECT
    ws.append(UInt8(9))  # plen
    for i in range(9):
        ws.append(UInt8(ord("websocket"[i])))
    seeds.append(ws^)
    # CONNECT + :protocol but server didn't enable it.
    var off = List[UInt8]()
    off.append(UInt8(0))  # enable_connect = False
    off.append(UInt8(0x1F))
    off.append(UInt8(0x1))
    off.append(UInt8(9))
    for i in range(9):
        off.append(UInt8(ord("websocket"[i])))
    seeds.append(off^)
    # Plain GET, no :protocol.
    seeds.append(_seed(1, 0x0F, 0x0, 0))
    # Pseudo-only :protocol with no :method (malformed).
    seeds.append(_seed(1, 0x10, 0, 4, ord("a"), ord("b"), ord("c"), ord("d")))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/extended_connect",
            corpus_dir="fuzz/corpus/extended_connect",
            max_input_len=128,
        ),
        seeds,
    )
