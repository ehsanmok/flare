"""Fuzz harness: ``flare.http.alpn_dispatch.dispatch_alpn`` /
``negotiate_alpn``.

The ALPN identifier is attacker-influenced (it comes off the TLS
handshake / client advertisement) and steers which wire-protocol
driver the reactor hands the connection to. The dispatcher must map
*any* string to a valid ``WireProtocol`` codepoint without panicking,
and ``negotiate_alpn`` must pick a server-supported protocol or none.

Properties:

1. **No crash / valid codepoint.** ``dispatch_alpn`` on arbitrary
   bytes returns one of the five known codepoints.
2. **Idempotent.** Two calls agree.
3. **negotiate_alpn safety.** The RFC 7301 picker never panics and
   only ever returns a protocol the server actually supports (or "").

Run:
    pixi run --environment fuzz fuzz-alpn-dispatch
"""

from mozz import fuzz, FuzzConfig

from flare.http.alpn_dispatch import (
    ALPN_HTTP_1_1,
    ALPN_HTTP_2,
    ALPN_HTTP_3,
    WireProtocol,
    dispatch_alpn,
    negotiate_alpn,
)


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


def _printable(data: List[UInt8], start: Int, n: Int) -> String:
    var out = String()
    var end = start + n
    if end > len(data):
        end = len(data)
    for i in range(start, end):
        out += chr(Int(data[i]) % 64 + 32)
    return out^


def target(data: List[UInt8]) raises:
    if len(data) == 0:
        return
    var s = _printable(data, 1, Int(data[0]) & 0x1F)

    var cp = dispatch_alpn(s)
    var ok = (
        cp == WireProtocol.UNKNOWN
        or cp == WireProtocol.HTTP_1_1
        or cp == WireProtocol.H2C
        or cp == WireProtocol.HTTP_2
        or cp == WireProtocol.HTTP_3
    )
    if not ok:
        raise Error("dispatch_alpn returned invalid codepoint")
    if dispatch_alpn(s) != cp:
        raise Error("dispatch_alpn not idempotent")

    # negotiate_alpn: server supports h2 + http/1.1; whatever it picks
    # must be one of those (or empty).
    var client = List[String]()
    client.append(s)
    client.append(String(ALPN_HTTP_2))
    var server = List[String]()
    server.append(String(ALPN_HTTP_2))
    server.append(String(ALPN_HTTP_1_1))
    var picked = negotiate_alpn(client, server)
    if picked != "" and picked != ALPN_HTTP_2 and picked != ALPN_HTTP_1_1:
        raise Error("negotiate_alpn picked an unsupported protocol")


def main() raises:
    print("=" * 60)
    print("fuzz_alpn_dispatch.mojo — RFC 7301 ALPN dispatch")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes("\x02h2"))
    seeds.append(_bytes("\x08http/1.1"))
    seeds.append(_bytes("\x02h3"))
    seeds.append(_bytes("\x00"))
    seeds.append(_bytes("\x04spdy"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/alpn_dispatch",
            corpus_dir="fuzz/corpus/alpn_dispatch",
            max_input_len=64,
        ),
        seeds,
    )
