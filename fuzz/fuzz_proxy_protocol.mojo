"""Fuzz harness: ``flare.http.proxy_protocol.parse_proxy_protocol``.

Two soundness properties:

1. ``parse_proxy_protocol`` never panics on arbitrary input. It must
   either return ``None`` (incomplete buffer), an
   ``Optional[ProxyHeader]`` with ``consumed > 0`` (well-formed), or
   raise a regular ``Error``. No undefined behaviour, no
   out-of-bounds reads on truncated payloads, no infinite loops on
   adversarial CR-only / LF-only / NUL-injected bytes.
2. When parsing succeeds, the reported ``consumed`` count is bounded
   by ``len(input)`` (the parser cannot claim to have consumed bytes
   that aren't there).

Defends against the same threat surface as the v1 / v2 unit tests
(spec violations, truncations, signature-prefix attacks) but with
random bytes uncovered by the unit corpus.

Run:
    pixi run fuzz-proxy-protocol
"""

from mozz import fuzz, FuzzConfig

from flare.http.proxy_protocol import parse_proxy_protocol


def target(data: List[UInt8]) raises:
    """Soundness check.

    The parser now raises typed :class:`ProxyParseError`, which
    can't share a single ``try`` block with a generic
    ``raise Error("...")`` (Mojo doc § "Don't mix error types in
    a single try block"). Split into two stages: first the parse
    call (typed-error catch), then the soundness check on
    ``consumed`` (generic Error raises only fire when the parser
    succeeded but reported nonsensical bookkeeping)."""
    var span = Span[UInt8, _](data)
    var consumed: Int = 0
    var got_value = False
    try:
        var got = parse_proxy_protocol(span)
        if got:
            got_value = True
            consumed = got.value().consumed
    except _e:
        return
    if not got_value:
        return
    if consumed <= 0:
        raise Error("PROXY parse: consumed <= 0 (got " + String(consumed) + ")")
    if consumed > len(data):
        raise Error(
            "PROXY parse: consumed > input length ("
            + String(consumed)
            + " > "
            + String(len(data))
            + ")"
        )


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


def _v2_signature_seed() -> List[UInt8]:
    """Seed: bare 12-byte v2 signature (no version + command + length
    yet). Drives the parser into the "incomplete header" branch."""
    var out = List[UInt8](capacity=12)
    out.append(UInt8(0x0D))
    out.append(UInt8(0x0A))
    out.append(UInt8(0x0D))
    out.append(UInt8(0x0A))
    out.append(UInt8(0x00))
    out.append(UInt8(0x0D))
    out.append(UInt8(0x0A))
    out.append(UInt8(0x51))
    out.append(UInt8(0x55))
    out.append(UInt8(0x49))
    out.append(UInt8(0x54))
    out.append(UInt8(0x0A))
    return out^


def _v2_inet_seed() -> List[UInt8]:
    var out = _v2_signature_seed()
    out.append(UInt8(0x21))  # version=2 / command=PROXY
    out.append(UInt8(0x11))  # family=INET / proto=STREAM
    out.append(UInt8(0x00))
    out.append(UInt8(12))
    # src 1.2.3.4
    out.append(UInt8(1))
    out.append(UInt8(2))
    out.append(UInt8(3))
    out.append(UInt8(4))
    # dst 5.6.7.8
    out.append(UInt8(5))
    out.append(UInt8(6))
    out.append(UInt8(7))
    out.append(UInt8(8))
    # ports 80 / 8080
    out.append(UInt8(0))
    out.append(UInt8(80))
    out.append(UInt8(0x1F))
    out.append(UInt8(0x90))
    return out^


def main() raises:
    print("[mozz] fuzzing flare.http.proxy_protocol.parse_proxy_protocol...")

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes(""))
    seeds.append(_bytes("PROXY"))  # truncated v1 prefix
    seeds.append(_bytes("PROXY "))  # bare v1 prefix
    seeds.append(_bytes("PROXY TCP4 1.2.3.4 5.6.7.8 80 8080\r\n"))
    seeds.append(_bytes("PROXY TCP6 ::1 ::1 1 2\r\n"))
    seeds.append(_bytes("PROXY UNKNOWN\r\n"))
    seeds.append(_bytes("PROXY UNKNOWN whatever bytes here\r\n"))
    # Mojo doesn't support shorthand string repetition in StringLiteral,
    # so pass an oversized v1 header literally — drives the > 107 cap.
    seeds.append(
        _bytes(
            "PROXY TCP4"
            " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            " 1 2\r\n"
        )
    )
    seeds.append(_v2_signature_seed())
    seeds.append(_v2_inet_seed())
    # Adversarial: garbage prefix that is neither v1 nor v2.
    seeds.append(_bytes("HELLO\r\n"))
    seeds.append(_bytes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/proxy_protocol",
            corpus_dir="fuzz/corpus/proxy_protocol",
            max_input_len=512,
        ),
        seeds,
    )
