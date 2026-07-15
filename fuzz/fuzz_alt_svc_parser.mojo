"""Fuzz harness: ``flare.http._client.alt_svc.parse_alt_svc``.

The ``Alt-Svc`` response header (RFC 7838) is untrusted server
input that steers the client's HTTP/3 upgrade decision, so its
parser is attacker-adjacent. It is lenient by design (a malformed
alt-value is skipped, the literal ``clear`` resets state), which
widens the surface for crashes.

Properties checked:

1. **No crashes.** ``parse_alt_svc`` on arbitrary printable bytes
   must return an ``AltSvcParse`` (or raise, which is a valid
   rejection) -- never panic / SIGSEGV / abort.
2. **Idempotent re-parse.** Two parses of the same input agree on
   ``cleared`` and on the number of entries.

Run:
    pixi run --environment fuzz fuzz-alt-svc-parser
"""

from mozz import fuzz, FuzzConfig

from flare.http._client.alt_svc import parse_alt_svc


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


def _printable_ascii(data: List[UInt8]) -> String:
    var n = len(data)
    if n == 0:
        return ""
    var out = String(capacity=n)
    for i in range(n):
        var c = Int(data[i]) % 64 + 32  # printable [32, 95]
        out += chr(c)
    return out^


def target(data: List[UInt8]) raises:
    var s = _printable_ascii(data)
    try:
        var a = parse_alt_svc(s)
        var b = parse_alt_svc(s)
        if a.cleared != b.cleared:
            raise Error("alt-svc re-parse: cleared flag drift")
        if len(a.entries) != len(b.entries):
            raise Error("alt-svc re-parse: entry count drift")
    except:
        # A raised rejection is acceptable; only a panic is a bug.
        pass


def main() raises:
    print("=" * 60)
    print("fuzz_alt_svc_parser.mojo — RFC 7838 Alt-Svc grammar")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes('h3=":443"'))
    seeds.append(_bytes('h3=":443"; ma=3600'))
    seeds.append(_bytes('h3=":443"; ma=3600; persist=1'))
    seeds.append(_bytes('h2="alt.example.com:443", h3=":443"'))
    seeds.append(_bytes("clear"))
    seeds.append(_bytes('h3-29=":443"'))
    seeds.append(_bytes(""))
    seeds.append(_bytes(", , ,, "))
    seeds.append(_bytes('h3=":notaport"'))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/alt_svc_parser",
            corpus_dir="fuzz/corpus/alt_svc_parser",
            max_input_len=256,
        ),
        seeds,
    )
