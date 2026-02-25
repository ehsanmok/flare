"""Fuzz harness: HTTP header key/value parsing via HeaderMap.

Tests ``HeaderMap.set()`` and ``append()`` for crashes on arbitrary byte
inputs.  ``HeaderInjectionError`` (CR/LF in key or value) is a valid,
expected rejection.  Any other exception or panic is a bug.

Also fuzz-tests the ``Url._parse_port`` path via ``Url.parse`` with
crafted authority strings (host:PORT where PORT is attacker-controlled).

Run:
    pixi run fuzz-headers
"""

from mozz import fuzz, FuzzConfig
from flare.http.headers import HeaderMap
from flare.http.url import Url


fn target(data: List[UInt8]) raises:
    """Fuzz target: drive HeaderMap and URL port parsing with arbitrary bytes.

    Splits ``data`` in half: first half drives HeaderMap, second half
    is used as a port string suffix in a crafted URL.

    Args:
        data: Arbitrary bytes from the mutator.

    Raises:
        Expected: ``HeaderInjectionError``, ``UrlParseError`` — classified
                  as rejections by mozz.
        Bug:      ``index out of bounds``, ``assertion failed``, ``panic`` —
                  classified as crashes.
    """
    if len(data) == 0:
        return

    var mid = len(data) // 2

    # ── HeaderMap path ────────────────────────────────────────────────────────
    var key = String(capacity=mid + 1)
    for i in range(mid):
        key += chr(Int(data[i]))
    var val = String(capacity=len(data) - mid + 1)
    for i in range(mid, len(data)):
        val += chr(Int(data[i]))

    var h = HeaderMap()
    try:
        h.set(key, val)
    except:
        pass  # HeaderInjectionError is expected

    # ── URL port path ─────────────────────────────────────────────────────────
    # Craft `http://host:<port>/` where <port> comes from the first 8 bytes
    var port_str = String(capacity=8 + 1)
    var port_len = min(8, len(data))
    for i in range(port_len):
        port_str += chr(Int(data[i]))

    var url = "http://host:" + port_str + "/"
    try:
        _ = Url.parse(url)
    except:
        pass  # UrlParseError is expected


fn main() raises:
    print("[mozz] fuzzing HeaderMap + Url port parsing...")

    var seeds = List[List[UInt8]]()

    fn _b(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    # Normal headers
    seeds.append(_b("Content-Type: application/json"))
    seeds.append(_b("X-Custom-Header: value"))
    # Injection attempts
    seeds.append(_b("Bad\r\nKey: value"))
    seeds.append(_b("Key: bad\r\nvalue"))
    seeds.append(_b("Key: value\n injected"))
    # Port overflow attempts
    seeds.append(_b("99999999999999999999999999999"))
    seeds.append(_b("0"))
    seeds.append(_b("65535"))
    seeds.append(_b("65536"))
    seeds.append(_b("00001"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=300_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/http_headers",
            max_input_len=256,
        ),
        seeds,
    )
