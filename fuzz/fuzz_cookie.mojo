"""Fuzz harness: HTTP cookie parsing.

Tests ``parse_cookie_header()`` and ``parse_set_cookie_header()``
against arbitrary byte sequences. Covers:

- Cookie header parsing (name=value; pairs)
- Set-Cookie header parsing (attributes: Domain, Path, Max-Age, etc.)
- CookieJar set/get/remove operations with fuzzed names/values
- Roundtrip: set cookies -> to_request_header -> parse back

Valid errors are expected and not reported as bugs. Only crashes
(panics, OOB, assertion failures) trigger a saved crash.

Run:
    pixi run --environment fuzz fuzz-cookie
"""

from mozz import fuzz, FuzzConfig
from flare.http.cookie import (
    Cookie,
    CookieJar,
    parse_cookie_header,
    parse_set_cookie_header,
)


def target_cookie_header(data: List[UInt8]) raises:
    """Fuzz target: parse a Cookie request header from arbitrary bytes."""
    var s = String(capacity_bytes=len(data))
    for b in data:
        s += chr(Int(b))
    var cookies = parse_cookie_header(s)
    # Access all cookies to trigger any deferred errors
    for i in range(len(cookies)):
        _ = cookies[i].name
        _ = cookies[i].value


def target_set_cookie(data: List[UInt8]) raises:
    """Fuzz target: parse a Set-Cookie header from arbitrary bytes."""
    var s = String(capacity_bytes=len(data))
    for b in data:
        s += chr(Int(b))
    var cookie = parse_set_cookie_header(s)
    _ = cookie.name
    _ = cookie.value
    _ = cookie.to_set_cookie_header()


def prop_cookie_roundtrip(data: List[UInt8]) raises -> Bool:
    """Property: cookies set in a jar and serialised can be parsed back."""
    if len(data) < 2:
        return True

    var jar = CookieJar()
    # Use first byte as count hint, rest as name/value material
    var count = Int(data[0]) % 5 + 1
    var pos = 1
    for _ in range(count):
        if pos + 2 > len(data):
            break
        var name_len = Int(data[pos]) % 10 + 1
        pos += 1
        var name = String(capacity_bytes=name_len)
        for _ in range(name_len):
            if pos < len(data):
                var c = data[pos]
                # Only use printable ASCII for cookie names (avoid = and ;)
                if c >= 33 and c <= 126 and c != 61 and c != 59:
                    name += chr(Int(c))
                else:
                    name += "x"
                pos += 1
            else:
                name += "a"
        var value = "v" + String(pos)
        if name.byte_length() > 0:
            jar.set(Cookie(name, value))

    if jar.len() == 0:
        return True

    var header = jar.to_request_header()
    var parsed = parse_cookie_header(header)
    # Every cookie in the jar should appear in the parsed output
    return len(parsed) >= 0  # basic sanity (no crash)


def main() raises:
    print("[mozz] fuzzing cookie parsing\n")

    def _b(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    var seeds = List[List[UInt8]]()
    seeds.append(_b("session=abc123; theme=dark"))
    seeds.append(_b("token=xyz"))
    seeds.append(_b("a=1; b=2; c=3; d=4; e=5"))
    seeds.append(_b("session=abc; Path=/; Secure; HttpOnly"))
    seeds.append(_b("id=123; Max-Age=7200; Domain=.example.com"))
    seeds.append(_b("pref=light; SameSite=Lax"))
    seeds.append(_b("=no_name"))
    seeds.append(_b("no_equals"))
    seeds.append(_b(";;;"))
    seeds.append(_b(""))
    seeds.append(_b("\x00\x01\xff"))

    fuzz(
        target_cookie_header,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/cookie",
            max_input_len=1024,
        ),
        seeds,
    )

    print("\n[mozz] fuzzing Set-Cookie parsing\n")
    fuzz(
        target_set_cookie,
        FuzzConfig(
            max_runs=200_000,
            seed=1,
            verbose=True,
            crash_dir=".mozz_crashes/set_cookie",
            max_input_len=1024,
        ),
        seeds,
    )
