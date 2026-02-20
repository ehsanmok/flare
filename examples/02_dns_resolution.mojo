# Example 02: DNS Resolution
#
# Demonstrates: resolve(), resolve_v4(), resolve_v6(), numeric IP passthrough,
# and security guards on hostnames.
#
# Phase 2 — flare.dns (working)
#
# Usage:
#     pixi run example-dns

from flare.dns import resolve, resolve_v4, resolve_v6
from flare.net import IpAddr


fn main() raises:
    print("=== flare Example 02: DNS Resolution ===")
    print()

    # ── Basic resolution ─────────────────────────────────────────────────────────

    print("── resolve('localhost') ──")
    var addrs = resolve("localhost")
    print("Got", len(addrs), "address(es):")
    for a in addrs:
        print("  -", a)
    print()

    # ── IPv4-only resolution ──────────────────────────────────────────────────────

    print("── resolve_v4('localhost') ──")
    var v4_addrs = resolve_v4("localhost")
    print("Got", len(v4_addrs), "IPv4 address(es):")
    for a in v4_addrs:
        print("  -", a, "(is_v4:", a.is_v4(), ")")
    print()

    # ── IPv6 resolution (may not be available in all environments) ────────────────

    print("── resolve_v6('::1') ──")
    try:
        var v6_addrs = resolve_v6("::1")
        print("Got", len(v6_addrs), "IPv6 address(es):")
        for a in v6_addrs:
            print("  -", a, "(is_v6:", a.is_v6(), ")")
    except e:
        print("  (IPv6 not available in this environment — OK)")
    print()

    # ── Numeric IP passthrough ────────────────────────────────────────────────────

    print("── Numeric IP passthrough (no DNS round-trip) ──")
    var numeric_v4 = resolve("127.0.0.1")
    print("resolve('127.0.0.1')[0]:", numeric_v4[0])  # 127.0.0.1

    var numeric_v6 = resolve("::1")
    var found_v6 = False
    for a in numeric_v6:
        if String(a) == "::1":
            found_v6 = True
    print("resolve('::1') contains '::1':", found_v6)  # True
    print()

    # ── FQDN with trailing dot ────────────────────────────────────────────────────

    print("── FQDN with trailing dot ──")
    try:
        var fqdn_addrs = resolve("localhost.")
        print("resolve('localhost.') got", len(fqdn_addrs), "address(es)")
    except e:
        print("  (resolver rejected trailing dot — OK):", e)
    print()

    # ── Error handling: non-existent host ────────────────────────────────────────

    print("── Non-existent hostname ──")
    try:
        _ = resolve("this.host.does.not.exist.flare.invalid")
        print("  ERROR: expected DnsError!")
    except e:
        print("  ✓ DnsError raised as expected:", e)
    print()

    # ── Security: hostname injection guards ───────────────────────────────────────

    print("── Security: Hostname Injection Guards ──")

    # Null byte injection: "localhost\x00evil" truncates to "localhost" at libc boundary
    print("Attempting resolve('localhost\\x00evil') ...")
    try:
        _ = resolve("localhost\x00evil")
        print("  ERROR: should have raised!")
    except e:
        print("  ✓ Raised as expected (null-byte injection blocked)")

    # CRLF injection: hostname embedded in HTTP Host header
    print("Attempting resolve('localhost\\r\\nevil') ...")
    try:
        _ = resolve("localhost\r\nevil")
        print("  ERROR: should have raised!")
    except e:
        print("  ✓ Raised as expected (CRLF injection blocked)")

    # At-sign injection: user-info prefix
    print("Attempting resolve('user@localhost') ...")
    try:
        _ = resolve("user@localhost")
        print("  ERROR: should have raised!")
    except e:
        print("  ✓ Raised as expected ('@' not valid in hostname)")

    # RFC 1035: hostname > 253 characters
    var long_host = String("a" * 254) + ".com"
    print("Attempting resolve with 254-char hostname ...")
    try:
        _ = resolve(long_host)
        print("  ERROR: should have raised!")
    except e:
        print("  ✓ Raised as expected (hostname too long)")

    # RFC 1035: single label > 63 characters
    var long_label = String("a" * 64) + ".com"
    print("Attempting resolve with 64-char label ...")
    try:
        _ = resolve(long_label)
        print("  ERROR: should have raised!")
    except e:
        print("  ✓ Raised as expected (label too long)")

    print()
    print("=== Example 02 complete ===")
