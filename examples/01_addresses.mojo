# Example 01: IP and Socket Addresses
#
# Demonstrates: IpAddr.parse, SocketAddr, classification methods,
# and injection-safe address handling.
#
# Phase 1 — flare.net (working)
#
# Usage:
#     pixi run example-addresses

from flare.net import IpAddr, SocketAddr


fn main() raises:
    print("=== flare Example 01: Addresses ===")
    print()

    # ── IPv4 parsing ────────────────────────────────────────────────────────────

    print("── IPv4 Parsing ──")
    var v4 = IpAddr.parse("192.168.1.100")
    print("Parsed:", v4)  # 192.168.1.100
    print("  is_v4():     ", v4.is_v4())  # True
    print("  is_private():", v4.is_private())  # True (192.168/16)
    print()

    var public = IpAddr.parse("8.8.8.8")
    print("Public IP:", public)
    print("  is_private():", public.is_private())  # False
    print("  is_loopback():", public.is_loopback())  # False
    print()

    # ── IPv6 parsing ────────────────────────────────────────────────────────────

    print("── IPv6 Parsing ──")
    var loopback_v6 = IpAddr.localhost_v6()
    print("Loopback v6:", loopback_v6)  # ::1
    print("  is_v6():     ", loopback_v6.is_v6())  # True
    print("  is_loopback():", loopback_v6.is_loopback())  # True
    print()

    var link_local = IpAddr.parse("fe80::1")
    print("Link-local:", link_local)
    print("  is_v6():", link_local.is_v6())  # True
    print()

    # ── Well-known constants ─────────────────────────────────────────────────────

    print("── Well-Known Constants ──")
    print("localhost     :", IpAddr.localhost())  # 127.0.0.1
    print("localhost_v6  :", IpAddr.localhost_v6())  # ::1
    print("unspecified   :", IpAddr.unspecified())  # 0.0.0.0
    print("unspecified_v6:", IpAddr.unspecified_v6())  # ::
    print()

    # ── Boundary values ──────────────────────────────────────────────────────────

    print("── Boundary Values ──")
    print("Broadcast:", IpAddr.parse("255.255.255.255"))
    print("Min valid:", IpAddr.parse("0.0.0.1"))
    print()

    # ── Socket addresses ─────────────────────────────────────────────────────────

    print("── SocketAddr ──")
    var sa = SocketAddr(IpAddr.parse("10.0.0.1"), 8080)
    print("Constructed:", sa)  # 10.0.0.1:8080
    print("  ip:  ", sa.ip)
    print("  port:", sa.port)
    print()

    var parsed_sa = SocketAddr.parse("127.0.0.1:9000")
    print("Parsed:", parsed_sa)  # 127.0.0.1:9000
    print()

    var ipv6_sa = SocketAddr.parse("[::1]:443")
    print("IPv6 socket addr:", ipv6_sa)  # [::1]:443
    print("  is_v6:", ipv6_sa.ip.is_v6())
    print()

    # Port boundary values
    print("Port 0 (OS-assigned):", SocketAddr.localhost(0))
    print("Port 65535 (max):    ", SocketAddr.localhost(65535))
    print()

    # ── Equality ─────────────────────────────────────────────────────────────────

    print("── Equality ──")
    var a1 = SocketAddr.localhost(8080)
    var a2 = SocketAddr.localhost(8080)
    var a3 = SocketAddr.localhost(9090)
    print("localhost:8080 == localhost:8080:", a1 == a2)  # True
    print("localhost:8080 != localhost:9090:", a1 != a3)  # True
    print()

    # ── Security: malformed inputs raise immediately ───────────────────────────────

    print("── Security: Invalid Inputs ──")
    print("Attempting IpAddr.parse('256.0.0.1') ...")
    try:
        _ = IpAddr.parse("256.0.0.1")
        print("  ERROR: should have raised!")
    except e:
        print("  ✓ Raised as expected:", e)

    print("Attempting IpAddr.parse('127.0.0.1\\x00evil') ...")
    try:
        _ = IpAddr.parse("127.0.0.1\x00evil")
        print("  ERROR: should have raised!")
    except e:
        print("  ✓ Raised as expected (null-byte injection blocked):", e)

    print("Attempting SocketAddr.parse with CRLF injection ...")
    try:
        _ = SocketAddr.parse("127.0.0.1:80\r\nX-Injected: evil")
        print("  ERROR: should have raised!")
    except e:
        print("  ✓ Raised as expected (CRLF injection blocked):", e)

    print()
    print("=== Example 01 complete ===")
