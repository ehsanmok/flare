# Example 03: Error Handling
#
# Demonstrates: flare's typed error hierarchy, how errors carry context,
# and how callers should handle each error type.
#
# All flare errors implement both Writable (print()) and Stringable (String()).
# Every error includes enough context to debug without a stack trace.
#
# Phase 1 — flare.net.error (working)
#
# Usage:
#     pixi run example-errors

from flare.net.error import (
    NetworkError,
    ConnectionRefused,
    ConnectionTimeout,
    AddressInUse,
    AddressParseError,
    BrokenPipe,
    DnsError,
)


fn main() raises:
    print("=== flare Example 03: Error Handling ===")
    print()

    # ── Error construction and display ────────────────────────────────────────────

    print("── NetworkError ──")
    var net_err = NetworkError("connection reset by peer", 104)
    print("  print():", net_err)
    print("  String():", String(net_err))
    print()

    print("── ConnectionRefused (includes the address) ──")
    var refused = ConnectionRefused("127.0.0.1:8080")
    print("  print():", refused)
    # Includes the address so you know which server was unreachable
    print()

    print("── ConnectionTimeout (includes address + errno) ──")
    var timeout = ConnectionTimeout("10.0.0.1:443", 110)
    print("  print():", timeout)
    print()

    print("── AddressInUse (port already bound) ──")
    var in_use = AddressInUse("0.0.0.0:8080")
    print("  print():", in_use)
    print()

    print("── AddressParseError (includes the bad input) ──")
    var parse_err = AddressParseError("256.0.0.1")
    print("  print():", parse_err)
    print()

    print("── BrokenPipe (peer closed connection) ──")
    var pipe_no_addr = BrokenPipe()
    var pipe_with_addr = BrokenPipe("10.0.0.5:9000")
    print("  no addr: ", pipe_no_addr)
    print("  with addr:", pipe_with_addr)
    print()

    print("── DnsError (includes host + resolver message) ──")
    var dns_err = DnsError(
        "nonexistent.example.com", 8, "Name or service not known"
    )
    print("  print():", dns_err)
    print()

    # ── Error handling patterns ───────────────────────────────────────────────────

    print("── Catching specific error types ──")
    print()

    # Pattern: catch the most specific error first
    fn try_connect(host: String) raises -> String:
        """Simulate a connection attempt that validates the address first."""
        from flare.net import IpAddr

        # This will raise AddressParseError for invalid IPs
        _ = IpAddr.parse(host)

        # In a real implementation, this would also raise ConnectionRefused,
        # ConnectionTimeout, BrokenPipe, etc. at the TCP layer.
        return "connected"

    # Valid address
    try:
        var result = try_connect("127.0.0.1")
        print("  Valid IP: connect succeeded (address parsed OK)")
    except e:
        print("  Unexpected error:", e)

    # Invalid address
    try:
        var result = try_connect("not.an.ip.address")
        print("  ERROR: should have raised!")
    except e:
        # In production you might match on error type and retry,
        # log with context, or convert to a user-facing message.
        print("  Caught AddressParseError (invalid IP):", e)
    print()

    # ── DNS error from real resolution ───────────────────────────────────────────

    print("── DNS error from real resolution ──")
    from flare.dns import resolve

    try:
        _ = resolve("this.definitely.does.not.exist.flare.test")
        print("  ERROR: should have raised!")
    except e:
        print("  Caught:", e)
        # The error message includes the hostname so log scraping can correlate it.
    print()

    # ── AddressParseError from injection attempt ──────────────────────────────────

    print("── AddressParseError preserves the bad input safely ──")
    try:
        from flare.net import IpAddr

        _ = IpAddr.parse("127.0.0.1\x00evil")
    except e:
        print("  Caught:", e)
        # Note: the null byte is preserved in the error message so you can log
        # the exact input that was rejected, aiding security audit trails.
    print()

    print("=== Example 03 complete ===")
