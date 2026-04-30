"""Example 12: TLS client with flare.tls.TlsStream.

Demonstrates:
  - Building a ``TlsConfig`` with the default (verified) mode
  - Dialling a real HTTPS endpoint, handshaking, and sending a minimal
    ``HTTP/1.0`` request
  - Reading the response headers
  - Graceful skip when the network or CA bundle is unavailable
  - The ``TlsVerify.NONE`` escape hatch (intentionally noisy)

Real production code should use ``flare.http.HttpClient`` which wraps
``TlsStream`` and speaks full HTTP/1.1. This example shows the raw
primitive for anyone building a non-HTTP TLS protocol (SMTPS, custom
binary protocol, etc.).

Run:
    pixi run example-tls
"""

from flare.tls import TlsStream, TlsConfig, TlsVerify


def zero_buf(n: Int) -> List[UInt8]:
    var b = List[UInt8]()
    b.resize(n, 0)
    return b^


def main() raises:
    print("=== flare Example 12: TLS ===")
    print()

    # ── 1. Default TlsConfig uses the pixi-managed CA bundle ─────────────────
    print("── 1. Default TlsConfig ──")
    var cfg = TlsConfig()
    print(
        " verify =",
        "REQUIRED" if cfg.verify == TlsVerify.REQUIRED else "(other)",
    )
    print(
        " ca_bundle =",
        "(default, resolved by TLS wrapper)" if cfg.ca_bundle
        == "" else cfg.ca_bundle,
    )
    print()

    # ── 2. Dial a real HTTPS endpoint ────────────────────────────────────────
    print("── 2. Handshake + GET https://example.com ──")
    try:
        var tls = TlsStream.connect("example.com", UInt16(443), cfg)
        print(" handshake OK")

        var req = String(
            "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        )
        var req_bytes = req.as_bytes()
        _ = tls.write(Span[UInt8](req_bytes))

        var buf = zero_buf(256)
        var n = tls.read(buf.unsafe_ptr(), 256)
        if n > 0:
            var line = String(capacity=32)
            for i in range(n):
                var c = buf[i]
                if c == 13 or c == 10:
                    break
                line += chr(Int(c))
            print(" status line: " + line)
        tls.close()
    except e:
        print(" [SKIP] network or CA bundle unavailable:", String(e))
    print()

    # ── 3. TlsVerify.NONE: insecure, prints a security warning ──────────────
    print("── 3. TlsVerify.NONE (insecure, prints a warning to stderr) ──")
    var insecure = TlsConfig(verify=TlsVerify.NONE)
    print(
        " verify = NONE" if insecure.verify
        == TlsVerify.NONE else " verify = (other)"
    )
    print(" (not actually connecting; just showing the config)")
    print()

    print("=== Example 12 complete ===")
