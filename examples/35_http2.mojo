"""Example 35: HTTP/2 + h2c upgrade detection.

Drives :class:`flare.http2.H2Connection` end-to-end without a
network: feeds the connection preface + a HEADERS frame, takes the
parsed :class:`flare.http.Request`, builds a
:class:`flare.http.Response`, calls :meth:`emit_response`, and
prints the encoded response frames.

Also demonstrates the ALPN dispatch helper
(:func:`flare.http2.is_h2_alpn`) and h2c-upgrade detection
(:func:`flare.http2.detect_h2c_upgrade`) so users can wire the
right protocol on a TLS or h2c connection.

Pure construction. Run:
    pixi run example-http2
"""

from flare.http import HeaderMap, Method, Request, Response
from flare.http2 import (
    Frame,
    FrameFlags,
    FrameType,
    H2Connection,
    H2_PREFACE,
    HpackEncoder,
    HpackHeader,
    detect_h2c_upgrade,
    encode_frame,
    is_h2_alpn,
    parse_frame,
)


def _preface_bytes() -> List[UInt8]:
    return List[UInt8](String(H2_PREFACE).as_bytes())


def main() raises:
    print("=== flare Example 35: HTTP/2 driver ===")
    print()

    # ── ALPN dispatch ────────────────────────────────────────────────────
    print("── 1. ALPN dispatch ──")
    print("  is_h2_alpn('h2')       :", is_h2_alpn("h2"))
    print("  is_h2_alpn('http/1.1') :", is_h2_alpn("http/1.1"))
    print()

    # ── h2c upgrade detection ────────────────────────────────────────────
    print("── 2. h2c upgrade detection ──")
    var h = HeaderMap()
    print("  no headers           :", detect_h2c_upgrade(h))
    h.set("Upgrade", "h2c")
    h.set("HTTP2-Settings", "AAMAAABkAAQAoAAAAAIAAAAA")
    print("  Upgrade: h2c + ...   :", detect_h2c_upgrade(h))
    print()

    # ── Synchronous round-trip ───────────────────────────────────────────
    print("── 3. Synchronous H2Connection round-trip ──")
    var c = H2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    var settings_bytes = c.drain()
    print("  bytes after preface  :", len(settings_bytes), "(SETTINGS frame)")

    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/api/users"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    hdrs.append(HpackHeader("user-agent", "flare-h2-demo"))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    var hf_bytes = encode_frame(f)
    print("  HEADERS frame bytes  :", len(hf_bytes))

    c.feed(Span[UInt8, _](hf_bytes))
    var ids = c.take_completed_streams()
    print("  completed streams    :", len(ids))

    var req = c.take_request(ids[0])
    print("  request method       :", req.method)
    print("  request url          :", req.url)
    print("  request version      :", req.version)
    print("  Host header          :", req.headers.get("host"))

    var resp = Response(status=200)
    resp.headers.set("Content-Type", "application/json")
    resp.body = List[UInt8](String('{"users":[]}').as_bytes())
    c.emit_response(ids[0], resp^)

    var out_bytes = c.drain()
    print("  outbound bytes       :", len(out_bytes), "(HEADERS + DATA)")
    print()

    print("=== Example 35 complete ===")
