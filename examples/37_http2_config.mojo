"""Example 37: HTTP/2 SETTINGS via :class:`flare.http2.Http2Config`.

Shows the configuration surface for the inline
:class:`flare.http2.H2Connection` driver. Three configurations:

1. Defaults — equivalent to ``H2Connection()`` with no
   per-connection tuning.
2. A relaxed config — bumps SETTINGS_MAX_CONCURRENT_STREAMS and
   SETTINGS_INITIAL_WINDOW_SIZE for high-fan-out internal services.
3. A tight config — clamps SETTINGS_MAX_HEADER_LIST_SIZE and the
   HPACK dynamic-table size budget; the shape an edge proxy would
   ship behind a public IP to defang header-bomb attacks.

Each configuration is validated up-front via
:meth:`flare.http2.Http2Config.validate` (boot-fail-fast at
server startup) and the resulting initial SETTINGS frame is
decoded back to verify the on-wire bytes.

Pure construction. Run:
    pixi run example-http2-config
"""

from flare.http2 import (
    H2Connection,
    H2_PREFACE,
    Http2Config,
    parse_frame,
)


def _preface_bytes() -> List[UInt8]:
    return List[UInt8](String(H2_PREFACE).as_bytes())


def _emit_initial_settings(var conn: H2Connection) raises -> List[UInt8]:
    """Drive the preface then drain the SETTINGS frame the server
    emits as its half of the handshake."""
    conn.feed(Span[UInt8, _](_preface_bytes()))
    return conn.drain()


def _print_emitted_settings(label: String, var bytes: List[UInt8]) raises:
    print(label, "—", len(bytes), "bytes after preface")
    var maybe = parse_frame(Span[UInt8, _](bytes))
    if not maybe:
        print("  (no frame parsed)")
        return
    var f = maybe.value().copy()
    print("  frame type:", Int(f.header.type.value), "(0x4 = SETTINGS)")
    print("  frame length:", Int(f.header.length))
    var i = 0
    # SETTINGS payload is a sequence of 6-byte (2-byte id, 4-byte value)
    # pairs, both big-endian per RFC 9113 §6.5.1.
    while i + 6 <= len(f.payload):
        var sid = (Int(f.payload[i]) << 8) | Int(f.payload[i + 1])
        var sval = (
            (Int(f.payload[i + 2]) << 24)
            | (Int(f.payload[i + 3]) << 16)
            | (Int(f.payload[i + 4]) << 8)
            | Int(f.payload[i + 5])
        )
        # ``hex()`` already prefixes ``0x`` so we don't double it here.
        print("  setting id=" + hex(sid) + " value=" + String(sval))
        i += 6


def main() raises:
    print("=== flare Example 37: HTTP/2 Http2Config ===")
    print()

    # ── 1. Defaults ──────────────────────────────────────────────────────
    print("── 1. Default Http2Config ──")
    var default_cfg = Http2Config()
    default_cfg.validate()
    print("  max_concurrent_streams:", default_cfg.max_concurrent_streams)
    print("  initial_window_size:", default_cfg.initial_window_size)
    print("  max_frame_size:", default_cfg.max_frame_size)
    print("  max_header_list_size:", default_cfg.max_header_list_size)
    print("  header_table_size:", default_cfg.header_table_size)
    print("  allow_huffman_decode:", default_cfg.allow_huffman_decode)
    var c1 = H2Connection.with_config(default_cfg^)
    _print_emitted_settings("  emitted SETTINGS", _emit_initial_settings(c1^))
    print()

    # ── 2. Relaxed config ────────────────────────────────────────────────
    print("── 2. Relaxed Http2Config (high-fan-out internal service) ──")
    var relaxed = Http2Config(
        max_concurrent_streams=500,
        initial_window_size=1048576,  # 1 MiB
        max_frame_size=65536,  # 64 KiB
        max_header_list_size=32768,  # 32 KiB
        header_table_size=8192,  # 8 KiB
        allow_huffman_decode=False,
        enable_connect_protocol=False,
    )
    relaxed.validate()
    var c2 = H2Connection.with_config(relaxed^)
    _print_emitted_settings("  emitted SETTINGS", _emit_initial_settings(c2^))
    print()

    # ── 3. Tight (edge-proxy) config ─────────────────────────────────────
    print("── 3. Tight Http2Config (edge proxy behind public IP) ──")
    var tight = Http2Config(
        max_concurrent_streams=64,
        initial_window_size=65535,  # 64 KiB - 1 (RFC default)
        max_frame_size=16384,  # 16 KiB (RFC floor)
        max_header_list_size=4096,  # 4 KiB
        header_table_size=2048,  # 2 KiB
        allow_huffman_decode=False,
        enable_connect_protocol=False,
    )
    tight.validate()
    var c3 = H2Connection.with_config(tight^)
    _print_emitted_settings("  emitted SETTINGS", _emit_initial_settings(c3^))
    print()

    # ── 4. Validation example ────────────────────────────────────────────
    print("── 4. Validation rejects out-of-bounds configs ──")
    var bad = Http2Config()
    bad.max_frame_size = 16383  # below RFC 9113 §6.5.2 floor
    var raised = False
    try:
        bad.validate()
    except e:
        raised = True
        print("  validate() raised:", String(e))
    if not raised:
        print("  (unexpected: validate accepted the bad config)")
    print()

    print("=== Example 37 complete ===")
