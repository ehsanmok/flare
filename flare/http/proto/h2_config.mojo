"""HTTP/2 SETTINGS and per-connection limits.

``Http2Config`` is pure configuration -- nine ``Int`` / ``Bool`` fields
and their RFC-mandated defaults, with no I/O and no dependency on the
HTTP/2 codec. It lives under :mod:`flare.http.proto` rather than in
:mod:`flare.http2` so that :class:`flare.http.ServerConfig` can nest it
without ``flare.http`` importing ``flare.http2``, which the layering
lint forbids outside a short allowlist.

:mod:`flare.http2` re-exports it, so ``from flare.http2 import
Http2Config`` keeps working and remains the spelling to use when
configuring an :class:`~flare.http2.Http2Connection` directly.
"""

# ── Http2Config ─────────────────────────────────────────────────────────────


comptime _H2_DEFAULT_MAX_CONCURRENT_STREAMS: Int = 100
"""RFC 9113 §5.1.2 has no protocol default; flare ships 100 to bound
per-connection memory under adversarial peers without breaking
common interactive workloads (a browser tab opening ~6 parallel
sub-requests sits well below this)."""

comptime _H2_DEFAULT_INITIAL_WINDOW_SIZE: Int = 65535
"""RFC 9113 §6.5.2 mandates 65535 as the default for new streams
until SETTINGS negotiates a different value. ``Http2Config`` ships
the same number so the default ``Http2Config()`` is observably
identical to the legacy ``Http2Connection()`` shape."""

comptime _H2_DEFAULT_MAX_FRAME_SIZE: Int = 16384
"""RFC 9113 §6.5.2 mandates 16384 (2^14) as both the protocol
default and the minimum any peer must accept."""

comptime _H2_DEFAULT_MAX_HEADER_LIST_SIZE: Int = 16384
"""RFC 9113 §6.5.2 default is unbounded; flare caps it because every
production proxy / origin we'd reasonably ship behind caps the header
list aggressively to defang request smuggling + header pollution
shaped at h2.

16 KiB rather than the 8 KiB flare shipped through v0.9: the size is
accounted with RFC 7541 §4.1's +32 bytes per field, so 8 KiB rejected
header lists that every other implementation accepts -- h2spec's
CONTINUATION test sends one at 8269 accounted bytes. 16 KiB matches
hyper's default and still bounds the accumulation hard."""

comptime _H2_DEFAULT_HEADER_TABLE_SIZE: Int = 4096
"""RFC 7541 §4.2 default for the HPACK dynamic table size."""


@fieldwise_init
struct Http2Config(Copyable, Defaultable):
    """Tunable HTTP/2 SETTINGS and limits for an :class:`Http2Connection`.

    Protocol fields map to RFC 9113 §6.5.2 SETTINGS identifiers
    (including the RFC 7541 HPACK header-table size). Defaults are the
    production-shape numbers flare's reactor wiring uses for both
    the inline test driver in :mod:`tests.test_h2_server` and the
    reactor-attached driver.

    The ``allow_huffman_decode`` flag gates HPACK Huffman decoding
    on the inbound HEADERS path. **Default ``True``, and it should
    stay that way.** RFC 7541 sec 5.2 lets the *encoder* choose
    whether a literal is Huffman-coded and signals it with the H bit;
    a decoder does not get the same choice. curl, every browser, and
    h2load Huffman-code by default, so a server that rejects H=1
    cannot talk to them -- it answers the client's first HEADERS
    frame by tearing down the connection. This defaulted to ``False``
    through v0.9, which is why flare's h2 interop was only ever
    exercised against flare's own client (which emits H=0).

    Set it to ``False`` only to reproduce the legacy raw-literal
    wire for a specific peer.

    The ``allow_huffman_encode`` flag is the emit-side twin and
    legitimately defaults to ``False``: what a server *sends* is its
    own choice, H=0 output is CRIME-class-side-channel-free by
    construction, and every compliant client accepts it. Set it
    ``True`` to pick the shorter of raw vs Huffman per literal.

    Example:

    ```mojo
    from flare.http2 import Http2Connection, Http2Config

    var cfg = Http2Config(
        max_concurrent_streams=200,
        max_body_size=10 * 1024 * 1024,
        initial_window_size=131072,
        max_frame_size=32768,
        max_header_list_size=16384,
        header_table_size=8192,
        allow_huffman_decode=True,
        allow_huffman_encode=False,
        enable_connect_protocol=False,
    )
    var conn = Http2Connection.with_config(cfg)
    ```

    Fields:
        max_concurrent_streams: SETTINGS_MAX_CONCURRENT_STREAMS
            (RFC 9113 §6.5.2). Bounds the per-connection live-stream
            count.
        max_body_size: Maximum buffered request bytes per stream, default
            10 MiB. Exceeding the limit resets the stream and frees its body.
            Zero permits only empty bodies; this is not a SETTINGS value.
        initial_window_size: SETTINGS_INITIAL_WINDOW_SIZE
            (RFC 9113 §6.5.2). Per-stream flow-control receive
            window the server advertises on inbound connections.
            Must be ``<= 2^31 - 1`` per RFC 9113 §6.9.2.
        max_frame_size: SETTINGS_MAX_FRAME_SIZE (RFC 9113 §6.5.2).
            Largest frame payload the server is willing to accept.
            Must be in ``[16384, 16777215]`` per RFC 9113 §6.5.2.
        max_header_list_size: SETTINGS_MAX_HEADER_LIST_SIZE
            (RFC 9113 §6.5.2). Header-list size cap (uncompressed,
            including 32-byte per-entry overhead).
        header_table_size: SETTINGS_HEADER_TABLE_SIZE (RFC 7541
            §4.2). HPACK dynamic-table size budget.
        allow_huffman_decode: When ``True``, the HPACK decoder
            accepts H=1 literals (Huffman-encoded) via the RFC
            7541 Appendix B codec. Defaults to ``False`` --
            reject-by-default until soak data justifies flipping
            it on.
        allow_huffman_encode: When ``True``, the HPACK encoder
            picks the shorter of raw vs Huffman per emitted
            literal (size-only optimisation; H=1 frames remain
            CRIME-safe because the encoder dynamic table stays
            empty). Defaults to ``False`` -- H=0-only wire
            output until peers and soak data confirm interop.
    """

    var max_concurrent_streams: Int
    var max_body_size: Int
    """Maximum buffered request bytes per stream (default 10 MiB)."""
    var initial_window_size: Int
    var max_frame_size: Int
    var max_header_list_size: Int
    var header_table_size: Int
    var allow_huffman_decode: Bool
    var allow_huffman_encode: Bool
    var enable_connect_protocol: Bool
    # ``enable_connect_protocol``: when True, the server advertises
    # SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (RFC 8441) in its initial
    # SETTINGS frame, allowing peers to issue Extended CONNECT
    # requests (the WebSocket-over-HTTP/2 bootstrap). Default
    # False -- the unified flare.http.HttpServer flips this on
    # automatically when the WebSocket-over-HTTP/2 bridge is
    # wired in (Phase 6).

    def __init__(out self):
        """Default to the production-shape SETTINGS pinned in
        the design doc: 100 concurrent streams, 64 KiB-1 initial
        window, 16 KiB max frame, 8 KiB max header list, 4 KiB
        HPACK dynamic table, Huffman decode **on** and encode off,
        Extended CONNECT disabled.
        """
        self.max_concurrent_streams = _H2_DEFAULT_MAX_CONCURRENT_STREAMS
        self.max_body_size = 10 * 1024 * 1024
        self.initial_window_size = _H2_DEFAULT_INITIAL_WINDOW_SIZE
        self.max_frame_size = _H2_DEFAULT_MAX_FRAME_SIZE
        self.max_header_list_size = _H2_DEFAULT_MAX_HEADER_LIST_SIZE
        self.header_table_size = _H2_DEFAULT_HEADER_TABLE_SIZE
        self.allow_huffman_decode = True
        self.allow_huffman_encode = False
        self.enable_connect_protocol = False

    def __init__(
        out self,
        max_concurrent_streams: Int,
        initial_window_size: Int,
        max_frame_size: Int,
        max_header_list_size: Int,
        header_table_size: Int,
        allow_huffman_decode: Bool,
        allow_huffman_encode: Bool,
        enable_connect_protocol: Bool,
        max_body_size: Int = 10 * 1024 * 1024,
    ):
        """Configure all SETTINGS, preserving the existing constructor shape."""
        self.max_concurrent_streams = max_concurrent_streams
        self.max_body_size = max_body_size
        self.initial_window_size = initial_window_size
        self.max_frame_size = max_frame_size
        self.max_header_list_size = max_header_list_size
        self.header_table_size = header_table_size
        self.allow_huffman_decode = allow_huffman_decode
        self.allow_huffman_encode = allow_huffman_encode
        self.enable_connect_protocol = enable_connect_protocol

    def validate(self) raises -> None:
        """Raise if any field violates the RFC 9113 / RFC 7541 bounds.

        The reactor-side wiring calls this once at acceptor handoff
        so a misconfigured server fails fast at boot rather than
        emitting malformed SETTINGS frames mid-handshake.
        """
        if self.max_concurrent_streams < 0:
            raise Error("Http2Config: max_concurrent_streams must be >= 0")
        if self.max_body_size < 0:
            raise Error("Http2Config: max_body_size must be >= 0")
        if self.initial_window_size < 0:
            raise Error("Http2Config: initial_window_size must be >= 0")
        if self.initial_window_size > 0x7FFFFFFF:
            raise Error(
                "Http2Config: initial_window_size must be <= 2^31-1"
                " (RFC 9113 §6.9.2)"
            )
        if self.max_frame_size < _H2_DEFAULT_MAX_FRAME_SIZE:
            raise Error(
                "Http2Config: max_frame_size must be >= 16384 (RFC 9113 §6.5.2)"
            )
        if self.max_frame_size > 16777215:
            raise Error(
                "Http2Config: max_frame_size must be <= 2^24-1"
                " (RFC 9113 §6.5.2)"
            )
        if self.max_header_list_size < 0:
            raise Error("Http2Config: max_header_list_size must be >= 0")
        if self.header_table_size < 0:
            raise Error("Http2Config: header_table_size must be >= 0")
