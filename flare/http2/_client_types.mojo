"""``flare.http2._client_types`` -- HTTP/2 client value types.

The response carrier, client SETTINGS config, and the small free
helpers (h2c SETTINGS payload builder, Http2Response -> flare.http
Response lowering) peeled out of the oversized
``flare.http2.client`` so the module keeps the stateful
:class:`Http2ClientConnection` driver as its focus.
``flare.http2.client`` re-exports these names, so existing imports
(``from flare.http2.client import Http2Response`` / ``Http2ClientConfig``
/ ``build_h2c_settings_payload`` / ``_h2_response_to_http`` and the
``flare.http2`` package re-exports) keep resolving unchanged.
"""

from std.collections import List

from .frame import H2_DEFAULT_FRAME_SIZE
from .hpack import HpackHeader
from ..http.wire import Response


# ── Http2Response ─────────────────────────────────────────────────────────


struct Http2Response(Movable):
    """A reassembled HTTP/2 response: status + headers + body bytes.

    Returned by :meth:`Http2ClientConnection.take_response`. The
    surface mirrors the bits of :class:`flare.http.Response` the
    high-level :class:`Http2Client` facade needs to lower the
    response into a :class:`flare.http.Response` for callers --
    keeping it as a separate struct here lets the low-level driver
    avoid pulling in any of :mod:`flare.http`'s response-encoding
    apparatus (which is HTTP/1.1-shaped).

    Fields:
        status: HTTP status code from the response's ``:status``
            pseudo-header.
        headers: Response headers, ``HpackHeader`` pairs in the
            order they appeared on the wire (lowercased per
            RFC 9113 §8.1.2). Pseudo-headers (``:status``) are
            stripped; only the regular headers remain.
        body: Response body bytes, concatenated in order from
            every DATA frame on this stream.
    """

    var status: Int
    var headers: List[HpackHeader]
    var body: List[UInt8]

    def __init__(
        out self,
        status: Int,
        var headers: List[HpackHeader],
        var body: List[UInt8],
    ):
        self.status = status
        self.headers = headers^
        self.body = body^


# ── Http2ClientConfig ─────────────────────────────────────────────────────


comptime _DEFAULT_CLIENT_INITIAL_WINDOW_SIZE: Int = 65535
"""RFC 9113 §6.5.2 default. The client's per-stream receive
window size; used to flow-control inbound response DATA frames."""

comptime _DEFAULT_CLIENT_MAX_FRAME_SIZE: Int = 16384
"""RFC 9113 §6.5.2 default + minimum. Largest frame payload
the client is willing to accept on the wire."""

comptime _DEFAULT_CLIENT_HEADER_TABLE_SIZE: Int = 4096
"""RFC 7541 §4.2 default for the HPACK dynamic table size."""

comptime _DEFAULT_CLIENT_MAX_HEADER_LIST_SIZE: Int = 8192
"""Same 8 KiB cap the server uses (see
``flare.http2.server._H2_DEFAULT_MAX_HEADER_LIST_SIZE``).
Bounds memory if a hostile origin sends an absurd response header
list. Emitted only when ``> 0``."""


@fieldwise_init
struct Http2ClientConfig(Copyable, Defaultable, Movable):
    """Client-advertised SETTINGS for an :class:`Http2ClientConnection`.

    Symmetric counterpart to
    :class:`flare.http2.server.Http2Config`. The fields map 1:1 to
    RFC 9113 §6.5.2 SETTINGS identifiers (plus the RFC 7541 HPACK
    header-table size). Defaults are the same production-shape
    numbers the server side ships, so the defaults are safe for
    both sides of an in-process roundtrip.

    Fields:
        initial_window_size: SETTINGS_INITIAL_WINDOW_SIZE
            (RFC 9113 §6.5.2). Per-stream flow-control receive
            window the client advertises for inbound response
            DATA frames. Must be ``<= 2^31 - 1`` per
            RFC 9113 §6.9.2.
        max_frame_size: SETTINGS_MAX_FRAME_SIZE (RFC 9113 §6.5.2).
            Largest frame payload the client is willing to
            accept. Must be in ``[16384, 16777215]``.
        header_table_size: SETTINGS_HEADER_TABLE_SIZE (RFC 7541
            §4.2). HPACK dynamic-table size budget for the
            decoder we run on inbound HEADERS.
        max_header_list_size: SETTINGS_MAX_HEADER_LIST_SIZE
            (RFC 9113 §6.5.2). Header-list size cap (uncompressed,
            including 32-byte per-entry overhead).
        allow_huffman_decode: When ``True``, the HPACK decoder
            accepts H=1 literals (Huffman-encoded) in inbound
            HEADERS via the RFC 7541 Appendix B codec. Defaults
            to ``False`` -- reject-by-default until a soak proves
            the scalar Huffman path is CRIME-class-side-channel-
            safe under client load.
        allow_huffman_encode: When ``True``, the HPACK encoder
            picks the shorter of raw vs Huffman per emitted
            literal on outbound HEADERS. Defaults to ``False`` --
            H=0-only wire output until peers and soak data confirm
            interop.
    """

    var initial_window_size: Int
    var max_frame_size: Int
    var header_table_size: Int
    var max_header_list_size: Int
    var allow_huffman_decode: Bool
    var allow_huffman_encode: Bool
    var enable_connect_protocol: Bool
    """RFC 8441 ``SETTINGS_ENABLE_CONNECT_PROTOCOL`` (id=0x8). When
    ``True`` the client advertises support for receiving the
    ``:protocol`` pseudo-header on inbound CONNECT responses, AND
    is willing to issue Extended CONNECT requests itself once the
    peer ACKs the same SETTINGS bit. Defaults to ``False`` --
    enabled only when the high-level facade (e.g. WS-over-h2)
    needs the extension."""

    def __init__(out self):
        self.initial_window_size = _DEFAULT_CLIENT_INITIAL_WINDOW_SIZE
        self.max_frame_size = _DEFAULT_CLIENT_MAX_FRAME_SIZE
        self.header_table_size = _DEFAULT_CLIENT_HEADER_TABLE_SIZE
        self.max_header_list_size = _DEFAULT_CLIENT_MAX_HEADER_LIST_SIZE
        self.allow_huffman_decode = False
        self.allow_huffman_encode = False
        self.enable_connect_protocol = False

    def validate(self) raises -> None:
        """Raise if any field violates the RFC 9113 / RFC 7541 bounds.

        The high-level :class:`Http2Client` constructor calls this
        once at boot so a misconfigured client fails fast instead
        of emitting a malformed SETTINGS frame mid-handshake.
        """
        if self.initial_window_size < 0:
            raise Error("Http2ClientConfig: initial_window_size must be >= 0")
        if self.initial_window_size > 0x7FFFFFFF:
            raise Error(
                "Http2ClientConfig: initial_window_size must be <= 2^31-1"
                " (RFC 9113 §6.9.2)"
            )
        if self.max_frame_size < H2_DEFAULT_FRAME_SIZE:
            raise Error(
                "Http2ClientConfig: max_frame_size must be >= 16384"
                " (RFC 9113 §6.5.2)"
            )
        if self.max_frame_size > 16777215:
            raise Error(
                "Http2ClientConfig: max_frame_size must be <= 2^24-1"
                " (RFC 9113 §6.5.2)"
            )
        if self.header_table_size < 0:
            raise Error("Http2ClientConfig: header_table_size must be >= 0")
        if self.max_header_list_size < 0:
            raise Error("Http2ClientConfig: max_header_list_size must be >= 0")


# ── h2c upgrade SETTINGS payload helper ──────────────────────────────────


def build_h2c_settings_payload(config: Http2ClientConfig) -> List[UInt8]:
    """Serialise ``config``'s non-default SETTINGS pairs as a raw
    SETTINGS frame *body* (no 9-byte frame header) suitable for the
    ``HTTP2-Settings`` request-header value (RFC 7540 §3.2.1).

    Each pair is 6 bytes: 2-byte big-endian id then 4-byte
    big-endian value (RFC 9113 §6.5.1). The encoded blob is the
    base64url-safe-no-pad encoding of these bytes; the higher-level
    h2c-via-Upgrade client base64url-encodes the return value of
    this function before stuffing it into ``HTTP2-Settings``.

    The set of pairs MUST agree with the SETTINGS frame the client
    later sends inside its h2 connection preface so the server's
    view of the negotiated values is consistent before and after the
    101-switch (RFC 7540 §3.2.1: the upgrade-time SETTINGS replaces
    the *protocol defaults* on the server, and the client's
    connection preface SETTINGS is then ACK'd as a normal SETTINGS
    frame).
    """
    var p = List[UInt8]()
    if config.header_table_size != 4096:
        _append_setting_pair(p, 0x1, config.header_table_size)
    _append_setting_pair(p, 0x2, 0)
    if config.initial_window_size != 65535:
        _append_setting_pair(p, 0x4, config.initial_window_size)
    if config.max_frame_size != H2_DEFAULT_FRAME_SIZE:
        _append_setting_pair(p, 0x5, config.max_frame_size)
    if config.max_header_list_size > 0:
        _append_setting_pair(p, 0x6, config.max_header_list_size)
    if config.enable_connect_protocol:
        _append_setting_pair(p, 0x8, 1)
    return p^


def _append_setting_pair(mut buf: List[UInt8], id: Int, value: Int):
    """Append one 6-byte SETTINGS pair (RFC 9113 §6.5.1):
    big-endian 2-byte id then big-endian 4-byte value."""
    buf.append(UInt8((id >> 8) & 0xFF))
    buf.append(UInt8(id & 0xFF))
    buf.append(UInt8((value >> 24) & 0xFF))
    buf.append(UInt8((value >> 16) & 0xFF))
    buf.append(UInt8((value >> 8) & 0xFF))
    buf.append(UInt8(value & 0xFF))


# ── Http2Response -> flare.http.Response lowering ────────────────────────


def _h2_response_to_http(var h2: Http2Response) raises -> Response:
    """Lower an :class:`Http2Response` (the low-level
    ``status + HpackHeader[] + body`` triple) into a
    :class:`flare.http.Response` suitable for the high-level
    facade's callers.

    The ``:status`` pseudo-header has already been stripped by
    :meth:`Http2ClientConnection.take_response`; here we just
    populate the regular headers + body. ``reason`` is left
    empty (HTTP/2 has no reason phrase per RFC 9113 §8.1.2.4);
    the existing :func:`flare.http._status_reason` helper fills
    it on serialise.
    """
    # Mojo's borrow checker rejects "move ``h2.body`` out + read
    # ``h2.status`` and ``h2.headers``" in the same scope (once a
    # field is moved, the rest of the value is partially-uninit
    # and Mojo refuses to destroy it). The work-around: copy the
    # body bytes once -- one-time per response, in the noise.
    var body_copy = h2.body.copy()
    var resp = Response(status=h2.status, body=body_copy^)
    for i in range(len(h2.headers)):
        try:
            resp.headers.set(h2.headers[i].name, h2.headers[i].value)
        except:
            pass
    return resp^
