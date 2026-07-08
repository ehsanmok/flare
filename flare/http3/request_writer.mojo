"""HTTP/3 request-stream writer -- sans-I/O byte emitter.

The client-side mirror of :mod:`flare.http3.response_writer`. Builds
the bytes an HTTP/3 client hands to the QUIC stream layer for a
request on a client-initiated bidirectional stream, plus the
preambles for the client's unidirectional control + QPACK streams.

A complete H3 request is at most three concatenated wire fragments
on the request (bidi) stream:

  HEADERS frame (``:method`` / ``:scheme`` / ``:authority`` /
                 ``:path`` pseudo-headers + application headers,
                 QPACK-encoded)
  DATA frame    (zero or more, request body)
  HEADERS frame (optional trailers, QPACK-encoded)

Before any request, the client opens three unidirectional streams
(RFC 9114 §6.2): the control stream (type 0x00, carrying SETTINGS
first) and the QPACK encoder / decoder streams (types 0x02 / 0x03,
empty in the static-only table mode flare uses). The preamble
encoders here emit the leading stream-type varint + initial frame
so the caller can ship them as the first bytes of each uni-stream.

Public surface:

* :func:`encode_request_headers` -- the initial HEADERS frame with
  the four request pseudo-headers in canonical order (RFC 9114
  §4.3.1) followed by the application headers (lowercased).
* :func:`encode_request_data` -- wrap a body chunk in a DATA frame.
* :func:`encode_request_trailers` -- the trailing HEADERS frame.
* :func:`encode_client_control_stream` -- the control-stream type
  byte + the client's SETTINGS frame (the mandatory first frame,
  RFC 9114 §6.2.1).
* :func:`encode_qpack_encoder_stream` / :func:`encode_qpack_decoder_stream`
  -- the single stream-type byte for each QPACK uni-stream.

Sans-I/O contract: every entry point is a pure function over its
inputs; the QUIC client driver owns the per-stream cursor + FIN.

References:
- RFC 9114 §4 (HTTP Message Exchanges) + §6.2 (uni-streams) + §7.
- RFC 9204 (QPACK) -- static-table field-section encoder.
"""

from std.collections import List
from std.memory import Span

from flare.http.proto.ascii import ascii_lower
from flare.qpack import QpackHeader, encode_field_section
from flare.quic.varint import encode_varint

from .frame import (
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    H3_FRAME_TYPE_SETTINGS,
    H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
    H3_SETTINGS_QPACK_BLOCKED_STREAMS,
    H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    Http3Setting,
    encode_http3_frame,
    encode_http3_settings,
)


# ── Unidirectional stream type prefixes (RFC 9114 §6.2 + RFC 9204 §4.2) ──

comptime H3_UNI_STREAM_CONTROL: UInt64 = 0x00
comptime H3_UNI_STREAM_QPACK_ENCODER: UInt64 = 0x02
comptime H3_UNI_STREAM_QPACK_DECODER: UInt64 = 0x03


def encode_request_headers(
    method: String,
    scheme: String,
    authority: String,
    path: String,
    headers: List[QpackHeader],
    mut out: List[UInt8],
) raises:
    """Append the HEADERS-frame bytes for an HTTP/3 request to ``out``.

    Emits the four request pseudo-headers ``:method`` / ``:scheme``
    / ``:authority`` / ``:path`` in canonical order (RFC 9114
    §4.3.1) before the supplied application headers (all names
    lowercased). The caller MUST NOT include any pseudo-header in
    ``headers`` -- the writer rejects a name starting with ``:``
    there, mirroring :func:`flare.http3.response_writer.encode_response_headers`.

    ``authority`` may be empty for the ``CONNECT``-less origin case
    where a ``Host`` header is used instead, but for normal
    requests it carries the ``host[:port]`` the request targets.
    """
    if len(method.as_bytes()) == 0:
        raise Error("h3 request writer: empty :method")
    if len(path.as_bytes()) == 0:
        raise Error("h3 request writer: empty :path")
    var emit = List[QpackHeader]()
    emit.append(QpackHeader(":method", method.copy()))
    emit.append(QpackHeader(":scheme", scheme.copy()))
    if len(authority.as_bytes()) > 0:
        emit.append(QpackHeader(":authority", authority.copy()))
    emit.append(QpackHeader(":path", path.copy()))
    for i in range(len(headers)):
        var name = ascii_lower(headers[i].name)
        if len(name.as_bytes()) > 0 and name.as_bytes()[0] == UInt8(ord(":")):
            raise Error(
                "h3 request writer: pseudo-header '"
                + name
                + "' not allowed in application headers"
            )
        emit.append(QpackHeader(name^, String(headers[i].value)))
    var qpack_payload = List[UInt8]()
    encode_field_section(emit, qpack_payload)
    encode_http3_frame(
        H3_FRAME_TYPE_HEADERS, Span[UInt8, _](qpack_payload), out
    )


def encode_request_data(
    payload: Span[UInt8, _],
    mut out: List[UInt8],
) raises:
    """Append an HTTP/3 DATA frame wrapping ``payload`` to ``out``.

    The client calls this once per body chunk. Empty payloads are
    legal and encode as a 2-byte frame (type=0x00 + length=0x00).
    """
    encode_http3_frame(H3_FRAME_TYPE_DATA, payload, out)


def encode_request_trailers(
    trailers: List[QpackHeader],
    mut out: List[UInt8],
) raises:
    """Append the trailing HEADERS-frame bytes to ``out``.

    Trailers MUST NOT include pseudo-headers; the writer rejects
    any field whose name starts with ``:``. The driver sends this
    frame followed by FIN to close the request side of the stream.
    """
    var emit = List[QpackHeader]()
    for i in range(len(trailers)):
        var name = ascii_lower(trailers[i].name)
        if len(name.as_bytes()) > 0 and name.as_bytes()[0] == UInt8(ord(":")):
            raise Error(
                "h3 request writer: pseudo-header '"
                + name
                + "' not allowed in trailers"
            )
        emit.append(QpackHeader(name^, String(trailers[i].value)))
    var qpack_payload = List[UInt8]()
    encode_field_section(emit, qpack_payload)
    encode_http3_frame(
        H3_FRAME_TYPE_HEADERS, Span[UInt8, _](qpack_payload), out
    )


def encode_client_control_stream(
    max_field_section_size: UInt64,
    mut out: List[UInt8],
) raises:
    """Append the client's control unidirectional stream preamble
    to ``out``: the stream-type varint (0x00) followed by the
    SETTINGS frame that MUST be the first frame (RFC 9114 §6.2.1).

    flare runs QPACK in static-table-only mode, so the QPACK
    capacity + blocked-streams settings are advertised as 0,
    telling the server not to use the dynamic table against us.
    The caller writes the returned bytes as the very first bytes of
    a fresh client-initiated unidirectional stream.
    """
    var type_var = encode_varint(H3_UNI_STREAM_CONTROL)
    for i in range(len(type_var)):
        out.append(type_var[i])
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
            value=max_field_section_size,
        )
    )
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, value=UInt64(0)
        )
    )
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_QPACK_BLOCKED_STREAMS, value=UInt64(0)
        )
    )
    var payload = List[UInt8]()
    encode_http3_settings(settings, payload)
    encode_http3_frame(H3_FRAME_TYPE_SETTINGS, Span[UInt8, _](payload), out)


def encode_qpack_encoder_stream(mut out: List[UInt8]) raises:
    """Append the QPACK encoder unidirectional stream type byte
    (0x02, RFC 9204 §4.2). No further bytes follow in static-only
    mode (no dynamic-table instructions are ever sent)."""
    var type_var = encode_varint(H3_UNI_STREAM_QPACK_ENCODER)
    for i in range(len(type_var)):
        out.append(type_var[i])


def encode_qpack_decoder_stream(mut out: List[UInt8]) raises:
    """Append the QPACK decoder unidirectional stream type byte
    (0x03, RFC 9204 §4.2). No further bytes follow in static-only
    mode."""
    var type_var = encode_varint(H3_UNI_STREAM_QPACK_DECODER)
    for i in range(len(type_var)):
        out.append(type_var[i])
