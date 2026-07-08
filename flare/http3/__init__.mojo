"""``flare.http3`` — sans-I/O HTTP/3 codec primitives (RFC 9114).

HTTP/3 maps onto QUIC streams: each request lives on its own
bidirectional stream, and the application data is a sequence of
type-length-payload framed messages defined in RFC 9114 §7.

This package ships the *codec* layer of HTTP/3: pure byte-in /
byte-out parsers and emitters for frames. The QUIC stream layer
(reactor + flow control) and the header-block decoder (QPACK)
are deliberately separate modules; this package depends only on
the varint codec in :mod:`flare.quic.varint`.

Public re-exports:

- :class:`Http3Frame`, :class:`Http3FrameType` — the parsed-frame
  carrier + named frame-type constants.
- :func:`encode_http3_frame`, :func:`decode_http3_frame` — byte-level
  codec helpers.
- :func:`decode_http3_settings`, :func:`encode_http3_settings` — the
  HTTP/3 SETTINGS frame payload codec (a list of ``identifier:
  value`` varint pairs, RFC 9114 §7.2.4).
- :class:`Http3RequestReader` + :trait:`Http3RequestEventHandler` +
  :func:`feed_into[H]` — sans-I/O state machine that consumes
  the request-stream byte stream and fires typed callbacks
  (``on_headers`` / ``on_data`` / ``on_trailers`` /
  ``on_unknown_frame`` / ``on_protocol_error``) per RFC 9114
  §4. The ``H3_REQUEST_STATE_*`` constants enumerate the
  reader's lifecycle states.
- :func:`encode_response_headers`, :func:`encode_response_data`,
  :func:`encode_response_trailers` — sans-I/O response-stream
  writer that emits the corresponding HTTP/3 frames (HEADERS,
  DATA, TRAILERS) with QPACK-encoded field sections, ASCII
  header-name lowercasing, and pseudo-header validation per
  RFC 9114 §4.
- :func:`encode_request_headers`, :func:`encode_request_data`,
  :func:`encode_request_trailers`, :func:`encode_client_control_stream`,
  and the QPACK uni-stream preamble encoders — the client-side
  request writer (mirror of the response writer) plus the
  unidirectional control / QPACK stream preambles (RFC 9114 §6.2).
- :class:`Http3ResponseReader` + :class:`Http3Response` — the stateful
  client-side response decoder that accumulates HEADERS / DATA /
  trailers into an assembled response (mirror of the request
  reader).
"""

from .frame import (
    Http3FrameType,
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    H3_FRAME_TYPE_CANCEL_PUSH,
    H3_FRAME_TYPE_SETTINGS,
    H3_FRAME_TYPE_PUSH_PROMISE,
    H3_FRAME_TYPE_GOAWAY,
    H3_FRAME_TYPE_MAX_PUSH_ID,
    H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
    H3_SETTINGS_QPACK_BLOCKED_STREAMS,
    H3_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    Http3Frame,
    Http3Setting,
    decode_http3_frame,
    encode_http3_frame,
    decode_http3_settings,
    encode_http3_settings,
)
from .request_reader import (
    H3_REQUEST_STATE_BODY,
    H3_REQUEST_STATE_DONE,
    H3_REQUEST_STATE_INIT,
    H3_REQUEST_STATE_TRAILERS,
    Http3RequestEventHandler,
    Http3RequestReader,
    feed_into,
)
from .response_writer import (
    encode_response_data,
    encode_response_headers,
    encode_response_trailers,
)
from .request_writer import (
    H3_UNI_STREAM_CONTROL,
    H3_UNI_STREAM_QPACK_DECODER,
    H3_UNI_STREAM_QPACK_ENCODER,
    encode_client_control_stream,
    encode_qpack_decoder_stream,
    encode_qpack_encoder_stream,
    encode_request_data,
    encode_request_headers,
    encode_request_trailers,
)
from .response_reader import (
    H3_RESPONSE_STATE_BODY,
    H3_RESPONSE_STATE_DONE,
    H3_RESPONSE_STATE_INIT,
    H3_RESPONSE_STATE_TRAILERS,
    Http3BodyChunk,
    Http3Response,
    Http3ResponseReader,
)
from .client import (
    Http3ClientConnection,
    Http3ZeroRttOutcome,
    is_idempotent_method,
)
from .server import (
    Http3Connection,
    Http3Config,
    Http3StreamType,
)
