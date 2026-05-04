"""``flare.http2`` -- low-level HTTP/2 driver primitives (RFC 9113 + RFC 7541).

This package exposes the byte-level HTTP/2 machinery: frame
codec, HPACK encoder + decoder, stream + connection state
machines, the byte-level server driver
:class:`H2Connection`, and the symmetric byte-level client
driver :class:`Http2ClientConnection`.

The **user-facing** HTTP/2 entry points live in
:mod:`flare.http`: :meth:`flare.http.HttpServer.serve`
auto-dispatches HTTP/1.1 vs HTTP/2 per accepted connection
(preface peek for cleartext, ALPN ``h2`` for TLS), and
:class:`flare.http.HttpClient` advertises ALPN
``["h2", "http/1.1"]`` for ``https://`` URLs (and speaks
HTTP/2 cleartext via prior knowledge when constructed with
``prefer_h2c=True``). Application code should reach for those
unified types; the primitives below are re-exported for callers
who want to drive the protocol themselves.

Out of scope (per the design doc):

- HTTP/2 push (``PUSH_PROMISE``); we accept it on inbound
  connections from clients (rare) but never originate it.
- HTTP/2 priority; we accept the frames and ignore them. RFC
  9113 §5.3.2 already deprecates the priority signalling.
- gRPC; the framing is HTTP/2 + a subprotocol -- we expose
  enough primitives that a gRPC server can be layered on, but
  no ``Code`` / ``Status`` machinery here.
"""

from .frame import (
    Frame,
    FrameHeader,
    FrameType,
    FrameFlags,
    parse_frame,
    encode_frame,
    H2_PREFACE,
    H2_DEFAULT_FRAME_SIZE,
    H2_MAX_FRAME_SIZE,
)
from .hpack import (
    HpackDecoder,
    HpackEncoder,
    HpackHeader,
    decode_integer,
    encode_integer,
)
from .state import (
    StreamState,
    StreamId,
    Stream,
    Connection,
    H2Error,
    H2ErrorCode,
)
from .server import (
    H2Connection,
    Http2Config,
    detect_h2c_upgrade,
    is_h2_alpn,
)
from .client import (
    Http2ClientConfig,
    Http2ClientConnection,
    Http2Response,
)
