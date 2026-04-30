"""``flare.http2`` — RFC 9113 / RFC 7541 server primitives.

Public surface:

- :mod:`frame` — RFC 9113 §4 frame codec (DATA, HEADERS, PRIORITY,
  RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE,
  CONTINUATION).
- :mod:`hpack` — RFC 7541 HPACK encoder + decoder (static table,
  dynamic table, integer codec).
- :mod:`state` — per-stream + per-connection state machines that
  enforce RFC 9113 §5 transitions.
- :mod:`server` — high-level ``HttpServer.serve_h2`` loop: prefix
  ``"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"`` verification,
  SETTINGS exchange, framed request/response shuttling, ``h2c``
  upgrade from HTTP/1.1, ALPN dispatch from
  :mod:`flare.tls.acceptor`.

The codec is byte-clean and Connection-agnostic so it can be driven
by the existing reactor or run synchronously in tests; the server
glue is what ties it to ``flare.runtime.Reactor``.

Out of scope for (per the design doc):

- HTTP/2 push (``PUSH_PROMISE``); we accept it on inbound
  connections from clients (rare) but never originate it.
- HTTP/2 priority; we accept the frames and ignore them. RFC 9113
  §5.3.2 already deprecates the priority signalling, so this is the
  modern recommendation.
- gRPC; the framing is HTTP/2 + a subprotocol — we expose enough
  primitives that a gRPC server can be layered on, but no
  ``Code``/``Status`` machinery here.
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
    detect_h2c_upgrade,
    is_h2_alpn,
)
