"""``flare.quic`` — sans-I/O QUIC v1 codec primitives (RFC 9000).

This package ships the *codec* layer of QUIC: pure byte-in /
byte-out parsers and emitters for the wire format. It contains
no socket I/O, no TLS handshake, no congestion controller, and
no reactor integration. Every public type's contract is "give me
bytes, get back a typed value (and optionally error context); give
me a typed value, get back bytes".

The codec layer is the load-bearing foundation that downstream
modules (the QUIC reactor + connection state machine, the TLS
handshake adapter, the congestion controllers) will build on top
of. Shipping the codec layer first lets us cross-validate against
reference implementations (aioquic, quiche) before committing to
a particular reactor / TLS / CC design.

Public re-exports:

- :class:`Varint` — variable-length integer codec (RFC 9000 §16).
- :func:`encode_varint`, :func:`decode_varint` — byte-level
  helpers around the ``Varint`` struct.
- :data:`VARINT_MAX` — largest representable varint value
  (``2 ** 62 - 1``).
"""

from .varint import (
    VARINT_MAX,
    Varint,
    decode_varint,
    encode_varint,
    varint_encoded_length,
)
from .packet import (
    QUIC_VERSION_1,
    QUIC_VERSION_NEGOTIATION,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ZERO_RTT,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_RETRY,
    MAX_CID_LENGTH,
    ConnectionId,
    LongHeader,
    InitialExtras,
    ShortHeader,
    encode_long_header,
    encode_short_header,
    parse_long_header,
    parse_initial_extras,
    parse_short_header,
)
