"""``flare.http.proto`` -- pure-function HTTP wire codecs and parsers.

This package is the **sans-I/O** face of flare's HTTP stack. Every
module re-exported here is a pure-function library over byte spans
and Mojo values: no sockets, no reactor, no TLS context, no
filesystem access, no syscalls beyond what the Mojo stdlib pulls in
for ``String`` / ``List[UInt8]`` allocation. The strict contract:

- No imports from ``flare.runtime`` (reactor, scheduler, cancel,
  timers, handoff, pools, blocking helpers).
- No imports from ``flare.io`` (``BufReader``).
- No imports from ``flare.tcp`` / ``flare.udp`` / ``flare.uds``.
- No imports from ``flare.tls`` (OpenSSL FFI).
- No imports from ``flare.net`` (socket address resolution).

The contract is enforced statically by ``pixi run check-sans-io``
which scans every file registered in ``tools/check_sans_io.sh``
for the forbidden import prefixes. Adding a file to the sans-I/O
list is a one-line change in that script.

## Why a separate namespace

The same parser modules feed multiple users: the reactor server,
the in-process ``TestClient``, fuzz harnesses, conformance test
runners, and downstream applications that want to embed flare's
parsers without pulling in the reactor. Today they live under
``flare.http.*`` next to reactor-coupled code; the layout buries
the boundary. ``flare.http.proto`` is the explicit, lint-enforced
public face for the parser-only surface.

## What lives here

This package re-exports the canonical sans-I/O modules from their
existing locations under ``flare.http.*`` and ``flare.http2.*``;
imports continue to work via either path. New pure-function
parsers added in future work land here directly.

```mojo
from flare.http.proto import (
    Cookie, CookieJar, parse_cookie_header,
    FormData, parse_form_urlencoded, urldecode, urlencode,
    MultipartForm, parse_multipart_form_data,
    Url, UrlParseError,
    HeaderMap, HeaderMapView,
    H2Frame, parse_h2_frame, encode_h2_frame,
    HpackEncoder, HpackDecoder,
    H2Connection, H2Stream, H2StreamState,
)
```

The H1 message parser, multipart boundary scanner, URL
percent-decoder, cookie / Set-Cookie parser, HPACK encoder /
decoder, and HTTP/2 frame codec / connection state machine are
all sans-I/O. The reactor-bound dispatcher in
``flare.http.server`` calls into this layer; downstream users
embedding flare-as-parser can do the same.

## H1 leniency

The H1 parser accepts a handful of widely-deployed RFC 9110 /
RFC 9112 relaxations as opt-in flags. The ``H1LeniencyConfig``
carrier surfaces them; strict mode (the no-argument constructor)
is the default. Each flag wires to a specific parser branch in
:func:`flare.http.server._parse_http_request_bytes`. The legacy
``_ExperimentalH1LeniencyConfig`` alias remains importable for
back-compat.
"""

# Cookies (RFC 6265) -- pure parsers / constructors / serialisers.
from flare.http.cookie import (
    Cookie,
    CookieJar,
    SameSite,
    parse_cookie_header,
    parse_set_cookie_header,
)

# Forms / URL percent-decoding (RFC 3986 §2.1 + RFC 7578) --
# pure parsers / encoders over ``String`` / ``List[UInt8]``.
from flare.http.form import (
    FormData,
    parse_form_urlencoded,
    urldecode,
    urlencode,
)

# Multipart bodies (RFC 7578) -- pure parser + value types.
from flare.http.multipart import (
    MultipartForm,
    MultipartPart,
    parse_multipart_form_data,
)

# URL parsing (RFC 3986) -- pure value types + parser.
from flare.http.url import Url, UrlParseError

# Header maps + zero-copy views (RFC 9110 §5).
from flare.http.headers import HeaderInjectionError, HeaderMap
from flare.http.header_view import HeaderMapView, parse_header_view

# Standard header perfect-hash lookup (RFC 7230 + RFC 9110 list).
from flare.http.header_phf import (
    StandardHeader,
    is_standard_header,
    lookup_standard_header_bytes,
    lookup_standard_header_string,
    standard_header_count,
    standard_header_name,
)

# Method + common-value interning -- ``StaticString`` returns.
from flare.http.intern import (
    MethodIntern,
    ValueIntern,
    intern_common_value,
    intern_common_value_string,
    intern_method_bytes,
    intern_method_string,
)

# SIMD-accelerated byte scanners + percent-decode.
from flare.http.simd_parsers import (
    HttpParseError,
    simd_cookie_scan,
    simd_memmem,
    simd_percent_decode,
)

# HPACK / QPACK Huffman codec (RFC 7541 §5.2 + Appendix B). Single
# canonical surface re-exported from ``flare.http.proto.huffman``;
# scalar reference + 256-entry 8-bit fast-table dispatcher today,
# real PSHUFB/TBL kernel slot reserved on the same symbols once
# Mojo exposes the byte-shuffle intrinsics. Pure functions over
# byte spans (no I/O imports anywhere on the path).
from flare.http.proto.huffman import (
    HuffmanError,
    SIMD_HUFFMAN_THRESHOLD_BYTES,
    huffman_decode,
    huffman_decode_dispatch,
    huffman_decode_simd,
    huffman_decoded_length,
    huffman_encode,
    huffman_encoded_length,
)

# HTTP/2 frame codec (RFC 9113 §4). Pure encode / decode over
# byte spans -- the reactor copies bytes in and out, the codec
# never touches a fd.
from flare.http2.frame import (
    Frame as H2Frame,
    FrameFlags as H2FrameFlags,
    FrameHeader as H2FrameHeader,
    FrameType as H2FrameType,
    encode_frame as encode_h2_frame,
    parse_frame as parse_h2_frame,
)

# HPACK encoder + decoder (RFC 7541). Both keep dynamic-table
# state internally but expose pure ``encode`` / ``decode`` methods
# over byte spans.
from flare.http2.hpack import (
    HpackDecoder,
    HpackEncoder,
    HpackHeader,
    StringPair as HpackStringPair,
    decode_integer as hpack_decode_integer,
    encode_integer as hpack_encode_integer,
)

# HTTP/2 connection + stream state machines (RFC 9113 §5).
# ``H2Connection`` exposes ``handle_frame`` as the single
# per-frame entry point; no timers, no fd, no reactor.
from flare.http2.state import (
    Connection as H2Connection,
    Stream as H2Stream,
    StreamState as H2StreamState,
)

# HTTP/1.1 parser leniency configuration carrier. Strict by
# default; every relaxation is opt-in and named after the RFC
# 9112 section it relaxes. Wired into the H1 request parser
# via :attr:`flare.http.server.ServerConfig.h1_leniency`. The
# ``_ExperimentalH1LeniencyConfig`` alias is preserved as a thin
# rebind for existing configuration code.
from flare.http.proto.h1_leniency import (
    H1LeniencyConfig,
    _ExperimentalH1LeniencyConfig,
)

# Zero-validation ASCII -> String helper. Promoted from the
# reactor-coupled ``flare.http.server`` to the sans-I/O parser
# layer because every consumer (H1 message parser, H2 wire codec,
# HPACK, gRPC metadata) is parser-shaped.
from flare.http.proto.ascii import (
    ascii_lower,
    ascii_unchecked_string,
    ascii_eq_ignore_case,
)

# RFC 7540 §3.2 ``Upgrade: h2c`` detector. Pure predicate over a
# parsed ``HeaderMap`` -- no reactor / socket / TLS coupling.
# Both ``flare.http2.server.detect_h2c_upgrade`` and the unified
# reactor's per-conn helper delegate to this canonical surface.
from flare.http.proto.h2c_upgrade import detect_h2c_upgrade
