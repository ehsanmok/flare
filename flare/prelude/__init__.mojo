"""``flare.prelude`` — wide-import surface.

This module re-exports **every** stable public symbol from the
flare submodules. It exists so users who want the everything-at-
the-top-level feel can write::

    from flare.prelude import *

The root :mod:`flare` package itself is curated to ~40 most-used
symbols (HttpServer / Router / Request / Response / extractors /
middleware / TLS / sockets / WsClient / TestClient). Everything
beyond that core surface lives in an opt-in submodule
(:mod:`flare.http2`, :mod:`flare.quic`, :mod:`flare.h3`,
:mod:`flare.grpc`, :mod:`flare.runtime`, :mod:`flare.crypto`,
:mod:`flare.openapi`, :mod:`flare.testing`). The prelude pulls
all of them in one shot.

Prefer direct imports from the relevant submodule in new code --
``from flare.runtime import Reactor`` is clearer than
``from flare.prelude import Reactor`` and the per-module imports
help the reader understand which layer the code is interacting
with. The prelude is meant for migrations and for the cookbook
examples that touch many layers at once.
"""

# ─────────────────────────────────────────────────────────────────────────
# Most-used surface — mirrored from the root ``flare`` package.
# ─────────────────────────────────────────────────────────────────────────

from ..errors import IoError, ValidationError
from ..http.auth_extract import AuthError
from ..http.proxy_protocol import ProxyParseError
from ..http.template import Template, TemplateContext, TemplateError
from ..http.sse import (
    SseChannel,
    SseEvent,
    SseStreamingResponse,
    format_sse_event,
    sse_response,
)
from ..net.address import IpAddr, SocketAddr
from ..http.server import (
    HttpServer,
    ServerConfig,
    ShutdownReport,
    ok,
    ok_json,
    ok_json_value,
    bad_request,
    not_found,
    internal_error,
    redirect,
)
from ..http.request import Request, Method
from ..http.response import Response, Status
from ..http.response_pool import ResponsePool
from ..http.intern import (
    MethodIntern,
    ValueIntern,
    intern_method_bytes,
    intern_method_string,
    intern_common_value,
    intern_common_value_string,
)
from ..http.header_phf import (
    StandardHeader,
    standard_header_count,
    standard_header_name,
    lookup_standard_header_bytes,
    lookup_standard_header_string,
    is_standard_header,
)
from ..http.hpack_huffman import (
    HuffmanError,
    huffman_encode,
    huffman_decode,
    huffman_encoded_length,
    huffman_decoded_length,
)
from ..http.simd_parsers import (
    HttpParseError,
    simd_memmem,
    simd_percent_decode,
    simd_cookie_scan,
)
from ..http.handler import (
    Handler,
    FnHandler,
    FnHandlerCT,
    CancelHandler,
    WithCancel,
    ViewHandler,
)
from ..http.router import Router
from ..http.client import HttpClient, get, post, put, patch, delete, head
from ..http.auth import Auth, BasicAuth, BearerAuth
from ..runtime._thread import num_cpus
from ..runtime.scheduler import default_worker_count

# ─────────────────────────────────────────────────────────────────────────
# Networking primitives.
# ─────────────────────────────────────────────────────────────────────────

from ..net.socket import RawSocket
from ..net.error import (
    NetworkError,
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionReset,
    AddressInUse,
    AddressParseError,
    BrokenPipe,
    DnsError,
    Timeout,
)

# flare.dns
from ..dns.resolver import resolve, resolve_v4, resolve_v6

# flare.tcp
from ..tcp.stream import TcpStream
from ..tcp.listener import TcpListener

# flare.udp
from ..udp.socket import UdpSocket, DatagramTooLarge

# flare.uds
from ..uds.listener import UnixListener, accept_uds_fd
from ..uds.stream import UnixStream

# flare.tls
from ..tls.config import TlsConfig, TlsVerify
from ..tls.stream import TlsStream
from ..tls.error import (
    TlsHandshakeError,
    CertificateExpired,
    CertificateHostnameMismatch,
    CertificateUntrusted,
)
from ..tls.acceptor import (
    TlsAcceptor,
    TlsServerConfig,
    TlsInfo,
    TlsServerError,
    TlsServerNotImplemented,
    TLS_PROTOCOL_TLS12,
    TLS_PROTOCOL_TLS13,
)

# flare.http additional surface
from ..http.cancel import Cancel, CancelCell, CancelReason
from ..http.headers import HeaderMap, HeaderInjectionError
from ..http.header_view import HeaderMapView, parse_header_view
from ..http.request_view import RequestView, parse_request_view
from ..http.body import (
    Body,
    ChunkSource,
    InlineBody,
    ChunkedBody,
    drain_body,
)
from ..http.streaming_response import StreamingResponse
from ..http.streaming_serialize import serialize_streaming_response
from ..http.url import Url, UrlParseError
from ..http.routes import ComptimeRoute, ComptimeRouter
from ..http.extract import (
    Extractor,
    PathInt,
    PathStr,
    PathFloat,
    PathBool,
    QueryInt,
    QueryStr,
    QueryFloat,
    QueryBool,
    OptionalQueryInt,
    OptionalQueryStr,
    OptionalQueryFloat,
    OptionalQueryBool,
    HeaderInt,
    HeaderStr,
    HeaderFloat,
    HeaderBool,
    OptionalHeaderInt,
    OptionalHeaderStr,
    OptionalHeaderFloat,
    OptionalHeaderBool,
    Peer,
    BodyBytes,
    BodyText,
    Json,
    Cookies,
    Form,
    Multipart,
    Extracted,
)
from ..http.form import (
    FormData,
    parse_form_urlencoded,
    urldecode,
    urlencode,
)
from ..http.multipart import (
    MultipartPart,
    MultipartForm,
    parse_multipart_form_data,
)
from ..http.session import (
    CookieSessionStore,
    InMemorySessionStore,
    Session,
    SessionCodec,
    StringSessionCodec,
    signed_cookie_decode,
    signed_cookie_decode_keys,
    signed_cookie_encode,
)
from ..crypto import (
    base64url_decode,
    base64url_encode,
    hmac_sha256,
    hmac_sha256_verify,
)
from ..http.encoding import (
    Encoding,
    compress_gzip,
    compress_brotli,
    decompress_gzip,
    decompress_deflate,
    decompress_brotli,
    decode_content,
)
from ..http.middleware import (
    CatchPanic,
    Compress,
    Logger,
    RequestId,
    negotiate_encoding,
)
from ..http.cache import (
    Cache,
    CacheControl,
    CacheEntry,
    CacheKey,
    CacheStore,
    InMemoryCacheStore,
    derive_cache_key,
    is_fresh as cache_is_fresh,
    parse_cache_control,
    parse_vary_header,
)
from ..openapi import (
    OpenApiInfo,
    OpenApiOperation,
    OpenApiParameter,
    OpenApiPath,
    OpenApiResponse,
    OpenApiSpec,
    emit_openapi_json,
)
from ..http.cors import Cors, CorsConfig
from ..http.fs import ByteRange, FileServer, parse_range
from ..http.reliability import (
    Retry,
    RetryPolicy,
    PostHocDeadline,
)
from ..http.error import HttpError, TooManyRedirects
from ..http.static_response import StaticResponse, precompute_response
from ..http.cookie import (
    Cookie,
    CookieJar,
    SameSite,
    parse_cookie_header,
    parse_set_cookie_header,
)

# flare.http2
from ..http2 import (
    H2Connection,
    H2Error,
    H2ErrorCode,
    H2_PREFACE,
    H2_DEFAULT_FRAME_SIZE,
    H2_MAX_FRAME_SIZE,
    HpackEncoder,
    HpackDecoder,
    HpackHeader,
    Connection as H2NetConnection,
    Frame as H2Frame,
    FrameFlags as H2FrameFlags,
    FrameHeader as H2FrameHeader,
    FrameType as H2FrameType,
    Stream as H2Stream,
    StreamState as H2StreamState,
    is_h2_alpn,
    detect_h2c_upgrade,
    encode_frame as h2_encode_frame,
    parse_frame as h2_parse_frame,
    encode_integer as h2_encode_integer,
    decode_integer as h2_decode_integer,
)

# flare.quic
from ..quic import (
    VARINT_MAX as QUIC_VARINT_MAX,
    Varint as QuicVarint,
    decode_varint as quic_decode_varint,
    encode_varint as quic_encode_varint,
    varint_encoded_length as quic_varint_encoded_length,
    QUIC_VERSION_1,
    QUIC_VERSION_NEGOTIATION,
    PACKET_TYPE_INITIAL as QUIC_PACKET_TYPE_INITIAL,
    PACKET_TYPE_ZERO_RTT as QUIC_PACKET_TYPE_ZERO_RTT,
    PACKET_TYPE_HANDSHAKE as QUIC_PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_RETRY as QUIC_PACKET_TYPE_RETRY,
    MAX_CID_LENGTH as QUIC_MAX_CID_LENGTH,
    ConnectionId as QuicConnectionId,
    LongHeader as QuicLongHeader,
    InitialExtras as QuicInitialExtras,
    ShortHeader as QuicShortHeader,
    encode_long_header as quic_encode_long_header,
    encode_short_header as quic_encode_short_header,
    parse_long_header as quic_parse_long_header,
    parse_initial_extras as quic_parse_initial_extras,
    parse_short_header as quic_parse_short_header,
)

# flare.h3
from ..h3 import (
    H3FrameType,
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
    H3Frame,
    H3Setting,
    decode_h3_frame,
    encode_h3_frame,
    decode_h3_settings,
    encode_h3_settings,
)

# flare.grpc
from ..grpc import (
    GRPC_COMPRESSION_NONE,
    GRPC_COMPRESSION_COMPRESSED,
    GrpcCompressionFlag,
    GrpcMessage,
    GrpcDecodeResult,
    decode_grpc_message,
    encode_grpc_message,
    GrpcMetadata,
    GrpcMetadataEntry,
    GRPC_STATUS_OK,
    GRPC_STATUS_CANCELLED,
    GRPC_STATUS_UNKNOWN,
    GRPC_STATUS_INVALID_ARGUMENT,
    GRPC_STATUS_DEADLINE_EXCEEDED,
    GRPC_STATUS_NOT_FOUND,
    GRPC_STATUS_ALREADY_EXISTS,
    GRPC_STATUS_PERMISSION_DENIED,
    GRPC_STATUS_RESOURCE_EXHAUSTED,
    GRPC_STATUS_FAILED_PRECONDITION,
    GRPC_STATUS_ABORTED,
    GRPC_STATUS_OUT_OF_RANGE,
    GRPC_STATUS_UNIMPLEMENTED,
    GRPC_STATUS_INTERNAL,
    GRPC_STATUS_UNAVAILABLE,
    GRPC_STATUS_DATA_LOSS,
    GRPC_STATUS_UNAUTHENTICATED,
    GrpcStatus,
)

# flare.ws
from ..ws.client import WsClient, WsHandshakeError, WsMessage
from ..ws.server import WsServer
from ..ws.frame import WsFrame, WsOpcode, WsCloseCode, WsProtocolError
from ..ws.client_h2 import WsOverH2Stream, bootstrap_ws_over_h2
from ..ws.permessage_deflate import (
    PermessageDeflateConfig,
    PermessageDeflateContext,
    compress_message,
    decompress_message,
)
from ..ws.extensions import (
    ExtensionOffer,
    ExtensionParameter,
    parse_extensions,
    build_permessage_deflate_offer,
    negotiate_permessage_deflate,
)

# flare.io
from ..io.buf_reader import Readable, BufReader

# flare.runtime
from ..runtime.reactor import Reactor
from ..runtime.timer_wheel import TimerWheel
from ..runtime.event import (
    Event,
    INTEREST_READ,
    INTEREST_WRITE,
    EVENT_READABLE,
    EVENT_WRITABLE,
    EVENT_ERROR,
    EVENT_HUP,
    WAKEUP_TOKEN,
)
from ..runtime.handoff import HandoffPolicy, HandoffQueue, WorkerHandoffPool
from ..runtime.date_cache import DateCache
from ..runtime.buffer_pool import BufferHandle, BufferPool
from ..runtime.iovec import IoVecBuf, writev_buf, writev_buf_all
from ..runtime.io_uring import (
    IoUringRing,
    IoUringParams,
    is_io_uring_available,
)

# flare.testing
from ..testing import TestClient, fork_server, kill_forked_server
