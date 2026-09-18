"""``flare.prelude`` -- the everyday surface, in one import.

    from flare.prelude import *

Exports exactly what the root :mod:`flare` package exports, covering
the server, client, routing, handlers and extractors, middleware, TLS,
sockets, WebSocket and the test client. One list, so there is no second
one to keep in sync.

**What is on the list.** A symbol belongs here if either:

1. another listed symbol's signature names it -- the *closure rule*, so
   anything you can reach you can also write down; or
2. the README's basic or intermediate examples need it.

**What never is:** wire-format codecs, anything in a ``_``-prefixed
module, ``flare.runtime`` primitives, protocol-specific types beyond
their configuration structs, and test helpers other than
``TestClient``.

The closure rule is what v0.11 added, after seven symbols were found to
break it: ``precompute_response`` returned a ``StaticResponse`` callers
could not name, ``Cache[Inner, S]`` needed a store they could not name,
``UnixListener`` / ``UnixStream`` were absent while their TCP peers and
the frame-mux codec layered over them were both present, the WebSocket
handler's argument type was absent, and the README documented
``HandlerInfallible`` that neither barrel exported.

**Changed in v0.10 (breaking).** This used to re-export every stable
public symbol in the library -- 454 of them, including protocol
codecs like ``quic_encode_varint``, ``h2_encode_frame``,
``qpack_encode_field_section``, ``huffman_encode`` and
``encode_grpc_message``. A prelude that wide is not a convenience:
it puts wire-format internals one ``import *`` away from application
code, and it means every name flare adds anywhere becomes a name that
can collide in a user's module.

Anything not here still has a home; import it from the submodule that
owns it::

    from flare.http2 import Http2Connection, HpackEncoder
    from flare.quic import quic_encode_varint
    from flare.http3 import encode_http3_frame
    from flare.qpack import qpack_encode_field_section
    from flare.grpc import GrpcClient, encode_grpc_message
    from flare.runtime import Reactor, BufferPool
    from flare.crypto import hmac_sha256
    from flare.openapi import OpenApiSpec
    from flare.testing import TestClient

That is also the better habit in code meant to last:
``from flare.runtime import Reactor`` says where ``Reactor`` comes
from, and ``from flare.prelude import *`` does not.

``tests/test_prelude_surface.mojo`` pins this list against the root
package, so the two cannot drift and the surface cannot quietly
regrow.
"""

from ..errors import HttpStatusError, IoError, ValidationError
from ..http.server import (
    HttpServer,
    ServerConfig,
    ShutdownReport,
    ok,
    ok_json,
    bad_request,
    unauthorized,
    forbidden,
    not_found,
    internal_error,
    redirect,
)
from ..http.client import HttpClient
from ..http._client.shortcuts import get, post, put, patch, delete, head
from ..http.request import Request, Method
from ..http.response import Response, Status, stream_response
from ..http.body import Body, ChunkSource
from ..http.request_view import RequestView
from ..http.url import Url, UrlParseError
from ..http.headers import HeaderMap, HeaderInjectionError
from ..http.cancel import Cancel
from ..http.handler import (
    Handler,
    CancelHandler,
    ViewHandler,
    WithCancel,
    WithViewCancel,
    HandlerInfallible,
    WithRaises,
)
from ..http.router import Router
from ..http.routes import ComptimeRoute, ComptimeRouter
from ..http.auth import Auth, BasicAuth, BearerAuth
from ..http.error import HttpError, TooManyRedirects
from ..http.static_response import precompute_response, StaticResponse
from ..http.cookie import Cookie, CookieJar, parse_set_cookie_header
from ..io import ByteReader, ByteWriter
from ..http.streaming_server import StreamHandler, StreamConn
from ..http.async_body import AsyncChunkSource, ChunkPoll, UpstreamChunkSource
from ..uds.frame_mux import (
    Frame,
    FrameDemux,
    FrameKind,
    FrameMux,
    encode_frame,
    decode_frame,
)
from ..http.extract import (
    Extractor,
    PathInt,
    PathStr,
    PathFloat,
    PathBool,
    OptionalPathInt,
    OptionalPathStr,
    OptionalPathFloat,
    OptionalPathBool,
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
    BodyBytes,
    BodyText,
    Json,
    FromJson,
    JsonAs,
    Cookies,
    Form,
    Multipart,
    Peer,
    Extracted,
)
from ..http.middleware import (
    CatchPanic,
    Compress,
    Logger,
    RequestId,
)
from ..http.cors import Cors, CorsConfig
from ..http.cache import Cache, InMemoryCacheStore
from ..http.fs import FileServer
from ..http.reliability import Retry, RetryPolicy, PostHocDeadline
from ..http.session import (
    Session,
    CookieSessionStore,
    InMemorySessionStore,
)
from ..tls.config import TlsConfig
from ..tls.acceptor import TlsAcceptor, TlsServerConfig
from ..net.address import IpAddr, SocketAddr
from ..tcp.stream import TcpStream
from ..tcp.listener import TcpListener
from ..uds.listener import UnixListener
from ..uds.stream import UnixStream
from ..ws.client import WsClient, WsMessage
from ..ws.server import WsServer, WsConnection
from ..testing import TestClient
from ..runtime._thread import num_cpus
from ..runtime.scheduler import default_worker_count
