"""gRPC unary client over the HTTP/2 ``HttpClient`` path (W3).

Composes on the existing :class:`flare.http.HttpClient` HTTP/2 surface
rather than introducing a new transport: a unary call is one POST whose
body is the length-prefix-message (LPM) request frame and whose response
body is the LPM reply frame, with ``grpc-status`` / ``grpc-message`` read
from the response header set. The flare H2 client appends trailing
HEADERS into the same header list as the initial response HEADERS, so a
real gRPC server's status trailer is read transparently here.

Scope: unary (one request frame, one reply frame). Server-streaming,
client-streaming, and bidi are future phases on the same H2 stream
machinery; this module ships the unary path so the common request/reply
RPC works end to end today.

```mojo
from flare.grpc import GrpcClient

var ch = GrpcClient("http://127.0.0.1:50051")  # h2c cleartext
var reply = ch.call("/echo.EchoService/Echo", "hello".as_bytes())
if reply.is_ok():
    print(len(reply.message), "bytes back")
```
"""

from std.collections import List
from std.memory import Span

from ..crypto.base64 import base64_encode
from ..http.client import HttpClient
from ..http.request import Method, Request
from ..http.headers import HeaderMap
from ..http.proto.ascii import ascii_unchecked_string
from ..http.url import Url
from ..http2.client import Http2ClientConnection
from ..tcp import TcpStream
from ..tls import TlsStream
from ..tls.config import TlsConfig
from .framing import decode_grpc_message, encode_grpc_message
from .metadata import GrpcMetadata
from .status import GRPC_STATUS_OK, GRPC_STATUS_UNKNOWN, GrpcStatus
from .streaming import (
    GrpcBidiStream,
    GrpcServerStream,
    _H2Transport,
    _authority,
    _grpc_request_headers,
)

comptime _GRPC_DIAL_TIMEOUT_MS: Int = 30_000
"""Connect timeout for a streaming RPC dial. Matches the HttpClient
default; streaming calls open their own h2 connection rather than going
through the unary HttpClient path."""


@fieldwise_init
struct GrpcCallResult(Movable):
    """The outcome of a unary call.

    Fields:
        status: the RPC :class:`GrpcStatus` (code + message), read from
            ``grpc-status`` / ``grpc-message`` in the response headers.
        message: the LPM-unwrapped reply payload bytes (empty on a
            non-OK status or a trailers-only response).
        http_status: the HTTP/2 ``:status`` (200 for a well-formed gRPC
            response regardless of the RPC status code).
        headers: the full response header set (initial HEADERS + merged
            trailing HEADERS), for reading response metadata.
    """

    var status: GrpcStatus
    var message: List[UInt8]
    var http_status: Int
    var headers: HeaderMap

    def is_ok(self) -> Bool:
        """True iff the RPC status code is ``OK`` (0)."""
        return self.status.is_ok()


struct GrpcClient(Movable):
    """A blocking gRPC unary client over HTTP/2.

    Wraps an :class:`HttpClient` configured for HTTP/2: cleartext h2c via
    prior knowledge (``cleartext=True``, the default, for an ``http://``
    base) or HTTP/2 over TLS via ALPN (``cleartext=False`` for an
    ``https://`` base). Response auto-decompression is disabled because
    gRPC carries its own ``grpc-encoding`` independent of HTTP
    ``Content-Encoding``.
    """

    var _client: HttpClient
    var _base_url: String
    var _cleartext: Bool

    def __init__(out self, base_url: String, *, cleartext: Bool = True):
        """Create a channel to ``base_url`` (origin only, e.g.
        ``http://host:port``). ``cleartext`` selects h2c prior knowledge
        vs HTTP/2 over TLS."""
        self._base_url = base_url
        self._cleartext = cleartext
        if cleartext:
            self._client = HttpClient(prefer_h2c=True, auto_decompress=False)
        else:
            self._client = HttpClient(auto_decompress=False)

    def __enter__(var self) -> GrpcClient:
        return self^

    def call(
        self,
        service_method: String,
        request: Span[UInt8, _],
        metadata: GrpcMetadata = GrpcMetadata(),
        timeout_ms: Int = 0,
    ) raises -> GrpcCallResult:
        """Invoke a unary RPC.

        Args:
            service_method: the fully-qualified method path
                (``/package.Service/Method``); a leading ``/`` is added
                if missing.
            request: the serialised request message bytes (LPM-wrapped
                here; the caller passes raw protobuf / codec bytes).
            metadata: optional initial metadata. Text entries become
                request headers verbatim; binary ``-bin`` entries are
                base64-encoded onto their ``-bin`` header per the gRPC
                wire format.
            timeout_ms: optional call deadline in milliseconds. When
                ``> 0`` it is emitted as the ``grpc-timeout`` header
                (``<n>m`` millisecond form) so a deadline-aware server
                can abort the RPC and reply ``DEADLINE_EXCEEDED``.

        Returns:
            A :class:`GrpcCallResult` with the RPC status + reply bytes.

        Raises:
            NetworkError: on transport failure (connection / H2 error).
        """
        var body = List[UInt8]()
        encode_grpc_message(request, body)

        var path = service_method
        if path.byte_length() == 0 or path.unsafe_ptr()[0] != UInt8(ord("/")):
            path = String("/") + path
        var req = Request(
            method=Method.POST, url=self._base_url + path, body=body^
        )
        req.headers.set("content-type", "application/grpc+proto")
        req.headers.set("te", "trailers")
        req.headers.set("grpc-encoding", "identity")
        req.headers.set("grpc-accept-encoding", "identity")
        if timeout_ms > 0:
            req.headers.set("grpc-timeout", String(timeout_ms) + "m")
        var entries = metadata.entries()
        for i in range(len(entries)):
            if entries[i].is_binary:
                # Binary metadata (``-bin`` key): the wire value is the
                # raw bytes base64-encoded (gRPC PROTOCOL-HTTP2). The
                # server's framing layer base64-decodes on ingress.
                var encoded = base64_encode(Span[UInt8, _](entries[i].value))
                req.headers.set(entries[i].key, encoded)
            else:
                req.headers.set(
                    entries[i].key,
                    ascii_unchecked_string(Span[UInt8, _](entries[i].value)),
                )

        var resp = self._client.send(req)

        var payload = List[UInt8]()
        if len(resp.body) >= 5:
            var dec = decode_grpc_message(Span[UInt8, _](resp.body))
            if not dec.needs_more:
                payload = dec.message.payload.copy()

        var status_str = resp.headers.get("grpc-status")
        var msg = resp.headers.get("grpc-message")
        var code = GRPC_STATUS_UNKNOWN
        if status_str.byte_length() > 0:
            try:
                code = Int(status_str)
            except:
                code = GRPC_STATUS_UNKNOWN
        var status = (
            GrpcStatus.ok() if code
            == GRPC_STATUS_OK else GrpcStatus.err(code, msg)
        )

        return GrpcCallResult(
            status=status^,
            message=payload^,
            http_status=resp.status,
            headers=resp.headers.copy(),
        )

    # ── Streaming RPCs (W6) ───────────────────────────────────────────────

    def _normalize_path(self, service_method: String) -> String:
        if service_method.byte_length() == 0 or service_method.unsafe_ptr()[
            0
        ] != UInt8(ord("/")):
            return String("/") + service_method
        return service_method

    def _connect(self, u: Url) raises -> _H2Transport:
        """Open a fresh HTTP/2 transport to ``u`` (h2c prior-knowledge
        TCP, or h2-over-TLS via ALPN) and write the connection preface
        is left to the caller."""
        if self._cleartext:
            var tcp = TcpStream.connect(u.host, u.port, _GRPC_DIAL_TIMEOUT_MS)
            return _H2Transport.from_tcp(tcp^)
        var cfg = TlsConfig()
        cfg.alpn = List[String]()
        cfg.alpn.append("h2")
        var tls = TlsStream.connect_timeout(
            u.host, u.port, cfg^, _GRPC_DIAL_TIMEOUT_MS
        )
        return _H2Transport.from_tls(tls^)

    def call_server_streaming(
        self,
        service_method: String,
        request: Span[UInt8, _],
        metadata: GrpcMetadata = GrpcMetadata(),
    ) raises -> GrpcServerStream:
        """Open a server-streaming RPC: send one request message, then
        receive N reply messages.

        The returned :class:`GrpcServerStream` yields reply payloads one
        at a time via ``recv()`` (``None`` at end of stream) as the
        server's DATA frames arrive -- only one message plus the
        partial-frame reassembly buffer are ever held in memory. Read
        the final ``grpc-status`` with ``status()`` after ``recv()``
        returns ``None``.

        Args:
            service_method: ``/package.Service/Method`` (leading ``/``
                added if missing).
            request: the single request message bytes (LPM-framed here).
            metadata: optional initial metadata (text entries only).
        """
        var path = self._normalize_path(service_method)
        var u = Url.parse(self._base_url + path)
        var body = List[UInt8]()
        encode_grpc_message(request, body)

        var conn = Http2ClientConnection()
        var t = self._connect(u)
        var preface = conn.drain()
        if len(preface) > 0:
            t.write_all(Span[UInt8, _](preface))
        var sid = conn.next_stream_id()
        conn.send_request(
            sid,
            "POST",
            u.scheme,
            _authority(u),
            u.request_target(),
            _grpc_request_headers(metadata),
            Span[UInt8, _](body),
        )
        var out = conn.drain()
        if len(out) > 0:
            t.write_all(Span[UInt8, _](out))
        return GrpcServerStream(t^, conn^, sid)

    def call_client_streaming(
        self,
        service_method: String,
        metadata: GrpcMetadata = GrpcMetadata(),
    ) raises -> GrpcBidiStream:
        """Open a client-streaming RPC: the request stream stays OPEN so
        the caller pumps request messages with ``send()`` then
        half-closes with ``close_send()``, after which ``recv()`` drains
        the (typically single) reply message and ``status()`` the final
        status.

        Implemented on the same OPEN-stream machinery as :meth:`call_bidi`
        (a client-streaming RPC is a bidi RPC the server answers only
        after the request half-closes)."""
        return self.call_bidi(service_method, metadata)

    def call_bidi(
        self,
        service_method: String,
        metadata: GrpcMetadata = GrpcMetadata(),
    ) raises -> GrpcBidiStream:
        """Open a bidirectional-streaming RPC. The returned
        :class:`GrpcBidiStream` keeps the request side OPEN: pump request
        messages with ``send()``, half-close with ``close_send()``, and
        drain replies with ``recv()`` (then ``status()``).

        Args:
            service_method: ``/package.Service/Method`` (leading ``/``
                added if missing).
            metadata: optional initial metadata (text entries only).
        """
        var path = self._normalize_path(service_method)
        var u = Url.parse(self._base_url + path)

        var conn = Http2ClientConnection()
        var t = self._connect(u)
        var preface = conn.drain()
        if len(preface) > 0:
            t.write_all(Span[UInt8, _](preface))
        var sid = conn.next_stream_id()
        conn.send_request_open(
            sid,
            "POST",
            u.scheme,
            _authority(u),
            u.request_target(),
            _grpc_request_headers(metadata),
        )
        var out = conn.drain()
        if len(out) > 0:
            t.write_all(Span[UInt8, _](out))
        return GrpcBidiStream(t^, conn^, sid)
