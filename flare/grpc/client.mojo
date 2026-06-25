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

from ..http.client import HttpClient
from ..http.request import Method, Request
from ..http.headers import HeaderMap
from ..http.proto.ascii import ascii_unchecked_string
from .framing import decode_grpc_message, encode_grpc_message
from .metadata import GrpcMetadata
from .status import GRPC_STATUS_OK, GRPC_STATUS_UNKNOWN, GrpcStatus


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

    def __init__(out self, base_url: String, *, cleartext: Bool = True):
        """Create a channel to ``base_url`` (origin only, e.g.
        ``http://host:port``). ``cleartext`` selects h2c prior knowledge
        vs HTTP/2 over TLS."""
        self._base_url = base_url
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
    ) raises -> GrpcCallResult:
        """Invoke a unary RPC.

        Args:
            service_method: the fully-qualified method path
                (``/package.Service/Method``); a leading ``/`` is added
                if missing.
            request: the serialised request message bytes (LPM-wrapped
                here; the caller passes raw protobuf / codec bytes).
            metadata: optional initial metadata (text entries become
                request headers; binary ``-bin`` entries are skipped in
                this unary v1).

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
        var entries = metadata.entries()
        for i in range(len(entries)):
            if entries[i].is_binary:
                continue  # binary metadata unsupported in unary v1
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
