"""HTTP/1.1 client and server.

Built on `flare.tcp` and `flare.tls` — no external HTTP library. Supports
persistent connections, redirects, chunked transfer encoding, gzip/deflate
decompression, and injection-safe header handling.

## Public API

```mojo
from flare.http import (
    HttpClient, HttpServer,
    Request, Response,
    HeaderMap, HeaderInjectionError,
    Url, UrlParseError,
    Method, Status, Encoding,
    HttpError, TooManyRedirects,
    BasicAuth, BearerAuth,
    get, post, put, delete, head,
)
```

- `HttpClient` — Send HTTP/HTTPS requests: `get`, `post`, `put`, etc.
- `HttpServer` — Accept and dispatch HTTP requests.
- `Request` — HTTP request (method, URL, headers, body).
- `Response` — HTTP response (status, headers, body, `text()`, `json()`).
- `HeaderMap` — Case-insensitive HTTP header collection.
- `HeaderInjectionError` — Raised on CR/LF characters in header names or values.
- `Url` — Parsed HTTP/HTTPS URL (scheme, host, port, path, query).
- `UrlParseError` — Raised on invalid URL syntax.
- `Method` — HTTP method string constants (`GET`, `POST`, …).
- `Status` — HTTP status code integer constants (`OK`, `NOT_FOUND`, …).
- `Encoding` — Content-Encoding token constants (`gzip`, `deflate`).
- `HttpError` — Raised by `Response.raise_for_status()` on non-2xx responses.
- `TooManyRedirects` — Raised when the redirect limit is exceeded.
- `BasicAuth` — HTTP Basic authentication (RFC 7617).
- `BearerAuth` — HTTP Bearer token authentication (RFC 6750).
- `ParamParser`, `ParamInt`, `ParamFloat64`, `ParamBool`, `ParamString`
  — Typed parsers for URL / header string values.
- `Extractor` — Trait implemented by each extractor.
- `Path`, `Query`, `OptionalQuery`, `Header`, `OptionalHeader`
  — Typed extractors for path params, query string, headers.
- `Peer`
  — Extracts the kernel-reported peer ``SocketAddr`` populated by the
    reactor at accept time.
- `BodyBytes`, `BodyText`, `Json`, `Cookies`, `Form`, `Multipart`
  — Extractors that read the request body.
- `FormData`, `parse_form_urlencoded`, `urlencode`, `urldecode`
  — ``application/x-www-form-urlencoded`` parsing helpers.
- `MultipartPart`, `MultipartForm`, `parse_multipart_form_data`
  — ``multipart/form-data`` parser (RFC 7578).
- `Extracted`
  — Reflective auto-injection wrapper: put your extractor set on the
    fields of any ``Handler`` struct (plus ``Defaultable``) and wrap
    it in ``Extracted[H]`` to get a ``Handler`` that pulls each field
    from the request before calling the inner ``serve``.
- `ComptimeRoute`, `ComptimeRouter`
  — Comptime-compiled route table: segment parsing runs at compile
    time and the dispatch loop unrolls per route. Same 404 / 405
    contract as ``Router``, parametric over a comptime
    ``List[ComptimeRoute]``.
- `StaticResponse`, `precompute_response`
  — Pre-encoded literal HTTP responses. Pair with
    ``HttpServer.serve_static(resp)`` for the fastest possible fast
    path: the reactor parses requests only far enough to find the
    terminator, then ``memcpy``s the canned bytes into the write
    queue. No ``Request``, no handler, no response serialisation.
- `get`, `post`, `put`, `delete`, `head` — Module-level one-shot helpers.
  `post` and `put` accept a `String` (JSON auto-set), `json.Value`
  (auto-serialised), or `List[UInt8]` (raw bytes).

## Example

```mojo
from flare.http import HttpClient, BasicAuth, BearerAuth, get, post

def main() raises:
    # One-shot GET
    var resp = get("https://httpbin.org/get")
    print(resp.status) # 200

    # One-shot POST — String body sets Content-Type: application/json automatically
    post("https://httpbin.org/post", '{"k": 1}').raise_for_status()

    # Session with base URL + auth — no repeated URL prefix
    with HttpClient("https://httpbin.org", BasicAuth("alice", "s3cr3t")) as c:
        var r = c.get("/basic-auth/alice/s3cr3t")
        r.raise_for_status()
        print(r.text())

    # Parse JSON response body (returns json.Value)
    var data = HttpClient().get("https://httpbin.org/json").json()
    print(data["slideshow"]["title"].string_value())
```
"""

from .cancel import Cancel, CancelCell, CancelReason
from .headers import HeaderMap, HeaderInjectionError
from .header_view import HeaderMapView, parse_header_view
from .request_view import RequestView, parse_request_view
from .body import Body, ChunkSource, InlineBody, ChunkedBody, drain_body
from .streaming_response import StreamingResponse
from .streaming_serialize import serialize_streaming_response
from .url import Url, UrlParseError
from .request import Request, Method
from .response import Response, Status
from .handler import (
    Handler,
    CancelHandler,
    WithCancel,
    ViewHandler,
    WithViewCancel,
    FnHandler,
    FnHandlerCT,
)
from .router import Router
from .routes import ComptimeRoute, ComptimeRouter
from .app import App, State
from .extract import (
    ParamParser,
    ParamInt,
    ParamFloat64,
    ParamBool,
    ParamString,
    Extractor,
    Path,
    Query,
    OptionalQuery,
    Header,
    OptionalHeader,
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
from .encoding import (
    Encoding,
    compress_gzip,
    compress_brotli,
    decompress_gzip,
    decompress_deflate,
    decompress_brotli,
    decode_content,
)
from .error import HttpError, TooManyRedirects
from .auth import Auth, BasicAuth, BearerAuth
from .client import HttpClient, get, post, put, patch, delete, head
from .server import (
    HttpServer,
    ServerConfig,
    ShutdownReport,
    ok,
    ok_json,
    bad_request,
    not_found,
    internal_error,
    redirect,
)
from .static_response import StaticResponse, precompute_response
from .cookie import (
    Cookie,
    CookieJar,
    SameSite,
    parse_cookie_header,
    parse_set_cookie_header,
)
from .form import (
    FormData,
    parse_form_urlencoded,
    urldecode,
    urlencode,
)
from .multipart import (
    MultipartPart,
    MultipartForm,
    parse_multipart_form_data,
)
from .session import (
    CookieSessionStore,
    InMemorySessionStore,
    Session,
    SessionCodec,
    StringSessionCodec,
    signed_cookie_decode,
    signed_cookie_decode_keys,
    signed_cookie_encode,
)
from .middleware import (
    CatchPanic,
    Compress,
    Logger,
    RequestId,
    negotiate_encoding,
)
from .cors import Cors, CorsConfig
from .fs import ByteRange, FileServer, parse_range
