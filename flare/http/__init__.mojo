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

- `HttpClient`          — Send HTTP/HTTPS requests: `get`, `post`, `put`, etc.
- `HttpServer`          — Accept and dispatch HTTP requests.
- `Request`             — HTTP request (method, URL, headers, body).
- `Response`            — HTTP response (status, headers, body, `text()`, `json()`).
- `HeaderMap`           — Case-insensitive HTTP header collection.
- `HeaderInjectionError` — Raised on CR/LF characters in header names or values.
- `Url`                 — Parsed HTTP/HTTPS URL (scheme, host, port, path, query).
- `UrlParseError`       — Raised on invalid URL syntax.
- `Method`              — HTTP method string constants (`GET`, `POST`, …).
- `Status`              — HTTP status code integer constants (`OK`, `NOT_FOUND`, …).
- `Encoding`            — Content-Encoding token constants (`gzip`, `deflate`).
- `HttpError`           — Raised by `Response.raise_for_status()` on non-2xx responses.
- `TooManyRedirects`    — Raised when the redirect limit is exceeded.
- `BasicAuth`           — HTTP Basic authentication (RFC 7617).
- `BearerAuth`          — HTTP Bearer token authentication (RFC 6750).
- `ParamParser`, `ParamInt`, `ParamFloat64`, `ParamBool`, `ParamString`
  — Typed parsers for URL / header string values.
- `Extractor`           — Trait implemented by each extractor.
- `Path`, `Query`, `QueryOpt`, `Header`, `HeaderOpt`
  — Typed extractors for path params, query string, headers.
- `BodyBytes`, `BodyText`, `Json`
  — Extractors that read the request body.
- `HandlerStruct`, `Extracted`
  — Reflective auto-injection: declare extractor fields on a struct
    and wrap in ``Extracted[H]`` to get a ``Handler`` that pulls each
    field from the request before calling ``handle``.
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
    print(resp.status)                            # 200

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

from .headers import HeaderMap, HeaderInjectionError
from .url import Url, UrlParseError
from .request import Request, Method
from .response import Response, Status
from .handler import Handler, FnHandler, FnHandlerCT
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
    QueryOpt,
    Header,
    HeaderOpt,
    BodyBytes,
    BodyText,
    Json,
    HandlerStruct,
    Extracted,
)
from .encoding import (
    Encoding,
    compress_gzip,
    decompress_gzip,
    decompress_deflate,
    decode_content,
)
from .error import HttpError, TooManyRedirects
from .auth import Auth, BasicAuth, BearerAuth
from .client import HttpClient, get, post, put, patch, delete, head
from .server import (
    HttpServer,
    ServerConfig,
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
