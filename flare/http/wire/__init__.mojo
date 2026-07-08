"""``flare.http.wire`` -- neutral wire-shape types shared by every HTTP wire.

The canonical handler-facing types -- ``Request``, ``Response``,
``HeaderMap``, ``Method``, ``Status`` -- are constructed by every
HTTP wire (HTTP/1.1, HTTP/2, HTTP/3) and emitted by every handler.
They are deliberately wire-agnostic: the same ``Request`` struct
is built from an H1 message parser, an H2 ``HEADERS`` frame plus
``DATA`` frames, or an H3 request-stream reader, and the same
``Response`` is serialized back through any of those wires.

Before this package existed, h1 and h2 both reached into each
other for these types: ``flare.http2.server`` imported
``Request`` / ``Response`` / ``HeaderMap`` / ``Method`` from
``flare.http``, while ``flare.http._h2_conn_handle`` (the
reactor bridge) imported ``Http2Connection`` / ``Http2Config`` from
``flare.http2.server``. The cycle made layering hard to reason
about and hard to lint.

``flare.http.wire`` factors the shared shapes into a leaf module
below both ``flare.http`` (h1) and ``flare.http2``. The actual
struct definitions stay in their canonical files
(``flare/http/{request,response,headers}.mojo``) so callers that
already import ``from flare.http import Request`` keep working;
this package is the import path the HTTP/2 server and the future
HTTP/3 server use to reach those leaf types without pulling the
parent ``flare.http`` namespace.

Layering contract enforced by ``pixi run check-no-http-http2-cycle``:

- ``flare/http/**`` MAY NOT import ``from flare.http2`` except in
  the explicitly allowlisted reactor-bridge module
  (``flare/http/_h2_conn_handle.mojo``) and helpers that need the
  ``Http2Connection`` driver.
- ``flare/http2/**`` MAY NOT import ``from flare.http`` -- it
  imports ``from flare.http.wire`` for the shared types and
  ``from flare.http.proto`` for codec primitives instead.
- ``flare/http3/**`` follows the same rule: ``from flare.http.wire``
  for the canonical handler-facing types; no reach into
  ``flare.http``.

## Public surface

```mojo
from flare.http.wire import (
    Request,
    Response,
    HeaderMap, HeaderInjectionError,
    Method,
    Status,
)
```

- ``Request`` -- HTTP request (method, URL, headers, body, peer,
  TLS info, cancel cell). Wire-agnostic.
- ``Response`` -- HTTP response (status, headers, body). Wire-
  agnostic; serialized back into the right wire by the
  corresponding reactor.
- ``HeaderMap`` -- case-insensitive header collection with RFC
  7230 token validation on insertion.
- ``HeaderInjectionError`` -- raised on CR/LF in header name or
  value (request smuggling defense).
- ``Method`` -- HTTP method ASCII constants (RFC 9110 §9.3) plus
  the codec / interning helpers.
- ``Status`` -- HTTP status integer constants (RFC 9110 §15) plus
  reason-phrase helpers.

The package re-exports; the implementations live in
``flare/http/{request,response,headers}.mojo``. Moving the
implementations into this directory is a follow-up cleanup; the
import path is the load-bearing piece.
"""

from flare.http.request import Request, Method
from flare.http.response import Response, Status
from flare.http.headers import HeaderMap, HeaderInjectionError
