"""``flare.http._client`` -- free-function helpers extracted from
``flare.http.client``.

This sub-package holds the response-side helper layers that used to
trail the ``HttpClient`` struct in ``client.mojo`` (which grew past
the reactor-size budget). Splitting them out keeps each unit inside a
reviewer's working memory and lets the size lint guard the result:

* :mod:`flare.http._client.parse` -- HTTP/1.1 response parsing: raw
  socket draining, the RFC 7230 response parser, status-line + header
  splitting, chunked / Content-Length body extraction, and the framed
  TCP / TLS readers.
* :mod:`flare.http._client.h2_send` -- the HTTP/2 + h2c request
  drivers (header build, over-TLS / over-TCP send, h2c upgrade).

``flare.http.client`` re-exports the names it and its callers rely on,
so existing ``from flare.http.client import ...`` call sites keep
resolving unchanged.
"""
