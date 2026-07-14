"""Fluent-ish per-request builder for the HTTP client.

``HttpClient.get(url)`` / ``post(url, body)`` cover the common cases but
take nothing else -- no per-request headers, query parameters, or
content-type without hand-rolling a ``Request`` and calling
``client.send(req)``. ``RequestBuilder`` is the ergonomic middle ground:
accumulate method, URL, headers, query parameters, and a typed body,
then ``build()`` a ``Request`` to hand to ``client.send``.

    var b = RequestBuilder(Method.POST, "https://api.example.com/items")
    b.header("Authorization", "Bearer " + token)
    b.query("page", "2")
    b.json('{"name":"widget"}')
    var resp = client.send(b^.build())

Query values are percent-encoded (``flare.http.form.urlencode``) and
appended to the URL, so callers pass raw values. The builder is
move-only (it owns a ``HeaderMap`` + body buffer); ``build`` consumes it.
"""

from .form import urlencode
from .headers import HeaderMap
from .request import Request, Method


struct RequestBuilder(Movable):
    """Accumulates a request; ``build()`` produces the ``Request``."""

    var _method: String
    var _url: String
    var _headers: HeaderMap
    var _query: String
    var _body: List[UInt8]
    var _content_type: String

    def __init__(out self, method: String, url: String):
        """Start a builder for ``method`` ``url``."""
        self._method = method
        self._url = url
        self._headers = HeaderMap()
        self._query = String("")
        self._body = List[UInt8]()
        self._content_type = String("")

    def header(mut self, name: String, value: String) raises:
        """Add a request header (repeatable; appends, does not replace)."""
        self._headers.append(name, value)

    def query(mut self, name: String, value: String):
        """Add a query parameter; ``name`` and ``value`` are
        percent-encoded and joined with ``&``."""
        if self._query.byte_length() > 0:
            self._query += "&"
        self._query += urlencode(name) + "=" + urlencode(value)

    def body(mut self, var data: List[UInt8], content_type: String = ""):
        """Set a raw byte body (optionally with a content type)."""
        self._body = data^
        if content_type != "":
            self._content_type = content_type

    def text(mut self, data: String, content_type: String = "text/plain"):
        """Set a UTF-8 text body (default ``text/plain``)."""
        self._body = List[UInt8](data.as_bytes())
        self._content_type = content_type

    def json(mut self, data: String):
        """Set a JSON string body + ``Content-Type: application/json``."""
        self._body = List[UInt8](data.as_bytes())
        self._content_type = "application/json"

    def build(var self) raises -> Request:
        """Materialise the ``Request`` (consumes the builder).

        Query parameters are appended to the URL (``?`` or ``&`` as
        appropriate); accumulated headers are copied; ``Content-Type``
        is set from the typed-body helpers when present.
        """
        var url = self._url
        if self._query.byte_length() > 0:
            if url.find("?") != -1:
                url += "&" + self._query
            else:
                url += "?" + self._query
        var req = Request(method=self._method, url=url, body=self._body^)
        for i in range(self._headers.len()):
            req.headers.append(self._headers._keys[i], self._headers._values[i])
        if self._content_type.byte_length() > 0:
            req.headers.set("Content-Type", self._content_type)
        return req^
