"""URL parser for HTTP/HTTPS URLs.

Handles the subset of RFC 3986 URIs relevant to HTTP clients:

    scheme://[user:pass@]host[:port]/path[?query][#fragment]

Only ``http`` and ``https`` schemes are supported. Fragment is parsed
but ignored for request purposes (not sent to server per RFC 7230 §5.1).

Example:
    ```mojo
    var u = Url.parse("https://api.example.com:8443/v1/items?filter=active")
    print(u.host)   # api.example.com
    print(u.port)   # 8443
    print(u.path)   # /v1/items
    print(u.query)  # filter=active
    ```
"""

from format import Writable, Writer


struct UrlParseError(Copyable, Movable, Stringable, Writable):
    """Raised when a URL string cannot be parsed."""

    var message: String

    fn __init__(out self, message: String):
        self.message = message

    fn write_to[W: Writer](self, mut writer: W):
        writer.write("UrlParseError: ", self.message)

    fn __str__(self) -> String:
        return "UrlParseError: " + self.message


struct Url(Movable):
    """A parsed HTTP/HTTPS URL.

    Fields:
        scheme:   ``"http"`` or ``"https"``.
        host:     Hostname or IP, without brackets (IPv6 brackets stripped).
        port:     Numeric port; defaults to 80 (http) or 443 (https).
        path:     URL path including leading ``/``; ``"/"`` if absent.
        query:    Query string without leading ``?``; ``""`` if absent.
        fragment: Fragment without leading ``#``; ``""`` if absent.

    This type is ``Movable`` but not ``Copyable``.
    """

    var scheme: String
    var host: String
    var port: UInt16
    var path: String
    var query: String
    var fragment: String

    fn __init__(
        out self,
        scheme: String,
        host: String,
        port: UInt16,
        path: String,
        query: String = "",
        fragment: String = "",
    ):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
        self.query = query
        self.fragment = fragment

    fn __moveinit__(out self, deinit take: Url):
        self.scheme = take.scheme^
        self.host = take.host^
        self.port = take.port
        self.path = take.path^
        self.query = take.query^
        self.fragment = take.fragment^

    @staticmethod
    fn parse(raw: String) raises -> Url:
        """Parse a URL string into a ``Url``.

        Args:
            raw: Full URL string (``http://...`` or ``https://...``).

        Returns:
            Parsed ``Url``.

        Raises:
            UrlParseError: If the URL is missing a scheme, host, or uses an
                           unsupported scheme.
        """
        var s = raw

        # ── 1. Scheme ─────────────────────────────────────────────────────────
        var scheme_end = _find(s, "://")
        if scheme_end < 0:
            raise UrlParseError("missing scheme in URL: " + raw)
        var scheme = String(s[:scheme_end])
        if scheme != "http" and scheme != "https":
            raise UrlParseError(
                "unsupported scheme '" + scheme + "' in URL: " + raw
            )
        s = String(s[scheme_end + 3 :])  # skip "://"

        # ── 2. Strip fragment ─────────────────────────────────────────────────
        var fragment = String("")
        var frag_pos = _rfind(s, "#")
        if frag_pos >= 0:
            fragment = String(s[frag_pos + 1 :])
            s = String(s[:frag_pos])

        # ── 3. Authority and path split ────────────────────────────────────────
        var path_start = _find(s, "/")
        var authority: String
        var path_and_query: String
        if path_start < 0:
            authority = s
            path_and_query = "/"
        else:
            authority = String(s[:path_start])
            path_and_query = String(s[path_start:])

        # ── 4. Query split ────────────────────────────────────────────────────
        var query = String("")
        var q_pos = _find(path_and_query, "?")
        var path: String
        if q_pos >= 0:
            path = String(path_and_query[:q_pos])
            query = String(path_and_query[q_pos + 1 :])
        else:
            path = path_and_query

        if len(path) == 0:
            path = "/"

        # ── 5. Host and port ──────────────────────────────────────────────────
        # Strip optional userinfo (user:pass@) — we don't support auth in v0.1
        var at_pos = _find(authority, "@")
        if at_pos >= 0:
            authority = String(authority[at_pos + 1 :])

        var host: String
        var port: UInt16
        if authority.startswith("["):
            # IPv6 literal: [::1]:8080 or [::1]
            var bracket_end = _find(authority, "]")
            if bracket_end < 0:
                raise UrlParseError("unterminated IPv6 literal in: " + raw)
            host = String(authority[1:bracket_end])
            var after = String(authority[bracket_end + 1 :])
            if after.startswith(":"):
                port = UInt16(_parse_port(String(after[1:]), raw))
            else:
                port = _default_port(scheme)
        else:
            var colon = _rfind(authority, ":")
            if colon >= 0:
                host = String(authority[:colon])
                port = UInt16(_parse_port(String(authority[colon + 1 :]), raw))
            else:
                host = authority
                port = _default_port(scheme)

        if len(host) == 0:
            raise UrlParseError("missing host in URL: " + raw)

        return Url(scheme^, host^, port, path^, query^, fragment^)

    fn request_target(self) -> String:
        """Return the request-target for the HTTP request line.

        Returns:
            ``/path?query`` or ``/path`` if query is empty.
        """
        if len(self.query) == 0:
            return self.path
        return self.path + "?" + self.query

    fn is_tls(self) -> Bool:
        """Return True if the scheme is ``https``.

        Returns:
            True for ``https``, False for ``http``.
        """
        return self.scheme == "https"


@always_inline
fn _find(s: String, sub: String) -> Int:
    """Return the index of the first occurrence of ``sub`` in ``s``, or -1."""
    var n = len(s)
    var m = len(sub)
    if m == 0:
        return 0
    if m > n:
        return -1
    for i in range(n - m + 1):
        var ok = True
        for j in range(m):
            if s.unsafe_ptr()[i + j] != sub.unsafe_ptr()[j]:
                ok = False
                break
        if ok:
            return i
    return -1


@always_inline
fn _rfind(s: String, sub: String) -> Int:
    """Return the index of the last occurrence of ``sub`` in ``s``, or -1."""
    var n = len(s)
    var m = len(sub)
    if m == 0:
        return n
    if m > n:
        return -1
    for i in range(n - m, -1, -1):
        var ok = True
        for j in range(m):
            if s.unsafe_ptr()[i + j] != sub.unsafe_ptr()[j]:
                ok = False
                break
        if ok:
            return i
    return -1


@always_inline
fn _default_port(scheme: String) -> UInt16:
    """Return the default port for ``scheme``."""
    if scheme == "https":
        return 443
    return 80


fn _parse_port(s: String, raw: String) raises -> Int:
    """Parse a decimal port string.

    Args:
        s:   The port string (e.g. ``"8080"``).
        raw: The original URL for error context.

    Returns:
        Port as ``Int``.

    Raises:
        UrlParseError: If ``s`` is empty, non-numeric, or out of range.
    """
    if len(s) == 0:
        raise UrlParseError("empty port in URL: " + raw)
    var result = 0
    for i in range(len(s)):
        var c = Int(s.unsafe_ptr()[i])
        if c < 48 or c > 57:  # '0'..'9'
            raise UrlParseError("invalid port '" + s + "' in URL: " + raw)
        result = result * 10 + (c - 48)
    if result < 1 or result > 65535:
        raise UrlParseError("port out of range in URL: " + raw)
    return result
