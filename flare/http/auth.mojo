"""HTTP authentication helpers.

Provides an ``Auth`` trait and two concrete implementations — ``BasicAuth``
(RFC 7617) and ``BearerAuth`` (RFC 6750) — that attach an ``Authorization``
header to a request's ``HeaderMap``.

Usage with ``HttpClient``::

    from flare.http import HttpClient, BasicAuth, BearerAuth

    var client = HttpClient(auth=BasicAuth("alice", "s3cr3t"))
    var resp = client.get("https://httpbin.org/basic-auth/alice/s3cr3t")

Example:
    ```mojo
    from flare.http.auth import BasicAuth, BearerAuth
    from flare.http.headers import HeaderMap

    var h = HeaderMap()
    BasicAuth("alice", "s3cr3t").apply(h)
    print(h.get("Authorization"))  # Basic YWxpY2U6czNjcjN0
    ```
"""

from format import Writable, Writer
from .headers import HeaderMap


# ── Base64 encoder (RFC 4648) ─────────────────────────────────────────────────

comptime _B64_TABLE: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


fn _b64_encode(data: Span[UInt8]) -> String:
    """Encode ``data`` to standard RFC 4648 base64.

    Args:
        data: Input bytes.

    Returns:
        Base64-encoded string with ``=`` padding.
    """
    var n = len(data)
    var out = String(capacity=((n + 2) // 3) * 4 + 1)
    var tbl = _B64_TABLE.unsafe_ptr()
    var i = 0
    while i + 3 <= n:
        var a = Int(data[i])
        var b = Int(data[i + 1])
        var c = Int(data[i + 2])
        out += chr(Int(tbl[a >> 2]))
        out += chr(Int(tbl[((a & 3) << 4) | (b >> 4)]))
        out += chr(Int(tbl[((b & 0xF) << 2) | (c >> 6)]))
        out += chr(Int(tbl[c & 0x3F]))
        i += 3
    if n - i == 1:
        var a = Int(data[i])
        out += chr(Int(tbl[a >> 2]))
        out += chr(Int(tbl[(a & 3) << 4]))
        out += "=="
    elif n - i == 2:
        var a = Int(data[i])
        var b = Int(data[i + 1])
        out += chr(Int(tbl[a >> 2]))
        out += chr(Int(tbl[((a & 3) << 4) | (b >> 4)]))
        out += chr(Int(tbl[(b & 0xF) << 2]))
        out += "="
    return out^


# ── Auth trait ────────────────────────────────────────────────────────────────


trait Auth:
    """Authentication strategy that sets one or more request headers.

    Implementors write their credentials into ``headers`` (typically the
    ``Authorization`` header) before the request is sent.

    Example:
        ```mojo
        struct MyAuth(Auth):
            fn apply(self, mut headers: HeaderMap) raises:
                headers.set("Authorization", "MyScheme token")
        ```
    """

    fn apply(self, mut headers: HeaderMap) raises:
        """Apply authentication credentials to ``headers``.

        Implementors must set the ``Authorization`` header (and any other
        required headers) on ``headers``.

        Args:
            headers: The request ``HeaderMap`` to modify in place.

        Raises:
            HeaderInjectionError: If the generated header value contains
                CRLF characters.
        """
        ...


# ── BasicAuth ─────────────────────────────────────────────────────────────────


struct BasicAuth(Auth, Copyable, Movable):
    """HTTP Basic authentication (RFC 7617).

    Encodes ``username:password`` as base64 and sets the ``Authorization``
    header to ``Basic <encoded>``.

    Fields:
        username: The account username.
        password: The account password (transmitted in plaintext over TLS).

    Example:
        ```mojo
        var auth = BasicAuth("alice", "s3cr3t")
        var client = HttpClient(auth=auth)
        ```
    """

    var username: String
    var password: String

    fn __init__(out self, username: String, password: String):
        """Initialise ``BasicAuth`` with ``username`` and ``password``.

        Args:
            username: The account username.
            password: The account password.
        """
        self.username = username
        self.password = password

    fn __copyinit__(out self, copy: BasicAuth):
        self.username = copy.username
        self.password = copy.password

    fn __moveinit__(out self, deinit take: BasicAuth):
        self.username = take.username^
        self.password = take.password^

    fn apply(self, mut headers: HeaderMap) raises:
        """Set ``Authorization: Basic <credentials>`` on ``headers``.

        The credential string ``username:password`` is UTF-8 encoded then
        base64-encoded per RFC 7617.

        Args:
            headers: The ``HeaderMap`` to modify in place.
        """
        var credential = self.username + ":" + self.password
        var encoded = _b64_encode(credential.as_bytes())
        headers.set("Authorization", "Basic " + encoded)


# ── BearerAuth ────────────────────────────────────────────────────────────────


struct BearerAuth(Auth, Copyable, Movable):
    """HTTP Bearer token authentication (RFC 6750).

    Sets ``Authorization: Bearer <token>``.

    Fields:
        token: The bearer token string (e.g. a JWT).

    Example:
        ```mojo
        var auth = BearerAuth("eyJhbGciOi...")
        var client = HttpClient(auth=auth)
        ```
    """

    var token: String

    fn __init__(out self, token: String):
        """Initialise ``BearerAuth`` with ``token``.

        Args:
            token: The bearer token (e.g. a JWT or opaque token).
        """
        self.token = token

    fn __copyinit__(out self, copy: BearerAuth):
        self.token = copy.token

    fn __moveinit__(out self, deinit take: BearerAuth):
        self.token = take.token^

    fn apply(self, mut headers: HeaderMap) raises:
        """Set ``Authorization: Bearer <token>`` on ``headers``.

        Args:
            headers: The ``HeaderMap`` to modify in place.
        """
        headers.set("Authorization", "Bearer " + self.token)
