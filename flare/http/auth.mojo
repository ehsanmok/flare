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
    print(h.get("Authorization")) # Basic YWxpY2U6czNjcjN0
    ```
"""

from std.format import Writable, Writer

from flare.crypto.base64 import base64_encode as _b64_encode

from .headers import HeaderMap


# ── BasicAuth uses RFC 4648 §4 base64 from flare.crypto.base64 ────────────────
#
# The standard-alphabet base64 implementation lives in
# :mod:`flare.crypto.base64`; the local ``_b64_encode`` alias keeps
# call-site readability while routing through the canonical
# helper. (The previous private table + chunk-of-3 loop is gone
# in favour of the single source of truth shared with the WS
# handshake helpers.)


# ── Auth trait ────────────────────────────────────────────────────────────────


trait Auth:
    """Authentication strategy that sets one or more request headers.

    Implementors write their credentials into ``headers`` (typically the
    ``Authorization`` header) before the request is sent.

    Example:
        ```mojo
        struct MyAuth(Auth):
            def apply(self, mut headers: HeaderMap) raises:
                headers.set("Authorization", "MyScheme token")
        ```
    """

    def apply(self, mut headers: HeaderMap) raises:
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

    def __init__(out self, username: String, password: String):
        """Initialise ``BasicAuth`` with ``username`` and ``password``.

        Args:
            username: The account username.
            password: The account password.
        """
        self.username = username
        self.password = password

    def apply(self, mut headers: HeaderMap) raises:
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

    def __init__(out self, token: String):
        """Initialise ``BearerAuth`` with ``token``.

        Args:
            token: The bearer token (e.g. a JWT or opaque token).
        """
        self.token = token

    def apply(self, mut headers: HeaderMap) raises:
        """Set ``Authorization: Bearer <token>`` on ``headers``.

        Args:
            headers: The ``HeaderMap`` to modify in place.
        """
        headers.set("Authorization", "Bearer " + self.token)
