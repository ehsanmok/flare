"""Interior-mutable client cookie jar handle.

Mirrors :class:`flare.http._client.alt_svc.AltSvcStore`: a pointer-backed
``Copyable`` handle over a heap :class:`flare.http.cookie.CookieJar` so the
read-``self`` :meth:`flare.http.client.HttpClient.send` path can capture
``Set-Cookie`` response headers and replay them as a ``Cookie`` request
header without forcing ``mut self`` onto ``get`` / ``post`` / ``send``.

The owner (an :class:`HttpClient`) allocates via :meth:`new` (opted in
through ``with_cookies``) and frees via :meth:`free` in ``__deinit__``. The
empty handle (:meth:`disabled`, ``_addr == 0``) is the never-allocated /
moved-from state: every method is a no-op on it, so a client that did not
opt into cookies pays nothing and behaves exactly as before.

Cookies are scoped as RFC 6265 sec 5 describes: each is stored with the
domain it may be sent to (host-only unless a ``Domain`` attribute names
the setting host or a parent of it), a path, and its ``Secure`` flag, and
:meth:`CookieStore.request_header` returns only the cookies that match
the request URL. The jar used to be origin-agnostic and replayed every
cookie on every request, which a redirect to another origin turned into
a session leak -- and let that origin plant cookies for this one.
"""

from std.memory import Pointer
from std.memory.alloc import unsafe_alloc

from ..cookie import Cookie, CookieJar, parse_set_cookie_header
from ..url import Url


@fieldwise_init
struct _StoredCookie(Copyable):
    var name: String
    var value: String
    var domain: String
    """Lowercase, no leading dot."""
    var host_only: Bool
    var path: String
    var secure: Bool


@fieldwise_init
struct _CookieState(Movable):
    """Heap-allocated mutable state behind a :class:`CookieStore`."""

    var cookies: List[_StoredCookie]


def _domain_match(host: String, domain: String) -> Bool:
    """RFC 6265 sec 5.1.3: ``host`` is ``domain`` or a subdomain of it."""
    if host == domain:
        return True
    return host.endswith("." + domain)


def _default_path(path: String) -> String:
    """RFC 6265 sec 5.1.4 default-path: the request path up to, not
    including, its last ``/``; ``/`` when that is empty."""
    if path.byte_length() == 0 or not path.startswith("/"):
        return "/"
    var last = path.rfind("/")
    if last <= 0:
        return "/"
    return String(String(unsafe_from_utf8=path.as_bytes()[:last]))


def _path_match(request_path: String, cookie_path: String) -> Bool:
    """RFC 6265 sec 5.1.4 path-match."""
    var rp = request_path if request_path.byte_length() > 0 else "/"
    if rp == cookie_path:
        return True
    if not rp.startswith(cookie_path):
        return False
    if cookie_path.endswith("/"):
        return True
    return rp.as_bytes()[cookie_path.byte_length()] == 47  # '/'


struct CookieStore(Copyable):
    """Pointer-backed, interior-mutable client cookie jar handle."""

    var _addr: Int
    """Heap address of the :class:`_CookieState`. ``0`` == empty/no-op."""

    @staticmethod
    def disabled() -> CookieStore:
        """The no-op handle (``_addr == 0``)."""
        return CookieStore(0)

    @staticmethod
    def new() -> CookieStore:
        """Allocate a fresh, empty jar."""
        var p = unsafe_alloc[_CookieState](1)
        p.unsafe_write(_CookieState(List[_StoredCookie]()))
        return CookieStore(Int(p))

    @always_inline
    def __init__(out self, addr: Int):
        self._addr = addr

    @always_inline
    def enabled(imm self) -> Bool:
        """Return ``True`` when the jar is allocated."""
        return self._addr != 0

    def _state(imm self) -> Pointer[_CookieState, MutUntrackedOrigin]:
        """Re-materialise a typed pointer from :attr:`_addr` (mirrors the
        :class:`flare.http._client.alt_svc.AltSvcStore._state` pattern)."""
        return Pointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=self._addr
        ).unsafe_bitcast[_CookieState]()

    def record_set_cookie(
        imm self, header_value: String, request_url: String
    ) raises:
        """Parse + store one ``Set-Cookie`` header value received in
        response to ``request_url``.

        Refused: a ``Domain`` that does not domain-match the request
        host (a site setting cookies for another), and a ``Secure``
        cookie over cleartext. ``Max-Age=0`` (RFC 6265 sec 5.2.2 delete
        directive) evicts the matching cookie instead of storing it.
        No-op on the empty handle or an unparseable header."""
        if not self.enabled():
            return
        var c = parse_set_cookie_header(header_value)
        if c.name.byte_length() == 0:
            return
        var u = Url.parse(request_url)
        var host = u.host.lower()
        var domain = c.domain.lower()
        if domain.startswith("."):
            domain = String(String(unsafe_from_utf8=domain.as_bytes()[1:]))
        var host_only = domain.byte_length() == 0
        if host_only:
            domain = host
        elif not _domain_match(host, domain):
            return
        if c.secure and not u.is_tls():
            return
        var path = c.path
        if path.byte_length() == 0 or not path.startswith("/"):
            path = _default_path(u.path)
        ref cookies = self._state()[].cookies
        for i in range(len(cookies)):
            if (
                cookies[i].name == c.name
                and cookies[i].domain == domain
                and cookies[i].path == path
            ):
                _ = cookies.pop(i)
                break
        if c.max_age == 0:
            return
        cookies.append(
            _StoredCookie(c.name, c.value, domain, host_only, path, c.secure)
        )

    def request_header(imm self, request_url: String) raises -> String:
        """The ``Cookie`` request header value for ``request_url``: every
        stored cookie whose domain, path and ``Secure`` flag match it,
        or ``""`` if none do / the handle is empty."""
        if not self.enabled():
            return String("")
        var u = Url.parse(request_url)
        var host = u.host.lower()
        var out = String("")
        ref cookies = self._state()[].cookies
        for i in range(len(cookies)):
            ref c = cookies[i]
            if c.host_only:
                if host != c.domain:
                    continue
            elif not _domain_match(host, c.domain):
                continue
            if not _path_match(u.path, c.path):
                continue
            if c.secure and not u.is_tls():
                continue
            if out.byte_length() > 0:
                out += "; "
            out += c.name + "=" + c.value
        return out^

    def count(imm self) raises -> Int:
        """Number of stored cookies (``0`` on the empty handle)."""
        if not self.enabled():
            return 0
        return len(self._state()[].cookies)

    def free(mut self) raises -> None:
        """Destroy + free the heap state. Idempotent on ``_addr == 0``."""
        if self._addr == 0:
            return
        var sp = self._state()
        sp.unsafe_deinit_pointee()
        sp.unsafe_free()
        self._addr = 0
