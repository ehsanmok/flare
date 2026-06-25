"""Interior-mutable client cookie jar handle.

Mirrors :class:`flare.http._client.alt_svc.AltSvcStore`: a pointer-backed
``Copyable`` handle over a heap :class:`flare.http.cookie.CookieJar` so the
read-``self`` :meth:`flare.http.client.HttpClient.send` path can capture
``Set-Cookie`` response headers and replay them as a ``Cookie`` request
header without forcing ``mut self`` onto ``get`` / ``post`` / ``send``.

The owner (an :class:`HttpClient`) allocates via :meth:`new` (opted in
through ``with_cookies``) and frees via :meth:`free` in ``__del__``. The
empty handle (:meth:`disabled`, ``_addr == 0``) is the never-allocated /
moved-from state: every method is a no-op on it, so a client that did not
opt into cookies pays nothing and behaves exactly as before.

ponytail: this jar is origin-agnostic -- every stored cookie is replayed on
every request from this client (no RFC 6265 domain/path matching). That is
the correct shape for the common single-origin ``HttpClient(base_url=...)``
session; the upgrade path is per-(domain, path) scoping keyed on the
request URL when a multi-origin jar is needed.
"""

from std.memory import UnsafePointer, alloc

from ..cookie import Cookie, CookieJar, parse_set_cookie_header


@fieldwise_init
struct _CookieState(Movable):
    """Heap-allocated mutable state behind a :class:`CookieStore`."""

    var jar: CookieJar


struct CookieStore(Copyable, Movable):
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
        var p = alloc[_CookieState](1)
        p.init_pointee_move(_CookieState(CookieJar()))
        return CookieStore(Int(p))

    @always_inline
    def __init__(out self, addr: Int):
        self._addr = addr

    @always_inline
    def enabled(read self) -> Bool:
        """Return ``True`` when the jar is allocated."""
        return self._addr != 0

    def _state(read self) -> UnsafePointer[_CookieState, MutUntrackedOrigin]:
        """Re-materialise a typed pointer from :attr:`_addr` (mirrors the
        :class:`flare.http._client.alt_svc.AltSvcStore._state` pattern)."""
        return UnsafePointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=self._addr
        ).bitcast[_CookieState]()

    def record_set_cookie(read self, header_value: String) raises:
        """Parse + store one ``Set-Cookie`` header value.

        ``Max-Age=0`` (RFC 6265 sec 5.2.2 delete directive) evicts the
        named cookie instead of storing it. No-op on the empty handle or
        an unparseable (empty-name) header."""
        if not self.enabled():
            return
        var c = parse_set_cookie_header(header_value)
        if c.name.byte_length() == 0:
            return
        if c.max_age == 0:
            _ = self._state()[].jar.remove(c.name)
            return
        self._state()[].jar.set(c^)

    def request_header(read self) raises -> String:
        """The ``Cookie`` request header value for all stored cookies,
        or ``""`` if none are stored / the handle is empty."""
        if not self.enabled():
            return String("")
        return self._state()[].jar.to_request_header()

    def count(read self) raises -> Int:
        """Number of stored cookies (``0`` on the empty handle)."""
        if not self.enabled():
            return 0
        return self._state()[].jar.len()

    def free(mut self) raises -> None:
        """Destroy + free the heap state. Idempotent on ``_addr == 0``."""
        if self._addr == 0:
            return
        var sp = self._state()
        sp.destroy_pointee()
        sp.free()
        self._addr = 0
