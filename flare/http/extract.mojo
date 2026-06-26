"""Typed request extractors with reflective auto-injection.

Extractors turn a ``Request`` into a typed value. Each extractor is a
zero-runtime-allocation wrapper over the request: the compile-time
parameter ``name: StaticString`` names the path / query / header key,
and the concrete extractor (``PathInt`` / ``QueryStr`` / ...) decides
how the captured string is parsed into a concrete type. The
``.value`` accessor returns the primitive directly -- no
``.value.value`` chain.

## Primary surface

Value-constructor extractors usable from inside a handler body:

```mojo
from flare.http import (
    Request, Response, ok, bad_request,
    PathInt, OptionalQueryInt, HeaderStr,
)

def get_user(req: Request) raises -> Response:
    var id = PathInt["id"].extract(req).value
    var page = OptionalQueryInt["page"].extract(req).value
    var auth = HeaderStr["Authorization"].extract(req).value
    return ok("user " + String(id))
```

## Auto-injection

For the axum-style "the handler's signature IS the extractor spec",
declare the extractor set as the fields of a ``Handler`` struct and
wrap it in ``Extracted[H]``:

```mojo
from flare.http import (
    Extracted, Handler, Request, Response, ok,
    PathInt, OptionalQueryInt,
)

@fieldwise_init
struct GetUser(Copyable, Defaultable, Handler, Movable):
    var id: PathInt["id"]
    var page: OptionalQueryInt["page"]

    def __init__(out self):
        self.id = PathInt["id"]()
        self.page = OptionalQueryInt["page"]()

    def serve(self, req: Request) raises -> Response:
        return ok("user " + String(self.id.value))

# Register with any Router / HttpServer that accepts a ``Handler``:
# r.get("/users/:id", Extracted[GetUser]())
```

``Extracted[H]`` is itself a ``Handler`` and reflects on ``H``'s field
list via ``reflect[H].field_count()`` + ``trait_downcast``:
per request, it default-constructs ``H``, walks each field with a
``comptime for`` loop, calls ``field.apply(req)`` through the
``Extractor`` trait, and invokes ``h.serve(req)``. No per-arity
wrapper types, no runtime dispatch — every field's type is known at
compile time and monomorphised through.

``H`` is just a regular ``Handler``; wrapping in ``Extracted[H]`` is
what gives it the field-population step. Passing ``H()`` directly to
a ``Router`` still compiles and calls ``serve(req)`` on default-
initialised fields — technically valid, almost never what you want,
so reach for ``Extracted[H]()`` whenever the struct has extractor
fields.

## Custom-type extraction

For types beyond ``Int`` / ``Float64`` / ``Bool`` / ``String``, write
a small extractor struct directly. The contract is simple: implement
the :trait:`Extractor` trait by populating a single ``value`` field
from the request, then add it to a handler struct or call
``extract(req)`` as a value constructor. The 20 concrete shipped
extractors (``PathInt`` ... ``OptionalHeaderBool``) are the canonical
templates::

    @fieldwise_init
    struct PathUuid[name: StaticString](
        Copyable, Defaultable, Extractor, Movable
    ):
        var value: Uuid

        def __init__(out self):
            self.value = Uuid()

        def apply(mut self, req: Request) raises:
            if not req.has_param(String(Self.name)):
                raise Error("missing path parameter: " + String(Self.name))
            self.value = Uuid.parse(req.param(String(Self.name)))

Custom types belong as their own ``Extractor`` struct directly --
the framework deliberately does not expose a parametric
``Path[T: ParamParser, name]`` shape, because in practice it
adds a ``.value.value`` chain at every call site without
carrying a parser implementation that could not just live in
the ``Extractor`` itself.

## Parse-failure handling

Each extractor's ``apply`` raises an ``Error`` if the request is
missing the parameter or the captured value fails to parse. The
``Extracted[H]`` adapter catches extractor errors and returns **400
Bad Request** with the error message in the body; the handler's
``serve`` is never called on a bad extraction.
"""

# reflect[T] is auto-imported via the prelude in Mojo 1.0.0b2
# (replaces the legacy struct_field_count free function and the
# __struct_field_ref builtin; field access is reflect[T].field_ref[idx]).
from std.builtin.rebind import trait_downcast
from std.collections import Optional
from json import loads, Value, Null

from .handler import Handler
from .headers import HeaderMap
from .cookie import CookieJar
from .form import FormData, parse_form_urlencoded
from .multipart import MultipartForm, parse_multipart_form_data
from .request import Request
from .response import Response, Status
from ._extract_core import (
    Extractor,
    _parse_bool_param,
    _parse_float64_param,
    _parse_int_param,
)
from ..net import IpAddr, SocketAddr


# ── Scalar parsing helpers ──────────────────────────────────────────────────
#
# These were originally exposed via ``ParamInt`` / ``ParamFloat64`` /
# ``ParamBool`` / ``ParamString`` wrappers plus a ``ParamParser`` trait,
# but the wrappers added a ``.value.value`` chain at every concrete-
# extractor call site without carrying a custom ``ParamParser`` impl in
# practice, so the parametric layer was collapsed. The parsing logic
# lives here as private helpers; the 20 concrete extractors below call
# them directly.


# ── Concrete primitive extractors ──────────────
#
# Each concrete extractor is a thin ``value``-carrier whose ``apply``
# pulls the named field from the request (path / query / header) and
# parses the captured bytes via one of the ``_parse_*_param``
# helpers above. ``OptionalQuery*`` / ``OptionalHeader*`` variants
# expose ``Optional[T]`` and never raise on a missing field; a parse
# error on a present field still propagates.
#
# Naming convention: ``<location><type>``.
# - ``Path`` × {Int, Str, Float, Bool}
# - ``Query`` × {Int, Str, Float, Bool}
# - ``OptionalQuery`` × the same
# - ``Header`` × {Int, Str, Float, Bool}
# - ``OptionalHeader`` × the same
#
# Plus the non-scalar request-shape extractors: ``Peer``,
# ``BodyBytes``, ``BodyText``, ``Cookies``, ``Form``, ``Multipart``,
# ``Json``. These live below the scalar block and follow the same
# trait shape.


# ── Path concretes ──────────────────────────────────────────────────────────


@fieldwise_init
struct PathInt[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required path parameter named ``name``, parsed as ``Int``.

    ``apply`` raises if the route did not capture ``name`` or if the
    captured bytes don't parse as a signed integer (optional leading
    ``-`` followed by ASCII digits).
    """

    var value: Int

    def __init__(out self):
        self.value = 0

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            raise Error("missing path parameter: " + String(Self.name))
        self.value = _parse_int_param(req.param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct PathStr[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required path parameter named ``name``, exposed as ``String``."""

    var value: String

    def __init__(out self):
        self.value = ""

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            raise Error("missing path parameter: " + String(Self.name))
        self.value = req.param(String(Self.name))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct PathFloat[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required path parameter named ``name``, parsed as ``Float64``."""

    var value: Float64

    def __init__(out self):
        self.value = Float64(0.0)

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            raise Error("missing path parameter: " + String(Self.name))
        self.value = _parse_float64_param(req.param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct PathBool[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required path parameter named ``name``, parsed as ``Bool``."""

    var value: Bool

    def __init__(out self):
        self.value = False

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            raise Error("missing path parameter: " + String(Self.name))
        self.value = _parse_bool_param(req.param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


# ── Query concretes ─────────────────────────────────────────────────────────


@fieldwise_init
struct QueryInt[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required query-string parameter named ``name``, parsed as ``Int``."""

    var value: Int

    def __init__(out self):
        self.value = 0

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            raise Error("missing query parameter: " + String(Self.name))
        self.value = _parse_int_param(req.query_param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct QueryStr[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required query-string parameter named ``name``, exposed as ``String``."""

    var value: String

    def __init__(out self):
        self.value = ""

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            raise Error("missing query parameter: " + String(Self.name))
        self.value = req.query_param(String(Self.name))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct QueryFloat[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Required query parameter named ``name``, parsed as ``Float64``."""

    var value: Float64

    def __init__(out self):
        self.value = Float64(0.0)

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            raise Error("missing query parameter: " + String(Self.name))
        self.value = _parse_float64_param(req.query_param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct QueryBool[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required query parameter named ``name``, parsed as ``Bool``."""

    var value: Bool

    def __init__(out self):
        self.value = False

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            raise Error("missing query parameter: " + String(Self.name))
        self.value = _parse_bool_param(req.query_param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


# ── OptionalQuery concretes ─────────────────────────────────────────────────


@fieldwise_init
struct OptionalQueryInt[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional query parameter as ``Optional[Int]``. ``value`` is
    ``None`` when absent."""

    var value: Optional[Int]

    def __init__(out self):
        self.value = Optional[Int]()

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            self.value = Optional[Int]()
            return
        self.value = Optional[Int](
            _parse_int_param(req.query_param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalQueryStr[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional query parameter as ``Optional[String]``."""

    var value: Optional[String]

    def __init__(out self):
        self.value = Optional[String]()

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            self.value = Optional[String]()
            return
        self.value = Optional[String](req.query_param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalQueryFloat[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional query parameter as ``Optional[Float64]``."""

    var value: Optional[Float64]

    def __init__(out self):
        self.value = Optional[Float64]()

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            self.value = Optional[Float64]()
            return
        self.value = Optional[Float64](
            _parse_float64_param(req.query_param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalQueryBool[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional query parameter as ``Optional[Bool]``."""

    var value: Optional[Bool]

    def __init__(out self):
        self.value = Optional[Bool]()

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            self.value = Optional[Bool]()
            return
        self.value = Optional[Bool](
            _parse_bool_param(req.query_param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


# ── Header concretes ────────────────────────────────────────────────────────


@fieldwise_init
struct HeaderInt[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required header named ``name``, parsed as ``Int``."""

    var value: Int

    def __init__(out self):
        self.value = 0

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            raise Error("missing header: " + String(Self.name))
        self.value = _parse_int_param(req.headers.get(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct HeaderStr[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required header named ``name``, exposed as ``String``."""

    var value: String

    def __init__(out self):
        self.value = ""

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            raise Error("missing header: " + String(Self.name))
        self.value = req.headers.get(String(Self.name))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct HeaderFloat[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Required header named ``name``, parsed as ``Float64``."""

    var value: Float64

    def __init__(out self):
        self.value = Float64(0.0)

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            raise Error("missing header: " + String(Self.name))
        self.value = _parse_float64_param(req.headers.get(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct HeaderBool[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Required header named ``name``, parsed as ``Bool``."""

    var value: Bool

    def __init__(out self):
        self.value = False

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            raise Error("missing header: " + String(Self.name))
        self.value = _parse_bool_param(req.headers.get(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


# ── OptionalHeader concretes ────────────────────────────────────────────────


@fieldwise_init
struct OptionalHeaderInt[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional header as ``Optional[Int]``."""

    var value: Optional[Int]

    def __init__(out self):
        self.value = Optional[Int]()

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            self.value = Optional[Int]()
            return
        self.value = Optional[Int](
            _parse_int_param(req.headers.get(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalHeaderStr[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional header as ``Optional[String]``."""

    var value: Optional[String]

    def __init__(out self):
        self.value = Optional[String]()

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            self.value = Optional[String]()
            return
        self.value = Optional[String](req.headers.get(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalHeaderFloat[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional header as ``Optional[Float64]``."""

    var value: Optional[Float64]

    def __init__(out self):
        self.value = Optional[Float64]()

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            self.value = Optional[Float64]()
            return
        self.value = Optional[Float64](
            _parse_float64_param(req.headers.get(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalHeaderBool[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional header as ``Optional[Bool]``."""

    var value: Optional[Bool]

    def __init__(out self):
        self.value = Optional[Bool]()

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            self.value = Optional[Bool]()
            return
        self.value = Optional[Bool](
            _parse_bool_param(req.headers.get(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


# ── Peer extractor ──────────────────────────────────────────────────────────


struct Peer(Copyable, Defaultable, Extractor, Movable):
    """Kernel-reported peer ``SocketAddr`` of the connection.

    The reactor captures ``TcpStream.peer_addr()`` at accept time and
    threads it onto every ``Request`` for the connection. ``Peer.value``
    surfaces it without parsing or any optionality — it always has a
    value when the request came through ``HttpServer.serve``.

    Note that this is the *kernel's* view of the peer. flare does not
    interpret ``X-Forwarded-For``, ``Forwarded:``, or PROXY-protocol
    metadata for you. If you sit behind a reverse proxy and need the
    upstream client IP, read the relevant header explicitly.

    Example:
        ```mojo
        from flare.http import Peer

        def who(req: Request) raises -> Response:
            var p = Peer.extract(req).value
            return ok(String(p.ip))
        ```
    """

    var value: SocketAddr

    def __init__(out self):
        self.value = SocketAddr(IpAddr("127.0.0.1", False), UInt16(0))

    def apply(mut self, req: Request) raises:
        self.value = req.peer

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


# ── Body extractors ──────────────────────────────────────────────────────────


struct BodyBytes(Copyable, Defaultable, Extractor, Movable):
    """Extracts the raw request body as ``List[UInt8]``.

    Always succeeds; the body is a byte copy so ownership is clean
    across the handler invocation.
    """

    var value: List[UInt8]

    def __init__(out self):
        self.value = List[UInt8]()

    def apply(mut self, req: Request) raises:
        self.value = req.body.copy()

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


struct BodyText(Copyable, Defaultable, Extractor, Movable):
    """Extracts the request body decoded as a UTF-8 ``String``.

    Non-ASCII bytes are preserved verbatim by ``Request.text``; callers
    who need strict UTF-8 validation should use ``BodyBytes`` and
    validate themselves.
    """

    var value: String

    def __init__(out self):
        self.value = ""

    def apply(mut self, req: Request) raises:
        self.value = req.text()

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


struct Cookies(Copyable, Defaultable, Extractor, Movable):
    """Extracts the request cookies as a ``CookieJar``.

    Equivalent to ``req.cookies()`` but registerable as a field on a
    ``Handler`` struct via ``Extracted[H]`` for axum-style typed
    handler signatures.
    """

    var value: CookieJar

    def __init__(out self):
        self.value = CookieJar()

    def apply(mut self, req: Request) raises:
        self.value = req.cookies()

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


struct Form(Copyable, Defaultable, Extractor, Movable):
    """Extracts the request body as ``application/x-www-form-urlencoded``.

    Raises if the request body is empty or contains a malformed
    percent-escape. Use with ``Extracted[H]`` to map parse errors to
    400.
    """

    var value: FormData

    def __init__(out self):
        self.value = FormData()

    def apply(mut self, req: Request) raises:
        if len(req.body) == 0:
            raise Error("missing form body")
        self.value = parse_form_urlencoded(req.text())

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


struct Multipart(Copyable, Defaultable, Extractor, Movable):
    """Extracts the request body as ``multipart/form-data`` (RFC 7578).

    Reads the boundary parameter from the request's ``Content-Type``
    header and parses the body into a ``MultipartForm``. Raises on
    missing or malformed multipart bodies.
    """

    var value: MultipartForm

    def __init__(out self):
        self.value = MultipartForm()

    def apply(mut self, req: Request) raises:
        if len(req.body) == 0:
            raise Error("missing multipart body")
        var ct = req.headers.get("content-type")
        self.value = parse_multipart_form_data(req.body, ct)

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


struct Json(Copyable, Defaultable, Extractor, Movable):
    """Extracts the request body as a parsed ``json.Value``.

    ``apply`` raises if the body is empty or not valid JSON; pair with
    ``Extracted[H]`` to have the server map the error to a 400.
    """

    var value: Value

    def __init__(out self):
        self.value = Value(Null())

    def apply(mut self, req: Request) raises:
        if len(req.body) == 0:
            raise Error("missing JSON body")
        self.value = loads(req.text())

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


# ── Extracted adapter ───────────────────────────────────────────────────────


struct Extracted[H: Copyable & Defaultable & Handler & Movable](
    Copyable, Handler, Movable
):
    """Reflective auto-injection adapter: ``H``'s fields are its extractor set.

    Per request:

    1. Default-construct ``H``.
    2. For each field index ``idx`` in ``0..reflect[H].field_count()``:
       downcast the field reference to ``Extractor`` and call
       ``apply(req)``. Each call raises on extractor failure.
    3. Call ``h.serve(req)``.

    Extractor failures are caught and mapped to **400 Bad Request** with
    the error message in the body. ``serve`` exceptions are allowed to
    propagate and the server's top-level catch maps them to 500.

    ``H`` is a regular ``Handler``; nothing about this adapter depends
    on a separate "handler struct" trait. The only extra bound is
    ``Defaultable`` (so ``Extracted`` can build ``Self.H()`` before
    populating fields) — exactly the bound the reflection step needs.

    This type is the direct analogue of axum's "the handler's parameter
    list declares the extractor chain" pattern, but implemented via
    Mojo's struct reflection so the Router doesn't need per-arity
    wrapper types and the whole pipeline monomorphises per ``H``.
    """

    def __init__(out self):
        pass

    def __init__(out self, *, copy: Self):
        pass

    def serve(self, req: Request) raises -> Response:
        var h = Self.H()
        comptime n = reflect[Self.H].field_count()
        var expose = req.expose_errors
        comptime for idx in range(n):
            try:
                ref field = trait_downcast[Extractor](
                    reflect[Self.H].field_ref[idx](h)
                )
                field.apply(req)
            except e:
                return _extractor_error_response(e, expose)
        return h.serve(req)


@always_inline
def _bad_request_from_error(e: Error, expose: Bool = False) -> Response:
    """Build a 400 Bad Request response from a raised extractor ``Error``.

    Default (production) behaviour, since : the response
    body is the **fixed reason** ``"Bad Request"`` — *not* the raised
    error message. The full message is logged to stderr with a
    ``[flare:bad-request]`` prefix so server-side debugging still
    works. This closes the criticism (§2.7): extractor errors
    constructed from request bytes (e.g.
    ``raise Error("expected integer, got '" + s + "'")``) must not
    echo user input back into a 400 body, since logs that auto-link
    and terminals that ANSI-interpret can be surprised by attacker-
    controlled bytes.

    Local-dev override: set
    ``ServerConfig(expose_error_messages=True)``. The reactor copies
    the flag onto every parsed ``Request.expose_errors``, which the
    caller passes here as ``expose=True``.

    Kept separate from ``flare.http.server.bad_request`` to avoid the
    circular import ``extract.mojo`` -> ``server.mojo`` -> handler
    code.

    Args:
        e: The error raised by an extractor.
        expose: ``True`` to echo ``String(e)`` into the response body
                (verbatim user input). ``False`` (default) to send
                ``"Bad Request"`` and log the full message.
    """
    var msg = String(e)
    # Always log the raised message (with the user-controlled bytes)
    # so production debugging works even when the response body is
    # sanitised. ``stderr`` is the conventional sink for flare
    # diagnostics; ``[flare:bad-request]`` is the grep prefix.
    print("[flare:bad-request] ", msg)

    var body_str = "Bad Request" if not expose else msg
    var body = List[UInt8](capacity=body_str.byte_length())
    for b in body_str.as_bytes():
        body.append(b)
    var resp = Response(
        status=Status.BAD_REQUEST, reason="Bad Request", body=body^
    )
    try:
        resp.headers.set("Content-Type", "text/plain; charset=utf-8")
    except:
        pass
    return resp^


def _extractor_error_response(e: Error, expose: Bool = False) -> Response:
    """Map an extractor's raised error to the right 4xx response.

    A failed ``Authorization`` parse (``flare.http.auth_extract``
    raises :class:`AuthError`, which renders as ``AuthError(...)``)
    means *not authenticated* -> ``401 Unauthorized`` with a
    ``WWW-Authenticate: Bearer`` challenge, not the catch-all 400 that
    every other extractor failure (bad path int, missing query param,
    ...) maps to.

    The concrete error type is erased through the bare-``raises``
    ``Extractor`` trait, so -- as with :func:`flare.errors.map_handler_error`
    -- we recover intent from the typed error's ``Writable`` rendering
    (the ``AuthError(`` prefix is fixed in its ``write_to``). The
    detail is sanitized by default and only echoed under ``expose``.

    ponytail: string-prefix recovery (not an ``import AuthError`` +
    typed catch) deliberately avoids the ``extract -> auth_extract ->
    extract`` import cycle; the prefix is the contract.
    """
    var msg = String(e)
    if msg.startswith("AuthError("):
        print("[flare:unauthorized] ", msg)
        var body_str = "Unauthorized" if not expose else msg
        var body = List[UInt8](capacity=body_str.byte_length())
        for b in body_str.as_bytes():
            body.append(b)
        var resp = Response(
            status=Status.UNAUTHORIZED, reason="Unauthorized", body=body^
        )
        try:
            resp.headers.set("Content-Type", "text/plain; charset=utf-8")
            resp.headers.set("WWW-Authenticate", "Bearer")
        except:
            pass
        return resp^
    return _bad_request_from_error(e, expose)
