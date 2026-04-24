"""Typed request extractors with reflective auto-injection.

Extractors turn a ``Request`` into a typed value. Each extractor is a
zero-runtime-allocation wrapper over the request: the compile-time
parameter ``name: StaticString`` names the path / query / header key,
and ``T: ParamParser`` decides how the captured string is parsed into
a concrete type.

## Primary surface

Value-constructor extractors usable from inside a handler body:

```mojo
from flare.http import (
    Request, Response, ok, bad_request,
    Path, Query, OptionalQuery, Header, ParamInt, ParamString,
)

def get_user(req: Request) raises -> Response:
    var id   = Path[ParamInt,    "id"].extract(req).value.value
    var page = OptionalQuery[ParamInt, "page"].extract(req).value
    var auth = Header[ParamString, "Authorization"].extract(req).value.value
    return ok("user " + String(id))
```

## Auto-injection

For the axum-style "the handler's signature IS the extractor spec",
declare the extractor set as the fields of a ``Handler`` struct and
wrap it in ``Extracted[H]``:

```mojo
from flare.http import (
    Extracted, Handler, Request, Response, ok,
    Path, OptionalQuery, ParamInt,
)

@fieldwise_init
struct GetUser(Copyable, Defaultable, Handler, Movable):
    var id: Path[ParamInt, "id"]
    var page: OptionalQuery[ParamInt, "page"]

    def __init__(out self):
        self.id = Path[ParamInt, "id"]()
        self.page = OptionalQuery[ParamInt, "page"]()

    def serve(self, req: Request) raises -> Response:
        return ok("user " + String(self.id.value.value))

# Register with any Router / HttpServer that accepts a ``Handler``:
# r.get("/users/:id", Extracted[GetUser]())
```

``Extracted[H]`` is itself a ``Handler`` and reflects on ``H``'s field
list via ``std.reflection.struct_field_count`` + ``trait_downcast``:
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

## Parse-failure handling

Each extractor's ``apply`` raises an ``Error`` if the request is
missing the parameter or the captured value fails to parse. The
``Extracted[H]`` adapter catches extractor errors and returns **400
Bad Request** with the error message in the body; the handler's
``serve`` is never called on a bad extraction.
"""

from std.reflection import struct_field_count
from std.builtin.rebind import trait_downcast
from std.collections import Optional
from json import loads, Value, Null

from .handler import Handler
from .headers import HeaderMap
from .request import Request
from .response import Response, Status


# ── ParamParser: scalar text → typed value ──────────────────────────────────


trait ParamParser(Copyable, Defaultable, ImplicitlyDestructible, Movable):
    """Parse a URL / header string into a concrete value.

    Implementors are wrapper structs with a single ``value`` field; a
    valid default (zero, false, empty) is required so extractors can
    be default-constructed before ``apply`` runs.
    """

    @staticmethod
    def parse(s: String) raises -> Self:
        ...


@fieldwise_init
struct ParamInt(Copyable, Defaultable, Movable, ParamParser):
    """``Int`` parameter parser. Accepts optional leading ``-``."""

    var value: Int

    def __init__(out self):
        self.value = 0

    @staticmethod
    def parse(s: String) raises -> Self:
        var n = s.byte_length()
        if n == 0:
            raise Error("expected integer, got empty string")
        var p = s.unsafe_ptr()
        var i = 0
        var neg = False
        if p[0] == 45:  # '-'
            neg = True
            i = 1
        if i == n:
            raise Error("expected integer, got '" + s + "'")
        var acc = 0
        while i < n:
            var c = Int(p[i])
            if c < 48 or c > 57:
                raise Error("expected integer, got '" + s + "'")
            acc = acc * 10 + (c - 48)
            i += 1
        return Self(value=-acc) if neg else Self(value=acc)


@fieldwise_init
struct ParamFloat64(Copyable, Defaultable, Movable, ParamParser):
    """``Float64`` parameter parser. Accepts decimal and exponent forms."""

    var value: Float64

    def __init__(out self):
        self.value = Float64(0.0)

    @staticmethod
    def parse(s: String) raises -> Self:
        if s.byte_length() == 0:
            raise Error("expected float, got empty string")
        # Delegate to Mojo's built-in Float64 constructor; catches NaN,
        # Infinity, malformed exponents.
        try:
            var f = Float64(s)
            return Self(value=f)
        except:
            raise Error("expected float, got '" + s + "'")


@fieldwise_init
struct ParamBool(Copyable, Defaultable, Movable, ParamParser):
    """``Bool`` parameter parser. Accepts ``true`` / ``false`` / ``1`` /
    ``0`` / ``yes`` / ``no`` (case-insensitive).
    """

    var value: Bool

    def __init__(out self):
        self.value = False

    @staticmethod
    def parse(s: String) raises -> Self:
        var n = s.byte_length()
        if n == 0:
            raise Error("expected bool, got empty string")
        # Lower-case compare.
        var lower = String(capacity=n)
        var p = s.unsafe_ptr()
        for i in range(n):
            var c = p[i]
            if c >= 65 and c <= 90:
                c = c + 32
            lower += chr(Int(c))
        if lower == "true" or lower == "1" or lower == "yes":
            return Self(value=True)
        if lower == "false" or lower == "0" or lower == "no":
            return Self(value=False)
        raise Error("expected bool, got '" + s + "'")


@fieldwise_init
struct ParamString(Copyable, Defaultable, Movable, ParamParser):
    """``String`` parameter parser. Always succeeds on UTF-8 input."""

    var value: String

    def __init__(out self):
        self.value = ""

    @staticmethod
    def parse(s: String) raises -> Self:
        return Self(value=s)


# ── Extractor trait ─────────────────────────────────────────────────────────


trait Extractor(Copyable, Defaultable, ImplicitlyDestructible, Movable):
    """Anything that can extract itself from a ``Request`` in place.

    ``Extracted[H]`` default-constructs the handler struct ``H`` and then
    calls ``apply(req)`` on each field in declaration order. Implementors
    should replace their default value with the parsed request value
    during ``apply``; raising propagates as a 400 through ``Extracted``.
    """

    def apply(mut self, req: Request) raises:
        ...


# ── Path / Query / Header extractors ────────────────────────────────────────


@fieldwise_init
struct Path[T: ParamParser, name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Required path parameter named ``name``, parsed into ``T``.

    ``apply`` raises if the route did not capture ``name`` or if
    ``T.parse`` rejected the captured bytes.
    """

    var value: Self.T

    def __init__(out self):
        self.value = Self.T()

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            raise Error("missing path parameter: " + String(Self.name))
        self.value = Self.T.parse(req.param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        """Convenience value-constructor. Builds and applies in one step."""
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct Query[T: ParamParser, name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Required query-string parameter named ``name``, parsed into ``T``.

    ``apply`` raises if the query string does not contain ``name``.
    """

    var value: Self.T

    def __init__(out self):
        self.value = Self.T()

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            raise Error("missing query parameter: " + String(Self.name))
        self.value = Self.T.parse(req.query_param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalQuery[T: ParamParser, name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional query-string parameter. ``value`` is ``None`` when absent.

    ``apply`` never raises on a missing parameter; a parse failure on a
    present parameter still raises.
    """

    var value: Optional[Self.T]

    def __init__(out self):
        self.value = Optional[Self.T]()

    def apply(mut self, req: Request) raises:
        if not req.has_query_param(String(Self.name)):
            self.value = Optional[Self.T]()
            return
        self.value = Optional[Self.T](
            Self.T.parse(req.query_param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct Header[T: ParamParser, name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Required header named ``name``, parsed into ``T``.

    Header-name match is case-insensitive; parse runs on the raw header
    value with no additional trimming beyond what the HTTP parser already
    performed.
    """

    var value: Self.T

    def __init__(out self):
        self.value = Self.T()

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            raise Error("missing header: " + String(Self.name))
        self.value = Self.T.parse(req.headers.get(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalHeader[T: ParamParser, name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional header. ``value`` is ``None`` when absent."""

    var value: Optional[Self.T]

    def __init__(out self):
        self.value = Optional[Self.T]()

    def apply(mut self, req: Request) raises:
        if not req.headers.contains(String(Self.name)):
            self.value = Optional[Self.T]()
            return
        self.value = Optional[Self.T](
            Self.T.parse(req.headers.get(String(Self.name)))
        )

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
    2. For each field index ``idx`` in ``0..struct_field_count[H]()``:
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

    def __copyinit__(out self, existing: Self):
        pass

    def serve(self, req: Request) raises -> Response:
        var h = Self.H()
        comptime n = struct_field_count[Self.H]()
        comptime for idx in range(n):
            try:
                ref field = trait_downcast[Extractor](
                    __struct_field_ref(idx, h)
                )
                field.apply(req)
            except e:
                return _bad_request_from_error(e)
        return h.serve(req)


@always_inline
def _bad_request_from_error(e: Error) -> Response:
    """Build a 400 Bad Request response whose body is the error message.

    Kept separate from ``flare.http.server.bad_request`` to avoid the
    circular import ``extract.mojo`` → ``server.mojo`` → handler code.
    """
    var msg = String(e)
    var body = List[UInt8](capacity=msg.byte_length())
    for b in msg.as_bytes():
        body.append(b)
    var resp = Response(
        status=Status.BAD_REQUEST, reason="Bad Request", body=body^
    )
    try:
        resp.headers.set("Content-Type", "text/plain; charset=utf-8")
    except:
        pass
    return resp^
