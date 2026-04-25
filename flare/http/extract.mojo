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
from ..net import IpAddr, SocketAddr


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


# ── Concrete primitive extractors (v0.5.0 Step 2 / Track 1.3) ──────────────
#
# The parametric ``Path[T: ParamParser, name]`` / ``Query[...]`` /
# ``Header[...]`` / ``OptionalQuery[...]`` / ``OptionalHeader[...]``
# extractors wrap the parsed value in a ``ParamParser`` (``ParamInt``,
# ``ParamString``, ...) which itself wraps a primitive. The result
# is the v0.4.x ``.value.value`` chain that every example apologised
# for.
#
# These concrete types collapse the chain by exposing ``.value`` as
# the primitive directly. Internally they call the same ``Param*``
# parsers, so the parsing logic is shared and there's no behaviour
# drift.
#
# Naming convention: ``<extractor><type>``. ``Path`` × {Int, Str,
# Float, Bool}, ``Query`` × the same, ``Header`` × the same, plus
# the ``OptionalQuery`` and ``OptionalHeader`` variants for fields
# whose absence is not an error.
#
# Use these in handler structs registered through ``Extracted[H]``
# or as value-constructors inside plain handlers. The parametric
# ``Path[T, name]`` etc. stay public for users who want to plug in
# a custom ``ParamParser``.


# ── Path concretes ──────────────────────────────────────────────────────────


@fieldwise_init
struct PathInt[name: StaticString](Copyable, Defaultable, Extractor, Movable):
    """Required path parameter named ``name``, parsed as ``Int``.

    Equivalent to ``Path[ParamInt, name]`` but with ``.value`` of
    type ``Int`` directly (no ``.value.value`` chain).
    """

    var value: Int

    def __init__(out self):
        self.value = 0

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            raise Error("missing path parameter: " + String(Self.name))
        self.value = ParamInt.parse(req.param(String(Self.name))).value

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
        self.value = ParamFloat64.parse(req.param(String(Self.name))).value

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
        self.value = ParamBool.parse(req.param(String(Self.name))).value

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
        self.value = ParamInt.parse(req.query_param(String(Self.name))).value

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
        self.value = ParamFloat64.parse(
            req.query_param(String(Self.name))
        ).value

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
        self.value = ParamBool.parse(req.query_param(String(Self.name))).value

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
            ParamInt.parse(req.query_param(String(Self.name))).value
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
            ParamFloat64.parse(req.query_param(String(Self.name))).value
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
            ParamBool.parse(req.query_param(String(Self.name))).value
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
        self.value = ParamInt.parse(req.headers.get(String(Self.name))).value

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
        self.value = ParamFloat64.parse(
            req.headers.get(String(Self.name))
        ).value

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
        self.value = ParamBool.parse(req.headers.get(String(Self.name))).value

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
            ParamInt.parse(req.headers.get(String(Self.name))).value
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
            ParamFloat64.parse(req.headers.get(String(Self.name))).value
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
            ParamBool.parse(req.headers.get(String(Self.name))).value
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
        var expose = req.expose_errors
        comptime for idx in range(n):
            try:
                ref field = trait_downcast[Extractor](
                    __struct_field_ref(idx, h)
                )
                field.apply(req)
            except e:
                return _bad_request_from_error(e, expose)
        return h.serve(req)


@always_inline
def _bad_request_from_error(e: Error, expose: Bool = False) -> Response:
    """Build a 400 Bad Request response from a raised extractor ``Error``.

    Default (production) behaviour, since v0.5.0 Step 1: the response
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
        e:      The error raised by an extractor.
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
