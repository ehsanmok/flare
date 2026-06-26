"""``flare.http._extract_typed`` -- optional-path + typed-JSON extractors.

Split out of :mod:`flare.http.extract` to keep that file within the
file-size budget. Holds the ``OptionalPath{Int,Str,Float,Bool}``
concretes (a path capture that may be absent) and the typed-JSON body
path (:trait:`FromJson` + :struct:`JsonAs`). ``flare.http.extract``
re-exports all of these so existing
``from flare.http import OptionalPathInt`` / ``JsonAs`` call sites keep
resolving.
"""

from std.collections import Optional

from json import loads, Value

from ._extract_core import (
    Extractor,
    _parse_bool_param,
    _parse_float64_param,
    _parse_int_param,
)
from .request import Request


# ── Optional path concretes ─────────────────────────────────────────────────
#
# ``OptionalPath*`` mirror ``OptionalQuery*``: ``value`` is ``None`` when the
# route did not capture ``name`` (rather than raising as the required ``Path*``
# do). A parse error on a *present* capture still propagates -> 400. These let
# a single handler serve overlapping routes (e.g. ``/items`` and
# ``/items/:id``) without a separate struct per arity.


@fieldwise_init
struct OptionalPathInt[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional path parameter as ``Optional[Int]``. ``value`` is
    ``None`` when the route did not capture ``name``."""

    var value: Optional[Int]

    def __init__(out self):
        self.value = Optional[Int]()

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            self.value = Optional[Int]()
            return
        self.value = Optional[Int](
            _parse_int_param(req.param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalPathStr[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional path parameter as ``Optional[String]``."""

    var value: Optional[String]

    def __init__(out self):
        self.value = Optional[String]()

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            self.value = Optional[String]()
            return
        self.value = Optional[String](req.param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalPathFloat[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional path parameter as ``Optional[Float64]``."""

    var value: Optional[Float64]

    def __init__(out self):
        self.value = Optional[Float64]()

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            self.value = Optional[Float64]()
            return
        self.value = Optional[Float64](
            _parse_float64_param(req.param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalPathBool[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional path parameter as ``Optional[Bool]``."""

    var value: Optional[Bool]

    def __init__(out self):
        self.value = Optional[Bool]()

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            self.value = Optional[Bool]()
            return
        self.value = Optional[Bool](
            _parse_bool_param(req.param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


# ── Typed JSON body extraction ──────────────────────────────────────────────


trait FromJson(Copyable, Defaultable, ImplicitlyDestructible, Movable):
    """A type that can populate itself from a parsed JSON ``Value``.

    Implement ``parse_json`` to read the decoded document into ``self``
    (raising on a missing / wrong-typed field). Conforming types plug
    into :struct:`JsonAs` for typed request-body extraction, the
    typed mirror of the dynamic :struct:`Json` extractor.

    Example:
        ```mojo
        from json import Value
        from flare.http import FromJson

        @fieldwise_init
        struct CreateUser(Copyable, Defaultable, FromJson, Movable):
            var name: String
            var age: Int

            def __init__(out self):
                self.name = ""
                self.age = 0

            def parse_json(mut self, value: Value) raises:
                self.name = value["name"].string_value()
                self.age = Int(value["age"].int_value())
        ```
    """

    def parse_json(mut self, value: Value) raises:
        ...


struct JsonAs[T: FromJson](Copyable, Defaultable, Extractor, Movable):
    """Extracts + deserializes the request body into a typed ``T: FromJson``.

    The typed counterpart to :struct:`Json` (which yields a dynamic
    ``json.Value``). ``apply`` raises on an empty body, invalid JSON,
    or any failure ``T.parse_json`` reports; pair with ``Extracted[H]``
    to map those to 400.

    Example:
        ```mojo
        @fieldwise_init
        struct Create(Copyable, Defaultable, Handler, Movable):
            var body: JsonAs[CreateUser]

            def __init__(out self):
                self.body = JsonAs[CreateUser]()

            def serve(self, req: Request) raises -> Response:
                return ok("hello " + self.body.value.name)
        # r.post("/users", Extracted[Create]())
        ```
    """

    var value: Self.T

    def __init__(out self):
        self.value = Self.T()

    def apply(mut self, req: Request) raises:
        if len(req.body) == 0:
            raise Error("missing JSON body")
        self.value.parse_json(loads(req.text()))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^
