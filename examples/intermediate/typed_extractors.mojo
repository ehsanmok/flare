"""Example: typed request extractors (OptionalPath* + JsonAs[T]).

Two v0.9 additions to the extractor surface:

- ``OptionalPath{Int,Str,Float,Bool}`` -- a path parameter that may or
  may not be captured by the route (``None`` when absent), so one
  handler can serve ``/items`` and ``/items/:id``.
- ``JsonAs[T: FromJson]`` -- deserialize the request body straight into
  a typed struct (the typed mirror of the dynamic ``Json`` extractor).
  Implement ``FromJson.parse_json`` once and the body arrives parsed.

Pure construction + a couple of in-process ``serve`` calls so the
example doubles as a smoke test under ``pixi run``.

Run:
    pixi run mojo -I . examples/intermediate/typed_extractors.mojo
"""

from json import Value

from flare.http import (
    Extracted,
    FromJson,
    Handler,
    JsonAs,
    Method,
    OptionalPathInt,
    Request,
    Response,
    ok,
)


@fieldwise_init
struct NewArticle(Copyable, Defaultable, FromJson, Movable):
    """Typed request body for ``POST /articles``."""

    var title: String
    var words: Int

    def __init__(out self):
        self.title = ""
        self.words = 0

    def parse_json(mut self, value: Value) raises:
        self.title = value["title"].string_value()
        self.words = Int(value["words"].int_value())


@fieldwise_init
struct CreateArticle(Copyable, Defaultable, Handler, Movable):
    var body: JsonAs[NewArticle]

    def __init__(out self):
        self.body = JsonAs[NewArticle]()

    def serve(self, req: Request) raises -> Response:
        return ok(
            "created '"
            + self.body.value.title
            + "' ("
            + String(self.body.value.words)
            + " words)"
        )


@fieldwise_init
struct ListOrGetItem(Copyable, Defaultable, Handler, Movable):
    """Serves both ``/items`` (list) and ``/items/:id`` (single)."""

    var id: OptionalPathInt["id"]

    def __init__(out self):
        self.id = OptionalPathInt["id"]()

    def serve(self, req: Request) raises -> Response:
        if self.id.value:
            return ok("item " + String(self.id.value.value()))
        return ok("all items")


def _body(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def main() raises:
    print("=== flare: typed extractors ===")
    print()

    # JsonAs[T]: body deserialized into NewArticle.
    var create = Extracted[CreateArticle]()
    var post = Request(
        method=Method.POST,
        url="/articles",
        body=_body('{"title":"Mojo","words":1200}'),
    )
    var r1 = create.serve(post)
    print("POST /articles ->", r1.status, r1.text())

    # OptionalPathInt: the same handler with and without :id.
    var items = Extracted[ListOrGetItem]()
    var list_req = Request(method=Method.GET, url="/items")
    print("GET /items     ->", items.serve(list_req).text())

    var get_req = Request(method=Method.GET, url="/items/42")
    get_req.params_mut()["id"] = "42"
    print("GET /items/42  ->", items.serve(get_req).text())
