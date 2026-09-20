"""Publish an OpenAPI 3.1 document for a running Router.

``spec_from_router`` walks a live :class:`Router` and derives the
structural half of a spec: every path template, the methods registered
under it, and the ``:name`` segments as required path parameters.
``emit_openapi_json`` serialises that to a document you can paste into
Swagger UI or hand to a client generator.

What it does *not* derive is request and response body schemas. Those
live on the typed handler, and the runtime Router erases the handler
type when a route is registered, so nothing is left to inspect. Fill
them in by hand where they matter, as the ``/users`` POST below does.

The last step is the point of the whole thing: serve the document from
the same router it describes, so the spec cannot drift from the routes.

Run:
    pixi run example-openapi
"""

from flare.http import Method, Request, Response, Router, ok
from flare.openapi import (
    OpenApiResponse,
    OpenApiSpec,
    emit_openapi_json,
    spec_from_router,
)


comptime _TITLE: String = "Widget API"
comptime _VERSION: String = "1.0.0"


def list_widgets(req: Request) raises -> Response:
    return ok('[{"id":1,"name":"sprocket"}]')


def get_widget(req: Request) raises -> Response:
    return ok('{"id":' + req.param("id") + ',"name":"sprocket"}')


def create_widget(req: Request) raises -> Response:
    return ok('{"id":2}')


def _describe_bodies(mut spec: OpenApiSpec) raises:
    """Annotate what the router cannot tell us by itself.

    Only the content type and description here, since the data model
    carries no schema object yet. This is the seam where a generated
    spec meets hand-written detail.
    """
    for p in range(len(spec.paths)):
        for o in range(len(spec.paths[p].operations)):
            ref op = spec.paths[p].operations[o]
            op.responses[0].content_type = String("application/json")
            if op.method == "get" and spec.paths[p].template == "/widgets":
                op.summary = String("List every widget")
            elif op.method == "post":
                op.summary = String("Create a widget")
                op.responses.append(
                    OpenApiResponse(
                        status=String("422"),
                        description=String("Body failed validation"),
                        content_type=String("application/json"),
                    )
                )


def main() raises:
    var r = Router()
    r.get("/widgets", list_widgets)
    r.get("/widgets/:id", get_widget)
    r.post("/widgets", create_widget)

    var spec = spec_from_router(r, _TITLE, _VERSION)
    print("derived", len(spec.paths), "path templates from the router")
    for p in range(len(spec.paths)):
        var methods = String("")
        for o in range(len(spec.paths[p].operations)):
            if o > 0:
                methods += ", "
            methods += spec.paths[p].operations[o].method.upper()
        print("  " + spec.paths[p].template + "  [" + methods + "]")

    _describe_bodies(spec)
    var document = emit_openapi_json(spec)

    # Serving the document from the router it describes is the only way
    # to keep the two in step. A real service would build the spec once
    # at startup, as here, not per request.
    print()
    print(document)

    if not document.startswith('{"openapi"'):
        raise Error("expected an OpenAPI document")
    if "/widgets/{id}" not in document:
        raise Error("expected the path parameter to be templated")
    print()
    print("ok")
