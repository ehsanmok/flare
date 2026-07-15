"""Derive an :class:`OpenApiSpec` from a runtime :class:`Router`.

Walks the router's registered route table -- method + path template +
path-parameter names -- and builds a spec whose ``paths`` group by
template with one operation per method. Path parameters (``:name``
segments) surface as required ``path`` parameters; every operation gets a
default ``200`` response.

ponytail: this derives the *structural* surface the runtime Router
retains (methods, path templates, path params). Request/response body
schemas and query/header parameters live on the typed ``Extracted[H]``
handler, which the Router erases at registration -- deriving those needs
a comptime walk of ``reflect[H]`` at the registration site (the
ComptimeRouter path), not runtime introspection. Mounted sub-routers are
not walked yet (top-level routes only).
"""

from flare.http.router import Router

from .spec import (
    OpenApiOperation,
    OpenApiParameter,
    OpenApiPath,
    OpenApiResponse,
    OpenApiSpec,
)


def _sanitize_op_id(method: String, template: String) -> String:
    """Build a stable operationId from method + template (non-alnum ->
    ``_``)."""
    var out = method
    var p = template.unsafe_ptr()
    for i in range(template.byte_length()):
        var c = Int(p[i])
        var alnum = (
            (c >= 48 and c <= 57)
            or (c >= 65 and c <= 90)
            or (c >= 97 and c <= 122)
        )
        out += chr(c) if alnum else "_"
    return out^


def spec_from_router(
    r: Router, title: String, version: String
) raises -> OpenApiSpec:
    """Build an :class:`OpenApiSpec` from ``r``'s registered routes.

    Operations under the same template are merged into one
    :class:`OpenApiPath`; first-seen template order is preserved so the
    emitted JSON is deterministic.
    """
    var spec = OpenApiSpec.new(title, version)
    for i in range(r.route_count()):
        var template = r.route_openapi_template(i)
        var method = r.route_method(i).lower()

        var params = List[OpenApiParameter]()
        var pnames = r.route_path_params(i)
        for k in range(len(pnames)):
            params.append(
                OpenApiParameter(
                    name=pnames[k],
                    location=String("path"),
                    required=True,
                    schema_type=String("string"),
                )
            )
        var responses = List[OpenApiResponse]()
        responses.append(
            OpenApiResponse(
                status=String("200"),
                description=String("OK"),
                content_type=String(""),
            )
        )
        var op = OpenApiOperation(
            method=method,
            summary=String(""),
            operation_id=_sanitize_op_id(method, template),
            parameters=params^,
            responses=responses^,
        )

        var found = -1
        for p in range(len(spec.paths)):
            if spec.paths[p].template == template:
                found = p
                break
        if found >= 0:
            spec.paths[found].operations.append(op^)
        else:
            var ops = List[OpenApiOperation]()
            ops.append(op^)
            spec.paths.append(OpenApiPath(template=template, operations=ops^))
    return spec^
