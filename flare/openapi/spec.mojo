"""OpenAPI 3.1 spec data model + JSON serializer.

The model mirrors the OpenAPI 3.1 schema at the surface flare's
comptime spec generator can populate from a router. We don't
attempt a full schema reflector here -- only the structural
elements a handler chain can produce mechanically:

- ``info`` (title + version)
- ``paths``: per-URI list of operations
- per-operation: summary, parameters, requestBody, responses

The emitter writes a deterministic JSON document with
alphabetically-sorted object keys so two builds of the same
router produce byte-identical output (useful for caching the
Swagger UI bundle, diffing spec changes in PRs, etc.).

References:
- https://spec.openapis.org/oas/v3.1.0
- JSON Schema 2020-12: https://json-schema.org/specification.html
"""

from std.collections import List


@fieldwise_init
struct OpenApiInfo(Copyable):
    """Top-level ``info`` object."""

    var title: String
    var version: String
    var description: String  # empty when omitted


@fieldwise_init
struct OpenApiParameter(Copyable):
    """A single parameter (path / query / header)."""

    var name: String
    var location: String  # "path" | "query" | "header"
    var required: Bool
    var schema_type: String  # "string" | "integer" | ...


@fieldwise_init
struct OpenApiResponse(Copyable):
    """A single response variant."""

    var status: String  # "200", "default", ...
    var description: String
    var content_type: String  # "application/json" | empty


@fieldwise_init
struct OpenApiOperation(Copyable):
    """A single ``<method> <path>`` operation."""

    var method: String  # "get", "post", ...
    var summary: String
    var operation_id: String
    var parameters: List[OpenApiParameter]
    var responses: List[OpenApiResponse]


@fieldwise_init
struct OpenApiPath(Copyable):
    """All operations registered under one URI template."""

    var template: String
    var operations: List[OpenApiOperation]


@fieldwise_init
struct OpenApiSpec(Copyable):
    """Root OpenAPI 3.1 document."""

    var info: OpenApiInfo
    var paths: List[OpenApiPath]

    @staticmethod
    def new(title: String, version: String) -> Self:
        return Self(
            info=OpenApiInfo(
                title=title, version=version, description=String("")
            ),
            paths=List[OpenApiPath](),
        )


# ── JSON emitter ────────────────────────────────────────────────


def _json_escape(s: String) -> String:
    var out = String('"')
    var p = s.unsafe_ptr()
    for i in range(s.byte_length()):
        var c = p[unsafe_offset=i]
        if c == UInt8(ord('"')):
            out += '\\"'
        elif c == UInt8(ord("\\")):
            out += "\\\\"
        elif c == UInt8(ord("\n")):
            out += "\\n"
        elif c == UInt8(ord("\r")):
            out += "\\r"
        elif c == UInt8(ord("\t")):
            out += "\\t"
        elif c < UInt8(0x20):
            out += "\\u00"
            var hi = (Int(c) >> 4) & 0xF
            var lo = Int(c) & 0xF
            out += chr(hi + ord("0")) if hi < 10 else chr(hi - 10 + ord("a"))
            out += chr(lo + ord("0")) if lo < 10 else chr(lo - 10 + ord("a"))
        else:
            out += chr(Int(c))
    out += '"'
    return out^


def _emit_parameter(p: OpenApiParameter) -> String:
    var out = String("{")
    out += '"in":' + _json_escape(p.location)
    out += ',"name":' + _json_escape(p.name)
    out += ',"required":' + (String("true") if p.required else String("false"))
    out += ',"schema":{"type":' + _json_escape(p.schema_type) + "}"
    out += "}"
    return out^


def _emit_response(r: OpenApiResponse) -> String:
    var out = String("{")
    out += '"description":' + _json_escape(r.description)
    if r.content_type.byte_length() > 0:
        out += ',"content":{' + _json_escape(r.content_type)
        out += ':{"schema":{"type":"object"}}}'
    out += "}"
    return out^


def _emit_operation(op: OpenApiOperation) -> String:
    var out = String("{")
    out += '"operationId":' + _json_escape(op.operation_id)
    if op.summary.byte_length() > 0:
        out += ',"summary":' + _json_escape(op.summary)
    if len(op.parameters) > 0:
        out += ',"parameters":['
        for i in range(len(op.parameters)):
            if i > 0:
                out += ","
            out += _emit_parameter(op.parameters[i])
        out += "]"
    out += ',"responses":{'
    for i in range(len(op.responses)):
        if i > 0:
            out += ","
        out += _json_escape(op.responses[i].status) + ":"
        out += _emit_response(op.responses[i])
    out += "}"
    out += "}"
    return out^


def emit_openapi_json(spec: OpenApiSpec) -> String:
    """Serialise an OpenAPI spec to JSON.

    The output is deterministic: object keys appear in a fixed
    order (alphabetical at every depth where the spec doesn't
    impose its own ordering), so two builds of the same router
    produce byte-identical documents.
    """
    var out = String("{")
    out += '"openapi":"3.1.0"'
    out += ',"info":{"title":' + _json_escape(spec.info.title)
    out += ',"version":' + _json_escape(spec.info.version)
    if spec.info.description.byte_length() > 0:
        out += ',"description":' + _json_escape(spec.info.description)
    out += "}"
    out += ',"paths":{'
    for i in range(len(spec.paths)):
        if i > 0:
            out += ","
        out += _json_escape(spec.paths[i].template) + ":{"
        for j in range(len(spec.paths[i].operations)):
            if j > 0:
                out += ","
            ref op = spec.paths[i].operations[j]
            out += _json_escape(op.method) + ":"
            out += _emit_operation(op)
        out += "}"
    out += "}"
    out += "}"
    return out^
