"""``flare.openapi`` — OpenAPI 3.1 spec data model + JSON emitter.

OpenAPI 3.1 (which aligns with JSON Schema 2020-12) describes
the request/response surface of an HTTP API in a single
machine-readable document. This package ships the data model +
emitter plus :func:`spec_from_router`, which derives a spec
(paths, methods, path parameters) by walking a runtime
:class:`flare.http.Router`. Deriving request/response body schemas
from the typed ``Extracted[H]`` handler is a comptime follow-up
(the Router erases the handler type at registration).

The data model is deliberately small: only the subset of
OpenAPI 3.1 that flare handlers can produce mechanically (paths,
operations, parameters, request bodies, responses, schema refs)
is modelled. Authentication schemes, callbacks, webhooks, and
the more exotic spec corners can land as additive surface when
real users ask for them.

Public re-exports:

- :class:`OpenApiInfo` — top-level metadata (title, version).
- :class:`OpenApiOperation` — per-method documentation.
- :class:`OpenApiSpec` — the root document.
- :func:`emit_openapi_json` — serialise a spec to JSON.
- :func:`spec_from_router` — derive a spec from a runtime Router.
"""

from .spec import (
    OpenApiInfo,
    OpenApiOperation,
    OpenApiPath,
    OpenApiParameter,
    OpenApiResponse,
    OpenApiSpec,
    emit_openapi_json,
)
from .from_router import spec_from_router
