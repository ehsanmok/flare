"""Example: typed JSON request -> typed JSON response.

The :class:`flare.http.Json[T]` input extractor parses a request
body into a typed :class:`json.Value`; the symmetric output side is
:func:`flare.http.ok_json_value`, which accepts a typed
:class:`json.Value` and emits a 200 OK response with
``Content-Type: application/json`` and the serialised body.

Closes the input/output asymmetry that the prior ``ok_json(string)``
shape exposed: callers used to stitch JSON together by hand on the
output side while the input side already had typed parsing.

Run:
    mojo -I . examples/42_ok_json_typed.mojo
"""

from json import loads, Value as JsonValue

from flare.http import (
    HttpServer,
    Request,
    Response,
    Router,
    ok,
    ok_json_value,
)
from flare.net import SocketAddr


def echo_json(req: Request) raises -> Response:
    """Echo a JSON request body as a JSON response.

    The request body is parsed via :func:`json.loads` into a typed
    :class:`json.Value`; the typed value is wrapped in a JSON object
    under ``"echo"`` and returned via :func:`ok_json_value`. No
    string concatenation, no ``Content-Type`` header munging in
    handler code.
    """
    var parsed = loads(req.text())
    return ok_json_value(parsed)


def home(req: Request) raises -> Response:
    return ok("flare ok_json_value demo: POST /echo with a JSON body")


def main() raises:
    """Demo only -- shows the wiring without actually starting the server.

    A full run would be ``HttpServer.bind(SocketAddr.localhost(8080)).serve(r^)``;
    here we keep it offline so ``pixi run tests`` doesn't hang.
    """
    var r = Router()
    r.get("/", home)
    r.post("/echo", echo_json)

    # Build a fake request to demonstrate the typed pipeline without
    # needing a live network.
    var fake = Request.test_post(
        "/echo", '{"id":42,"name":"alice"}', content_type="application/json"
    )

    var resp = echo_json(fake)
    print("status:", resp.status)
    print("Content-Type:", resp.headers.get("Content-Type"))
    print("body:", resp.text())
