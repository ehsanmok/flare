"""Module-level HTTP convenience functions (one-shot client).

The ``get`` / ``post`` / ``put`` / ``delete`` / ``head`` / ``patch``
shortcuts that create a temporary :class:`flare.http.client.HttpClient`
per call. Extracted from ``client.mojo`` so the module stays within the
size budget; the public ``flare`` / ``flare.http`` / ``flare.prelude``
namespaces import these directly. For multiple requests, use a shared
``HttpClient`` instead.
"""

from json import dumps, Value as JsonValue

from ..client import HttpClient
from ..response import Response


def get(url: String) raises -> Response:
    """Perform a one-shot HTTP GET request.

    Creates a temporary ``HttpClient`` for this single request. For multiple
    requests, use a shared ``HttpClient`` instance instead.

    Args:
        url: The URL to request (``http://`` or ``https://``).

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().get(url)


def post(url: String, body: String) raises -> Response:
    """Perform a one-shot HTTP POST with a JSON string body.

    Sets ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: The JSON request body as a ``String``.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.

    Example:
        ```mojo
        var resp = post("https://httpbin.org/post", '{"k": 1}')
        resp.raise_for_status()
        ```
    """
    return HttpClient().post(url, body)


def post(url: String, body: JsonValue) raises -> Response:
    """Perform a one-shot HTTP POST with a ``json.Value`` body.

    Serialises ``body`` to JSON with ``dumps`` and sets
    ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: A ``json.Value`` to serialise and send.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().post(url, body)


def post(url: String, body: List[UInt8]) raises -> Response:
    """Perform a one-shot HTTP POST with a raw byte body.

    Args:
        url: The target URL.
        body: The raw request body bytes.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().post(url, body)


def put(url: String, body: String) raises -> Response:
    """Perform a one-shot HTTP PUT with a JSON string body.

    Sets ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: The JSON request body as a ``String``.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().put(url, body)


def put(url: String, body: JsonValue) raises -> Response:
    """Perform a one-shot HTTP PUT with a ``json.Value`` body.

    Serialises ``body`` to JSON with ``dumps`` and sets
    ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: A ``json.Value`` to serialise and send.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().put(url, body)


def put(url: String, body: List[UInt8]) raises -> Response:
    """Perform a one-shot HTTP PUT with a raw byte body.

    Args:
        url: The target URL.
        body: The raw request body bytes.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().put(url, body)


def delete(url: String) raises -> Response:
    """Perform a one-shot HTTP DELETE request.

    Args:
        url: The target URL.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().delete(url)


def head(url: String) raises -> Response:
    """Perform a one-shot HTTP HEAD request.

    Args:
        url: The target URL.

    Returns:
        The server's ``Response`` (body is empty).

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().head(url)


def patch(url: String, body: String) raises -> Response:
    """Perform a one-shot HTTP PATCH with a JSON string body.

    Sets ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: The JSON request body as a ``String``.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().patch(url, body)


def patch(url: String, body: JsonValue) raises -> Response:
    """Perform a one-shot HTTP PATCH with a ``json.Value`` body.

    Serialises ``body`` to JSON with ``dumps`` and sets
    ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: A ``json.Value`` to serialise and send.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().patch(url, body)


def patch(url: String, body: List[UInt8]) raises -> Response:
    """Perform a one-shot HTTP PATCH with a raw byte body.

    Args:
        url: The target URL.
        body: The raw request body bytes.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().patch(url, body)
