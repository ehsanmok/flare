"""Cross-module typed-error vocabulary for flare.

flare adopts Mojo's **typed errors**
(https://docs.modular.com/mojo/manual/errors/#typed-errors) as the
default error-handling style for new code. Typed errors carry
structured fields, conform to ``Writable`` for ``print()`` /
``String(e)`` rendering, and let callers pattern-match on
condition without ``String(e).startswith(...)`` heuristics.

This module ships the **cross-module** typed errors. Module-local
errors (e.g. :class:`flare.http.template.TemplateError`,
:class:`flare.http.auth_extract.AuthError`,
:class:`flare.http.proxy_protocol.ProxyParseError`) live next to
the parser that raises them, per the Mojo doc's "Define a custom
error type" guidance.

## Convention summary

1. **Prefer ``raises ConcreteError`` over bare ``raises``.**
   Bare ``raises`` erases the error type at compile time (per
   the Mojo doc § "Avoid bare raises with typed errors") so
   callers can no longer access structured fields without
   ``String(e)`` parsing.
2. **One error type per function.** When a function naturally
   raises multiple unrelated conditions, use an
   *enumerated* error type (one struct, ``comptime`` aliases
   for each variant). When each condition needs different
   carried data, use a ``Variant[...]`` of separate structs.
   See :class:`flare.http.template.TemplateError` for the
   enumerated pattern, :class:`flare.http.proxy_protocol.ProxyParseError`
   for the structured-fields-on-one-struct pattern.
3. **Wrap at trait / framework boundaries.** The
   :class:`flare.http.handler.Handler` trait and
   :class:`flare.http.extract.Extractor` trait declare
   bare ``raises`` for backwards compatibility with the original
   surface. Impls that need typed errors internally should
   raise typed errors directly from their bare-raises body — the
   Mojo runtime preserves the typed error's identity (its
   ``Writable`` rendering) even when the function signature is
   bare-raises (see Mojo doc § "Avoid bare raises with typed
   errors" / "type erasure only affects *uncaught* errors").
4. **Don't mix error types in one ``try`` block.** Mojo rejects
   a ``try`` whose body calls functions raising different
   typed-error types. Use sequential / nested ``try`` blocks
   instead.

## What's in this module

- :class:`ValidationError` — invalid input / argument validation
  failures. Carries ``field`` + ``reason`` so callers can
  distinguish per-field failures. ``HttpServer`` maps an uncaught
  ``ValidationError`` to a sanitized ``400 Bad Request`` (see
  :func:`map_handler_error`).
- :class:`HttpStatusError` — a handler-authored error that names the
  exact status to return (mapped through the bare-``raises``
  ``Handler.serve`` boundary by :func:`map_handler_error`).
- :class:`IoError` — I/O-layer failure not covered by the more
  specific :class:`flare.net.NetworkError` subtypes (e.g. a
  generic syscall that returned ``-1`` with a not-otherwise-
  classified errno). Carries ``op`` + ``code`` (errno) +
  ``detail``.

Both types are ``Copyable``, ``Movable``, ``Writable``, and
shaped per the Mojo typed-errors guidance.
"""

from std.collections import Optional
from std.format import Writable, Writer


comptime HTTP_STATUS_ERROR_PREFIX: String = "HttpStatusError("
"""Shared prefix for the :struct:`HttpStatusError` wire format, used by
both the renderer (:meth:`HttpStatusError.write_to`) and the parser
(:func:`parse_status_error`) so the codec cannot drift."""


# ── ValidationError ────────────────────────────────────────────────────────


@fieldwise_init
struct ValidationError(Copyable, Movable, Writable):
    """Generic input / argument-validation failure.

    Use when a function rejects an argument value that fails a
    precondition (e.g. ``chunk_size <= 0``, ``port out of range``,
    ``CSRF token wrong shape``). The ``field`` names *what*
    failed; ``reason`` says *why*.

    Maps cleanly to a 400 Bad Request response when surfaced
    through an HTTP handler — flare's
    :class:`flare.http.HttpServer` catches uncaught errors and
    sanitises them to a 400 / 500; with this typed error the
    handler can map ``field`` to the request field-name in the
    error body.

    Example:
        ```mojo
        from flare.errors import ValidationError

        def validate_chunk_size(n: Int) raises ValidationError:
            if n <= 0:
                raise ValidationError(
                    field=String("chunk_size"),
                    reason=String("must be > 0, got ") + String(n),
                )
        ```
    """

    var field: String
    var reason: String

    def write_to[W: Writer](self, mut writer: W):
        """Write ``ValidationError(field): reason`` to ``writer``."""
        writer.write("ValidationError(", self.field, "): ", self.reason)


# ── HttpStatusError ─────────────────────────────────────────────────────────


def http_reason_phrase(status: Int) -> String:
    """Canonical RFC 9110 reason phrase for the common status codes.

    Falls back to a generic class phrase ("Client Error" / "Server
    Error") for codes without a dedicated entry so the body is never
    empty.
    """
    if status == 400:
        return "Bad Request"
    if status == 401:
        return "Unauthorized"
    if status == 403:
        return "Forbidden"
    if status == 404:
        return "Not Found"
    if status == 405:
        return "Method Not Allowed"
    if status == 406:
        return "Not Acceptable"
    if status == 409:
        return "Conflict"
    if status == 410:
        return "Gone"
    if status == 412:
        return "Precondition Failed"
    if status == 413:
        return "Payload Too Large"
    if status == 415:
        return "Unsupported Media Type"
    if status == 422:
        return "Unprocessable Entity"
    if status == 429:
        return "Too Many Requests"
    if status == 500:
        return "Internal Server Error"
    if status == 501:
        return "Not Implemented"
    if status == 502:
        return "Bad Gateway"
    if status == 503:
        return "Service Unavailable"
    if status == 504:
        return "Gateway Timeout"
    if status >= 500:
        return "Server Error"
    return "Client Error"


@fieldwise_init
struct HttpStatusError(Copyable, Movable, Writable):
    """An error that names the exact HTTP status a handler wants returned.

    Raise this from a handler (or anything it calls) to short-circuit
    to a specific status instead of the catch-all 500. ``HttpServer``
    recognizes it -- even across the bare-``raises`` ``Handler.serve``
    boundary -- by its ``Writable`` rendering and maps it to
    ``status`` with ``message`` as the response body.

    Because the message is *deliberately authored by the handler*
    (unlike a parser error built from request bytes) it is echoed to
    the client regardless of ``ServerConfig.expose_error_messages`` --
    it is the escape hatch for intentional, client-facing errors.

    Example:
        ```mojo
        from flare.errors import HttpStatusError

        def get_user(req: Request) raises -> Response:
            var u = lookup(req.param("id"))
            if not u:
                raise HttpStatusError(status=404, message="user not found")
            return ok(u.value().name)
        ```
    """

    var status: Int
    var message: String

    def __init__(out self, status: Int):
        """Construct with the canonical reason phrase for ``status``."""
        self.status = status
        self.message = http_reason_phrase(status)

    def write_to[W: Writer](self, mut writer: W):
        """Render the defined status-error wire format
        ``HttpStatusError(<status>): <message>``.

        Mojo's ``raises`` erases the concrete error type at the catch
        site and offers no typed downcast (and no thread-local
        side-channel to plumb one), so the rendered string is the only
        transport across the ``Handler.serve`` boundary. This format is
        therefore a *defined codec*, not an incidental rendering: it is
        produced only here and parsed only by
        :func:`parse_status_error`, which the round-trip test pins.
        """
        writer.write(HTTP_STATUS_ERROR_PREFIX, self.status, "): ", self.message)


@fieldwise_init
struct MappedHandlerError(Copyable, Movable):
    """The (status, reason) an uncaught handler error maps to.

    Returned by :func:`map_handler_error`; the reactor feeds it to its
    error-response builder.
    """

    var status: Int
    var reason: String


def parse_status_error(error_str: String) -> Optional[MappedHandlerError]:
    """Decode the :struct:`HttpStatusError` wire format.

    The single authoritative parser for the format
    :meth:`HttpStatusError.write_to` produces -- ``None`` when
    ``error_str`` is not a well-formed status-error rendering (wrong
    prefix, non-numeric or out-of-range status). Kept as its own
    function so producer + consumer are one defined codec pair (pinned
    by the round-trip test) rather than a sniff duplicated at call
    sites.
    """
    if not error_str.startswith(HTTP_STATUS_ERROR_PREFIX):
        return Optional[MappedHandlerError]()
    var lp = HTTP_STATUS_ERROR_PREFIX.byte_length() - 1  # index of the '('
    var rp = error_str.find(")", lp)
    if rp <= lp + 1:
        return Optional[MappedHandlerError]()
    try:
        var status = Int(String(error_str[byte = lp + 1 : rp]))
        if status < 100 or status > 599:
            return Optional[MappedHandlerError]()
        var marker = error_str.find("): ", lp)
        var message = http_reason_phrase(status)
        if marker != -1:
            message = String(error_str[byte = marker + 3 :])
        return Optional[MappedHandlerError](MappedHandlerError(status, message))
    except:
        return Optional[MappedHandlerError]()


def map_handler_error(error_str: String, expose: Bool) -> MappedHandlerError:
    """Map an uncaught handler error's rendered string to (status, reason).

    Mojo's ``Handler.serve`` is bare ``raises``, which erases the
    concrete error type at the catch site (no typed downcast). The
    typed error's ``Writable`` rendering is the transport; we recover
    intent from it:

    - ``HttpStatusError(<n>): <msg>`` -> ``(n, msg)`` via the defined
      :func:`parse_status_error` codec (message always echoed -- the
      handler authored it on purpose).
    - ``ValidationError(...)`` -> ``(400, "Bad Request")`` (or the raw
      string when ``expose``).
    - anything else -> ``(500, "Internal Server Error")`` (or the raw
      string when ``expose``).
    """
    var mapped = parse_status_error(error_str)
    if mapped:
        return mapped.value().copy()
    if error_str.startswith("ValidationError("):
        if expose:
            return MappedHandlerError(400, error_str)
        return MappedHandlerError(400, "Bad Request")
    if expose:
        return MappedHandlerError(500, error_str)
    return MappedHandlerError(500, "Internal Server Error")


# ── IoError ─────────────────────────────────────────────────────────────────


@fieldwise_init
struct IoError(Copyable, Movable, Writable):
    """Generic I/O failure not covered by the more specific
    :class:`flare.net.NetworkError` family.

    Use for local-filesystem syscalls, allocator failures, and
    any other I/O-layer error that doesn't have a dedicated
    typed family yet. For network-specific errors, prefer
    :class:`flare.net.NetworkError` and friends.

    Carries:

    - ``op`` — the operation being performed at the time of
      failure (``"open"``, ``"read"``, ``"alloc"``, ``"unlink"``,
      ...). Matches the strings in libc's syscall manpages so
      the message is greppable.
    - ``code`` — the OS errno value, or 0 if not applicable.
    - ``detail`` — human-readable context (the path, the
      requested size, the FFI return code, ...).

    Example:
        ```mojo
        from flare.errors import IoError

        def read_file(path: String) raises IoError -> List[UInt8]:
            ...
            raise IoError(
                op=String("open"),
                code=2,  # ENOENT
                detail=path,
            )
        ```
    """

    var op: String
    var code: Int
    var detail: String

    def write_to[W: Writer](self, mut writer: W):
        """Write ``IoError(op): detail (errno=N)`` to ``writer``."""
        writer.write("IoError(", self.op, "): ", self.detail)
        if self.code != 0:
            writer.write(" (errno=", self.code, ")")
