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
   bare ``raises`` for backwards compatibility with the v0.6
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
  distinguish per-field failures (and ``HttpServer`` can map
  to a 400 with the field name as the body).
- :class:`IoError` — I/O-layer failure not covered by the more
  specific :class:`flare.net.NetworkError` subtypes (e.g. a
  generic syscall that returned ``-1`` with a not-otherwise-
  classified errno). Carries ``op`` + ``code`` (errno) +
  ``detail``.

Both types are ``Copyable``, ``Movable``, ``Writable``, and
shaped per the Mojo typed-errors guidance.
"""

from std.format import Writable, Writer


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
