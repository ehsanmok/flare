"""Tests for :mod:`flare.errors` — the cross-module typed-error
vocabulary.

Coverage:

1. :class:`ValidationError` constructor + field access.
2. :class:`ValidationError.write_to` rendering.
3. :class:`ValidationError` round-trips through a typed-raises
   function (``raises ValidationError``) — the caller catches the
   typed error and accesses ``field`` / ``reason`` directly per
   the Mojo doc § "Catch a typed error".
4. :class:`ValidationError` propagates through bare-``raises``
   wrappers with its ``Writable`` rendering preserved (the
   "type erasure only affects compile-time type, not runtime
   identity" rule from the Mojo doc § "Avoid bare raises with
   typed errors").
5. :class:`IoError` constructor + field access + ``write_to``
   with and without an ``errno`` value.
6. :class:`IoError` round-trips through a ``raises IoError``
   function the same way :class:`ValidationError` does.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_true,
)

from flare.errors import (
    HttpStatusError,
    IoError,
    ValidationError,
    http_reason_phrase,
    map_handler_error,
    parse_status_error,
)


# ── ValidationError ────────────────────────────────────────────────────────


def test_validation_error_construct_and_field_access() raises:
    var e = ValidationError(
        field=String("username"), reason=String("too short")
    )
    assert_equal(e.field, String("username"))
    assert_equal(e.reason, String("too short"))


def test_validation_error_write_to_renders_field_and_reason() raises:
    var e = ValidationError(
        field=String("port"), reason=String("must be 1..65535")
    )
    assert_equal(String(e), String("ValidationError(port): must be 1..65535"))


def _validate_chunk_size(n: Int) raises ValidationError -> Int:
    """Typed-raises helper used by the round-trip tests."""
    if n <= 0:
        raise ValidationError(
            field=String("chunk_size"),
            reason=String("must be > 0, got ") + String(n),
        )
    return n


def test_validation_error_typed_round_trip_preserves_fields() raises:
    """The Mojo doc says ``except e:`` infers the typed error's
    type from the function being called — so field access works
    without ``String(e)`` heuristics."""
    var got_field = String("")
    var got_reason = String("")
    try:
        var _n = _validate_chunk_size(-3)
    except e:
        got_field = e.field.copy()
        got_reason = e.reason.copy()
    assert_equal(got_field, String("chunk_size"))
    assert_true(got_reason.find("got -3") >= 0)


def _wrap_chunk_size_in_bare_raises(n: Int) raises -> Int:
    """Bare-``raises`` wrapper around a typed-raises function.

    The Mojo runtime preserves the typed error's ``Writable``
    identity through the bare-raises propagation; only the
    compile-time type at the catch site collapses to
    ``Error``."""
    return _validate_chunk_size(n)


def test_validation_error_survives_bare_raises_propagation() raises:
    """The wrapping bare-raises function erases the typed error's
    compile-time type, but ``String(e)`` at the catch site still
    produces the original typed rendering."""
    var msg = String("")
    try:
        var _n = _wrap_chunk_size_in_bare_raises(0)
    except e:
        msg = String(e)
    assert_true(msg.find("ValidationError(chunk_size)") >= 0)
    assert_true(msg.find("must be > 0") >= 0)


# ── IoError ─────────────────────────────────────────────────────────────────


def test_io_error_construct_and_field_access() raises:
    var e = IoError(op=String("open"), code=2, detail=String("/etc/secret.txt"))
    assert_equal(e.op, String("open"))
    assert_equal(e.code, 2)
    assert_equal(e.detail, String("/etc/secret.txt"))


def test_io_error_write_to_includes_errno_when_nonzero() raises:
    var e = IoError(op=String("read"), code=11, detail=String("would block"))
    assert_equal(String(e), String("IoError(read): would block (errno=11)"))


def test_io_error_write_to_omits_errno_when_zero() raises:
    """``code=0`` means "errno is not applicable here" so we
    don't render it (would otherwise look like a real errno=0
    "no such error" code, which is misleading)."""
    var e = IoError(
        op=String("alloc"), code=0, detail=String("requested 1 GiB")
    )
    assert_equal(String(e), String("IoError(alloc): requested 1 GiB"))


def _read_file(path: String) raises IoError -> Int:
    """Typed-raises helper used by the round-trip test."""
    if path.byte_length() == 0:
        raise IoError(
            op=String("open"),
            code=22,
            detail=String("empty path"),
        )
    return 0


def test_io_error_typed_round_trip_preserves_fields() raises:
    var got_op = String("")
    var got_code = -1
    try:
        var _r = _read_file(String(""))
    except e:
        got_op = e.op.copy()
        got_code = e.code
    assert_equal(got_op, String("open"))
    assert_equal(got_code, 22)


# ── HttpStatusError + map_handler_error ─────────────────────────────────────


def test_http_status_error_render() raises:
    var e = HttpStatusError(status=404, message=String("user not found"))
    assert_equal(String(e), String("HttpStatusError(404): user not found"))


def test_http_status_error_default_message() raises:
    var e = HttpStatusError(409)
    assert_equal(e.message, String("Conflict"))
    assert_equal(String(e), String("HttpStatusError(409): Conflict"))


def test_status_error_codec_round_trip() raises:
    """render -> String -> parse_status_error must reproduce the exact
    (status, message) the codec is defined to carry."""
    var e = HttpStatusError(status=418, message=String("teapot: 3): x"))
    var parsed = parse_status_error(String(e))
    assert_true(Bool(parsed))
    assert_equal(parsed.value().status, 418)
    # Message-containing-"): " must survive (delimiter is the first
    # "): " after the numeric status).
    assert_equal(parsed.value().reason, String("teapot: 3): x"))


def test_status_error_codec_rejects_non_status() raises:
    assert_true(not parse_status_error(String("kaboom")))
    assert_true(not parse_status_error(String("HttpStatusError(abc): x")))
    assert_true(not parse_status_error(String("HttpStatusError(700): x")))


def _raise_status() raises -> Int:
    """Bare-raises wrapper: erases the type but keeps the rendering."""
    raise HttpStatusError(status=403, message=String("nope"))


def test_map_http_status_error_through_bare_raises() raises:
    var rendered = String("")
    try:
        var _r = _raise_status()
    except e:
        rendered = String(e)
    var mapped = map_handler_error(rendered, expose=False)
    assert_equal(mapped.status, 403)
    # HttpStatusError message is always echoed (handler-authored).
    assert_equal(mapped.reason, String("nope"))


def test_map_validation_error_sanitized() raises:
    var rendered = String("ValidationError(email): bad <user> input")
    var mapped = map_handler_error(rendered, expose=False)
    assert_equal(mapped.status, 400)
    assert_equal(mapped.reason, String("Bad Request"))


def test_map_validation_error_exposed() raises:
    var rendered = String("ValidationError(email): why")
    var mapped = map_handler_error(rendered, expose=True)
    assert_equal(mapped.status, 400)
    assert_equal(mapped.reason, rendered)


def test_map_generic_error_defaults_to_500() raises:
    var mapped = map_handler_error(String("kaboom"), expose=False)
    assert_equal(mapped.status, 500)
    assert_equal(mapped.reason, String("Internal Server Error"))


def test_map_malformed_status_error_falls_back_to_500() raises:
    # Looks like the prefix but the code is junk -> safe 500.
    var mapped = map_handler_error(
        String("HttpStatusError(abc): x"), expose=False
    )
    assert_equal(mapped.status, 500)


def test_map_out_of_range_status_falls_back_to_500() raises:
    var mapped = map_handler_error(
        String("HttpStatusError(700): x"), expose=False
    )
    assert_equal(mapped.status, 500)


def test_reason_phrase_fallbacks() raises:
    assert_equal(http_reason_phrase(404), String("Not Found"))
    assert_equal(http_reason_phrase(599), String("Server Error"))
    assert_equal(http_reason_phrase(450), String("Client Error"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
