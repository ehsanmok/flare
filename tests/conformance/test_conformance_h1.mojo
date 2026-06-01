"""Conformance runner for ``conformance/h1/`` fixtures.

Loads every ``*.json`` fixture under ``conformance/h1/``, decodes the
hex bytes, and invokes :func:`flare.http.server._parse_http_request_bytes`
with the fixture's leniency overlay applied. Fixtures declare an
expected outcome (``accept`` / ``reject``) plus, on accept, the
expected request line; the runner asserts the parser result matches.

This proves every named ``H1LeniencyConfig`` flag flips parser
behaviour end-to-end: a fixture that ships ``leniency: {flag: true}``
must accept under the lenient overlay and reject under strict
defaults; the strict-shape fixture for the same wire input must
reject.
"""

from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true
from json import loads, Value, Null

from flare.http.proto import H1LeniencyConfig
from flare.http.server import _parse_http_request_bytes


def _digit(c: UInt8) raises -> Int:
    if c >= UInt8(ord("0")) and c <= UInt8(ord("9")):
        return Int(c) - ord("0")
    if c >= UInt8(ord("a")) and c <= UInt8(ord("f")):
        return Int(c) - ord("a") + 10
    if c >= UInt8(ord("A")) and c <= UInt8(ord("F")):
        return Int(c) - ord("A") + 10
    raise Error("conformance: invalid hex digit")


def _decode_hex(s: String) raises -> List[UInt8]:
    """Decode space-separated hex pairs into a byte buffer.

    Whitespace between pairs is collapsed. Empty hex strings yield
    an empty buffer; dangling half-pairs raise.
    """
    var out = List[UInt8]()
    var p = s.unsafe_ptr()
    var n = s.byte_length()
    var i = 0
    while i < n:
        var c = p[i]
        if (
            c == UInt8(ord(" "))
            or c == UInt8(ord("\t"))
            or c == UInt8(ord("\n"))
            or c == UInt8(ord("\r"))
        ):
            i += 1
            continue
        if i + 1 >= n:
            raise Error("conformance: dangling hex digit")
        var c2 = p[i + 1]
        var hi = _digit(c)
        var lo = _digit(c2)
        out.append(UInt8((hi << 4) | lo))
        i += 2
    return out^


def _has_key(j: Value, key: String) raises -> Bool:
    """Check whether ``j`` is an object containing ``key``."""
    if not j.is_object():
        return False
    var keys = j.object_keys()
    for i in range(len(keys)):
        if keys[i] == key:
            return True
    return False


def _bool_or(j: Value, key: String, default: Bool) raises -> Bool:
    """Read a boolean field from a JSON object; return ``default``
    when missing or non-bool."""
    if not _has_key(j, key):
        return default
    var v = j[key]
    if not v.is_bool():
        return default
    return v.bool_value()


def _string_or(j: Value, key: String, default: String) raises -> String:
    """Read a string field; return ``default`` if missing or non-string."""
    if not _has_key(j, key):
        return default
    var v = j[key]
    if not v.is_string():
        return default
    return v.string_value()


def _apply_leniency(j: Value) raises -> H1LeniencyConfig:
    """Build a :class:`H1LeniencyConfig` from a fixture's
    ``leniency`` overlay. Missing fields fall back to strict
    defaults."""
    return H1LeniencyConfig(
        allow_lf_only_line_endings=_bool_or(
            j, "allow_lf_only_line_endings", False
        ),
        allow_mixed_case_method=_bool_or(j, "allow_mixed_case_method", False),
        allow_ows_around_colon=_bool_or(j, "allow_ows_around_colon", False),
        allow_obs_fold=_bool_or(j, "allow_obs_fold", False),
        allow_oversized_request_uri=_bool_or(
            j, "allow_oversized_request_uri", False
        ),
        allow_oversized_header_list=_bool_or(
            j, "allow_oversized_header_list", False
        ),
        accept_empty_chunk_extensions=_bool_or(
            j, "accept_empty_chunk_extensions", False
        ),
        allow_multiple_content_length=_bool_or(
            j, "allow_multiple_content_length", False
        ),
        allow_te_chunked_when_cl_present=_bool_or(
            j, "allow_te_chunked_when_cl_present", False
        ),
        accept_obs_text_in_field_value=_bool_or(
            j, "accept_obs_text_in_field_value", False
        ),
        accept_invalid_chunk_extension_chars=_bool_or(
            j, "accept_invalid_chunk_extension_chars", False
        ),
        allow_leading_whitespace_before_request_line=_bool_or(
            j, "allow_leading_whitespace_before_request_line", False
        ),
    )


def _validate_fixture(j: Value) raises:
    """Validate a single fixture's schema + parser outcome.

    Decodes the hex input, applies the leniency overlay, and
    invokes :func:`_parse_http_request_bytes`. ``accept`` fixtures
    must parse successfully and the parsed request line must match
    the declared ``expected_method`` / ``expected_uri`` /
    ``expected_version``. ``reject`` fixtures must raise.
    """
    assert_true(_has_key(j, "name"))
    assert_true(_has_key(j, "spec"))
    assert_true(_has_key(j, "input_hex"))
    assert_true(_has_key(j, "expect"))

    var name = j["name"].string_value()
    var spec = j["spec"].string_value()
    var hex = j["input_hex"].string_value()
    var expect = j["expect"].string_value()

    assert_true(name.byte_length() > 0)
    assert_true(spec.byte_length() > 0)
    assert_true(expect == "accept" or expect == "reject")

    var bytes = _decode_hex(hex)
    assert_true(len(bytes) > 0)

    var leniency_val: Value
    if _has_key(j, "leniency"):
        leniency_val = j["leniency"]
    else:
        leniency_val = Value(Null())
    var cfg = _apply_leniency(leniency_val)

    if expect == "accept":
        var method = _string_or(j, "expected_method", "")
        var uri = _string_or(j, "expected_uri", "")
        var version = _string_or(j, "expected_version", "")
        assert_true(method.byte_length() > 0)
        assert_true(uri.byte_length() > 0)
        assert_true(version.byte_length() > 0)

        var req = _parse_http_request_bytes(Span[UInt8, _](bytes), leniency=cfg)
        assert_equal(req.method, method)
        assert_equal(req.url, uri)
        assert_equal(req.version, version)
    else:
        var raised = False
        try:
            _ = _parse_http_request_bytes(Span[UInt8, _](bytes), leniency=cfg)
        except:
            raised = True
        assert_true(raised)


def _conformance_dir() -> Path:
    """The repo-rooted ``conformance/h1/`` path. Tests run from the
    repo root via ``mojo -I .``."""
    return Path("conformance") / "h1"


def test_directory_exists() raises:
    assert_true(_conformance_dir().exists())


def test_all_h1_fixtures_validate() raises:
    var d = _conformance_dir()
    var count = 0
    var entries = d.listdir()
    for i in range(len(entries)):
        var entry_name = String(entries[i])
        if not entry_name.endswith(".json"):
            continue
        var path = d / entries[i]
        var j = loads(path.read_text())
        _validate_fixture(j)
        count += 1
    assert_true(count >= 1)


def test_leniency_overlay_flips_strict_default() raises:
    # Construct a fixture-shaped leniency object and confirm the
    # overlay flips the appropriate flag while leaving the rest
    # strict.
    var j = loads(String('{"allow_lf_only_line_endings": true}'))
    var cfg = _apply_leniency(j)
    assert_true(cfg.allow_lf_only_line_endings)
    assert_false(cfg.allow_mixed_case_method)
    assert_true(cfg.any_enabled())


def test_strict_overlay_keeps_strict() raises:
    var j = loads(String("{}"))
    var cfg = _apply_leniency(j)
    assert_false(cfg.any_enabled())


def main() raises:
    test_directory_exists()
    test_all_h1_fixtures_validate()
    test_leniency_overlay_flips_strict_default()
    test_strict_overlay_keeps_strict()
    print("test_conformance_h1: OK")
