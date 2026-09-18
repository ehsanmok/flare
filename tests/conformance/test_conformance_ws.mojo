"""Conformance runner for ``tests/conformance/ws/`` fixtures.

Loads every ``*.json`` fixture under ``tests/conformance/ws/``, decodes
the hex bytes, and validates the schema:

- accept-fixtures declare the expected opcode + FIN bit + (when
  present) the post-unmask payload bytes, the explicit length,
  and -- for close frames -- the 2-byte status code.
- reject-fixtures declare only the expected failure mode through
  the ``expect_reason`` field; the schema check is structural.

Fixture outcomes are driven through
:meth:`flare.ws.frame.WsFrame.decode_one`, the same shape
:func:`test_conformance_h1` settled on: accept-fixtures must decode
and match their declared opcode / FIN / payload / close code, and
reject-fixtures must raise. Schema validation still runs first, so a
malformed fixture fails as a fixture bug rather than a parser bug.

Autobahn case-number prefixes (e.g. ``1.1.1``, ``5.4.1``,
``7.7.1``) are preserved in the ``name`` field as anchors to the
upstream test suite -- the corpus is not a full Autobahn run but
a hand-rolled subset that exercises the RFC 6455 §5 wire shapes
flare must accept and reject.
"""

from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true
from json import loads, Value, Null

from flare.ws.frame import WsFrame


def _digit(c: UInt8) raises -> Int:
    if c >= UInt8(ord("0")) and c <= UInt8(ord("9")):
        return Int(c) - ord("0")
    if c >= UInt8(ord("a")) and c <= UInt8(ord("f")):
        return Int(c) - ord("a") + 10
    if c >= UInt8(ord("A")) and c <= UInt8(ord("F")):
        return Int(c) - ord("A") + 10
    raise Error("conformance: invalid hex digit")


def _decode_hex(s: String) raises -> List[UInt8]:
    """Decode space-separated hex pairs into a byte buffer."""
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
    if not j.is_object():
        return False
    var keys = j.object_keys()
    for i in range(len(keys)):
        if keys[i] == key:
            return True
    return False


def _string_or(j: Value, key: String, default: String) raises -> String:
    if not _has_key(j, key):
        return default
    var v = j[key]
    if not v.is_string():
        return default
    return v.string_value()


def _int_or(j: Value, key: String, default: Int) raises -> Int:
    if not _has_key(j, key):
        return default
    var v = j[key]
    if not v.is_int():
        return default
    return Int(v.int_value())


def _bool_or(j: Value, key: String, default: Bool) raises -> Bool:
    if not _has_key(j, key):
        return default
    var v = j[key]
    if not v.is_bool():
        return default
    return v.bool_value()


def _validate_fixture(j: Value) raises:
    """Validate one fixture's schema, then run it through the parser.

    Raises if any required field is missing, the ``expect`` value
    is unknown, the hex pairs are malformed, an accept-fixture
    omits its expected-opcode declaration, or the parser's verdict
    disagrees with the fixture.
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
    assert_true(len(bytes) >= 2)  # WS frames are >= 2 header bytes

    if expect == "accept":
        # accept-fixtures MUST declare the expected opcode (0..0xF
        # per RFC 6455 §11.8) and the FIN bit. Payload-bearing
        # fixtures may also declare the explicit payload bytes or
        # just the length when the payload is content-neutral.
        assert_true(_has_key(j, "expected_opcode"))
        var opcode = _int_or(j, "expected_opcode", -1)
        assert_true(opcode >= 0)
        assert_true(opcode <= 0xF)
        assert_true(_has_key(j, "expected_fin"))
        var fin = _bool_or(j, "expected_fin", True)
        # CLOSE-fixtures (opcode 0x8) MUST declare their status
        # code. Status codes are 2-byte big-endian per §5.5.1.
        var close_code = -1
        if opcode == 0x8:
            assert_true(_has_key(j, "expected_close_code"))
            close_code = _int_or(j, "expected_close_code", -1)
            assert_true(close_code >= 0)
            assert_true(close_code <= 0xFFFF)

        var res = WsFrame.decode_one(Span[UInt8, _](bytes))
        assert_equal(Int(res.frame.opcode), opcode)
        assert_equal(res.frame.fin, fin)
        # Payload is compared post-unmask: a masked fixture declares
        # the plaintext it should decode to, not its wire bytes.
        if _has_key(j, "expected_payload_hex"):
            var want = _decode_hex(j["expected_payload_hex"].string_value())
            assert_equal(len(res.frame.payload), len(want))
            for k in range(len(want)):
                assert_equal(res.frame.payload[k], want[k])
        if close_code >= 0:
            assert_true(len(res.frame.payload) >= 2)
            var got_code = (Int(res.frame.payload[0]) << 8) | Int(
                res.frame.payload[1]
            )
            assert_equal(got_code, close_code)
    else:
        var raised = False
        try:
            _ = WsFrame.decode_one(Span[UInt8, _](bytes))
        except:
            raised = True
        assert_true(raised)


def _conformance_dir() -> Path:
    return Path("tests") / "conformance" / "ws"


def test_directory_exists() raises:
    assert_true(_conformance_dir().exists())


def test_all_ws_fixtures_validate() raises:
    var d = _conformance_dir()
    var count = 0
    var entries = d.listdir()
    for i in range(len(entries)):
        var entry_name = String(entries[i])
        if not entry_name.endswith(".json"):
            continue
        var path = d / entries[i]
        var j = loads(path.read_text())
        try:
            _validate_fixture(j)
        except e:
            raise Error(
                "conformance/ws fixture '"
                + String(entries[i])
                + "' failed: "
                + String(e)
            )
        count += 1
    assert_true(count >= 6)


def test_accept_and_reject_fixtures_both_present() raises:
    """Sanity-check coverage shape: every conformance corpus
    needs both branches or the runner has nothing to learn from
    when parser wiring goes live."""
    var d = _conformance_dir()
    var seen_accept = False
    var seen_reject = False
    var entries = d.listdir()
    for i in range(len(entries)):
        var entry_name = String(entries[i])
        if not entry_name.endswith(".json"):
            continue
        var path = d / entries[i]
        var j = loads(path.read_text())
        var expect = j["expect"].string_value()
        if expect == "accept":
            seen_accept = True
        elif expect == "reject":
            seen_reject = True
    assert_true(seen_accept)
    assert_true(seen_reject)


def main() raises:
    test_directory_exists()
    test_all_ws_fixtures_validate()
    test_accept_and_reject_fixtures_both_present()
    print("test_conformance_ws: OK")
