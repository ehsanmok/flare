"""Tests for flare.grpc.proto -- proto3 wire-format codec."""

from std.testing import assert_equal, assert_true, TestSuite

from flare.grpc.proto import (
    ProtoReader,
    ProtoWriter,
    WIRE_VARINT,
    WIRE_LEN,
    WIRE_I64,
    WIRE_I32,
)


def test_varint_round_trip() raises:
    var w = ProtoWriter()
    w.write_uint64(1, 300)  # multi-byte varint
    w.write_int64(2, -1)  # 10-byte two's complement
    w.write_bool(3, True)
    var bytes = w.take()

    var r = ProtoReader(Span[UInt8, _](bytes))
    var t1 = r.read_tag()
    assert_equal(t1[0], 1)
    assert_equal(t1[1], WIRE_VARINT)
    assert_equal(r.read_uint64(), UInt64(300))
    var t2 = r.read_tag()
    assert_equal(t2[0], 2)
    assert_equal(r.read_int64(), Int64(-1))
    var t3 = r.read_tag()
    assert_equal(t3[0], 3)
    assert_true(r.read_bool())
    assert_true(not r.has_more())


def test_zigzag_sint() raises:
    var w = ProtoWriter()
    w.write_sint64(1, -75)
    w.write_sint64(2, 75)
    var bytes = w.take()
    var r = ProtoReader(Span[UInt8, _](bytes))
    _ = r.read_tag()
    assert_equal(r.read_sint64(), Int64(-75))
    _ = r.read_tag()
    assert_equal(r.read_sint64(), Int64(75))


def test_string_and_bytes() raises:
    var w = ProtoWriter()
    w.write_string(1, "hello world")
    var raw = List[UInt8]()
    raw.append(UInt8(0xDE))
    raw.append(UInt8(0xAD))
    w.write_bytes(2, Span[UInt8, _](raw))
    var bytes = w.take()

    var r = ProtoReader(Span[UInt8, _](bytes))
    var t1 = r.read_tag()
    assert_equal(t1[1], WIRE_LEN)
    assert_equal(r.read_string(), "hello world")
    _ = r.read_tag()
    var got = r.read_bytes()
    assert_equal(len(got), 2)
    assert_equal(got[0], UInt8(0xDE))
    assert_equal(got[1], UInt8(0xAD))


def test_fixed_and_float() raises:
    var w = ProtoWriter()
    w.write_fixed64(1, UInt64(0x1122334455667788))
    w.write_fixed32(2, UInt32(0xAABBCCDD))
    w.write_double(3, 3.14159)
    w.write_float(4, Float32(2.5))
    var bytes = w.take()

    var r = ProtoReader(Span[UInt8, _](bytes))
    var t1 = r.read_tag()
    assert_equal(t1[1], WIRE_I64)
    assert_equal(r.read_fixed64(), UInt64(0x1122334455667788))
    var t2 = r.read_tag()
    assert_equal(t2[1], WIRE_I32)
    assert_equal(r.read_fixed32(), UInt32(0xAABBCCDD))
    _ = r.read_tag()
    var d = r.read_double()
    assert_true(d > 3.1415 and d < 3.1416)
    _ = r.read_tag()
    assert_equal(r.read_float(), Float32(2.5))


def test_embedded_message() raises:
    var inner = ProtoWriter()
    inner.write_string(1, "nested")
    var inner_bytes = inner.take()

    var outer = ProtoWriter()
    outer.write_message(5, Span[UInt8, _](inner_bytes))
    var bytes = outer.take()

    var r = ProtoReader(Span[UInt8, _](bytes))
    var t = r.read_tag()
    assert_equal(t[0], 5)
    assert_equal(t[1], WIRE_LEN)
    var sub = r.read_bytes()
    var rr = ProtoReader(Span[UInt8, _](sub))
    _ = rr.read_tag()
    assert_equal(rr.read_string(), "nested")


def test_skip_unknown_field() raises:
    # Writer emits fields 1,2,3; reader only wants field 2 and skips
    # the rest (proto3 forward compatibility).
    var w = ProtoWriter()
    w.write_string(1, "ignore me")
    w.write_int64(2, 7)
    w.write_fixed64(3, UInt64(99))
    var bytes = w.take()

    var r = ProtoReader(Span[UInt8, _](bytes))
    var found = Int64(0)
    var seen = False
    while r.has_more():
        var t = r.read_tag()
        if t[0] == 2:
            found = r.read_int64()
            seen = True
        else:
            r.skip(t[1])
    assert_true(seen)
    assert_equal(found, Int64(7))


def main() raises:
    print("=" * 60)
    print("test_grpc_proto.mojo -- proto3 wire codec")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
