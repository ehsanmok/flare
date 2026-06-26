"""Round-trip test for tools/proto_gen.py generated code.

Run with the generated module's directory on the import path::

    mkdir -p build/gen
    python tools/proto_gen.py tests/grpc/proto/sample.proto \
        -o build/gen/sample_pb.mojo
    mojo -I . -I build/gen tests/grpc/proto/test_codegen.mojo

(the ``test-grpc-codegen`` pixi alias does exactly this). The module
``sample_pb`` is generated from ``sample.proto`` by
``tools/proto_gen.py`` into the gitignored ``build/gen`` so a stale or
unformatted fixture never lands in the tree; this test encodes a
populated message, decodes
it back, and asserts every field survived -- proving the generator
emits a self-consistent proto3 codec over the ``flare.grpc.proto``
runtime. A protoc cross-check (decoding our bytes with the reference
compiler) is tracked separately; this guards the generator's own
encode/decode symmetry, including packed repeated-scalar reads.
"""

from std.memory import Span
from std.testing import assert_equal, assert_true, TestSuite

from flare.grpc.proto import ProtoWriter

from sample_pb import Color_BLUE, Color_RED, Point, Shape


def test_point_round_trip() raises:
    var p = Point()
    p.x = -7
    p.y = 42
    p.color = Color_BLUE
    var bytes = p.encode()
    var back = Point.decode(Span[UInt8, _](bytes))
    assert_equal(back.x, -7)
    assert_equal(back.y, 42)
    assert_equal(back.color, Color_BLUE)


def test_point_defaults_omitted() raises:
    # proto3: zero-valued scalars are not written on the wire.
    var p = Point()
    var bytes = p.encode()
    assert_equal(len(bytes), 0)


def test_shape_round_trip() raises:
    var s = Shape()
    s.name = String("triangle")
    s.area = 12.5
    s.filled = True
    s.blob = [1, 2, 3, 255]
    s.tags = [10, 20, 30]
    var o = Point()
    o.x = 1
    o.y = 2
    o.color = Color_RED
    s.origin = Optional[Point](o^)
    var v0 = Point()
    v0.x = 5
    var v1 = Point()
    v1.y = 6
    var verts = List[Point]()
    verts.append(v0^)
    verts.append(v1^)
    s.vertices = verts^

    var bytes = s.encode()
    var back = Shape.decode(Span[UInt8, _](bytes))
    assert_equal(back.name, String("triangle"))
    assert_equal(back.area, 12.5)
    assert_true(back.filled)
    assert_equal(len(back.blob), 4)
    assert_equal(back.blob[3], UInt8(255))
    assert_equal(len(back.tags), 3)
    assert_equal(back.tags[0], 10)
    assert_equal(back.tags[2], 30)
    assert_true(Bool(back.origin))
    assert_equal(back.origin.value().x, 1)
    assert_equal(back.origin.value().color, Color_RED)
    assert_equal(len(back.vertices), 2)
    assert_equal(back.vertices[0].x, 5)
    assert_equal(back.vertices[1].y, 6)


def test_packed_repeated_scalar_decodes() raises:
    # A protoc-style packed repeated int64 (field 5, wire LEN) must
    # decode even though our encoder emits the unpacked form.
    # Hand-assemble the packed payload: 3 single-byte varints 1,2,3.
    var packed: List[UInt8] = [1, 2, 3]
    var w = ProtoWriter()
    w.write_bytes(5, Span[UInt8, _](packed))  # field 5, LEN -> packed block
    var bytes = w.take()
    var back = Shape.decode(Span[UInt8, _](bytes))
    assert_equal(len(back.tags), 3)
    assert_equal(back.tags[0], 1)
    assert_equal(back.tags[1], 2)
    assert_equal(back.tags[2], 3)


def main() raises:
    print("=" * 60)
    print("test_codegen.mojo -- proto_gen round-trip")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
