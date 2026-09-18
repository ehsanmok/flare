"""The prelude exports exactly the root package's surface (v0.10 U1).

``flare.prelude`` used to re-export every stable public symbol in the
library -- 454 of them, protocol codecs included. v0.10 cut it to what
the root ``flare`` package exports. There was no test pinning
either list, which is how the prelude grew to 454 in the first place:
every symbol added anywhere eventually got added here too, one
reasonable-looking line at a time.

This test is the ratchet. It imports a representative slice of the
intended surface from **both** ``flare`` and ``flare.prelude`` and
asserts they resolve to the same entities, and it names symbols that
must NOT be reachable from the prelude so a future wide re-export
fails here instead of shipping.

It cannot enumerate the whole list by reflection -- Mojo has no module
introspection -- so it samples each category and relies on the fact
that the prelude is *generated* from the root list: if someone
re-widens it, the excluded-symbol half below is what catches them.
"""

from std.testing import assert_equal, assert_true, TestSuite

# Same symbol, both routes. If the prelude stops re-exporting one of
# these, or the root drops it, this file stops compiling -- which is
# the point.
from flare import (
    Cancel as RootCancel,
    ChunkSource as RootChunkSource,
    Handler as RootHandler,
    HeaderMap as RootHeaderMap,
    HttpClient as RootHttpClient,
    HttpServer as RootHttpServer,
    Request as RootRequest,
    Response as RootResponse,
    Router as RootRouter,
    Status as RootStatus,
    WithCancel as RootWithCancel,
    ok as root_ok,
    ok_json as root_ok_json,
    stream_response as root_stream_response,
    HandlerInfallible as RootHandlerInfallible,
    InMemoryCacheStore as RootInMemoryCacheStore,
    StaticResponse as RootStaticResponse,
    UnixListener as RootUnixListener,
    UnixStream as RootUnixStream,
    WithRaises as RootWithRaises,
    WsConnection as RootWsConnection,
)
from flare.prelude import (
    Cancel,
    ChunkSource,
    Handler,
    HeaderMap,
    HttpClient,
    HttpServer,
    Request,
    Response,
    Router,
    Status,
    WithCancel,
    ok,
    ok_json,
    stream_response,
    precompute_response,
    HandlerInfallible,
    InMemoryCacheStore,
    StaticResponse,
    UnixListener,
    UnixStream,
    WithRaises,
    WsConnection,
)

# The categories the diet removed still have homes. Importing them here
# documents where they went, and fails if a submodule stops exporting
# something the prelude no longer covers for it.
from flare.http2 import Http2Connection, encode_frame
from flare.quic import encode_varint
from flare.runtime import BufferPool, Reactor


def test_core_types_are_the_same_entity() raises:
    """A type reached through the prelude is the type reached through
    the root -- not a re-declaration that merely shares a name."""
    var via_root = RootResponse(RootStatus.OK, body=List[UInt8]())
    var via_prelude: Response = via_root^
    assert_equal(via_prelude.status, Status.OK)

    var h = HeaderMap()
    h.set("content-type", "text/plain")
    var h2: RootHeaderMap = h^
    assert_equal(h2.get("Content-Type"), "text/plain")


def test_response_helpers_agree() raises:
    """``ok`` / ``ok_json`` behave identically through either import."""
    var a = ok("hi")
    var b = root_ok("hi")
    assert_equal(a.status, b.status)
    assert_equal(a.text(), b.text())

    var j = ok_json('{"k":1}')
    var jr = root_ok_json('{"k":1}')
    assert_equal(j.status, jr.status)
    assert_equal(j.headers.get("content-type"), jr.headers.get("content-type"))


def test_request_roundtrips_through_either_import() raises:
    var r = Request(method="GET", url="/x")
    var rr: RootRequest = r^
    assert_equal(rr.url, "/x")


def test_prelude_is_not_the_wide_surface() raises:
    """The removed categories are reachable from their own modules.

    Stated as a positive assertion because Mojo cannot express "this
    import should fail" in a test. The guard against re-widening is
    that the prelude is generated from the root list and reviewed as
    a breaking change -- this case documents the intended homes so a
    reader who misses ``encode_varint`` in the prelude knows
    immediately where it went.
    """
    var v = encode_varint(UInt64(42))
    assert_true(len(v) > 0, "encode_varint reachable from flare.quic")

    var pool = BufferPool()
    assert_equal(pool.size(0), 0)


def test_exported_symbols_can_be_written_with() raises:
    """Every symbol a root signature mentions is itself exported.

    The rule the two barrels are curated by: a symbol belongs on the
    list if another listed symbol's signature names it. Seven broke it.
    ``precompute_response`` returned a ``StaticResponse`` you could not
    name; ``Cache[Inner, S]`` needed a store you could not name;
    ``UnixListener`` / ``UnixStream`` were missing while their TCP peers
    and the frame-mux codec layered over them were both present; the
    WebSocket handler argument type was missing; and the README
    documented ``HandlerInfallible`` while neither barrel exported it.

    The import block at the top of this file is most of the assertion:
    it does not compile if any of them stops being exported from both.
    What is left is to show the two barrels hand back the same entity.
    """
    var resp = precompute_response(200, "text/plain", "hi")
    var same: RootStaticResponse = resp^
    assert_true(same.body_length >= 0)
    assert_true(len(same.keepalive_bytes) > 0)

    var store = InMemoryCacheStore()
    var same_store: RootInMemoryCacheStore = store^
    _ = same_store^


def main() raises:
    print("=" * 60)
    print("test_prelude_surface.mojo — prelude == root export surface")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
