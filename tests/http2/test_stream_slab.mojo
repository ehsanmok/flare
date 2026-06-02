"""Tests for :class:`flare.http2.stream_slab.StreamSlab` (Track O).

The slab replaces the previous ``Dict[StreamId, Stream]`` storage in
:class:`flare.http2.state.Connection`. It exposes the same surface but
routes dense small-int keys (``[0, FAST_CAPACITY)``) through a flat
``List[Optional[S]]`` for the typical h2 working set, falling
through to a Dict only when a stream id exceeds the hot range.

Test coverage:

- Empty-state contract (``len`` / ``__contains__`` / ``get``).
- Insert into the fast tier; read it back.
- Insert into the overflow tier (id >= ``FAST_CAPACITY``); read it
  back.
- ``__contains__`` distinguishes between the two tiers.
- ``__setitem__`` overwrites without double-counting.
- ``pop`` clears the slot and returns the value; second ``pop`` on
  the same id raises.
- ``items`` returns every entry across both tiers; eager-copies
  preserve the values.
- Round-trip stress: insert 200 ids straddling both tiers, then
  pop them and confirm the slab is empty again.

Uses a trivial value struct ``StreamLike`` to exercise the
parametric ``S`` boundary without depending on the heavy
``flare.http2.state.Stream`` shape.
"""

from std.testing import assert_equal, assert_raises, assert_true

from flare.http2.stream_slab import StreamSlab, FAST_CAPACITY


struct StreamLike(Copyable, Defaultable, Movable):
    """Minimal stand-in for ``Stream`` so the slab tests don't have
    to construct full ``HpackHeader`` lists or flow-control state.
    """

    var id: Int
    var payload: Int

    def __init__(out self):
        self.id = 0
        self.payload = 0

    def __init__(out self, id: Int, payload: Int):
        self.id = id
        self.payload = payload


def test_empty_slab_is_empty() raises:
    var slab = StreamSlab[StreamLike]()
    assert_equal(len(slab), 0)
    assert_true(not (0 in slab))
    assert_true(not (1 in slab))
    assert_true(not (FAST_CAPACITY + 1 in slab))
    assert_true(not Bool(slab.get(0)))
    assert_true(not Bool(slab.get(FAST_CAPACITY + 1)))


def test_fast_tier_roundtrip() raises:
    var slab = StreamSlab[StreamLike]()
    slab[1] = StreamLike(id=1, payload=42)
    slab[3] = StreamLike(id=3, payload=43)
    slab[5] = StreamLike(id=5, payload=44)

    assert_equal(len(slab), 3)
    assert_true(1 in slab)
    assert_true(3 in slab)
    assert_true(5 in slab)
    assert_true(not (7 in slab))

    var s1 = slab[1]
    assert_equal(s1.id, 1)
    assert_equal(s1.payload, 42)

    var s3 = slab[3]
    assert_equal(s3.payload, 43)


def test_overflow_tier_roundtrip() raises:
    var slab = StreamSlab[StreamLike]()
    var big = FAST_CAPACITY + 100
    slab[big] = StreamLike(id=big, payload=99)

    assert_equal(len(slab), 1)
    assert_true(big in slab)
    assert_true(not (big - 1 in slab))

    var got = slab[big]
    assert_equal(got.id, big)
    assert_equal(got.payload, 99)


def test_both_tiers_coexist() raises:
    var slab = StreamSlab[StreamLike]()
    slab[1] = StreamLike(id=1, payload=10)
    slab[FAST_CAPACITY + 7] = StreamLike(id=FAST_CAPACITY + 7, payload=20)

    assert_equal(len(slab), 2)
    var fast = slab[1]
    assert_equal(fast.payload, 10)
    var slow = slab[FAST_CAPACITY + 7]
    assert_equal(slow.payload, 20)


def test_overwrite_does_not_double_count() raises:
    var slab = StreamSlab[StreamLike]()
    slab[3] = StreamLike(id=3, payload=1)
    assert_equal(len(slab), 1)

    slab[3] = StreamLike(id=3, payload=2)
    assert_equal(len(slab), 1)
    var got = slab[3]
    assert_equal(got.payload, 2)

    var big = FAST_CAPACITY + 5
    slab[big] = StreamLike(id=big, payload=10)
    assert_equal(len(slab), 2)
    slab[big] = StreamLike(id=big, payload=20)
    assert_equal(len(slab), 2)
    var got_big = slab[big]
    assert_equal(got_big.payload, 20)


def test_getitem_on_missing_raises() raises:
    var slab = StreamSlab[StreamLike]()
    with assert_raises():
        _ = slab[1]
    with assert_raises():
        _ = slab[FAST_CAPACITY + 1]


def test_get_returns_optional() raises:
    var slab = StreamSlab[StreamLike]()
    slab[1] = StreamLike(id=1, payload=99)

    var present = slab.get(1)
    assert_true(Bool(present))
    assert_equal(present.value().payload, 99)

    var missing = slab.get(2)
    assert_true(not Bool(missing))


def test_pop_clears_slot() raises:
    var slab = StreamSlab[StreamLike]()
    slab[1] = StreamLike(id=1, payload=42)
    slab[FAST_CAPACITY + 3] = StreamLike(id=FAST_CAPACITY + 3, payload=43)
    assert_equal(len(slab), 2)

    var popped = slab.pop(1)
    assert_equal(popped.payload, 42)
    assert_equal(len(slab), 1)
    assert_true(not (1 in slab))

    var popped_overflow = slab.pop(FAST_CAPACITY + 3)
    assert_equal(popped_overflow.payload, 43)
    assert_equal(len(slab), 0)

    with assert_raises():
        _ = slab.pop(1)
    with assert_raises():
        _ = slab.pop(FAST_CAPACITY + 3)


def test_items_lists_everything() raises:
    var slab = StreamSlab[StreamLike]()
    slab[1] = StreamLike(id=1, payload=1)
    slab[5] = StreamLike(id=5, payload=2)
    slab[FAST_CAPACITY + 1] = StreamLike(id=FAST_CAPACITY + 1, payload=3)
    slab[FAST_CAPACITY + 100] = StreamLike(id=FAST_CAPACITY + 100, payload=4)

    var pairs = slab.items()
    assert_equal(len(pairs), 4)
    var seen_payload_sum = 0
    for p in pairs:
        seen_payload_sum += p[1].payload
    assert_equal(seen_payload_sum, 10)


def test_stress_roundtrip() raises:
    # 200 ids straddling the fast / overflow boundary. Insert and
    # then pop; the slab must return to empty without leaking the
    # internal counts.
    var slab = StreamSlab[StreamLike]()
    var n = 200
    for i in range(n):
        slab[i] = StreamLike(id=i, payload=i * 7)

    assert_equal(len(slab), n)
    for i in range(n):
        assert_true(i in slab)
        var got = slab[i]
        assert_equal(got.payload, i * 7)

    for i in range(n):
        var popped = slab.pop(i)
        assert_equal(popped.payload, i * 7)
    assert_equal(len(slab), 0)


def main() raises:
    test_empty_slab_is_empty()
    test_fast_tier_roundtrip()
    test_overflow_tier_roundtrip()
    test_both_tiers_coexist()
    test_overwrite_does_not_double_count()
    test_getitem_on_missing_raises()
    test_get_returns_optional()
    test_pop_clears_slot()
    test_items_lists_everything()
    test_stress_roundtrip()
    print("test_stream_slab: 10 passed")
