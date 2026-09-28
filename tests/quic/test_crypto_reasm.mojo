"""Tests for the per-level CRYPTO reassembly buffer's bounds."""

from std.testing import assert_equal, assert_true

from flare.quic._server_support import (
    CRYPTO_REASM_MAX_FRAGMENTS,
    CRYPTO_REASM_WINDOW,
    _CryptoStream,
)


def _bytes(n: Int) -> List[UInt8]:
    return List[UInt8](length=n, fill=UInt8(0x16))


def test_in_order_and_reordered_fragments_still_drain() raises:
    var cs = _CryptoStream()
    cs.insert(UInt64(10), _bytes(5))
    cs.insert(UInt64(0), _bytes(10))
    assert_equal(len(cs.drain_contiguous()), 15)
    cs.insert(UInt64(3), _bytes(4))  # a retransmit below the prefix
    assert_equal(len(cs.frag_offsets), 0)


def test_far_offset_is_refused() raises:
    """Any offset was buffered: one CRYPTO frame at offset 2^40 held
    its bytes for good, and the drain rescanned every fragment."""
    var cs = _CryptoStream()
    var raised = False
    try:
        cs.insert(UInt64(1) << 40, _bytes(10))
    except:
        raised = True
    assert_true(raised, "a fragment 2^40 bytes ahead was buffered")


def test_fragment_count_is_bounded() raises:
    var cs = _CryptoStream()
    var raised = False
    try:
        for i in range(CRYPTO_REASM_MAX_FRAGMENTS + 1):
            cs.insert(UInt64(1 + 2 * i), _bytes(1))  # all ahead of a gap
    except:
        raised = True
    assert_true(raised, "unbounded fragment count")
    assert_true(len(cs.frag_offsets) <= CRYPTO_REASM_MAX_FRAGMENTS)


def main() raises:
    test_in_order_and_reordered_fragments_still_drain()
    test_far_offset_is_refused()
    test_fragment_count_is_bounded()
    print("test_crypto_reasm: 3 passed")
