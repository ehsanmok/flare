"""The client authenticates the server's connection IDs (QUIC-12).

RFC 9000 §7.3: absence of initial_source_connection_id is a
TRANSPORT_PARAMETER_ERROR even when the server's connection ID is
zero-length, and so is retry_source_connection_id when no Retry was
received; §18.2: a server with a zero-length connection ID MUST NOT send
preferred_address.

The tests drive :func:`check_server_transport_params` (what
``QuicClientConnection._check_peer_cids`` calls) with crafted blobs.
"""

from std.collections import List, Optional
from std.collections.span import Span
from std.testing import assert_false, assert_true

from flare.quic.transport_params import (
    check_server_transport_params,
    empty_transport_parameters,
    encode_transport_parameters,
)


def _cid(seed: UInt8, n: Int = 8) -> List[UInt8]:
    var b = List[UInt8]()
    for _ in range(n):
        b.append(seed)
    return b^


def _tlv(mut out: List[UInt8], id: UInt8, value: List[UInt8]):
    out.append(id)
    out.append(UInt8(len(value)))
    for i in range(len(value)):
        out.append(value[i])


def _blob(
    iscid: Optional[List[UInt8]], rscid: Optional[List[UInt8]]
) raises -> List[UInt8]:
    """ODCID 0xAA..., plus an initial_source_connection_id and a
    retry_source_connection_id when given (an empty value is written as
    a present, zero-length parameter)."""
    var tp = empty_transport_parameters()
    tp.original_destination_connection_id = _cid(0xAA)
    tp.initial_max_data = Optional(UInt64(1 << 20))
    tp.initial_max_streams_bidi = Optional(UInt64(16))
    if iscid and len(iscid.value()) > 0:
        tp.initial_source_connection_id = iscid.value().copy()
    if rscid and len(rscid.value()) > 0:
        tp.retry_source_connection_id = rscid.value().copy()
    var out = encode_transport_parameters(tp)
    if iscid and len(iscid.value()) == 0:
        _tlv(out, 0x0F, List[UInt8]())
    if rscid and len(rscid.value()) == 0:
        _tlv(out, 0x10, List[UInt8]())
    return out^


def _rejects(
    blob: List[UInt8],
    server_scid: List[UInt8],
    retried: Bool = False,
    retry_scid: List[UInt8] = List[UInt8](),
) raises -> Bool:
    try:
        check_server_transport_params(
            Span[UInt8, _](blob), _cid(0xAA), server_scid, retried, retry_scid
        )
    except e:
        assert_true("TRANSPORT_PARAMETER_ERROR" in String(e))
        return True
    return False


def test_correct_server_params_pass() raises:
    assert_false(
        _rejects(
            _blob(Optional(_cid(0xBB)), Optional[List[UInt8]]()), _cid(0xBB)
        )
    )
    # A zero-length server SCID sent as a present, empty parameter.
    assert_false(
        _rejects(
            _blob(Optional(List[UInt8]()), Optional[List[UInt8]]()),
            List[UInt8](),
        )
    )
    # After a Retry: retry_source_connection_id present and equal.
    assert_false(
        _rejects(
            _blob(Optional(_cid(0xBB)), Optional(_cid(0xCC, 4))),
            _cid(0xBB),
            True,
            _cid(0xCC, 4),
        )
    )


def test_absent_iscid_rejected_even_for_a_zero_length_server_cid() raises:
    """Case A of the repro: absent is not the same as zero-length."""
    var blob = _blob(Optional[List[UInt8]](), Optional[List[UInt8]]())
    assert_true(_rejects(blob, List[UInt8]()))
    assert_true(_rejects(blob, _cid(0xBB)))


def test_mismatched_iscid_rejected() raises:
    var blob = _blob(Optional(_cid(0xCC)), Optional[List[UInt8]]())
    assert_true(_rejects(blob, _cid(0xBB)))
    # A non-empty parameter against a zero-length server CID.
    assert_true(_rejects(blob, List[UInt8]()))


def test_retry_scid_without_a_retry_rejected() raises:
    """Case B of the repro: a zero-length retry_source_connection_id is
    still a present one."""
    var empty_rscid = _blob(Optional(_cid(0xBB)), Optional(List[UInt8]()))
    assert_true(_rejects(empty_rscid, _cid(0xBB)))
    var full_rscid = _blob(Optional(_cid(0xBB)), Optional(_cid(0xCC, 4)))
    assert_true(_rejects(full_rscid, _cid(0xBB)))


def test_missing_or_wrong_retry_scid_after_a_retry_rejected() raises:
    var absent = _blob(Optional(_cid(0xBB)), Optional[List[UInt8]]())
    assert_true(_rejects(absent, _cid(0xBB), True, _cid(0xCC, 4)))
    var wrong = _blob(Optional(_cid(0xBB)), Optional(_cid(0xDD, 4)))
    assert_true(_rejects(wrong, _cid(0xBB), True, _cid(0xCC, 4)))


def test_preferred_address_with_a_zero_length_cid_rejected() raises:
    """Case C of the repro."""
    var pa = List[UInt8]()
    for _ in range(4 + 2 + 16 + 2):
        pa.append(0)
    pa.append(8)
    for _ in range(8):
        pa.append(0x44)
    for _ in range(16):
        pa.append(0x55)
    var blob = _blob(Optional(List[UInt8]()), Optional[List[UInt8]]())
    _tlv(blob, 0x0D, pa)
    assert_true(_rejects(blob, List[UInt8]()))


def test_undecodable_blob_rejected() raises:
    var blob = _blob(Optional(_cid(0xBB)), Optional[List[UInt8]]())
    blob.append(0x08)
    assert_true(_rejects(blob, _cid(0xBB)))


def main() raises:
    test_correct_server_params_pass()
    test_absent_iscid_rejected_even_for_a_zero_length_server_cid()
    test_mismatched_iscid_rejected()
    test_retry_scid_without_a_retry_rejected()
    test_missing_or_wrong_retry_scid_after_a_retry_rejected()
    test_preferred_address_with_a_zero_length_cid_rejected()
    test_undecodable_blob_rejected()
    print("test_quic_client_peer_params: 7 passed")
