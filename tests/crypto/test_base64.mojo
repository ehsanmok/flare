"""Tests for :mod:`flare.crypto.base64` (RFC 4648 §4 standard).

Covers the round-trip identity over a representative byte set,
the ``=`` padding boundary cases (lengths n mod 3 == {0, 1, 2}),
canonical RFC 4648 §10 test vectors, lenient decode of inputs
without padding, and the alphabet-membership rejection on
invalid bytes.

Centralised on :func:`flare.crypto.base64.base64_encode` /
:func:`flare.crypto.base64.base64_decode` per critique register
§C1: the same algorithm previously lived as three near-duplicate
private encoders in ``flare.http.auth``, ``flare.ws.client``,
and ``flare.ws.server``.
"""

from std.testing import assert_equal, assert_true

from flare.crypto.base64 import base64_decode, base64_encode


def test_base64_rfc4648_test_vectors() raises:
    """RFC 4648 §10 published test vectors (standard alphabet).

    The leftmost three vectors (``f``, ``fo``, ``foo``) cover the
    three pad boundaries: 1 byte -> ``Zg==`` (two pads), 2 bytes
    -> ``Zm8=`` (one pad), 3 bytes -> ``Zm9v`` (zero pads).
    """
    assert_equal(base64_encode("".as_bytes()), "")
    assert_equal(base64_encode("f".as_bytes()), "Zg==")
    assert_equal(base64_encode("fo".as_bytes()), "Zm8=")
    assert_equal(base64_encode("foo".as_bytes()), "Zm9v")
    assert_equal(base64_encode("foob".as_bytes()), "Zm9vYg==")
    assert_equal(base64_encode("fooba".as_bytes()), "Zm9vYmE=")
    assert_equal(base64_encode("foobar".as_bytes()), "Zm9vYmFy")


def test_base64_round_trip_byte_range() raises:
    """Round-trip every byte 0..255 in three input lengths.

    Sanity-checks each pad boundary against arbitrary bytes
    (not just the printable subset RFC 4648 vectors use).
    """
    var seed = List[UInt8]()
    for i in range(256):
        seed.append(UInt8(i))
    for cut in [0, 1, 2, 3, 16, 100, 256]:
        var slice = List[UInt8]()
        for i in range(cut):
            slice.append(seed[i])
        var encoded = base64_encode(Span[UInt8, _](slice))
        var decoded = base64_decode(encoded)
        assert_equal(len(decoded), cut)
        for i in range(cut):
            assert_equal(decoded[i], slice[i])


def test_base64_decode_tolerates_missing_padding() raises:
    """Decoder accepts inputs without trailing ``=`` padding.

    The encoder always emits ``=``-padded output (RFC 4648 §3.2);
    being lenient on input matches the spirit of Postel's law and
    matches the URL-safe sibling at :mod:`flare.crypto.hmac`.
    """
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](base64_decode("Zg"))), "f"
    )
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](base64_decode("Zm8"))), "fo"
    )
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](base64_decode("Zm9vYmE"))),
        "fooba",
    )


def test_base64_decode_rejects_invalid_byte() raises:
    """Decoder raises on any byte outside the alphabet (incl. space)."""
    var raised = False
    try:
        _ = base64_decode("Zg !=")
    except:
        raised = True
    assert_true(raised)


def test_decode_rejects_non_canonical_input() raises:
    """Trailing bits and padding runs were ignored, so one value had
    several spellings. Missing padding is still fine."""
    from flare.crypto.hmac import base64url_decode

    assert_equal(len(base64_decode("QQ==")), 1)
    assert_equal(len(base64_decode("QQ")), 1)
    assert_equal(len(base64url_decode("QUI")), 2)
    for bad in ["QR==", "QQ=====", "QUJ=", "Q===", "QQ="]:
        var raised = False
        try:
            _ = base64_decode(String(bad))
        except:
            raised = True
        assert_true(raised, "base64_decode accepted " + String(bad))
    for bad in ["QR", "QUJ", "QQ====="]:
        var raised = False
        try:
            _ = base64url_decode(String(bad))
        except:
            raised = True
        assert_true(raised, "base64url_decode accepted " + String(bad))


def main() raises:
    test_base64_rfc4648_test_vectors()
    test_base64_round_trip_byte_range()
    test_base64_decode_tolerates_missing_padding()
    test_base64_decode_rejects_invalid_byte()
    test_decode_rejects_non_canonical_input()
    print("test_base64: 5 passed")
