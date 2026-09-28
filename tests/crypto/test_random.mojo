"""Tests for :mod:`flare.crypto.random`.

A CSPRNG cannot be proven random by a unit test; these pin the
contract instead: exact lengths (including the chunk boundary at
256 bytes that ``getentropy`` imposes), distinct outputs across
calls, every byte of a long fill actually written, and a negative
length refused rather than silently returning empty.
"""

from std.testing import assert_equal, assert_true, assert_false

from flare.crypto.random import random_bytes, fill_random


def test_random_bytes_exact_lengths() raises:
    for n in [0, 1, 4, 16, 255, 256, 257, 1000]:
        assert_equal(len(random_bytes(n)), n)


def test_random_bytes_differ_between_calls() raises:
    var a = random_bytes(32)
    var b = random_bytes(32)
    var same = True
    for i in range(32):
        if a[i] != b[i]:
            same = False
    assert_false(same, "two 32-byte draws were identical")


def test_fill_random_writes_past_the_chunk_boundary() raises:
    # 1024 zero bytes; after the fill, a run of 64 zeros anywhere
    # would mean a chunk was skipped (probability ~2^-512).
    var buf = List[UInt8](length=1024, fill=0)
    fill_random(buf)
    assert_equal(len(buf), 1024)
    var run = 0
    var longest = 0
    for b in buf:
        if b == 0:
            run += 1
            if run > longest:
                longest = run
        else:
            run = 0
    assert_true(longest < 64, "a chunk of the buffer was left unwritten")


def test_random_bytes_rejects_negative_length() raises:
    var raised = False
    try:
        _ = random_bytes(-1)
    except:
        raised = True
    assert_true(raised)


def main() raises:
    test_random_bytes_exact_lengths()
    test_random_bytes_differ_between_calls()
    test_fill_random_writes_past_the_chunk_boundary()
    test_random_bytes_rejects_negative_length()
    print("test_random: 4 passed")
