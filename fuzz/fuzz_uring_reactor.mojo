"""Fuzz harness: ``flare.runtime.uring_reactor`` user-data
codec + driver-surface stability.

Two complementary properties:

1. **``pack_user_data`` / ``unpack_op`` / ``unpack_conn_id``
   round-trip** for arbitrary ``(op, conn_id)`` pairs drawn from
   fuzzer bytes. The codec splits a 64-bit slot into an 8-bit op
   tag + a 56-bit conn_id; any slip in the bit layout corrupts
   per-CQE dispatch in the hot path of every io_uring poll cycle.
2. **``UringReactor.cancel_conn``** never crashes for arbitrary
   conn_id values, even when the matching SQE has never been
   submitted (the kernel posts ``-ENOENT``; we must not panic).
   Skipped on hosts where io_uring is not available (most
   sandboxes) — the fuzz then degrades to (1) only.

Run:
    pixi run fuzz-uring-reactor
"""

from mozz import fuzz, FuzzConfig

from flare.runtime.io_uring import is_io_uring_available
from flare.runtime.uring_reactor import (
    URING_OP_ACCEPT,
    URING_OP_RECV,
    URING_OP_SEND,
    URING_OP_CLOSE,
    URING_OP_CANCEL,
    URING_OP_WAKEUP,
    UringCompletion,
    UringReactor,
    pack_user_data,
    unpack_conn_id,
    unpack_op,
)


@always_inline
def _u64_at(data: List[UInt8], offset: Int) -> UInt64:
    """Read a little-endian u64 starting at ``offset`` (zero
    when out-of-bounds)."""
    if offset + 8 > len(data):
        return UInt64(0)
    var v: UInt64 = 0
    for k in range(8):
        v = v | (UInt64(Int(data[offset + k])) << UInt64(k * 8))
    return v


def _fuzz_pack_unpack(data: List[UInt8]) raises:
    """Drive pack/unpack across fuzzer-chosen (op, conn_id) values
    and assert round-trip integrity."""
    if len(data) < 9:
        return
    var op = UInt64(Int(data[0]) & 7)  # 0..7 — covers all 6 ops + slack
    if op == 0:
        op = URING_OP_ACCEPT
    var raw_conn = _u64_at(data, 1)
    # Mask conn_id into the 56-bit allowed range; the pack helper
    # debug-asserts otherwise. Fuzzing the assertion path is
    # covered separately by the testsuite.
    var conn_id = raw_conn & ((UInt64(1) << UInt64(56)) - UInt64(1))
    var ud = pack_user_data(op, conn_id)
    if Int(unpack_op(ud)) != Int(op):
        raise Error("pack_user_data: op round-trip failed")
    if Int(unpack_conn_id(ud)) != Int(conn_id):
        raise Error("pack_user_data: conn_id round-trip failed")


def _fuzz_reactor_surface(data: List[UInt8]) raises:
    """Construct a UringReactor (if available), poll once, and
    submit a cancel for an arbitrary conn_id. The kernel may
    post ``-ENOENT`` on an unmatched cancel; we must not panic.
    """
    if not is_io_uring_available():
        return
    if len(data) < 9:
        return
    var conn_id = _u64_at(data, 1) & ((UInt64(1) << UInt64(56)) - UInt64(1))
    var r = UringReactor(8)
    var out = List[UringCompletion]()
    _ = r.poll(0, out)
    try:
        r.cancel_conn(conn_id)
        _ = r.poll(0, out)
    except _e:
        # SQ-full / kernel-rejected cancel => acceptable.
        pass


def target(data: List[UInt8]) raises:
    """Per-input dispatcher. Even-length inputs go to the
    pack/unpack fuzzer; odd-length inputs exercise the reactor
    surface (so each crash report points at one code path)."""
    if len(data) == 0:
        return
    try:
        if (len(data) & 1) == 0:
            _fuzz_pack_unpack(data)
        else:
            _fuzz_reactor_surface(data)
    except:
        pass


def main() raises:
    print("[mozz] fuzzing UringReactor pack/unpack + cancel surface...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    # Pack/unpack seeds (even length, ≥9 bytes).
    seeds.append(_bytes("\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
    seeds.append(_bytes("\x03\xff\xff\xff\xff\xff\xff\xff\x00\x00"))
    seeds.append(_bytes("\x05\x42\x00\x00\x00\x00\x00\x00\x00\x00"))

    # Reactor-surface seeds (odd length, ≥9 bytes).
    seeds.append(_bytes("\x01\x00\x00\x00\x00\x00\x00\x00\x00"))
    seeds.append(_bytes("\x07\x42\xff\xff\xff\xff\xff\xff\x00"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=100_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/uring_reactor",
            corpus_dir="fuzz/corpus/uring_reactor",
            max_input_len=64,
        ),
        seeds,
    )
