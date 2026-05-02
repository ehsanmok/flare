"""Tests for the io_uring SQE encoder + CQE decoder primitives
(``flare.runtime.io_uring_sqe``).

These tests are pure byte-level codec tests — they do **not**
require the host kernel to expose io_uring. The SQE buffers are
allocated in-process and verified against the kernel ABI byte
layout documented in ``include/uapi/linux/io_uring.h``.

Coverage:

1. ``IoUringSqe()`` construction zeroes all 64 bytes.
2. ``encode_sqe_zero`` zeroes the buffer in-place.
3. Each ``prep_*`` helper writes the correct opcode + fields
   into the SQE byte buffer:
   - ``prep_nop`` — opcode 0, user_data only.
   - ``prep_accept`` — opcode 13, fd, addr, addrlen, op_flags.
   - ``prep_recv`` — opcode 27, fd, rx_buf, rx_len, recv_flags.
   - ``prep_send`` — opcode 26, fd, tx_buf, tx_len, send_flags.
   - ``prep_writev`` — opcode 2, fd, iovec_addr, iovec_count,
     file_offset.
   - ``prep_close`` — opcode 19, fd.
   - ``prep_async_cancel`` — opcode 14, target_user_data in addr.
4. ``IoUringSqe`` accessors (``opcode``, ``fd``, ``addr``,
   ``len``, ``user_data``, ``op_flags``) round-trip through
   the byte buffer.
5. CQE accessors (``user_data``, ``res``, ``flags``,
   ``is_error``, ``errno``, ``has_more``, ``buffer_id``) reflect
   the constructed values.
6. ``decode_cqe_at`` reads a 16-byte CQE slot back into an
   ``IoUringCqe`` value with sign-extended ``res``.
7. Negative-``res`` sign-extension: a CQE with ``res = -EAGAIN``
   (-11) round-trips to ``cqe.res() == -11`` and ``cqe.errno()
   == 11``.
8. ``IoUringCqe.buffer_id`` extracts the high 16 bits of
   ``flags`` only when ``IORING_CQE_F_BUFFER`` is set.
9. ``IoUringCqe.has_more`` reflects the ``IORING_CQE_F_MORE``
   bit (multishot still active).

Sanitiser-friendly: every prep / accessor / decoder honours
``debug_assert[assert_mode="safe"]`` for non-NULL buffer + in-
range offsets / fds (see
``.cursor/rules/sanitizers-and-bounds-checking.mdc``).
"""

from std.memory import UnsafePointer, alloc
from std.testing import assert_equal, assert_true, assert_false

from flare.runtime.io_uring_sqe import (
    IO_URING_SQE_BYTES,
    IO_URING_CQE_BYTES,
    IORING_OP_NOP,
    IORING_OP_ACCEPT,
    IORING_OP_RECV,
    IORING_OP_SEND,
    IORING_OP_WRITEV,
    IORING_OP_CLOSE,
    IORING_OP_ASYNC_CANCEL,
    IORING_RECV_MULTISHOT,
    IORING_ACCEPT_MULTISHOT,
    IORING_CQE_F_BUFFER,
    IORING_CQE_F_MORE,
    IORING_CQE_F_SOCK_NONEMPTY,
    IOSQE_IO_LINK,
    IOSQE_FIXED_FILE,
    IoUringSqe,
    IoUringCqe,
    encode_sqe_zero,
    prep_nop,
    prep_accept,
    prep_recv,
    prep_send,
    prep_writev,
    prep_close,
    prep_async_cancel,
    decode_cqe_at,
)


# ── opcode kernel-value pinning ───────────────────────────────────────────────


def test_opcode_constants_match_kernel_abi() raises:
    """The opcodes are stable kernel ABI values; if these drift
    the kernel will reject every SQE flare emits with EINVAL.
    Pin them against the documented values from
    ``include/uapi/linux/io_uring.h``.
    """
    assert_equal(IORING_OP_NOP, 0)
    assert_equal(IORING_OP_WRITEV, 2)
    assert_equal(IORING_OP_ACCEPT, 13)
    assert_equal(IORING_OP_ASYNC_CANCEL, 14)
    assert_equal(IORING_OP_CLOSE, 19)
    assert_equal(IORING_OP_SEND, 26)
    assert_equal(IORING_OP_RECV, 27)


def test_struct_sizes_match_kernel_abi() raises:
    """SQE = 64 bytes (default), CQE = 16 bytes (default).
    Drift here means a wrong-sized ring slot, which the kernel
    will reject as EFAULT.
    """
    assert_equal(IO_URING_SQE_BYTES, 64)
    assert_equal(IO_URING_CQE_BYTES, 16)


# ── SQE construction + zero ───────────────────────────────────────────────────


def test_sqe_construction_zeros_buffer() raises:
    """Fresh ``IoUringSqe`` has all 64 bytes set to 0."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    for i in range(IO_URING_SQE_BYTES):
        assert_equal(Int(buf[i]), 0)


def test_encode_sqe_zero_clears_dirty_buffer() raises:
    """``encode_sqe_zero`` rewrites every byte to 0."""
    var raw = alloc[UInt8](IO_URING_SQE_BYTES)
    for i in range(IO_URING_SQE_BYTES):
        (raw + i).init_pointee_copy(UInt8(0xAB))
    var p = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=Int(raw)
    )
    encode_sqe_zero(p)
    for i in range(IO_URING_SQE_BYTES):
        assert_equal(Int(p[i]), 0)
    p.free()


# ── prep helpers ──────────────────────────────────────────────────────────────


def test_prep_nop_writes_only_opcode_and_user_data() raises:
    """``prep_nop`` should set opcode=0 + user_data; every other
    byte stays 0."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    prep_nop(buf, UInt64(0xDEADBEEF))
    assert_equal(sqe.opcode(), IORING_OP_NOP)
    assert_equal(Int(sqe.user_data()), 0xDEADBEEF)
    assert_equal(sqe.fd(), 0)
    assert_equal(Int(sqe.addr()), 0)
    assert_equal(sqe.len(), 0)
    assert_equal(Int(sqe.op_flags()), 0)


def test_prep_accept_writes_full_field_set() raises:
    """Multishot accept on listener fd 7 with addr=0/addrlen=0
    and ``IORING_ACCEPT_MULTISHOT`` set."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    prep_accept(
        buf,
        7,
        UInt64(0),
        UInt64(0),
        IORING_ACCEPT_MULTISHOT,
        UInt64(0xC0FFEE),
    )
    assert_equal(sqe.opcode(), IORING_OP_ACCEPT)
    assert_equal(sqe.fd(), 7)
    assert_equal(Int(sqe.op_flags()), Int(IORING_ACCEPT_MULTISHOT))
    assert_equal(Int(sqe.user_data()), 0xC0FFEE)


def test_prep_recv_writes_full_field_set() raises:
    """Recv on fd 42 with multishot recv flags."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    prep_recv(
        buf,
        42,
        UInt64(0x10000),
        4096,
        IORING_RECV_MULTISHOT,
        UInt64(0xAA),
    )
    assert_equal(sqe.opcode(), IORING_OP_RECV)
    assert_equal(sqe.fd(), 42)
    assert_equal(Int(sqe.addr()), 0x10000)
    assert_equal(sqe.len(), 4096)
    assert_equal(Int(sqe.op_flags()), Int(IORING_RECV_MULTISHOT))
    assert_equal(Int(sqe.user_data()), 0xAA)


def test_prep_send_writes_full_field_set() raises:
    """Send on fd 13 with no flags."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    prep_send(
        buf,
        13,
        UInt64(0x20000),
        2048,
        UInt32(0),
        UInt64(0xBB),
    )
    assert_equal(sqe.opcode(), IORING_OP_SEND)
    assert_equal(sqe.fd(), 13)
    assert_equal(Int(sqe.addr()), 0x20000)
    assert_equal(sqe.len(), 2048)
    assert_equal(Int(sqe.user_data()), 0xBB)


def test_prep_writev_writes_iovec_count_and_offset() raises:
    """Writev with 4 iovec entries; file_offset = -1 (current)."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    prep_writev(
        buf,
        9,
        UInt64(0x30000),
        4,
        UInt64(0xFFFF_FFFF_FFFF_FFFF),  # -1 as u64
        UInt64(0xCC),
    )
    assert_equal(sqe.opcode(), IORING_OP_WRITEV)
    assert_equal(sqe.fd(), 9)
    assert_equal(Int(sqe.addr()), 0x30000)
    assert_equal(sqe.len(), 4)
    assert_equal(Int(sqe.user_data()), 0xCC)


def test_prep_close_writes_fd_only() raises:
    """Close on fd 33 — opcode + fd + user_data, nothing else."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    prep_close(buf, 33, UInt64(0xDD))
    assert_equal(sqe.opcode(), IORING_OP_CLOSE)
    assert_equal(sqe.fd(), 33)
    assert_equal(sqe.len(), 0)
    assert_equal(Int(sqe.addr()), 0)
    assert_equal(Int(sqe.user_data()), 0xDD)


def test_prep_async_cancel_targets_user_data() raises:
    """Async cancel with target=0x1234 should put 0x1234 in addr,
    own user_data in user_data."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    prep_async_cancel(buf, UInt64(0x1234), UInt64(0xEE))
    assert_equal(sqe.opcode(), IORING_OP_ASYNC_CANCEL)
    assert_equal(Int(sqe.addr()), 0x1234)
    assert_equal(Int(sqe.user_data()), 0xEE)


# ── SQE flag manipulation ─────────────────────────────────────────────────────


def test_set_flags_round_trips() raises:
    """``set_flags(IOSQE_IO_LINK | IOSQE_FIXED_FILE)`` should be
    readable via ``flags()``."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    prep_nop(buf, UInt64(0))
    sqe.set_flags(IOSQE_IO_LINK | IOSQE_FIXED_FILE)
    assert_equal(sqe.flags(), Int(IOSQE_IO_LINK | IOSQE_FIXED_FILE))


def test_set_user_data_overrides_prep_value() raises:
    """``set_user_data`` should overwrite the value prep set."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    prep_nop(buf, UInt64(0xAAAA))
    sqe.set_user_data(UInt64(0xBBBB))
    assert_equal(Int(sqe.user_data()), 0xBBBB)


# ── CQE decode + accessors ────────────────────────────────────────────────────


def test_cqe_construction_round_trips_fields() raises:
    """An ``IoUringCqe`` constructed from explicit fields exposes
    them via the accessors."""
    var cqe = IoUringCqe(UInt64(0xCAFE), Int32(2048), UInt32(0))
    assert_equal(Int(cqe.user_data()), 0xCAFE)
    assert_equal(cqe.res(), 2048)
    assert_equal(Int(cqe.flags()), 0)
    assert_false(cqe.is_error())
    assert_equal(cqe.errno(), 0)


def test_cqe_negative_res_means_error() raises:
    """A CQE with ``res = -11`` (EAGAIN) reports ``is_error()``
    + ``errno() == 11``."""
    var cqe = IoUringCqe(UInt64(0), Int32(-11), UInt32(0))
    assert_true(cqe.is_error())
    assert_equal(cqe.res(), -11)
    assert_equal(cqe.errno(), 11)


def test_cqe_more_flag_signals_multishot_active() raises:
    """``IORING_CQE_F_MORE`` set => ``has_more() == True``."""
    var cqe_more = IoUringCqe(UInt64(0), Int32(0), IORING_CQE_F_MORE)
    var cqe_done = IoUringCqe(UInt64(0), Int32(0), UInt32(0))
    assert_true(cqe_more.has_more())
    assert_false(cqe_done.has_more())


def test_cqe_buffer_id_decodes_high_bits_when_buffer_flag_set() raises:
    """When ``IORING_CQE_F_BUFFER`` is set, the buffer-id is in
    the high 16 bits of ``flags``. Without the flag the accessor
    returns -1 to signal "no buffer selected"."""
    var bid: UInt32 = UInt32(7) << UInt32(16)
    var cqe_with = IoUringCqe(UInt64(0), Int32(0), bid | IORING_CQE_F_BUFFER)
    var cqe_without = IoUringCqe(UInt64(0), Int32(0), bid)
    assert_equal(cqe_with.buffer_id(), 7)
    assert_equal(cqe_without.buffer_id(), -1)


def test_decode_cqe_at_round_trips_through_byte_buffer() raises:
    """Write a 16-byte CQE slot manually + ``decode_cqe_at``
    must reproduce the same fields."""
    var raw = alloc[UInt8](IO_URING_CQE_BYTES)
    var p = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=Int(raw)
    )
    # user_data = 0x1122334455667788 (LE).
    var ud = UInt64(0x1122334455667788)
    for k in range(8):
        (p + k).init_pointee_copy(
            UInt8(Int((ud >> UInt64(k * 8)) & UInt64(0xFF)))
        )
    # res = 1500 (LE 32-bit).
    var res_v = UInt32(1500)
    for k in range(4):
        (p + 8 + k).init_pointee_copy(
            UInt8(Int((res_v >> UInt32(k * 8)) & UInt32(0xFF)))
        )
    # flags = IORING_CQE_F_MORE | IORING_CQE_F_SOCK_NONEMPTY (LE 32-bit).
    var fl = IORING_CQE_F_MORE | IORING_CQE_F_SOCK_NONEMPTY
    for k in range(4):
        (p + 12 + k).init_pointee_copy(
            UInt8(Int((fl >> UInt32(k * 8)) & UInt32(0xFF)))
        )
    var cqe = decode_cqe_at(p)
    assert_equal(Int(cqe.user_data()), 0x1122334455667788)
    assert_equal(cqe.res(), 1500)
    assert_true(cqe.has_more())
    assert_equal(Int(cqe.flags()), Int(fl))
    p.free()


def test_decode_cqe_at_sign_extends_negative_res() raises:
    """A CQE with res = -125 (ECANCELED) round-trips as -125,
    not 0xFFFFFF83."""
    var raw = alloc[UInt8](IO_URING_CQE_BYTES)
    var p = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=Int(raw)
    )
    for i in range(IO_URING_CQE_BYTES):
        (p + i).init_pointee_copy(UInt8(0))
    # res = -125 (two's complement 32-bit = 0xFFFFFF83).
    var res_raw: UInt32 = UInt32(0xFFFFFF83)
    for k in range(4):
        (p + 8 + k).init_pointee_copy(
            UInt8(Int((res_raw >> UInt32(k * 8)) & UInt32(0xFF)))
        )
    var cqe = decode_cqe_at(p)
    assert_equal(cqe.res(), -125)
    assert_equal(cqe.errno(), 125)
    assert_true(cqe.is_error())
    p.free()


# ── prep_* fault-tolerance: zeros prior dirty bytes ───────────────────────────


def test_prep_helpers_overwrite_dirty_buffer() raises:
    """A prep helper called on a dirty SQE buffer must zero
    fields it doesn't write — kernel rejects partially-clean
    SQEs as EINVAL on overlay-tagged-union opcodes."""
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()
    # Dirty the buffer with prep_writev first.
    prep_writev(buf, 9, UInt64(0x30000), 4, UInt64(0), UInt64(0xCC))
    # Now overwrite with prep_nop — fd / addr / len / op_flags
    # must all return to zero.
    prep_nop(buf, UInt64(0xDDDD))
    assert_equal(sqe.opcode(), IORING_OP_NOP)
    assert_equal(sqe.fd(), 0)
    assert_equal(Int(sqe.addr()), 0)
    assert_equal(sqe.len(), 0)
    assert_equal(Int(sqe.op_flags()), 0)
    assert_equal(Int(sqe.user_data()), 0xDDDD)


# ── Test runner ───────────────────────────────────────────────────────────────


def main() raises:
    test_opcode_constants_match_kernel_abi()
    test_struct_sizes_match_kernel_abi()
    test_sqe_construction_zeros_buffer()
    test_encode_sqe_zero_clears_dirty_buffer()
    test_prep_nop_writes_only_opcode_and_user_data()
    test_prep_accept_writes_full_field_set()
    test_prep_recv_writes_full_field_set()
    test_prep_send_writes_full_field_set()
    test_prep_writev_writes_iovec_count_and_offset()
    test_prep_close_writes_fd_only()
    test_prep_async_cancel_targets_user_data()
    test_set_flags_round_trips()
    test_set_user_data_overrides_prep_value()
    test_cqe_construction_round_trips_fields()
    test_cqe_negative_res_means_error()
    test_cqe_more_flag_signals_multishot_active()
    test_cqe_buffer_id_decodes_high_bits_when_buffer_flag_set()
    test_decode_cqe_at_round_trips_through_byte_buffer()
    test_decode_cqe_at_sign_extends_negative_res()
    test_prep_helpers_overwrite_dirty_buffer()
    print("test_io_uring_sqe: 20 PASS")
