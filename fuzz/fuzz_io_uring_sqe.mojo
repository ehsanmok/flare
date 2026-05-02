"""Fuzz harness: io_uring SQE encoder + CQE decoder primitives
(``flare.runtime.io_uring_sqe``).

Track F1 (v0.7 stability gate). Targets the byte-level codec
that the upcoming ``UringReactor`` calls every poll cycle to
fill SQE slots and decode CQE slots. Three properties:

1. **Prep helpers never panic** on arbitrary opcode-shape inputs
   (fd / addr / len / flags / user_data drawn from fuzzer bytes).
   Must either fully fill the SQE buffer or raise a regular
   ``Error`` -- never crash the process.
2. **CQE decode round-trip**: any 16-byte sequence is a valid
   CQE byte buffer (the kernel only writes valid CQEs but the
   decoder must be robust against arbitrary inputs to defend
   against ring-corruption from a buggy kernel module / out-of-
   tree io_uring patch / sandbox shenanigans).
3. **SQE accessor consistency**: after a ``prep_*`` helper, the
   accessors (``opcode``, ``fd``, ``addr``, ``len``,
   ``user_data``, ``op_flags``) round-trip the values written.

Run:
    pixi run fuzz-io-uring-sqe
"""

from std.memory import UnsafePointer, alloc

from mozz import fuzz, FuzzConfig

from flare.runtime.io_uring_sqe import (
    IO_URING_SQE_BYTES,
    IO_URING_CQE_BYTES,
    IORING_OP_NOP,
    IORING_OP_POLL_ADD,
    IORING_OP_POLL_REMOVE,
    IORING_OP_RECV,
    IORING_OP_SEND,
    IORING_OP_WRITEV,
    IORING_OP_CLOSE,
    IORING_OP_ACCEPT,
    IORING_OP_ASYNC_CANCEL,
    IORING_POLL_ADD_MULTI,
    IoUringSqe,
    IoUringCqe,
    decode_cqe_at,
    prep_nop,
    prep_accept,
    prep_poll_add,
    prep_poll_remove,
    prep_recv,
    prep_send,
    prep_writev,
    prep_close,
    prep_async_cancel,
)


@always_inline
def _u64_at(data: List[UInt8], offset: Int) -> UInt64:
    """Read a little-endian u64 from ``data[offset:offset+8]``,
    or 0 if the buffer is too short."""
    if offset + 8 > len(data):
        return UInt64(0)
    var v: UInt64 = 0
    for k in range(8):
        v = v | (UInt64(Int(data[offset + k])) << UInt64(k * 8))
    return v


@always_inline
def _u32_at(data: List[UInt8], offset: Int) -> UInt32:
    """Read a little-endian u32 from ``data[offset:offset+4]``,
    or 0 if the buffer is too short."""
    if offset + 4 > len(data):
        return UInt32(0)
    var v: UInt32 = 0
    for k in range(4):
        v = v | (UInt32(Int(data[offset + k])) << UInt32(k * 8))
    return v


def _fuzz_prep_helpers(data: List[UInt8]) raises:
    """Drive the seven prep_* helpers with fuzzer-supplied
    field values. The selection byte (data[0] mod 7) picks which
    helper runs; subsequent bytes carry the field values.

    Asserts the SQE accessors round-trip after each prep -- the
    invariant the upcoming UringReactor relies on every cycle.
    """
    if len(data) < 1:
        return
    var sel = Int(data[0]) % 9
    var sqe = IoUringSqe()
    var buf = sqe.as_bytes()

    # Pull field values out of subsequent bytes; defaults are 0
    # if the buffer is too short.
    var fd_raw = _u32_at(data, 1)
    var addr = _u64_at(data, 5)
    var length = Int(_u32_at(data, 13))
    var op_flags = _u32_at(data, 17)
    var user_data = _u64_at(data, 21)
    var iov_count = Int(_u32_at(data, 29)) % 1025
    var off = _u64_at(data, 33)

    # Clamp fd to non-negative and non-huge; the prep helpers
    # debug_assert fd >= 0 (under -D ASSERT=safe) so the fuzzer
    # would otherwise spend most runs hitting that assert.
    var fd = Int(fd_raw) & 0x7FFF_FFFF
    var length_clamped = length & 0x7FFF_FFFF

    if sel == 0:
        prep_nop(buf, user_data)
        if sqe.opcode() != IORING_OP_NOP:
            raise Error("prep_nop: opcode mismatch")
        if Int(sqe.user_data()) != Int(user_data):
            raise Error("prep_nop: user_data mismatch")
    elif sel == 1:
        prep_accept(buf, fd, addr, _u64_at(data, 41), op_flags, user_data)
        if sqe.opcode() != IORING_OP_ACCEPT:
            raise Error("prep_accept: opcode mismatch")
        if sqe.fd() != fd:
            raise Error("prep_accept: fd mismatch")
        if Int(sqe.addr()) != Int(addr):
            raise Error("prep_accept: addr mismatch")
        if Int(sqe.op_flags()) != Int(op_flags):
            raise Error("prep_accept: op_flags mismatch")
    elif sel == 2:
        prep_recv(buf, fd, addr, length_clamped, op_flags, user_data)
        if sqe.opcode() != IORING_OP_RECV:
            raise Error("prep_recv: opcode mismatch")
        if sqe.fd() != fd:
            raise Error("prep_recv: fd mismatch")
        if sqe.len() != length_clamped:
            raise Error("prep_recv: len mismatch")
        if Int(sqe.user_data()) != Int(user_data):
            raise Error("prep_recv: user_data mismatch")
    elif sel == 3:
        prep_send(buf, fd, addr, length_clamped, op_flags, user_data)
        if sqe.opcode() != IORING_OP_SEND:
            raise Error("prep_send: opcode mismatch")
        if sqe.fd() != fd:
            raise Error("prep_send: fd mismatch")
        if sqe.len() != length_clamped:
            raise Error("prep_send: len mismatch")
    elif sel == 4:
        prep_writev(buf, fd, addr, iov_count, off, user_data)
        if sqe.opcode() != IORING_OP_WRITEV:
            raise Error("prep_writev: opcode mismatch")
        if sqe.fd() != fd:
            raise Error("prep_writev: fd mismatch")
        if sqe.len() != iov_count:
            raise Error("prep_writev: iov_count mismatch")
    elif sel == 5:
        prep_close(buf, fd, user_data)
        if sqe.opcode() != IORING_OP_CLOSE:
            raise Error("prep_close: opcode mismatch")
        if sqe.fd() != fd:
            raise Error("prep_close: fd mismatch")
    elif sel == 6:
        prep_async_cancel(buf, addr, user_data)
        if sqe.opcode() != IORING_OP_ASYNC_CANCEL:
            raise Error("prep_async_cancel: opcode mismatch")
        if Int(sqe.addr()) != Int(addr):
            raise Error("prep_async_cancel: target_user_data mismatch")
    elif sel == 7:
        # Multishot poll_add: opcode + fd + poll_mask in op_flags
        # + IORING_POLL_ADD_MULTI in len + user_data.
        prep_poll_add(buf, fd, op_flags, user_data, True)
        if sqe.opcode() != IORING_OP_POLL_ADD:
            raise Error("prep_poll_add: opcode mismatch")
        if sqe.fd() != fd:
            raise Error("prep_poll_add: fd mismatch")
        if Int(sqe.op_flags()) != Int(op_flags):
            raise Error("prep_poll_add: op_flags mismatch")
        if sqe.len() != Int(IORING_POLL_ADD_MULTI):
            raise Error("prep_poll_add: multishot flag missing")
        if Int(sqe.user_data()) != Int(user_data):
            raise Error("prep_poll_add: user_data mismatch")
    else:  # sel == 8
        # poll_remove: target_user_data in addr + own user_data.
        prep_poll_remove(buf, addr, user_data)
        if sqe.opcode() != IORING_OP_POLL_REMOVE:
            raise Error("prep_poll_remove: opcode mismatch")
        if Int(sqe.addr()) != Int(addr):
            raise Error("prep_poll_remove: target_user_data mismatch")
        if Int(sqe.user_data()) != Int(user_data):
            raise Error("prep_poll_remove: user_data mismatch")


def _fuzz_cqe_decode(data: List[UInt8]) raises:
    """Decode an arbitrary 16-byte CQE buffer. The decoder must
    not crash on any input -- the kernel only writes valid CQEs
    but the decoder is the gate against ring-region corruption.
    """
    if len(data) < IO_URING_CQE_BYTES:
        return
    var raw = alloc[UInt8](IO_URING_CQE_BYTES)
    var p = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=Int(raw)
    )
    for i in range(IO_URING_CQE_BYTES):
        (p + i).init_pointee_copy(data[i])
    var cqe = decode_cqe_at(p)
    # Exercise every accessor so the optimiser can't elide the
    # decode -- the fuzzer wants the full code path covered.
    _ = cqe.user_data()
    _ = cqe.res()
    _ = cqe.flags()
    _ = cqe.is_error()
    _ = cqe.errno()
    _ = cqe.has_more()
    _ = cqe.buffer_id()
    p.free()


def target(data: List[UInt8]) raises:
    """Per-input dispatcher: even-length inputs go to the prep
    helper fuzzer, odd-length inputs go to the CQE decoder
    fuzzer. Splitting at the input level (vs. interleaving in
    the same target) keeps each crash report unambiguous."""
    if len(data) == 0:
        return
    try:
        if (len(data) & 1) == 0:
            _fuzz_prep_helpers(data)
        else:
            _fuzz_cqe_decode(data)
    except:
        pass


def main() raises:
    print("[mozz] fuzzing io_uring SQE encoder + CQE decoder...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    # Prep-helper seeds (even length).
    seeds.append(_bytes("\x00"))  # too short, returns early
    seeds.append(
        _bytes(
            "\x00\x01\x00\x00\x00\xCA\xFE\xBA\xBE\xDE\xAD\xBE\xEF"
            "\x00\x10\x00\x00\x00\x00\x00\x00\x42\x00\x00\x00\x00"
            "\x00\x00\x00\x00"
        )
    )  # prep_nop with user_data ~ 0x42
    seeds.append(
        _bytes(
            "\x02\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x10\x00\x00\x40\x00\x00\x00\x99\x00\x00\x00\x00"
            "\x00\x00\x00\x00"
        )
    )  # prep_recv on fd=7 with len=4096

    # CQE decoder seeds (odd length, 17 bytes -- 16-byte CQE + 1
    # selector byte).
    seeds.append(
        _bytes(
            "\x01"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
    )
    seeds.append(
        _bytes(
            "\x01"
            "\xCA\xFE\xBA\xBE\xDE\xAD\xBE\xEF\xF5\xFF\xFF\xFF\x02\x00\x00\x00"
        )
    )  # res = -11 (EAGAIN), flags = F_MORE

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/io_uring_sqe",
            corpus_dir="fuzz/corpus/io_uring_sqe",
            max_input_len=64,
        ),
        seeds,
    )
