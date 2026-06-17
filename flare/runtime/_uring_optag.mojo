"""io_uring operation-tag encoding + completion record for
:mod:`flare.runtime.uring_reactor`.

The ``URING_OP_*`` op-kind constants, the ``pack_user_data`` /
``unpack_op`` / ``unpack_conn_id`` bit-packing helpers that round-trip
the 64-bit SQE ``user_data`` tag, and the decoded ``UringCompletion``
record (plus ``_cqe_to_completion``) the server reactor's hot-path
dispatch consumes. Split out of ``uring_reactor.mojo`` to keep that
module within the file-size budget; ``uring_reactor`` re-exports every
name so existing ``from flare.runtime.uring_reactor import
pack_user_data / UringCompletion / URING_OP_ACCEPT ...`` (server
reactor, tests, fuzz) call sites keep resolving unchanged.
"""

from flare.runtime.io_uring_sqe import IoUringCqe

# ── op-kind tag bits ─────────────────────────────────────────────────────────
#
# Eight-bit tag we pack into the high byte of ``user_data`` so the
# CQE handler can dispatch without per-conn state-machine lookup.
# Numeric values are stable; the wire-in commit pins them as
# ``comptime`` so any accidental renumber breaks compilation.

comptime URING_OP_ACCEPT: UInt64 = 1
"""Multishot accept on the listener fd. ``conn_id`` is 0 or the
listener slot id."""
comptime URING_OP_RECV: UInt64 = 2
"""Multishot recv on a connected fd. ``conn_id`` is the
connection slot."""
comptime URING_OP_SEND: UInt64 = 3
"""Single send on a connected fd. ``conn_id`` is the connection
slot."""
comptime URING_OP_CLOSE: UInt64 = 4
"""Async close. ``conn_id`` is the connection slot."""
comptime URING_OP_CANCEL: UInt64 = 5
"""Async cancel of an in-flight op for ``conn_id``."""
comptime URING_OP_WAKEUP: UInt64 = 6
"""Cross-thread wakeup CQE; ``conn_id`` is 0."""
comptime URING_OP_POLL: UInt64 = 7
"""Multishot poll CQE; ``conn_id`` is the registered fd's slot.
The kernel posts one CQE per readiness change (analog of an
``epoll_wait`` event); the userspace driver inspects
``UringCompletion.res`` to see which poll bits fired."""
comptime URING_OP_POLL_REMOVE: UInt64 = 8
"""CQE for an ``IORING_OP_POLL_REMOVE`` we issued ourselves;
the kernel posts it under the remove SQE's own user_data and
the cancelled poll's final CQE arrives separately under
``URING_OP_POLL`` without ``IORING_CQE_F_MORE``."""
comptime URING_OP_PROVIDE_BUFFERS: UInt64 = 9
"""CQE for an ``IORING_OP_PROVIDE_BUFFERS`` we issued ourselves
to seed (or refill) a buffer ring that recv-buffer-select uses.
``conn_id`` is typically the buffer-group id so the dispatch
loop can route refill ACKs to the right ring without a separate
table."""


comptime _OP_SHIFT: UInt64 = 56
comptime _CONN_MASK: UInt64 = (UInt64(1) << _OP_SHIFT) - UInt64(1)


@always_inline
def pack_user_data(op: UInt64, conn_id: UInt64) -> UInt64:
    """Pack ``(op, conn_id)`` into the 64-bit user_data slot.

    ``op`` lives in the top 8 bits, ``conn_id`` in the bottom
    56 bits. ``debug_assert``ed: ``conn_id <= 2^56 - 1``.
    """
    debug_assert[assert_mode="safe"](
        Int(conn_id) <= Int(_CONN_MASK),
        "pack_user_data: conn_id exceeds 56-bit range; got ",
        Int(conn_id),
    )
    debug_assert[assert_mode="safe"](
        Int(op) <= 0xFF,
        "pack_user_data: op_kind exceeds 8-bit range; got ",
        Int(op),
    )
    return (op << _OP_SHIFT) | (conn_id & _CONN_MASK)


@always_inline
def unpack_op(user_data: UInt64) -> UInt64:
    """Return the op_kind portion of a packed user_data."""
    return (user_data >> _OP_SHIFT) & UInt64(0xFF)


@always_inline
def unpack_conn_id(user_data: UInt64) -> UInt64:
    """Return the conn_id portion of a packed user_data."""
    return user_data & _CONN_MASK


# ── Completion record ────────────────────────────────────────────────────────


@fieldwise_init
struct UringCompletion(Copyable, ImplicitlyCopyable, Movable):
    """A decoded io_uring completion, suitable for the
    server reactor's hot-path dispatch.

    Fields:
        op: One of ``URING_OP_*``.
        conn_id: Connection slot id from the original SQE tag.
        res: ``IoUringCqe.res()``; negative on failure
            (``-errno``).
        flags: ``IoUringCqe.flags()``; carries
            ``IORING_CQE_F_MORE`` (multishot still armed) and
            ``IORING_CQE_F_BUFFER`` (kernel-picked buffer id in
            the high 16 bits).
        has_more: True iff the originating multishot is still
            armed.
    """

    var op: UInt64
    var conn_id: UInt64
    var res: Int
    var flags: UInt32
    var has_more: Bool

    @always_inline
    def is_error(self) -> Bool:
        """Convenience: ``res < 0``."""
        return self.res < 0

    @always_inline
    def errno(self) -> Int:
        """Convenience: ``-res`` if it's an error, else 0."""
        if self.res >= 0:
            return 0
        return -self.res


@always_inline
def _cqe_to_completion(cqe: IoUringCqe) -> UringCompletion:
    """Decode an :class:`IoUringCqe` into a high-level
    :class:`UringCompletion` ready for the server reactor."""
    var ud = cqe.user_data()
    return UringCompletion(
        op=unpack_op(ud),
        conn_id=unpack_conn_id(ud),
        res=cqe.res(),
        flags=cqe.flags(),
        has_more=cqe.has_more(),
    )
