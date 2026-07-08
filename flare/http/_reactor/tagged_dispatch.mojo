"""Tagged-pointer dispatch helpers for the unified HTTP/1+HTTP/2 reactor.

The packed ``(kind << TAG_SHIFT) | addr`` dict-value encoding that lets
:mod:`flare.http._unified_reactor_impl` keep all three per-connection
state machines (PendingConnHandle / ConnHandle / Http2ConnHandle) in one
``Dict[Int, Int]`` table with a single lookup + bitshift per event.
Split out of ``_unified_reactor_impl.mojo`` to keep that module within
the file-size budget; the reactor imports these back unchanged.
"""

# ── Tagged-pointer dispatch ───────────────────────────────────────────────
#
# All three per-conn state machines (PendingConnHandle / ConnHandle /
# Http2ConnHandle) live in a single ``conns: Dict[Int, Int]`` table where
# each value is a packed ``(kind << TAG_SHIFT) | addr`` int. Linux
# x86_64 limits user-space virtual addresses to 47 bits (canonical
# form), and macOS arm64 to 47 bits as well, so the top 17 bits of any
# real heap address are always zero -- safe to repurpose.
#
# Why a single dict instead of the three-dict shape (pending_conns +
# h1_conns + h2_conns): every reactor event paid 3× ``fd in dict``
# lookups under the three-dict shape, which cost ~3.8% steady-state
# throughput on the keep-alive plaintext benchmark vs the legacy
# HTTP/1.1-only loop. Tagged dispatch collapses that to one dict op
# plus a 1-cycle bitshift+mask -- recovers the regression in full.

comptime _TAG_SHIFT: Int = 56
"""Number of bits the kind tag is shifted above the addr in the
packed dict value. 56 leaves 56 bits for the addr (heap addresses
fit in 47 bits on Linux x86_64 / macOS arm64; the extra slack is
deliberate)."""

comptime _ADDR_MASK: Int = (1 << _TAG_SHIFT) - 1
"""Mask to recover the addr bits from a packed value."""

comptime KIND_PENDING: Int = 0
"""Tag: addr points at a :class:`PendingConnHandle`."""

comptime KIND_H1: Int = 1
"""Tag: addr points at a :class:`flare.http._server_reactor_impl.ConnHandle`."""

comptime KIND_H2: Int = 2
"""Tag: addr points at a :class:`Http2ConnHandle`."""


@always_inline
def _pack(kind: Int, addr: Int) -> Int:
    """Pack ``(kind, addr)`` into the dict-value Int."""
    return (kind << _TAG_SHIFT) | (addr & _ADDR_MASK)


@always_inline
def _kind(packed: Int) -> Int:
    """Recover the kind tag from a packed value."""
    return packed >> _TAG_SHIFT


@always_inline
def _addr(packed: Int) -> Int:
    """Recover the addr bits from a packed value."""
    return packed & _ADDR_MASK
