"""Receive-completion decisions and provided-buffer accounting for the
io_uring buffer-ring server loop.

This is the sans-I/O kernel of ``run_uring_bufring_reactor_loop_shared``
(``flare/http/_server_reactor_uring.mojo``): the loop asks
:func:`classify_recv` what to do with every receive completion and does
exactly that. ``formal/Flare/Kernels/BufLedger.lean`` proves the decisions
never lose or double-return a provided buffer, so ``in_ring + in_cq ==
ring_size`` holds across any sequence of kernel fills and completions.
Issue #37 was a decision that skipped a stale completion without
returning its buffer, which drained the ring until every receive failed
with ``-ENOBUFS``.
"""


comptime RECV_STAGE: Int = 0
"""Copy the received bytes into the connection's read buffer."""
comptime RECV_DROP: Int = 1
"""The connection is already gone (a stale completion): skip it."""
comptime RECV_CLOSE: Int = 2
"""Error, EOF, or no buffer to read from: clean the connection up."""


@fieldwise_init
struct RecvDecision(Copyable, ImplicitlyCopyable):
    """What the loop does with one receive completion.

    ``action`` is one of ``RECV_*``. ``return_buf`` says whether the loop
    gives the completion's provided buffer back to the ring: after copying
    the bytes for ``RECV_STAGE``, before skipping or cleaning up otherwise.
    """

    var action: Int
    var return_buf: Bool


def classify_recv(conn_live: Bool, res: Int, has_buf: Bool) -> RecvDecision:
    """Decide how the loop handles a receive completion.

    Args:
        conn_live: The completion's conn_id is still in the loop's table.
        res: The completion result: bytes received, 0 on EOF, ``-errno``.
        has_buf: The completion carries ``IORING_CQE_F_BUFFER``, so the
            kernel took one provided buffer out of the ring for it.

    Returns:
        The action, and whether to return the buffer. Every completion
        that took a buffer gives it back exactly once, whatever the action.
    """
    if not conn_live:
        return RecvDecision(RECV_DROP, has_buf)
    if res <= 0 or not has_buf:
        return RecvDecision(RECV_CLOSE, has_buf)
    return RecvDecision(RECV_STAGE, has_buf)


struct BufLedger(Copyable, Movable):
    """Where the ring's provided buffers are: ``in_ring`` are available to
    the kernel, ``in_cq`` are held by receive completions the loop has not
    processed yet.

    The loop itself keeps no counters; this models it for tests and for
    the Lean differential test (``formal/difftest``), driving every
    decision through :func:`classify_recv`.
    """

    var ring_size: Int
    var in_ring: Int
    var in_cq: Int
    var enobufs: Int

    def __init__(out self, ring_size: Int):
        self.ring_size = ring_size
        self.in_ring = ring_size
        self.in_cq = 0
        self.enobufs = 0

    def on_fill(mut self) -> Bool:
        """The kernel completes a receive into a provided buffer.

        Returns False, and counts an ``-ENOBUFS`` completion, when the
        ring is empty.
        """
        if self.in_ring == 0:
            self.enobufs += 1
            return False
        self.in_ring -= 1
        self.in_cq += 1
        return True

    def on_complete(
        mut self, conn_live: Bool, res: Int, has_buf: Bool
    ) -> RecvDecision:
        """The loop processes one receive completion. ``has_buf`` needs a
        completion that holds a buffer, i.e. ``in_cq > 0``."""
        var d = classify_recv(conn_live, res, has_buf)
        if has_buf:
            self.in_cq -= 1
        if d.return_buf:
            self.in_ring += 1
        return d
