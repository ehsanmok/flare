"""``SO_REUSEPORT`` helpers for thread-per-core listeners.

On Linux (kernel >= 3.9) and macOS, multiple listening sockets can
bind to the same port when every listener has ``SO_REUSEPORT`` set;
the kernel then round-robins incoming connections across the set of
listeners. This is the shape a thread-per-core HTTP server wants:
N workers, each with its own listener, the kernel doing fair
dispatch.

``flare.tcp.TcpListener`` already exposes ``bind_with_options``; this
module just gives the multicore scheduler a self-documenting
function name (``bind_reuseport``) and a small sanity check over the
returned listener's address.
"""

from ..net import SocketAddr
from ..tcp import TcpListener


def bind_reuseport(addr: SocketAddr, backlog: Int = 1024) raises -> TcpListener:
    """Bind a ``TcpListener`` with ``SO_REUSEPORT`` enabled.

    Multiple workers can call ``bind_reuseport`` with the same
    ``addr`` and the kernel load-balances accepted connections
    across them by hashing the connection 4-tuple to one of the
    bound listeners.

    .. note::

       The 4-tuple hash distribution is uneven under bursty
       connection arrival: a 256-connection storm from a wrk2-style
       load generator can land 80+ conns on one listener and 30 on
       another. v0.6 prefers the shared-listener path
       (``bind_shared`` + ``Reactor.register_exclusive``) for
       multi-worker servers because the kernel-driven exclusive
       wakeup gives a fairer accept-time distribution. ``bind_reuseport``
       remains available for the multi-process load-balancing case
       across separate flare processes (where shared-fd inheritance
       is impossible) and for backward compatibility with v0.5.x
       benchmarks.

    Args:
        addr:    Local address to bind.
        backlog: Listen backlog (default 1024 — higher than the
            single-worker 128 so a burst of SYNs is less likely to
            overflow before any worker picks them up).

    Returns:
        A ``TcpListener`` ready to call ``accept()``. Close by
        dropping the handle; the underlying socket is owned by the
        listener.

    Raises:
        AddressInUse: If a previous bind did not set
            ``SO_REUSEPORT`` on the same port.
        NetworkError: For any other OS error.
    """
    return TcpListener.bind_with_options(addr, backlog=backlog, reuse_port=True)


def bind_shared(addr: SocketAddr, backlog: Int = 1024) raises -> TcpListener:
    """Bind a single ``TcpListener`` to be shared across workers (v0.6).

    The multi-worker ``Scheduler`` (v0.6) creates ONE listener via
    ``bind_shared``, then hands its fd to every worker. Each worker
    registers the fd in its own ``Reactor`` with
    ``Reactor.register_exclusive``, which sets ``EPOLLEXCLUSIVE`` on
    Linux (>= 4.5) so the kernel wakes only one worker per
    accept-event. On macOS / kqueue the flag is unavailable and the
    accept side falls back to non-blocking ``accept()`` returning
    ``EAGAIN`` for losers, so the wakeup pattern is "wake-all,
    one-wins" but practically still bounded by the single accept
    queue.

    Compared to ``bind_reuseport``, this avoids the 4-tuple-hash
    distribution variance that produces head-of-line tail latency on
    a busy worker — the kernel's exclusive wakeup naturally routes
    new accepts to whichever worker is currently waiting in
    ``epoll_wait``.

    Only one process can hold a ``bind_shared`` listener for a given
    port at a time. For cross-process load balancing (multiple
    flare processes on the same port), use ``bind_reuseport``.

    Args:
        addr:    Local address to bind.
        backlog: Listen backlog (default 1024). With ``EPOLLEXCLUSIVE``
            the accept queue is shared across all workers so the
            backlog can be the same as the single-worker default
            without head-of-line risk.

    Returns:
        A ``TcpListener`` ready to be shared. The caller (typically
        ``Scheduler``) owns the listener and is responsible for
        closing it on shutdown — workers receive the fd as an
        ``Int`` and must NOT close it.

    Raises:
        AddressInUse: If the port is already in use.
        NetworkError: For any other OS bind/listen error.
    """
    return TcpListener.bind_with_options(
        addr, backlog=backlog, reuse_port=False
    )
