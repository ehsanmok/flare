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
    across them.

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
