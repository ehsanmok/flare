"""Multi-worker QUIC: which worker owns a connection ID, and the inbox
a worker forwards another worker's packets through.

Each worker of a multi-worker listener has its own ``SO_REUSEPORT`` UDP
socket, so the kernel spreads flows by 4-tuple. A connection keeps its
4-tuple, and so its worker, until the client migrates or a NAT rebinds
it; then its packets can land on any worker. Server-chosen connection
IDs therefore name their owner: ``HMAC-SHA256(route key, CID)[0] mod N``,
drawn so that it equals the issuing worker. The owner is not readable
without the key, so a CID does not link a client's paths to one server
(the concern QUIC-LB's encrypted server IDs address). A worker that
receives a short-header packet for an unknown CID owned by another
worker hands it to that worker's :class:`DatagramInbox` instead of
answering with a stateless reset.
"""

from std.collections import List
from std.memory import Layout, Pointer, alloc

from flare.crypto.hmac import hmac_sha256
from flare.net import SocketAddr
from flare.runtime.handoff import (
    _MUTEX_BYTES,
    _mutex_init,
    _mutex_lock,
    _mutex_unlock,
)


comptime _INBOX_MAX_BYTES: Int = 4 * 1024 * 1024
"""Most forwarded bytes an inbox holds; past it datagrams are dropped
(the peer's loss recovery re-sends them)."""


def cid_owner(key: List[UInt8], cid: List[UInt8], workers: Int) raises -> Int:
    """The worker that owns ``cid`` among ``workers``."""
    if workers <= 1:
        return 0
    return Int(hmac_sha256(key, cid)[0]) % workers


struct DatagramInbox(Movable):
    """Datagrams forwarded to one worker by the others. Shared across
    threads through its heap address; every access holds the mutex."""

    var mu: Pointer[UInt8, MutUntrackedOrigin]
    var data: List[UInt8]
    var lens: List[Int]
    var peers: List[SocketAddr]

    def __init__(out self):
        self.mu = alloc(Layout[UInt8](count=_MUTEX_BYTES)).unsafe_leak()
        for i in range(_MUTEX_BYTES):
            self.mu[unsafe_offset=i] = UInt8(0)
        _ = _mutex_init(self.mu)
        self.data = List[UInt8]()
        self.lens = List[Int]()
        self.peers = List[SocketAddr]()

    def push(mut self, datagram: Span[UInt8, _], peer: SocketAddr) -> Bool:
        """Queue one datagram; False (dropped) when the inbox is full."""
        _mutex_lock(self.mu)
        var ok = len(self.data) + len(datagram) <= _INBOX_MAX_BYTES
        if ok:
            self.data.extend(datagram)
            self.lens.append(len(datagram))
            self.peers.append(peer)
        _mutex_unlock(self.mu)
        return ok

    def take(
        mut self,
        mut data: List[UInt8],
        mut lens: List[Int],
        mut peers: List[SocketAddr],
    ):
        """Move everything queued into the (emptied) caller lists."""
        data.clear()
        lens.clear()
        peers.clear()
        _mutex_lock(self.mu)
        swap(data, self.data)
        swap(lens, self.lens)
        swap(peers, self.peers)
        _mutex_unlock(self.mu)


def new_inbox_table(workers: Int) -> Int:
    """Heap-allocate one :class:`DatagramInbox` per worker; returns the
    address of the table of their addresses. Freed by
    :func:`free_inbox_table` once every worker has stopped."""
    var table = alloc(Layout[Int](count=workers)).unsafe_leak()
    for w in range(workers):
        var box = alloc(Layout[DatagramInbox](count=1)).unsafe_leak()
        box.unsafe_write(DatagramInbox())
        table[unsafe_offset=w] = Int(box)
    return Int(table)


def inbox_at(
    table: Int, worker: Int
) -> Pointer[DatagramInbox, MutUntrackedOrigin]:
    """The inbox of ``worker`` in a table from :func:`new_inbox_table`."""
    var t = Pointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=table
    ).unsafe_bitcast[Int]()
    return Pointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=t[unsafe_offset=worker]
    ).unsafe_bitcast[DatagramInbox]()


def free_inbox_table(table: Int, workers: Int):
    """Free a table from :func:`new_inbox_table`, once no worker uses it."""
    if table == 0:
        return
    for w in range(workers):
        var box = inbox_at(table, w)
        box.unsafe_deinit_pointee()
        box.unsafe_bitcast[UInt8]().unsafe_free()
    Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=table).unsafe_free()
