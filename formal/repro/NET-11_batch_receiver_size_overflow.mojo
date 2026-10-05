# PLATFORM: any
# RESOLVED: NET-11 fixed on fix/formal-findings
"""NET-11: BatchReceiver sizes its data region with an unchecked Int product.

Lean: Flare.Bugs.NET_11.allocSize_wraps (counterexample) and
Flare.Bugs.NET_11.covers_fixed (fix meets spec).
flare/udp/batch.mojo:176-206 @59bda50.

Expected: the data region holds capacity * max_payload bytes, so the
span [data, data + max_payload) that iovec 0 hands to recvmmsg belongs to
the receiver alone (or the constructor refuses the arguments).
Before the fix: only `capacity > 0 and max_payload > 0` is asserted. With
capacity = 16 and max_payload = 2^60 the product wraps to 0, the data
region is a 0-byte allocation, and iovec 0 still announces 2^60 bytes.
A buffer allocated right after the receiver lies inside that span; on
Linux the repro also runs recv() on one queued datagram and shows that
recvmmsg overwrites that unrelated buffer.

Minimal fix: make __init__ raise when capacity > Int.MAX // max_payload
(and likewise guard capacity * _MMSGHDR).
"""

from std.memory import Layout, alloc
from std.sys.info import CompilationTarget
from flare.net import SocketAddr
from flare.udp import UdpSocket
from flare.udp.batch import BatchReceiver


def _peek_u64(addr: Int) -> Int:
    var p = Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=addr)
    var v = 0
    for k in range(8):
        v |= Int(p.unsafe_offset(k)[]) << (8 * k)
    return v


def main() raises:
    var cap = 16
    var mp = 1 << 60
    var rx: BatchReceiver
    try:
        rx = BatchReceiver(capacity=cap, max_payload=mp)
    except e:
        print("OK: BatchReceiver refused capacity=16, max_payload=2^60:", e)
        return
    var canary = alloc(Layout[UInt8](count=8)).unsafe_leak()
    for k in range(8):
        canary.unsafe_offset(k).unsafe_write(UInt8(0xAA))
    var data = Int(rx._data)
    var iov0_base = _peek_u64(Int(rx._iov))
    var iov0_len = _peek_u64(Int(rx._iov) + 8)
    var c = Int(canary)
    if iov0_base != data or iov0_len != mp:
        print("inconclusive: iovec 0 is", iov0_base, iov0_len)
        raise Error("NET-11 inconclusive")
    if not (c >= data and c < data + 256):
        print(
            "inconclusive: next allocation is not near the data region:",
            hex(c),
            hex(data),
        )
        raise Error("NET-11 inconclusive")
    var detail = (
        String("data region is a wrapped capacity*max_payload = ")
        + String(cap * mp)
        + " byte allocation at "
        + hex(data)
        + "; iovec 0 announces "
        + String(iov0_len)
        + " bytes there; a later 8-byte allocation sits at "
        + hex(c)
    )
    comptime if CompilationTarget.is_linux():
        var sock = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
        var tx = UdpSocket.bind(SocketAddr.parse("127.0.0.1:0"))
        var payload = List[UInt8](length=512, fill=UInt8(0x55))
        _ = tx.send_to(payload, sock.local_addr())
        var n = 0
        try:
            n = rx.recv(sock.fd())
        except e:
            print("inconclusive: recv raised", e)
            raise Error("NET-11 inconclusive")
        _ = sock.local_addr()
        _ = tx.local_addr()
        var hit = 0
        for k in range(8):
            if Int(canary.unsafe_offset(k)[]) == 0x55:
                hit += 1
        if n < 1 or hit != 8:
            print(
                "inconclusive: recv returned",
                n,
                "and",
                hit,
                "canary bytes changed",
            )
            raise Error("NET-11 inconclusive")
        print(
            "BUG REPRODUCED:",
            detail,
            "; recvmmsg of a 512-byte datagram overwrote all 8 of its bytes",
        )
        raise Error("NET-11")
    print("BUG REPRODUCED:", detail, "(inside iovec 0's span)")
    raise Error("NET-11")
