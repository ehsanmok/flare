"""Batched UDP I/O: ``recvmmsg`` / ``sendmmsg`` + GSO segmentation.

A QUIC server's hot loop is dominated by per-datagram syscalls: one
``recvfrom`` per inbound packet, one ``sendto`` per outbound packet.
Under a burst that is N syscalls for N datagrams. Linux's
``recvmmsg(2)`` / ``sendmmsg(2)`` move a whole vector of datagrams
across the user/kernel boundary in a single call, and UDP generic
segmentation offload (GSO, ``UDP_SEGMENT``) lets one ``sendmsg`` hand
the kernel a big buffer that it slices into many equal-sized wire
datagrams. Together these cut the syscall count on a saturated path by
~Nx.

These syscalls are Linux-only and version-gated (``recvmmsg`` 2.6.33,
``sendmmsg`` 3.0, ``UDP_SEGMENT`` 4.18). This module is the capability
probe + safe wrapper:

* :func:`udp_batch_supported` -- compile-time Linux gate. On any other
  target the helpers are never reached; callers use the per-datagram
  path.
* :class:`UdpBatchUnsupported` -- raised when a *running* kernel lacks
  the syscall (``ENOSYS``). Callers catch it once and latch back to the
  per-datagram path for the rest of the process lifetime.
* :class:`BatchReceiver` -- owns the ``struct mmsghdr[]`` + ``iovec[]``
  + name + data arrays and drains a burst with one ``recvmmsg``.
* :func:`send_batch` -- one ``sendmmsg`` for a vector of
  (payload, destination) pairs.
* :func:`send_segmented` -- one GSO ``sendmsg`` that slices ``data``
  into ``seg_size`` wire datagrams to a single destination.

Struct layout (x86_64 / aarch64 Linux, the only targets these calls
run on):

    struct iovec   { void *base; size_t len; }              // 16 B
    struct msghdr  { void *name; socklen_t namelen; (pad)   //  0,  8
                     struct iovec *iov; size_t iovlen;       // 16, 24
                     void *control; size_t controllen;       // 32, 40
                     int flags; (pad) }                      // 48  -> 56 B
    struct mmsghdr { struct msghdr hdr; unsigned len; (pad)} // 56  -> 64 B

The arrays are modeled as flat ``UnsafePointer[UInt8]`` regions with
the fields poked at fixed offsets, mirroring
``flare.runtime.iovec.IoVecBuf``.

ponytail: IPv4 + IPv6 sized name slots (28 B) but the wire structs are
pinned to the 64-bit Linux ABI -- the only ABI where these syscalls
exist in this codebase. A 32-bit Linux port would need different
offsets (upgrade path: branch the comptime offsets on pointer width).
"""

from std.ffi import c_int, c_uint, get_errno, ErrNo
from std.memory import UnsafePointer, alloc
from std.sys.info import CompilationTarget
from std.format import Writable, Writer

from ..net import SocketAddr, NetworkError
from ..net.socket import _build_sockaddr_in, _sockaddr_to_socket_addr
from ..net._libc import (
    _recvmmsg,
    _sendmmsg,
    _sendmsg,
    _strerror,
    MSG_DONTWAIT,
    IPPROTO_UDP,
)


# ── Wire struct sizes / offsets (64-bit Linux ABI) ───────────────────────────
comptime _IOVEC: Int = 16
comptime _MSGHDR: Int = 56
comptime _MMSGHDR: Int = 64
comptime _NAME: Int = 28  # sockaddr_in6 (>= sockaddr_in 16)

# msghdr field offsets
comptime _OFF_NAME: Int = 0
comptime _OFF_NAMELEN: Int = 8
comptime _OFF_IOV: Int = 16
comptime _OFF_IOVLEN: Int = 24
comptime _OFF_CONTROL: Int = 32
comptime _OFF_CONTROLLEN: Int = 40
comptime _OFF_FLAGS: Int = 48
# mmsghdr.msg_len offset (after the embedded msghdr)
comptime _OFF_MSGLEN: Int = 56

# ── GSO control message (SOL_UDP / UDP_SEGMENT) ──────────────────────────────
comptime SOL_UDP: c_int = IPPROTO_UDP  # 17
comptime UDP_SEGMENT: c_int = 103
# struct cmsghdr { size_t len; int level; int type; } = 16 B header.
comptime _CMSG_HDR: Int = 16
# CMSG_LEN(sizeof(u16)) = 16 + 2 = 18; padded space = 24.
comptime _CMSG_DATA_OFF: Int = 16
comptime _CMSG_LEN_GSO: Int = 18
comptime _CMSG_SPACE_GSO: Int = 24


@always_inline
def udp_batch_supported() -> Bool:
    """``True`` when batched UDP syscalls can be attempted.

    Compile-time Linux gate. A ``True`` result still does not promise
    the *running* kernel implements the syscall -- the first call may
    raise :class:`UdpBatchUnsupported` (``ENOSYS``), which the caller
    latches to disable the path. On macOS / other targets this is
    ``False`` and the wrappers are never invoked.
    """
    return CompilationTarget.is_linux()


struct UdpBatchUnsupported(Copyable, Movable, Writable):
    """Raised when the running kernel lacks ``recvmmsg`` / ``sendmmsg``
    (``ENOSYS``). The caller falls back to per-datagram I/O."""

    var op: String

    def __init__(out self, op: String):
        self.op = op

    def write_to[W: Writer](self, mut writer: W):
        writer.write("UdpBatchUnsupported: ", self.op, " (ENOSYS)")


@always_inline
def _poke_u64(p: UnsafePointer[UInt8, MutUntrackedOrigin], off: Int, v: UInt64):
    for k in range(8):
        (p + off + k).init_pointee_copy(UInt8(Int((v >> UInt64(k * 8)) & 0xFF)))


@always_inline
def _poke_u32(p: UnsafePointer[UInt8, MutUntrackedOrigin], off: Int, v: UInt32):
    for k in range(4):
        (p + off + k).init_pointee_copy(UInt8(Int((v >> UInt32(k * 8)) & 0xFF)))


@always_inline
def _poke_u16(p: UnsafePointer[UInt8, MutUntrackedOrigin], off: Int, v: UInt16):
    (p + off).init_pointee_copy(UInt8(Int(v & 0xFF)))
    (p + off + 1).init_pointee_copy(UInt8(Int((v >> 8) & 0xFF)))


@always_inline
def _peek_u32(p: UnsafePointer[UInt8, MutUntrackedOrigin], off: Int) -> UInt32:
    var v = UInt32(0)
    for k in range(4):
        v = v | (UInt32(Int((p + off + k)[])) << UInt32(k * 8))
    return v


struct BatchReceiver(Movable):
    """Owns the ``mmsghdr`` vector + backing buffers for a single
    ``recvmmsg`` drain of up to ``capacity`` datagrams.

    Reuse one receiver across reactor ticks: :meth:`recv` re-arms the
    per-message lengths in place, so steady-state has zero allocation.

    Example:
        ```mojo
        var rx = BatchReceiver(capacity=64, max_payload=1500)
        var n = rx.recv(sock.fd())
        for i in range(n):
            var dg = rx.message(i)        # Span[UInt8] of the payload
            var who = rx.sender(i)        # SocketAddr of the source
        ```
    """

    var _mmsg: UnsafePointer[UInt8, MutUntrackedOrigin]
    var _iov: UnsafePointer[UInt8, MutUntrackedOrigin]
    var _names: UnsafePointer[UInt8, MutUntrackedOrigin]
    var _data: UnsafePointer[UInt8, MutUntrackedOrigin]
    var _capacity: Int
    var _max_payload: Int
    var _count: Int

    def __init__(out self, capacity: Int, max_payload: Int):
        """Allocate the vector for ``capacity`` datagrams of at most
        ``max_payload`` bytes each.

        Args:
            capacity: Max datagrams drained per :meth:`recv`. Must be > 0.
            max_payload: Per-datagram buffer size (e.g. the connection's
                max UDP payload). Must be > 0.
        """
        debug_assert[assert_mode="safe"](
            capacity > 0 and max_payload > 0,
            "BatchReceiver: capacity and max_payload must be positive",
        )
        self._capacity = capacity
        self._max_payload = max_payload
        self._count = 0
        self._mmsg = _alloc_zeroed(capacity * _MMSGHDR)
        self._iov = _alloc_zeroed(capacity * _IOVEC)
        self._names = _alloc_zeroed(capacity * _NAME)
        self._data = _alloc_zeroed(capacity * max_payload)
        # Wire the static pointers once: each msghdr points at its own
        # name slot + a one-cell iovec into its data slot.
        for i in range(capacity):
            var hdr = self._mmsg + i * _MMSGHDR
            var iov = self._iov + i * _IOVEC
            _poke_u64(iov, 0, UInt64(Int(self._data) + i * max_payload))
            _poke_u64(iov, 8, UInt64(max_payload))
            _poke_u64(hdr, _OFF_NAME, UInt64(Int(self._names) + i * _NAME))
            _poke_u32(hdr, _OFF_NAMELEN, UInt32(_NAME))
            _poke_u64(hdr, _OFF_IOV, UInt64(Int(self._iov) + i * _IOVEC))
            _poke_u64(hdr, _OFF_IOVLEN, UInt64(1))

    def __del__(deinit self):
        if Int(self._mmsg) != 0:
            self._mmsg.free()
        if Int(self._iov) != 0:
            self._iov.free()
        if Int(self._names) != 0:
            self._names.free()
        if Int(self._data) != 0:
            self._data.free()

    def recv(mut self, fd: Int) raises -> Int:
        """Drain up to ``capacity`` datagrams with one non-blocking
        ``recvmmsg``.

        Returns the number of datagrams received (0 when the socket
        queue is empty -- ``EAGAIN`` / ``EWOULDBLOCK``).

        Raises:
            UdpBatchUnsupported: kernel lacks ``recvmmsg`` (``ENOSYS``).
            NetworkError: any other libc errno.
        """
        # Re-arm the kernel-mutated input field (msg_namelen) for every
        # cell; iov_len is read-only to the kernel so it stays put.
        for i in range(self._capacity):
            _poke_u32(
                self._mmsg + i * _MMSGHDR + _OFF_NAMELEN, 0, UInt32(_NAME)
            )
        var ret = _recvmmsg(
            c_int(fd),
            self._mmsg,
            c_uint(self._capacity),
            MSG_DONTWAIT,
            0,  # NULL timeout: MSG_DONTWAIT keeps it non-blocking
        )
        if ret < 0:
            var e = get_errno()
            if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                self._count = 0
                return 0
            if e == ErrNo.ENOSYS:
                raise UdpBatchUnsupported("recvmmsg")
            raise NetworkError(_strerror(e.value) + " (recvmmsg)", Int(e.value))
        self._count = Int(ret)
        return self._count

    def count(self) -> Int:
        """Number of datagrams from the last :meth:`recv`."""
        return self._count

    def message(self, i: Int) -> Span[UInt8, MutUntrackedOrigin]:
        """Borrow the ``i``-th received datagram's payload.

        The span aliases the receiver's internal buffer and is only
        valid until the next :meth:`recv`. Bounds-checked under
        ``-D ASSERT=safe``.
        """
        debug_assert[assert_mode="safe"](
            i >= 0 and i < self._count,
            "BatchReceiver.message: index out of range",
        )
        var n = Int(_peek_u32(self._mmsg + i * _MMSGHDR + _OFF_MSGLEN, 0))
        if n > self._max_payload:
            n = self._max_payload  # MSG_TRUNC guard
        return Span[UInt8, MutUntrackedOrigin](
            ptr=self._data + i * self._max_payload, length=n
        )

    def sender(self, i: Int) raises -> SocketAddr:
        """Decode the ``i``-th datagram's source address."""
        debug_assert[assert_mode="safe"](
            i >= 0 and i < self._count,
            "BatchReceiver.sender: index out of range",
        )
        return _sockaddr_to_socket_addr(self._names + i * _NAME)


def _alloc_zeroed(n: Int) -> UnsafePointer[UInt8, MutUntrackedOrigin]:
    var raw = alloc[UInt8](n)
    for i in range(n):
        (raw + i).init_pointee_copy(UInt8(0))
    return UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=Int(raw)
    )


def send_batch(
    fd: Int,
    payloads: List[List[UInt8]],
    addrs: List[SocketAddr],
) raises -> Int:
    """Send a vector of (payload, destination) pairs with one
    ``sendmmsg``.

    Args:
        fd: UDP socket fd.
        payloads: One byte buffer per datagram.
        addrs: Matching destination addresses (``len == len(payloads)``).

    Returns:
        Number of datagrams the kernel accepted (may be < requested on a
        partial send; the caller resends the tail).

    Raises:
        UdpBatchUnsupported: kernel lacks ``sendmmsg`` (``ENOSYS``).
        NetworkError: any other libc errno.
    """
    var n = len(payloads)
    debug_assert[assert_mode="safe"](
        n == len(addrs), "send_batch: payloads / addrs length mismatch"
    )
    if n == 0:
        return 0
    var mmsg = _alloc_zeroed(n * _MMSGHDR)
    var iov = _alloc_zeroed(n * _IOVEC)
    # One heap sockaddr per datagram; freed after the call.
    var sas = List[type_of(_build_sockaddr_in(addrs[0])[0])]()
    try:
        for i in range(n):
            var sa = _build_sockaddr_in(addrs[i])
            var sa_ptr = Int(sa[0])
            var sa_len = Int(sa[1])
            sas.append(sa[0])
            var cell_iov = iov + i * _IOVEC
            _poke_u64(cell_iov, 0, UInt64(Int(payloads[i].unsafe_ptr())))
            _poke_u64(cell_iov, 8, UInt64(len(payloads[i])))
            var hdr = mmsg + i * _MMSGHDR
            _poke_u64(hdr, _OFF_NAME, UInt64(sa_ptr))
            _poke_u32(hdr, _OFF_NAMELEN, UInt32(sa_len))
            _poke_u64(hdr, _OFF_IOV, UInt64(Int(iov) + i * _IOVEC))
            _poke_u64(hdr, _OFF_IOVLEN, UInt64(1))
        var ret = _sendmmsg(c_int(fd), mmsg, c_uint(n), c_int(0))
        if ret < 0:
            var e = get_errno()
            mmsg.free()
            iov.free()
            for j in range(len(sas)):
                sas[j].free()
            if e == ErrNo.ENOSYS:
                raise UdpBatchUnsupported("sendmmsg")
            raise NetworkError(_strerror(e.value) + " (sendmmsg)", Int(e.value))
        mmsg.free()
        iov.free()
        for j in range(len(sas)):
            sas[j].free()
        return Int(ret)
    except e:
        # Defensive: free anything still owned on an unexpected raise
        # from _build_sockaddr_in mid-loop.
        if Int(mmsg) != 0:
            mmsg.free()
        if Int(iov) != 0:
            iov.free()
        for j in range(len(sas)):
            sas[j].free()
        raise e^


def send_segmented(
    fd: Int,
    addr: SocketAddr,
    data: Span[UInt8, _],
    seg_size: Int,
) raises -> Int:
    """Send ``data`` to ``addr`` as GSO segments of ``seg_size`` bytes.

    One ``sendmsg`` hands the kernel the whole ``data`` buffer plus a
    ``UDP_SEGMENT`` control message; the kernel (or NIC) slices it into
    wire datagrams of ``seg_size`` bytes (the final one may be shorter).
    The socket must already be 1-RTT-saturated to the same destination
    for this to help; it is a pure egress optimization.

    Returns bytes accepted by the kernel.

    Raises:
        UdpBatchUnsupported: kernel lacks ``UDP_SEGMENT`` (``EINVAL`` on
            the cmsg is mapped here as unsupported).
        NetworkError: any other libc errno.
    """
    debug_assert[assert_mode="safe"](
        seg_size > 0 and seg_size <= 0xFFFF,
        "send_segmented: seg_size out of range",
    )
    var sa = _build_sockaddr_in(addr)
    var sa_ptr = Int(sa[0])
    var sa_len = Int(sa[1])
    var iov = _alloc_zeroed(_IOVEC)
    var ctrl = _alloc_zeroed(_CMSG_SPACE_GSO)
    var hdr = _alloc_zeroed(_MSGHDR)
    _poke_u64(iov, 0, UInt64(Int(data.unsafe_ptr())))
    _poke_u64(iov, 8, UInt64(len(data)))
    # cmsghdr { len=CMSG_LEN(2); level=SOL_UDP; type=UDP_SEGMENT } + u16 size
    _poke_u64(ctrl, 0, UInt64(_CMSG_LEN_GSO))
    _poke_u32(ctrl, 8, UInt32(Int(SOL_UDP)))
    _poke_u32(ctrl, 12, UInt32(Int(UDP_SEGMENT)))
    _poke_u16(ctrl, _CMSG_DATA_OFF, UInt16(seg_size))
    _poke_u64(hdr, _OFF_NAME, UInt64(sa_ptr))
    _poke_u32(hdr, _OFF_NAMELEN, UInt32(sa_len))
    _poke_u64(hdr, _OFF_IOV, UInt64(Int(iov)))
    _poke_u64(hdr, _OFF_IOVLEN, UInt64(1))
    _poke_u64(hdr, _OFF_CONTROL, UInt64(Int(ctrl)))
    _poke_u64(hdr, _OFF_CONTROLLEN, UInt64(_CMSG_LEN_GSO))
    var ret = _sendmsg(c_int(fd), hdr, c_int(0))
    var e = get_errno()
    sa[0].free()
    iov.free()
    ctrl.free()
    hdr.free()
    if ret < 0:
        if e == ErrNo.ENOSYS or e == ErrNo.EINVAL or e == ErrNo.ENOPROTOOPT:
            raise UdpBatchUnsupported("sendmsg/UDP_SEGMENT")
        raise NetworkError(_strerror(e.value) + " (sendmsg)", Int(e.value))
    return Int(ret)
