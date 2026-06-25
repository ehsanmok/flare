"""``flare.quic._server_support`` -- non-I/O helpers for the QUIC
server reactor.

Holds the pure helper functions and per-slot reassembly carriers
that :mod:`flare.quic.server` composes. Split out of ``server.mojo``
to keep the reactor file within the file-size budget; nothing here
touches the socket -- it is byte math, ASCII key parsing, the
monotonic clock shim, and the per-level CRYPTO reassembly state.

References:
- RFC 9000 §13.2.4 "Limiting Ranges by Tracking ACK Frames".
- RFC 9000 §19.3.1 "ACK Ranges".
- RFC 9000 §19.6 "CRYPTO Frames" -- per-level handshake stream.
- RFC 9000 §19.8 "STREAM Frames".
"""

from std.collections import List
from std.ffi import c_int, external_call
from std.memory import Span, stack_allocation
from std.os import getenv

from .frame import AckFrame, AckRange, EcnCounts
from .varint import encode_varint
from ..tls.rustls_quic import QuicEncryptionLevel


def _bufsize_from_env(name: String, default: Int) -> Int:
    """Read a byte-count override from environment ``name``.

    Returns ``default`` when the variable is unset or not a valid
    non-negative integer. A value of ``0`` is honored and means "leave
    the kernel default in place".
    """
    var raw = getenv(name)
    if raw.byte_length() == 0:
        return default
    try:
        var v = Int(raw)
        if v < 0:
            return default
        return v
    except:
        return default


# Cap on the number of disjoint ACK ranges tracked per connection.
# Bounds the per-slot memory; the oldest (lowest) ranges are dropped
# once the cap is hit (RFC 9000 sec 13.2.4 allows acking a subset).
comptime _ACK_MAX_RANGES: Int = 32


def _ack_record(mut flat: List[UInt64], pn: UInt64):
    """Insert ``pn`` into the disjoint received-pn ranges held in
    ``flat`` (a [low, high] pair list kept descending by ``high``).

    Re-normalizes by collecting the pairs, adding ``[pn, pn]``,
    sorting ascending, merging overlapping/adjacent ranges, capping
    to :data:`_ACK_MAX_RANGES` (keeping the highest), then storing
    back descending. The range count stays tiny so the cost is
    negligible per packet.
    """
    var lows = List[UInt64]()
    var highs = List[UInt64]()
    var i = 0
    while i + 1 < len(flat):
        lows.append(flat[i])
        highs.append(flat[i + 1])
        i += 2
    lows.append(pn)
    highs.append(pn)
    var n = len(lows)
    # Insertion sort ascending by low (n is small, <= cap + 1).
    for a in range(1, n):
        var kl = lows[a]
        var kh = highs[a]
        var b = a - 1
        while b >= 0 and lows[b] > kl:
            lows[b + 1] = lows[b]
            highs[b + 1] = highs[b]
            b -= 1
        lows[b + 1] = kl
        highs[b + 1] = kh
    var ml = List[UInt64]()
    var mh = List[UInt64]()
    for a in range(n):
        if len(ml) > 0 and lows[a] <= mh[len(mh) - 1] + UInt64(1):
            if highs[a] > mh[len(mh) - 1]:
                mh[len(mh) - 1] = highs[a]
        else:
            ml.append(lows[a])
            mh.append(highs[a])
    var start = 0
    if len(ml) > _ACK_MAX_RANGES:
        start = len(ml) - _ACK_MAX_RANGES
    flat.clear()
    var c = len(ml) - 1
    while c >= start:
        flat.append(ml[c])
        flat.append(mh[c])
        c -= 1


def _ack_from_ranges(flat: List[UInt64], ack_delay: UInt64) raises -> AckFrame:
    """Build an :class:`AckFrame` from the descending [low, high]
    pair list ``flat`` produced by :func:`_ack_record`.

    The first (highest) range supplies ``largest_acknowledged`` and
    ``first_ack_range``; each lower range becomes an explicit
    gap/length pair per RFC 9000 sec 19.3.1.
    """
    if len(flat) < 2:
        raise Error("_ack_from_ranges: empty range set")
    var largest = flat[1]
    var first_low = flat[0]
    var ranges = List[AckRange]()
    var prev_low = first_low
    var i = 2
    while i + 1 < len(flat):
        var low = flat[i]
        var high = flat[i + 1]
        # gap = prev_smallest - this_largest - 2; length = high - low.
        var gap = prev_low - high - UInt64(2)
        var length = high - low
        ranges.append(AckRange(gap=gap, length=length))
        prev_low = low
        i += 2
    return AckFrame(
        largest_acknowledged=largest,
        ack_delay=ack_delay,
        first_ack_range=largest - first_low,
        ranges=ranges^,
        ecn=List[EcnCounts](),
    )


def _encode_h3_stream_frame(
    mut out: List[UInt8],
    stream_id: UInt64,
    stream_bytes: Span[UInt8, _],
    fin: Bool,
) raises:
    """Append one QUIC STREAM frame (RFC 9000 sec 19.8) carrying
    ``stream_bytes`` for ``stream_id`` to ``out``.

    Frame type bits: ``0b00001 | OFF | LEN | FIN``. OFF + LEN are
    always set (offset 0, explicit length) so multiple STREAM
    frames coalesce unambiguously into one packet payload; FIN
    per the caller's flag. Used by the coalescing 1-RTT drain
    (:meth:`QuicListener._drain_1rtt_coalesced`) so it can pack
    many responses into a single 1-RTT datagram.
    """
    var frame_type: Int = 0x08 | 0x04 | 0x02
    if fin:
        frame_type |= 0x01
    out.append(UInt8(frame_type))
    var sid_var = encode_varint(stream_id)
    for i in range(len(sid_var)):
        out.append(sid_var[i])
    var off_var = encode_varint(UInt64(0))
    for i in range(len(off_var)):
        out.append(off_var[i])
    var len_var = encode_varint(UInt64(len(stream_bytes)))
    for i in range(len(len_var)):
        out.append(len_var[i])
    out.extend(stream_bytes)


def _stream_id_from_key(k: String) -> Int:
    """Parse the QUIC stream id out of an ``h3_response_egress``
    key of the form ``"<slot>:<stream_id>"`` (ASCII only, so
    byte-level iteration is safe). Returns -1 if the key has no
    colon or no digits after it.
    """
    var key_bytes = k.as_bytes()
    var sid = 0
    var found_colon = False
    var any_digit = False
    for j in range(len(key_bytes)):
        var b = Int(key_bytes[j])
        if not found_colon:
            if b == 0x3A:  # ':'
                found_colon = True
            continue
        if b < 0x30 or b > 0x39:
            continue
        sid = sid * 10 + (b - 0x30)
        any_digit = True
    if not found_colon or not any_digit:
        return -1
    return sid


def _inbound_level_for_datagram(datagram: Span[UInt8, _]) -> Int:
    """Derive the QUIC encryption level of an inbound datagram
    from its first byte.

    The MSB of the first byte is the header-form bit: 1 == long
    header, 0 == short header.  Long-header type bits 4-5 encode
    the packet type per RFC 9000 §17.2 (0=Initial, 1=0-RTT,
    2=Handshake, 3=Retry).  Short-header packets are always 1-RTT
    (RFC 9000 §17.3).

    Returns the matching :data:`QuicEncryptionLevel` codepoint.
    Empty datagrams and Retry packets fall back to INITIAL --
    Retry doesn't carry CRYPTO so the level choice is moot for
    the rustls dispatch (Retry decode is a separate path that
    never reaches `_dispatch_crypto_frames`).
    """
    if len(datagram) < 1:
        return QuicEncryptionLevel.INITIAL
    var first = Int(datagram[0])
    var is_long = (first & 0x80) != 0
    if not is_long:
        return QuicEncryptionLevel.APPLICATION
    var pt = (first & 0x30) >> 4
    if pt == 0:
        return QuicEncryptionLevel.INITIAL
    if pt == 1:
        return QuicEncryptionLevel.EARLY_DATA
    if pt == 2:
        return QuicEncryptionLevel.HANDSHAKE
    return QuicEncryptionLevel.INITIAL  # Retry -- moot for CRYPTO dispatch


def _ready_sentinel() -> List[UInt8]:
    """Single-byte readiness marker stamped onto
    :attr:`QuicConnection.rx_handshake_secret` /
    `.tx_handshake_secret` / `.rx_1rtt_secret` / `.tx_1rtt_secret`
    when rustls installs per-level `Keys`.

    rustls keeps `quic::Secrets` sealed (`pub(crate)`) and only
    hands back trait-object key handles, so post-Initial AEAD
    routes through `RustlsQuicSession.packet_{encrypt,decrypt}` +
    `.header_{encrypt,decrypt}`. The Mojo side never sees raw
    traffic secrets; the sentinel just flips the
    `len(rx_*_secret) == 0` readiness gates.
    """
    var out = List[UInt8]()
    out.append(UInt8(0xFF))
    return out^


def _monotonic_ms() -> UInt64:
    """Return the monotonic clock in milliseconds.

    Uses ``clock_gettime(CLOCK_MONOTONIC, ...)``. The constant value
    1 for ``CLOCK_MONOTONIC`` is portable between Linux and macOS
    (macOS has supported it since 10.12). Same shape as
    :func:`flare.http._reactor.keepalive_scan._monotonic_ms` but
    returns ``UInt64`` so it composes with :class:`TimerWheel`
    without an extra cast.
    """
    var buf = stack_allocation[16, UInt8]()
    for i in range(16):
        (buf + i).init_pointee_copy(UInt8(0))
    _ = external_call["clock_gettime", c_int](c_int(1), buf.bitcast[NoneType]())
    var sec: Int64 = 0
    var nsec: Int64 = 0
    for i in range(8):
        sec |= Int64(Int((buf + i).load())) << Int64(8 * i)
    for i in range(8):
        nsec |= Int64(Int((buf + 8 + i).load())) << Int64(8 * i)
    return UInt64(Int(sec) * 1000 + Int(nsec) // 1_000_000)


def _random_bytes(n: Int) -> List[UInt8]:
    """Return ``n`` unpredictable bytes from ``/dev/urandom``.

    Used for server-issued Connection IDs + stateless-reset tokens
    (RFC 9000 sec 5.1.1 / 10.3: both must be unguessable). Falls
    back to a clock-mixed deterministic fill only if urandom is
    unavailable (should not happen on Linux / macOS).
    """
    var out = List[UInt8](capacity=n)
    try:
        with open("/dev/urandom", "r") as f:
            var raw = f.read_bytes(n)
            for i in range(n):
                out.append(raw[i])
    except:
        var seed = _monotonic_ms()
        for i in range(n):
            out.append(
                UInt8(
                    Int((seed >> UInt64(i * 8)) & UInt64(0xFF))
                    ^ (i * 31 + 0x5A)
                )
            )
    return out^


# -- Per-slot rustls QUIC session carrier ------------------------------


@fieldwise_init
struct _SessionSlot(Copyable, Movable):
    """Per-slot rustls QUIC session state.

    Non-owning carrier: the per-listener slab
    (:attr:`QuicListener.tls_sessions`) is the sole owner of the
    Rust-side ``Box<Session>``. Every per-connection bridge call
    routes the FFI through the listener's pinned
    ``tls_acceptor._lib`` borrow so :class:`OwnedDLHandle`'s
    refcount keeps ``libflare_rustls_quic.so`` mapped across the
    call. The slab's element type is ``_SessionSlot`` rather than
    :class:`flare.tls.rustls_quic.RustlsQuicSession` because the
    latter is ``Movable``-only and ``List[T]`` requires
    ``T: Copyable``. Carrier copy is safe: the integer ``handle``
    is a non-owning view, and the slab's :meth:`QuicListener.__del__`
    is the unique site that calls
    :func:`flare.tls._rustls_quic_ffi._do_session_free` -- never
    a slot's destructor.
    """

    var handle: Int
    """Raw ``Box<Session>*`` (as ``Int``); 0 = NULL sentinel
    (empty-PEM config or acceptor-rejected accept). The dispatcher
    treats 0 as the silent-drop path per RFC 9001 §5.2."""


struct _CryptoStream(Copyable, Defaultable, Movable):
    """Per-level inbound CRYPTO reassembly buffer.

    QUIC delivers CRYPTO frames carrying an offset into a
    per-encryption-level handshake byte stream (RFC 9000 sec 19.6),
    and a peer may fragment + reorder them within a single packet.
    rustls's ``read_hs`` consumes the handshake stream strictly in
    order, so the bridge must reassemble the contiguous prefix
    before feeding it. Out-of-order fragments are held until the
    gap ahead of them fills.
    """

    var expected: UInt64
    var frag_offsets: List[UInt64]
    var frag_data: List[List[UInt8]]

    def __init__(out self):
        self.expected = UInt64(0)
        self.frag_offsets = List[UInt64]()
        self.frag_data = List[List[UInt8]]()

    def insert(mut self, offset: UInt64, data: List[UInt8]):
        """Buffer one CRYPTO fragment for later contiguous drain."""
        self.frag_offsets.append(offset)
        self.frag_data.append(data.copy())

    def drain_contiguous(mut self) -> List[UInt8]:
        """Pop and concatenate every buffered fragment that
        extends the contiguous prefix from :attr:`expected`,
        trimming overlaps and dropping fully-consumed fragments.
        Returns the newly contiguous bytes (possibly empty)."""
        var out = List[UInt8]()
        var progress = True
        while progress:
            progress = False
            for idx in range(len(self.frag_offsets)):
                var o = self.frag_offsets[idx]
                var dlen = UInt64(len(self.frag_data[idx]))
                if o + dlen <= self.expected:
                    self._swap_remove(idx)
                    progress = True
                    break
                if o <= self.expected and o + dlen > self.expected:
                    var start = Int(self.expected - o)
                    for j in range(start, len(self.frag_data[idx])):
                        out.append(self.frag_data[idx][j])
                    self.expected = o + dlen
                    self._swap_remove(idx)
                    progress = True
                    break
        return out^

    def _swap_remove(mut self, idx: Int):
        var last = len(self.frag_offsets) - 1
        if idx != last:
            self.frag_offsets[idx] = self.frag_offsets[last]
            self.frag_data[idx] = self.frag_data[last].copy()
        _ = self.frag_offsets.pop()
        _ = self.frag_data.pop()


struct _CryptoReasm(Copyable, Defaultable, Movable):
    """Per-slot CRYPTO reassembly across encryption levels.

    Indexed by :class:`QuicEncryptionLevel` codepoint (INITIAL=0,
    EARLY_DATA=1, HANDSHAKE=2, APPLICATION=3); EARLY_DATA carries
    no CRYPTO but the slot is kept so indexing stays direct.
    """

    var levels: List[_CryptoStream]

    def __init__(out self):
        self.levels = List[_CryptoStream]()
        for _ in range(4):
            self.levels.append(_CryptoStream())
