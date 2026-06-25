"""Server-side 0-RTT (EarlyData) support helpers (W4a).

Carved out of :mod:`flare.quic.server` so the 1974-line listener
stays under the 1k-line budget and the security-sensitive 0-RTT
admission logic lives in one auditable place.

0-RTT lets a resuming client send application data in its first
flight, before the handshake completes (RFC 9001 §4.1). The reward is
a saved round trip; the hazard is **replay**: an on-path attacker can
capture the encrypted 0-RTT flight and re-send it. flare keeps 0-RTT
OFF by default (``max_early_data_size == 0``); a deployment opts in
per-listener.

This module provides:

* :class:`EarlyDataReplayGuard` -- a per-connection anti-replay window
  (RFC 9000 §13.2-style sliding bitmask) plus an early-data byte
  budget. It rejects duplicate / too-old packet numbers and caps the
  accepted early bytes at the configured maximum.
* :func:`early_data_packet_len` -- length of a coalesced 0-RTT
  long-header packet, so the datagram-walk in the listener can step
  over / into a 0-RTT packet instead of bailing.

ponytail: the replay window here is *intra-connection* (it stops a
replay within the same resumed connection and bounds the byte budget).
The ceiling is cross-connection replay -- an attacker replaying the
captured first flight against a *fresh* connection. rustls's
single-use stateful tickets give partial coverage; full coverage needs
a shared server-side seen-ticket/ODCID set with a strike window. That
is the documented upgrade path and is tracked as a follow-up, not
shipped here.
"""

from std.memory import Span

from .packet import decode_varint, parse_long_header


comptime _REPLAY_WINDOW_BITS: Int = 64
"""Width of the sliding anti-replay window, in packet numbers. A pn
more than this far below the highest accepted pn is treated as a
replay and rejected (it cannot be distinguished from one we already
forgot)."""


struct EarlyDataReplayGuard(Copyable, Movable):
    """Per-connection 0-RTT admission control: anti-replay window +
    byte budget.

    Construct with ``max_bytes == 0`` (the default) to keep 0-RTT
    disabled -- :meth:`admit` then always returns ``False``. A
    non-zero budget enables admission; each accepted packet's payload
    counts against the budget and each packet number is checked
    against the sliding window so a duplicate or stale pn is rejected.
    """

    var max_bytes: UInt64
    """Maximum total 0-RTT payload bytes to accept on this connection
    (mirrors the rustls ``max_early_data_size``). 0 disables 0-RTT."""
    var accepted_bytes: UInt64
    """Running total of admitted 0-RTT payload bytes."""
    var highest_pn: UInt64
    """Highest 0-RTT packet number admitted so far (valid only once
    :attr:`any_seen` is True)."""
    var window: UInt64
    """Sliding bitmask of admitted packet numbers; bit ``i`` set means
    ``highest_pn - i`` has been admitted."""
    var any_seen: Bool
    """False until the first 0-RTT packet is admitted."""

    def __init__(out self, max_bytes: UInt64 = UInt64(0)):
        self.max_bytes = max_bytes
        self.accepted_bytes = UInt64(0)
        self.highest_pn = UInt64(0)
        self.window = UInt64(0)
        self.any_seen = False

    @always_inline
    def enabled(self) -> Bool:
        """True iff this connection accepts 0-RTT (non-zero budget)."""
        return self.max_bytes > UInt64(0)

    def admit(mut self, pn: UInt64, payload_len: Int) -> Bool:
        """Decide whether a 0-RTT packet at ``pn`` carrying
        ``payload_len`` plaintext bytes may be processed.

        Returns ``True`` and records the packet when it is fresh and
        within budget; returns ``False`` (and records nothing) when
        0-RTT is disabled, the packet number is a replay / too old, or
        admitting it would exceed the early-data byte budget.
        """
        if not self.enabled():
            return False
        if payload_len < 0:
            return False
        var add = UInt64(payload_len)
        if self.accepted_bytes + add > self.max_bytes:
            return False

        if not self.any_seen:
            self.any_seen = True
            self.highest_pn = pn
            self.window = UInt64(1)
            self.accepted_bytes += add
            return True

        if pn > self.highest_pn:
            var shift = pn - self.highest_pn
            if shift >= UInt64(_REPLAY_WINDOW_BITS):
                self.window = UInt64(0)
            else:
                self.window = self.window << shift
            self.window |= UInt64(1)
            self.highest_pn = pn
            self.accepted_bytes += add
            return True

        var diff = self.highest_pn - pn
        if diff >= UInt64(_REPLAY_WINDOW_BITS):
            return False  # older than the window: treat as replay
        var mask = UInt64(1) << diff
        if (self.window & mask) != UInt64(0):
            return False  # duplicate packet number: replay
        self.window |= mask
        self.accepted_bytes += add
        return True


def early_data_packet_len(packet: Span[UInt8, _]) raises -> Int:
    """Return the on-wire length of a coalesced 0-RTT (EarlyData)
    long-header packet at the start of ``packet``.

    A 0-RTT packet uses the long-header form with an explicit Length
    varint after the SCID (RFC 9000 §17.2.3), identical in framing to
    a Handshake packet. The listener's datagram walk uses this to step
    over / into the 0-RTT packet rather than bailing the coalescing
    scan. Raises on a malformed header so the caller stops the scan.
    """
    var lh = parse_long_header(packet)
    var lv = decode_varint(packet[lh.payload_offset :])
    var total = lh.payload_offset + lv.consumed + Int(lv.value)
    if total <= 0:
        raise Error("early_data_packet_len: non-positive length")
    return total
