"""Server-side 0-RTT (EarlyData) support helpers.

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
* :class:`EarlyDataStrikeSet` -- a *listener-level* cross-connection
  anti-replay set keyed on the client-chosen DCID + a time window. It
  catches a captured first flight replayed against a *fresh*
  connection (after the original closed), which the per-connection
  guard cannot see.
* :func:`early_data_packet_len` -- length of a coalesced 0-RTT
  long-header packet, so the datagram-walk in the listener can step
  over / into a 0-RTT packet instead of bailing.

The two guards are layered. :class:`EarlyDataReplayGuard` is
*intra-connection* (a replay within one resumed connection, plus the
byte budget); :class:`EarlyDataStrikeSet` is *cross-connection* (the
same flight replayed as a new accept). The strike set is keyed on the
ODCID + a wall-clock window rather than an opaque session ticket --
rustls 0.23 cannot export single-use tickets (confirmed for this
project), so DCID+window is the achievable approximation. See
:class:`EarlyDataStrikeSet` for the exact ceiling.
"""

from std.collections import Dict, List
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


comptime _STRIKE_MAX_ENTRIES: Int = 4096
"""Hard cap on live strike entries. Once reached (after pruning
expired ones), further 0-RTT is refused fail-closed rather than
evicting a live strike -- refusing 0-RTT only costs the client a
round trip, whereas evicting a live strike would reopen the replay
window."""


struct EarlyDataStrikeSet(Movable):
    """Listener-level cross-connection 0-RTT replay defense (RFC 9001
    sec 9.2).

    :class:`EarlyDataReplayGuard` stops a replay *within* one resumed
    connection, but an attacker who captures a client's first flight
    can replay it later -- after the original connection closed and
    its CID was retired -- so it lands as a *fresh* accept whose guard
    window is empty. This set remembers the original Destination
    Connection ID (the client-chosen DCID) of every connection that
    began accepting 0-RTT, for a bounded time window. A second
    connection presenting the same ODCID within the window is a replay
    and its 0-RTT flight is refused -- it falls back to a full 1-RTT
    handshake, safe, just a round trip slower.

    Keyed on the client-chosen DCID + a wall-clock window,
    not on an opaque session ticket. rustls 0.23 cannot export
    single-use tickets (confirmed for this project), so ticket-keyed
    exact-once admission is unavailable; DCID+window is the achievable
    approximation. The captured 0-RTT packets are cryptographically
    bound to their ODCID (the Initial keys derive from it), so an
    attacker cannot keep the 0-RTT payload valid while swapping in a
    different DCID to dodge the strike. Ceiling: a replay arriving
    more than ``window_ms`` after the original is no longer caught
    here (it is still bounded by rustls's own single-use ticket
    check); the window trades memory for that horizon. Memory is
    capped at :data:`_STRIKE_MAX_ENTRIES` live entries -- when full,
    new 0-RTT is refused (fail-closed) instead of dropping a live
    strike.
    """

    var window_ms: UInt64
    """How long an accepted ODCID stays struck. A replay within this
    horizon of the original is refused; later replays fall through to
    rustls's ticket check."""
    var seen: Dict[String, UInt64]
    """ODCID hex -> expiry (wall-clock ms). An entry is live while
    ``expiry > now``."""

    def __init__(out self, window_ms: UInt64 = UInt64(10_000)):
        self.window_ms = window_ms
        self.seen = Dict[String, UInt64]()

    def _prune(mut self, now_ms: UInt64) raises:
        """Drop every expired entry. O(n) sweep; called only when the
        set hits capacity, so it is amortized off the steady-state
        admit path."""
        var dead = List[String]()
        for e in self.seen.items():
            if e.value <= now_ms:
                dead.append(e.key)
        for i in range(len(dead)):
            _ = self.seen.pop(dead[i])

    def strike(mut self, key: String, now_ms: UInt64) raises -> Bool:
        """Decide whether a connection whose ODCID is ``key`` may
        begin accepting 0-RTT, recording the ODCID when it may.

        Returns ``True`` (fresh -- recorded) when ``key`` has not been
        struck inside the current window; returns ``False`` (refuse
        0-RTT) when ``key`` is a live strike (cross-connection replay)
        or when the set is at capacity. Call once per connection, on
        its first 0-RTT packet, before admitting any early data.
        """
        if key in self.seen:
            if self.seen[key] > now_ms:
                return False  # live strike: cross-connection replay
            # Expired strike for the same ODCID: refresh it below.
        elif len(self.seen) >= _STRIKE_MAX_ENTRIES:
            self._prune(now_ms)
            if len(self.seen) >= _STRIKE_MAX_ENTRIES:
                return False  # fail-closed: capacity reached
        self.seen[key] = now_ms + self.window_ms
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
