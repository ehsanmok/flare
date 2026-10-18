"""Datagram Packetization Layer PMTU Discovery (RFC 8899, RFC 9000 sec 14.3).

Sans-I/O. A path starts at :data:`PMTU_BASE`, the size every QUIC path
must carry (RFC 9000 sec 14). Probes (PING + PADDING) test larger sizes
up to the ceiling, the smaller of the local limit and the peer's
``max_udp_payload_size``: the ceiling first, as most paths carry it,
then a binary search. A size is validated when its probe is
acknowledged; three unanswered probes rule it out. Probes are kept out
of loss recovery, so their loss is never taken for congestion (RFC 9002
sec 14.4). A path whose MTU later shrinks below a validated size is not
searched down again: the retransmit store re-sends frames at the size
they were built for, so such a connection ends at the PTO limit.
"""

comptime PMTU_BASE: Int = 1200
comptime _MAX_PROBES: Int = 3
comptime _SEARCH_DONE: Int = 20
"""Stop once the untested range is narrower than this many bytes."""


struct PmtuDiscovery(Copyable, Defaultable):
    var current: Int
    """The largest validated datagram size; what egress fills to."""
    var ceiling: Int
    var hi: Int
    """Largest size not yet ruled out."""
    var probe_size: Int
    """Size of the probe in flight, 0 when none."""
    var probe_pn: UInt64
    var probe_sent_ms: UInt64
    var fails: Int

    def __init__(out self):
        self.current = PMTU_BASE
        self.ceiling = PMTU_BASE
        self.hi = PMTU_BASE
        self.probe_size = 0
        self.probe_pn = 0
        self.probe_sent_ms = 0
        self.fails = 0

    def set_ceiling(mut self, ceiling: Int):
        """The most the path may carry, once the peer's limit is known."""
        self.ceiling = max(ceiling, PMTU_BASE)
        self.hi = self.ceiling

    def want_probe(self) -> Int:
        """The size to probe now, or 0."""
        if self.probe_size != 0:
            return 0
        if self.hi - self.current < _SEARCH_DONE:
            return 0
        if self.hi == self.ceiling:
            return self.hi
        return (self.current + self.hi + 1) // 2

    def on_probe_sent(mut self, pn: UInt64, size: Int, now_ms: UInt64):
        self.probe_pn = pn
        self.probe_size = size
        self.probe_sent_ms = now_ms

    def on_acked(mut self, ranges: List[UInt64]):
        """Feed the ``[lo, hi]`` pairs of an ACK; validates the probe if
        it is among them."""
        if self.probe_size == 0:
            return
        for i in range(0, len(ranges) - 1, 2):
            if ranges[i] <= self.probe_pn and self.probe_pn <= ranges[i + 1]:
                self.current = max(self.current, self.probe_size)
                self.probe_size = 0
                self.fails = 0
                return

    def check_lost(mut self, now_ms: UInt64, pto_ms: UInt64):
        """A probe unanswered for three PTOs is lost; three losses at one
        size rule it, and everything above it, out."""
        if self.probe_size == 0 or now_ms < self.probe_sent_ms + 3 * pto_ms:
            return
        self.fails += 1
        if self.fails >= _MAX_PROBES:
            self.hi = self.probe_size - 1
            self.fails = 0
        self.probe_size = 0
