"""Server-side connection-migration support helpers.

Carved out of :mod:`flare.quic.server` to keep the listener under the
1k-line budget and to isolate the path-validation + anti-amplification
policy in one auditable place.

When a 1-RTT packet for a known connection arrives from a *new* source
address (a NAT rebind or an explicit client ``migrate()``), RFC 9000
sec 9 requires the server to validate the new path before trusting it.
flare's listener implements a **strict egress hold**: it does NOT
follow the new address for general egress until the path validates.

* It keeps every non-probe 1-RTT egress (ACKs, H3 response STREAM
  frames) on the previously validated address; the candidate is
  promoted to the egress address only once the client echoes the
  server's ``PATH_CHALLENGE``
  (:meth:`flare.quic.server.QuicListener._process_one_packet`).
* It sends a server-initiated ``PATH_CHALLENGE`` (RFC 9000 sec 8.2) to
  the candidate; the client's matching ``PATH_RESPONSE`` flips the
  connection's ``path_validated`` event and releases the hold.
* Probe / echo egress to the unvalidated candidate is bounded at
  ``3x`` the bytes received from it (RFC 9000 sec 8.1 / sec 21.5.4
  anti-amplification), charged per *protected datagram* (not just the
  frame) in :meth:`QuicListener._drain_migration_probe`, so a
  spoofed-source migration cannot turn the server into a reflection
  amplifier. When the budget is exhausted the probe is held back and
  retried once more bytes arrive on the path.

The budget is seeded from the migration-triggering datagram
and grows with each received datagram on the candidate. The hold trades
a round trip of added latency on a genuine migration (the response to
the migrating request waits for validation) for the guarantee that no
1-RTT egress ever reflects off the server to an unvalidated address --
the security property the strict hold exists to provide.
"""

from std.collections import List

from ..net import SocketAddr
from .frame import PathChallengeFrame, encode_path_challenge


comptime _AMPLIFICATION_FACTOR: Int = 3
"""RFC 9000 sec 8.1: an endpoint must not send more than three times
the bytes it has received on an unvalidated path."""

comptime _PATH_CHALLENGE_LEN: Int = 8
"""RFC 9000 sec 19.17: PATH_CHALLENGE carries exactly 8 bytes."""


struct MigrationProbe(Copyable, Movable):
    """Per-connection path-validation + anti-amplification state.

    Tracks the address currently being probed (the candidate), whether
    it has been validated, and the byte counters that bound how much
    the server may send to it before validation.
    """

    var probing: Bool
    """True while a candidate path is being validated."""
    var validated: Bool
    """True once the candidate echoed our PATH_CHALLENGE."""
    var candidate: SocketAddr
    """The new source address under validation (valid iff probing)."""
    var rx_bytes: UInt64
    """Bytes received from the candidate since the probe started."""
    var tx_bytes: UInt64
    """Server-originated bytes sent to the candidate since the probe
    started (counts against the amplification budget)."""

    def __init__(out self):
        self.probing = False
        self.validated = False
        self.candidate = SocketAddr.localhost(0)
        self.rx_bytes = UInt64(0)
        self.tx_bytes = UInt64(0)

    def should_start(self, new_peer: SocketAddr) -> Bool:
        """True if a fresh probe is needed: either nothing is being
        probed, or the candidate address changed (the client moved
        again before the previous probe validated)."""
        if not self.probing:
            return True
        return self.candidate != new_peer

    def start(mut self, new_peer: SocketAddr, first_rx: UInt64):
        """Begin probing ``new_peer``; seed the received-byte counter
        with the datagram that triggered the migration."""
        self.probing = True
        self.validated = False
        self.candidate = new_peer
        self.rx_bytes = first_rx
        self.tx_bytes = UInt64(0)

    def note_rx(mut self, peer: SocketAddr, n: UInt64):
        """Add ``n`` received bytes if they came from the candidate
        under validation (grows the amplification budget)."""
        if self.probing and not self.validated and peer == self.candidate:
            self.rx_bytes += n

    def amplification_allows(self, n: Int) -> Bool:
        """RFC 9000 sec 8.1: may the server send ``n`` more bytes to
        the unvalidated candidate? Always True once validated."""
        if self.validated or not self.probing:
            return True
        return (
            self.tx_bytes + UInt64(n)
            <= UInt64(_AMPLIFICATION_FACTOR) * self.rx_bytes
        )

    def note_tx(mut self, n: Int):
        """Charge ``n`` server-sent bytes against the budget."""
        self.tx_bytes += UInt64(n)

    def on_validated(mut self):
        """Mark the candidate path validated -- the amplification cap
        lifts and no further probe is issued for it."""
        self.validated = True
        self.probing = False


def new_path_challenge(data: List[UInt8]) raises -> List[UInt8]:
    """Encode a PATH_CHALLENGE frame carrying ``data`` (must be 8
    bytes) into a fresh byte buffer ready to ride a 1-RTT datagram."""
    if len(data) != _PATH_CHALLENGE_LEN:
        raise Error("new_path_challenge: data must be 8 bytes")
    var out = List[UInt8]()
    encode_path_challenge(PathChallengeFrame(data=data.copy()), out)
    return out^
