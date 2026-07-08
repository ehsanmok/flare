"""Fuzz harness: QUIC migration anti-amplification budget.

The strict egress hold bounds server-originated bytes to an unvalidated
candidate path at 3x the bytes received from it (RFC 9000 sec 8.1 /
sec 21.5.4). A bug that lets the budget drift would turn the server
into a reflection amplifier, so this target drives arbitrary
receive / send / validate sequences through :class:`MigrationProbe` and
checks the core safety invariant after every accepted send.

Properties checked:

1. No panic on arbitrary op sequences.
2. While probing and unvalidated, the probe never *permits* a send that
   would push cumulative sent bytes past 3x cumulative received bytes;
   and after a permitted send the running ``tx_bytes <= 3 * rx_bytes``.
3. Validation lifts the cap: once validated, any size is permitted.

Run:
    pixi run --environment fuzz fuzz-quic-migration-amplification
"""

from mozz import FuzzConfig, fuzz

from flare.quic._server_migration import MigrationProbe
from flare.net import SocketAddr


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


comptime _FACTOR: UInt64 = 3


def target(data: List[UInt8]) raises:
    var n = len(data)
    if n < 2:
        return
    var cand = SocketAddr.localhost(UInt16(4000))
    var p = MigrationProbe()
    # Seed the probe from the migration-triggering datagram size.
    p.start(cand, UInt64(Int(data[0]) + 1))
    var validated = False
    var i = 1
    while i + 1 < n:
        var op = Int(data[i]) % 3
        var amount = UInt64(Int(data[i + 1]) * 4 + 1)
        if op == 0:
            # Received bytes from the candidate grow the budget.
            p.note_rx(cand, amount)
        elif op == 1:
            # Attempt to send `amount` bytes to the candidate.
            var allowed = p.amplification_allows(Int(amount))
            if not validated:
                var fits = p.tx_bytes + amount <= _FACTOR * p.rx_bytes
                _assert(
                    allowed == fits,
                    "amplification_allows disagreed with the 3x budget",
                )
            if allowed:
                p.note_tx(Int(amount))
                if not validated:
                    _assert(
                        p.tx_bytes <= _FACTOR * p.rx_bytes,
                        "tx exceeded 3x rx on an unvalidated path",
                    )
        else:
            # Validate: the cap must lift.
            p.on_validated()
            validated = True
            _assert(
                p.amplification_allows(1 << 30),
                "validated path must permit any size",
            )
        i += 2


def main() raises:
    print("=" * 60)
    print("fuzz_quic_migration_amplification.mojo -- RFC 9000 sec 8.1 budget")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    var s0 = List[UInt8]()
    for b in [10, 1, 50, 0, 30, 1, 40]:  # send, recv, send sequence
        s0.append(UInt8(b))
    seeds.append(s0^)
    var s1 = List[UInt8]()
    for b in [5, 2, 0, 1, 100]:  # validate then big send
        s1.append(UInt8(b))
    seeds.append(s1^)

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_migration_amplification",
            corpus_dir="fuzz/corpus/quic_migration_amplification",
            max_input_len=128,
        ),
        seeds,
    )
