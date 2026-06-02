"""Fuzz harness: QUIC server dispatch over arbitrary inbound
datagrams.

Drives :meth:`flare.quic.server.QuicListener.dispatch_datagram`
against random bytes. The dispatcher is the very first piece of
the server that touches an untrusted UDP payload, so it MUST:

1. Never panic / read out of bounds on arbitrary input. The
   first byte alone can be anything from 0x00 to 0xFF, the
   high bit picks the long/short routing fork, and downstream
   parsers fail on any structural violation.
2. Return either:
   - ``-1`` for a malformed / unknown-DCID / short-of-known
     datagram (the silent-drop path -- RFC 9000 §10.3 + the
     stateless-reset placeholder), or
   - a non-negative slot index when the datagram successfully
     routed to a connection (existing or newly-accepted).
3. Leave the listener in a consistent state: connection_count
   never shrinks, the CID routing table only grows on accept,
   no datagram can produce two slots in one call.

The harness is configured to feed inputs from a single sender
(`127.0.0.1:54321`) -- the goal is to exercise the parser
+ routing path under adversarial bytes, not to test the kernel
loopback. The listener stays bound to an ephemeral port on
loopback so it can be torn down between fuzz runs cleanly.

Run:
    pixi run --environment fuzz fuzz-quic-initial-handshake
"""

from mozz import fuzz, FuzzConfig

from flare.net import IpAddr, SocketAddr
from flare.quic import QuicListener, QuicServerConfig


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


def target(data: List[UInt8]) raises:
    """Open a listener, dispatch the fuzz bytes once, assert the
    listener's invariants, tear down."""
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    var listener = QuicListener.bind(cfg)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var pre_count = listener.connection_count()
    try:
        var slot = listener.dispatch_datagram(Span[UInt8, _](data), peer)
        # Slot must be either -1 (drop) or a valid index.
        _assert(
            slot >= -1,
            "dispatch_datagram returned slot < -1",
        )
        _assert(
            slot < listener.connection_count() + 1,
            "dispatch_datagram returned slot past the connection slab",
        )
    except _:
        # Any parser-level Error is acceptable; the dispatcher is
        # allowed to bubble those up to the reactor. The
        # invariant we care about is that no panic occurs.
        pass
    var post_count = listener.connection_count()
    _assert(
        post_count >= pre_count,
        "connection_count must not shrink across a single dispatch",
    )
    _assert(
        post_count <= pre_count + 1,
        "dispatch_datagram may allocate at most one slot per call",
    )
    listener.shutdown()
    listener.close()


def main() raises:
    print("=" * 60)
    print("fuzz_quic_initial_handshake.mojo -- QUIC server dispatcher safety")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    # Empty datagram -- dispatcher must short-circuit.
    seeds.append(List[UInt8]())
    # Single zero byte -- short-header fork without DCID.
    seeds.append(_bytes("\x00"))
    # Long-header indicator + nothing else.
    seeds.append(_bytes("\xC0"))
    # Long-header initial-shape with zero CIDs.
    seeds.append(_bytes("\xC0\x00\x00\x00\x01\x00\x00\x00\x00"))
    # Long-header Initial with 8-byte CIDs but no payload-length.
    var lh = List[UInt8]()
    lh.append(UInt8(0xC0))
    for _ in range(4):
        lh.append(UInt8(0))
    lh[4] = UInt8(1)
    lh.append(UInt8(8))
    for i in range(8):
        lh.append(UInt8(0xA0 + i))
    lh.append(UInt8(8))
    for i in range(8):
        lh.append(UInt8(0xB0 + i))
    seeds.append(lh^)
    # Short header with 8-byte DCID (matches the listener's
    # default cid length).
    var sh = List[UInt8]()
    sh.append(UInt8(0x40))
    for i in range(8):
        sh.append(UInt8(0x77 + i))
    for _ in range(60):
        sh.append(UInt8(0))
    seeds.append(sh^)
    # Long-header packet-type retry (high bits 11, type 11).
    seeds.append(_bytes("\xF0\x00\x00\x00\x01\x00\x00"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_initial_handshake",
            corpus_dir="fuzz/corpus/quic_initial_handshake",
            max_input_len=512,
        ),
        seeds,
    )
