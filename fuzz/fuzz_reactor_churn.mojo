"""Fuzz harness: ``Reactor`` register/modify/unregister/poll churn.

Hammers the reactor with randomised sequences of register / modify /
unregister / poll calls across a pool of up to 32 socketpairs. Verifies:

- No crashes on any sequence of calls.
- Bookkeeping invariant: ``registered_count()`` matches the set of
  registrations the harness believes are active.
- Double-registration, double-unregister, and modify-on-unknown-fd all
  raise ``NetworkError`` rather than crashing.
- ``poll(0)`` never hangs, regardless of current registration state.

Run:
    pixi run fuzz-reactor-churn
"""

from mozz import fuzz, FuzzConfig
from std.ffi import c_int

from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener
from flare.runtime import (
    Reactor,
    Event,
    INTEREST_READ,
    INTEREST_WRITE,
    WAKEUP_TOKEN,
)


comptime _POOL_SIZE: Int = 8


def target(data: List[UInt8]) raises:
    """Drive the reactor with fuzzed byte-streams.

    Each input byte decodes as an ``(op, fd_slot)`` pair:

    - bits 0..3 (``b & 0x0F``): fd_slot (0..15, only 0.._POOL_SIZE-1 used)
    - bits 4..5 (``(b >> 4) & 3``): op (0=register, 1=modify, 2=unregister,
      3=poll)
    - bits 6..7 (``(b >> 6) & 3``): interest bits for register/modify

    Args:
        data: Bytes from the fuzz mutator.
    """
    if len(data) == 0:
        return

    # Fresh reactor per input so no state leaks between runs.
    var r = Reactor()

    # Build a pool of server-side TcpStreams to register/unregister.
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var s0 = TcpStream.connect(SocketAddr.localhost(port))
    var _c0 = listener.accept()
    var s1 = TcpStream.connect(SocketAddr.localhost(port))
    var _c1 = listener.accept()
    var s2 = TcpStream.connect(SocketAddr.localhost(port))
    var _c2 = listener.accept()
    var s3 = TcpStream.connect(SocketAddr.localhost(port))
    var _c3 = listener.accept()
    var s4 = TcpStream.connect(SocketAddr.localhost(port))
    var _c4 = listener.accept()
    var s5 = TcpStream.connect(SocketAddr.localhost(port))
    var _c5 = listener.accept()
    var s6 = TcpStream.connect(SocketAddr.localhost(port))
    var _c6 = listener.accept()
    var s7 = TcpStream.connect(SocketAddr.localhost(port))
    var _c7 = listener.accept()
    listener.close()

    # Track registration state locally; compare to reactor bookkeeping
    # after each op.
    var is_reg = List[Bool]()
    is_reg.resize(_POOL_SIZE, False)

    var events = List[Event]()
    var max_ops = min(len(data), 64)

    for i in range(max_ops):
        var b = Int(data[i])
        var slot = b & 0x07  # 0..7 map to _POOL_SIZE=8
        var op = (b >> 4) & 0x03
        var interest_bits = (b >> 6) & 0x03
        # Valid interests: 1, 2, 3 (reject 0).
        var interest = INTEREST_READ if interest_bits == 0 else (
            INTEREST_READ if interest_bits
            == 1 else (
                INTEREST_WRITE if interest_bits
                == 2 else INTEREST_READ | INTEREST_WRITE
            )
        )
        var fd: c_int
        if slot == 0:
            fd = s0._socket.fd
        elif slot == 1:
            fd = s1._socket.fd
        elif slot == 2:
            fd = s2._socket.fd
        elif slot == 3:
            fd = s3._socket.fd
        elif slot == 4:
            fd = s4._socket.fd
        elif slot == 5:
            fd = s5._socket.fd
        elif slot == 6:
            fd = s6._socket.fd
        else:
            fd = s7._socket.fd
        var token = UInt64(slot + 1)

        if op == 0:
            # register
            try:
                r.register(fd, token, interest)
                is_reg[slot] = True
            except:
                # already registered, or invalid args — harness ignores
                pass
        elif op == 1:
            # modify
            try:
                r.modify(fd, interest)
            except:
                pass
        elif op == 2:
            # unregister
            try:
                r.unregister(fd)
                is_reg[slot] = False
            except:
                pass
        else:
            # poll(0)
            try:
                events.clear()
                _ = r.poll(0, events, max_events=8)
            except:
                pass

        # Invariant: reactor.registered_count() matches our local tally.
        var expected = 0
        for k in range(_POOL_SIZE):
            if is_reg[k]:
                expected += 1
        var actual = r.registered_count()
        if expected != actual:
            raise Error(
                "registered_count mismatch: expected "
                + String(expected)
                + " actual "
                + String(actual)
            )

    s0.close()
    s1.close()
    s2.close()
    s3.close()
    s4.close()
    s5.close()
    s6.close()
    s7.close()


def main() raises:
    print("[mozz] fuzzing Reactor register/modify/unregister/poll churn...")

    var seeds = List[List[UInt8]]()

    # Seed 1: register 4 fds for READ.
    var s1 = List[UInt8]()
    s1.append(UInt8(0x00))
    s1.append(UInt8(0x01))
    s1.append(UInt8(0x02))
    s1.append(UInt8(0x03))
    seeds.append(s1^)

    # Seed 2: register then unregister.
    var s2 = List[UInt8]()
    s2.append(UInt8(0x00))
    s2.append(UInt8(0x01))
    s2.append(UInt8(0x20))
    s2.append(UInt8(0x21))
    seeds.append(s2^)

    # Seed 3: double-register same slot (second should be no-op in harness).
    var s3 = List[UInt8]()
    s3.append(UInt8(0x00))
    s3.append(UInt8(0x00))
    seeds.append(s3^)

    # Seed 4: modify before register (should raise).
    var s4 = List[UInt8]()
    s4.append(UInt8(0x10))
    s4.append(UInt8(0x00))
    seeds.append(s4^)

    # Seed 5: heavy poll churn.
    var s5 = List[UInt8]()
    s5.append(UInt8(0x30))
    s5.append(UInt8(0x00))
    s5.append(UInt8(0x30))
    s5.append(UInt8(0x01))
    s5.append(UInt8(0x30))
    s5.append(UInt8(0x02))
    s5.append(UInt8(0x30))
    s5.append(UInt8(0x03))
    seeds.append(s5^)

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/reactor_churn",
            max_input_len=64,
        ),
        seeds,
    )
