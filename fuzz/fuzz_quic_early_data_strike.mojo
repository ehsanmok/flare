"""Fuzz harness: ``flare.quic._server_0rtt.EarlyDataStrikeSet``.

The strike set is the cross-connection 0-RTT replay defense (RFC 9001
sec 9.2): it remembers each accepting connection's original DCID for a
time window so a captured first flight replayed as a fresh accept is
refused. A bug that lets a live strike slip through reopens the replay
window, so this target hammers it with arbitrary
``(key, time-delta)`` operation sequences and checks every result
against an independent reference model.

Properties checked:

1. ``strike`` never panics on arbitrary operations.
2. Its return matches a reference mirror exactly: a key struck within
   its window is refused; an absent or expired key is admitted (and
   re-arms the window).

The fuzzer drives only 8 distinct keys with a small window so the
:data:`_STRIKE_MAX_ENTRIES` capacity fail-closed path never trips --
that branch is covered exhaustively by the unit tests; here the focus
is the time-window admit/refuse logic the reference can model exactly.

Run:
    pixi run --environment fuzz fuzz-quic-early-data-strike
"""

from mozz import fuzz, FuzzConfig

from flare.quic._server_0rtt import EarlyDataStrikeSet


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


comptime _WINDOW: UInt64 = 16


def target(data: List[UInt8]) raises:
    var s = EarlyDataStrikeSet(window_ms=_WINDOW)
    # Reference mirror: parallel key -> expiry lists (few keys, linear
    # scan is fine and keeps the model obviously correct).
    var ref_keys = List[String]()
    var ref_exp = List[UInt64]()
    var now = UInt64(0)
    var i = 0
    while i + 1 < len(data):
        var key = String(Int(data[i]) % 8)  # 8 keys, far below capacity
        now += UInt64(Int(data[i + 1]) % 40)  # monotonic non-decreasing
        var idx = -1
        for j in range(len(ref_keys)):
            if ref_keys[j] == key:
                idx = j
                break
        var expect = True
        if idx >= 0 and ref_exp[idx] > now:
            expect = False  # live strike -> must be refused
        var got = s.strike(key, now)
        _assert(
            got == expect,
            "strike(" + key + ", " + String(now) + ") = " + String(got),
        )
        if got:
            if idx >= 0:
                ref_exp[idx] = now + _WINDOW
            else:
                ref_keys.append(key)
                ref_exp.append(now + _WINDOW)
        i += 2


def main() raises:
    print("=" * 60)
    print("fuzz_quic_early_data_strike.mojo — cross-connection 0-RTT strike")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    var s0 = List[UInt8]()
    s0.append(UInt8(1))  # key 1
    s0.append(UInt8(0))  # dt 0
    s0.append(UInt8(1))  # key 1 again, same now -> refused
    s0.append(UInt8(0))
    seeds.append(s0^)
    var s1 = List[UInt8]()
    s1.append(UInt8(2))
    s1.append(UInt8(20))  # advance past window between same-key strikes
    s1.append(UInt8(2))
    s1.append(UInt8(20))
    seeds.append(s1^)

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_early_data_strike",
            corpus_dir="fuzz/corpus/quic_early_data_strike",
            max_input_len=128,
        ),
        seeds,
    )
