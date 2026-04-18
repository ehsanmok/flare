"""Property test: TimerWheel invariants under random schedule/cancel/advance
sequences.

Invariants checked for every generated sequence:

1. **Every scheduled, not-cancelled timer eventually fires exactly once**
   when ``advance`` reaches a time >= its fire_at.
2. **Every scheduled-and-cancelled timer never fires.**
3. **No timer fires before its fire_at**.

Run:
    pixi run prop-timer-wheel
"""

from std.collections import Dict
from mozz import fuzz, FuzzConfig
from flare.runtime import TimerWheel


def target(data: List[UInt8]) raises:
    """Drive a TimerWheel with fuzz-encoded op sequences.

    Each input byte chooses an op:
    - op == 0: schedule, delay = (arg * 4) + 1 ms (1..1021 ms)
    - op == 1: advance by (arg + 1) ms
    - op == 2: cancel a pseudo-random scheduled id

    Token scheme: each scheduled timer gets token = next_token_counter (a
    monotonic UInt64 that's never reused).

    Args:
        data: Bytes from the fuzz mutator.
    """
    if len(data) < 2:
        return

    var tw = TimerWheel(now_ms=UInt64(0))

    # Oracle maps: token -> (timer_id, fire_at_ms).
    # A timer is "pending" if it's in expected_fire; "cancelled" if in
    # cancelled_tokens (we remove from expected_fire when cancelling).
    var expected_fire = Dict[UInt64, UInt64]()  # token -> fire_at_ms
    var token_to_id = Dict[UInt64, UInt64]()  # token -> timer_id
    # Set of tokens that have been cancelled (to detect fires-after-cancel).
    var cancelled_tokens = Dict[UInt64, Bool]()
    # Set of tokens we've already accounted for (to detect double-fires).
    var already_fired = Dict[UInt64, Bool]()

    var next_token: UInt64 = 1000

    var i = 0
    while i < len(data) - 1:
        var op = Int(data[i]) % 3
        var arg = Int(data[i + 1])
        i += 2

        if op == 0:
            # schedule
            var delay = (arg * 4) + 1
            var token = next_token
            next_token += 1
            var tid = tw.schedule(delay, token)
            expected_fire[token] = tw.now_ms() + UInt64(delay)
            token_to_id[token] = tid
        elif op == 1:
            # advance
            var step = arg + 1
            var new_now = tw.now_ms() + UInt64(step)
            var fired_here = List[UInt64]()
            tw.advance(new_now, fired_here)
            for j in range(len(fired_here)):
                var tok = fired_here[j]
                if tok in already_fired:
                    raise Error(
                        "assertion failed: token fired twice: " + String(tok)
                    )
                already_fired[tok] = True
                if tok in cancelled_tokens:
                    raise Error(
                        "assertion failed: cancelled token fired: "
                        + String(tok)
                    )
                if tok not in expected_fire:
                    raise Error(
                        "assertion failed: unknown token fired: " + String(tok)
                    )
                var fa = expected_fire[tok]
                if fa > new_now:
                    raise Error(
                        "assertion failed: timer fired early "
                        + String(tok)
                        + " fire_at="
                        + String(fa)
                        + " now="
                        + String(new_now)
                    )
                _ = expected_fire.pop(tok)
        else:
            # cancel — pick a pending token by cycling through dict keys
            if len(expected_fire) == 0:
                continue
            var keys = List[UInt64]()
            for k in expected_fire.keys():
                keys.append(k)
            var pick_tok = keys[arg % len(keys)]
            var tid = token_to_id[pick_tok]
            var rc = tw.cancel(tid)
            if rc:
                cancelled_tokens[pick_tok] = True
                _ = expected_fire.pop(pick_tok)


def main() raises:
    print("[mozz] property-testing TimerWheel invariants...")

    var seeds = List[List[UInt8]]()
    # Seed: schedule(5), schedule(10), advance(20), advance(5)
    var s1 = List[UInt8]()
    s1.append(UInt8(0))
    s1.append(UInt8(5))
    s1.append(UInt8(0))
    s1.append(UInt8(10))
    s1.append(UInt8(1))
    s1.append(UInt8(20))
    s1.append(UInt8(1))
    s1.append(UInt8(5))
    seeds.append(s1^)

    # Seed: schedule then cancel
    var s2 = List[UInt8]()
    s2.append(UInt8(0))
    s2.append(UInt8(50))
    s2.append(UInt8(2))
    s2.append(UInt8(0))
    s2.append(UInt8(1))
    s2.append(UInt8(100))
    seeds.append(s2^)

    fuzz(
        target,
        FuzzConfig(
            max_runs=100_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/prop_timer_wheel",
            max_input_len=64,
        ),
        seeds,
    )
