"""Stress driver: hammer ``Scheduler.start/shutdown`` with random inputs.

Complements ``fuzz-scheduler-shutdown`` (which exercises the runtime
primitives individually under the mozz harness) by driving the full
``Scheduler[H].start`` → ``shutdown`` round-trip with randomised
``num_workers`` / ``pin_cores`` / ``extra_churn`` tuples. Runs under
the lean default env (no mozz dependency), so it's cheap to run
locally and in CI. The historical reason this file exists as a
non-mozz driver — a Mojo MLIR legalization conflict between
flare's libc ``free`` FFI and the stdlib's ``free`` declaration that
blocked ``mozz`` from importing ``flare.runtime.scheduler`` — is
resolved as of (flare now uses the native Mojo allocator
everywhere, see ``_scheduler_free_raw``).

Each iteration:

1. Samples ``num_workers`` uniformly in ``1..=16`` (kept well below
   the 256 guard so we don't spend minutes just spawning threads),
   ``pin_cores`` as a random Bool, and an ``extra_churn`` count in
   ``0..=3`` for how many extra idempotent ``shutdown()`` calls to
   make after the first one.
2. Calls ``Scheduler[_NopHandler].start(...)`` with a config whose
   timeouts are tight (``idle_timeout_ms=100``,
   ``shutdown_timeout_ms=200``) so a misbehaving shutdown surfaces
   quickly rather than hanging the whole driver.
3. Times the subsequent ``shutdown()`` (plus the extra churn).
4. Reports any iteration that exceeds ``ITERATION_WATCHDOG_MS``
   milliseconds as "slow" — this is the hang signal (the bug this
   file exists to regression-test).

Run:

    pixi run stress-scheduler # default: 200 iterations
    STRESS_ITERS=2000 pixi run stress-scheduler # longer soak
    STRESS_SEED=42 pixi run stress-scheduler # override seed

Expected behaviour: ``0 failed, 0 slow`` across every iteration.
"""

from std.memory import UnsafePointer
from std.os import getenv

from flare.http import Handler, Request, Response, ok
from flare.http.server import ServerConfig
from flare.http._server_reactor_impl import _monotonic_ms
from flare.net import SocketAddr
from flare.runtime.scheduler import Scheduler


# ── Handler: zero-size, Copyable, Handler-conforming, no side effects ───────


@fieldwise_init
struct _NopHandler(Copyable, Handler):
    var tag: Int

    def serve(self, req: Request) raises -> Response:
        return ok("nop")


# ── xorshift64 PRNG (deterministic, no external dep) ────────────────────────


def _xorshift64(mut state: UInt64) -> UInt64:
    var x = state
    x = x ^ (x << 13)
    x = x ^ (x >> 7)
    x = x ^ (x << 17)
    state = x
    return x


# ── Config used for every iteration (tight timeouts for responsiveness) ─────


def _stress_config() -> ServerConfig:
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 100
    cfg.write_timeout_ms = 200
    cfg.shutdown_timeout_ms = 200
    return cfg^


# ── Stress loop ─────────────────────────────────────────────────────────────


comptime ITERATION_WATCHDOG_MS: Int = 5_000
"""Any single start/shutdown cycle that exceeds this bound is
reported as a suspected hang. 5 s is roughly 50x the slowest
benign timing observed on EPYC 7R32 (4 workers + shutdown_timeout =
200 ms ends the whole cycle in well under 100 ms once the
stopping-flag fix is in place).
"""


def _run_one(mut rng: UInt64, iter_idx: Int) raises -> Int:
    """Run one random start/shutdown cycle. Returns wall time in ms.

    Raises if ``Scheduler.start`` raises (e.g. listener bind
    failure); any wall time beyond ``ITERATION_WATCHDOG_MS`` is
    *reported* back to the caller via the return value so the top
    level can flag it without killing the driver mid-soak.
    """
    var r0 = _xorshift64(rng)
    var r1 = _xorshift64(rng)
    var r2 = _xorshift64(rng)

    var num_workers = 1 + Int(r0 % UInt64(16))  # 1..=16
    var pin_cores = (r1 & UInt64(1)) == UInt64(1)
    var extra_churn = Int(r2 % UInt64(4))  # 0..=3

    var addr = SocketAddr.localhost(0)
    var h = _NopHandler(iter_idx)
    var cfg = _stress_config()

    var t_start = _monotonic_ms()
    var s = Scheduler[_NopHandler].start(
        addr=addr,
        config=cfg^,
        handler=h^,
        num_workers=num_workers,
        pin_cores=pin_cores,
    )
    s.shutdown()
    # Extra idempotent shutdowns exercise the ``_workers_len == 0`` /
    # ``_stopping_addr == 0`` no-op branches in ``Scheduler.shutdown``.
    for _ in range(extra_churn):
        s.shutdown()
    var t_end = _monotonic_ms()

    return t_end - t_start


def main() raises:
    print("=" * 68)
    print("stress_scheduler — Scheduler.start/shutdown soak test")
    print("=" * 68)
    var iters_str = getenv("STRESS_ITERS", "200")
    var iters = Int(iters_str)
    if iters < 1:
        iters = 1
    # Simple decimal-only seed override. Hex seeds aren't worth the
    # stdlib string-slice friction here; the driver is random enough
    # without a 64-bit seed space.
    var seed_str = getenv("STRESS_SEED", "12648430")  # 0xC0FFEE
    var seed: UInt64
    try:
        seed = UInt64(Int(seed_str))
    except:
        seed = UInt64(12648430)
    if seed == UInt64(0):
        # xorshift64 needs a non-zero seed or it stays at 0 forever.
        seed = UInt64(12648430)
    print(" iterations :", iters)
    print(" seed :", seed)
    print(" watchdog :", ITERATION_WATCHDOG_MS, "ms per iteration")
    print()

    var rng = seed
    var failed = 0
    var slow = 0
    var total_ms = 0
    var max_ms = 0

    for i in range(iters):
        try:
            var ms = _run_one(rng, i)
            total_ms += ms
            if ms > max_ms:
                max_ms = ms
            if ms > ITERATION_WATCHDOG_MS:
                slow += 1
                print(" [SLOW] iter", i, "took", ms, "ms")
        except e:
            failed += 1
            print(" [FAIL] iter", i, ":", e)

    print()
    print("──────────────────────────────────────────")
    print(" iterations :", iters)
    print(" failed :", failed)
    print(
        " slow :",
        slow,
        "(> " + String(ITERATION_WATCHDOG_MS) + " ms)",
    )
    if iters > 0:
        print(" mean :", total_ms // iters, "ms / iteration")
    print(" max :", max_ms, "ms")
    print("──────────────────────────────────────────")

    if failed > 0 or slow > 0:
        raise Error(
            "stress_scheduler: "
            + String(failed)
            + " failed, "
            + String(slow)
            + " slow — bug likely reintroduced"
        )
    print("OK — all iterations clean.")
