# Experimental: the AsyncRT thread engine

flare runs its worker threads on pthreads by default. Built with
`-D FLARE_ASYNCRT`, `ThreadHandle.spawn` instead enqueues a task on
AsyncRT, the work-queue runtime that the Mojo stdlib and the rest of
the Modular stack use. Every Mojo binary already links AsyncRT and
creates its pool before `main`, so this build puts flare's work on
that same pool and the process has a single thread engine.

This is opt-in and experimental. AsyncRT is internal to Mojo. flare
reaches it through the `KGEN_CompilerRT_AsyncRT_*` C entry points
(`Execute`, plus the `InitializeChain` / `Complete` / `Wait` /
`DestroyChain` chain calls). Those are the same shims the stdlib's
private `std.runtime._asyncrt` uses, and they can change in any Mojo
release. Without the flag the build contains no AsyncRT calls at all.

## Enabling it

```bash
mojo build -D FLARE_ASYNCRT -I . my_server.mojo -o my_server
pixi run tests-asyncrt          # the whole suite on AsyncRT
pixi run test-thread-asyncrt    # the engine tests, once per engine
```

## What moves, and what stays on pthreads

| Spawned by | Runs on under the flag | Why |
|---|---|---|
| `Scheduler` workers (HTTP/1, HTTP/2, static) | AsyncRT | Long-lived but joined on shutdown. Capacity-checked, see below. |
| WebSocket multicore workers | AsyncRT | Same as above. |
| `block_in_pool`, `resolve_async`, the H3/H2 connect race | AsyncRT | Short tasks. Fine-grained work is where a task pool pays off. |
| `DeadlineWatchdog` / `spawn_leaked_watchdog` | pthread (`spawn_os`) | Usually leaked for the life of the process. At exit AsyncRT waits for every running task, so a task that never returns would hang the exit. |
| WebSocket per-connection offload | pthread (`spawn_os`) | Lives as long as its connection. The pool has a fixed size and doesn't grow when a task blocks, so one task per connection would starve it. |

`ThreadHandle.pin_to_cpu` does nothing for an AsyncRT task, and the
`Scheduler` skips its self-pin: pinning would pin a shared pool
worker. AsyncRT has its own affinity setting (`MODULAR_ENABLE_AFFINITY=1`),
which is off by default.

## Capacity rule

Each serving worker holds one pool thread for as long as the server
runs. Under the flag, `Scheduler.start` and the WebSocket multicore
path raise when `num_workers > parallelism_level() - 1`, and
`default_worker_count()` is capped at that value. The check always
leaves one pool thread free for short tasks and for anything else in
the process that uses AsyncRT. It is applied per server, not
process-wide, so two servers started side by side can still
oversubscribe the pool together.

## Join, and why serving loops wait to start

`join` waits on the task's AsyncRT chain. If the caller is itself a
pool worker, that wait *donates* the worker: it runs other queued
tasks until the chain completes. Donation is what makes nested
fork/join work on a fixed pool. Without it, a pool full of parents
each blocked on a queued child deadlocks, and
`test_nested_join_under_load` is the regression test for that case.

The cost is that a donating waiter can pick up any queued task,
including a serving loop that never returns. So `Scheduler.start` and
the WebSocket multicore path call `ThreadHandle.wait_started()` on
every worker before returning. After that, no serving loop is left in
the queue for a waiter to pick up.

While `wait_started` waits, it enqueues a no-op task every
millisecond. AsyncRT wakes a sleeping worker only when one is asleep
at the moment a task is enqueued. Otherwise it relies on the awake
workers to drain the queue, and awake workers that pick up serving
loops never come back. Without the nudges, `stress_scheduler` could
leave one serving loop in the queue while two workers slept.

## Forked children

`fork` copies only the calling thread. A child forked from a Mojo
process inherits AsyncRT's queue but none of its worker threads. A
task enqueued there never runs, and on macOS enqueueing can crash
outright: AsyncRT wakes its workers through libdispatch, which traps
when used after `fork`. Pre-fork servers and flare's own fork-based
server tests both run into this.

So flare decides whether the pool is alive without calling into
AsyncRT. The first `spawn` in each process id counts the process's
threads, using `proc_pidinfo` on macOS and `/proc/self/stat` on Linux.
A live pool means at least `parallelism_level() + 1` threads: the
workers plus the caller. A forked child starts with one. When the
pool is dead, that process uses pthreads for everything, the capacity
rule and the `default_worker_count` cap stop applying, and flare
prints one line to stderr:

```
flare: AsyncRT pool has no worker threads in pid N (forked child?); using pthreads in this process
```

The answer is cached per pid, so every later `spawn` costs one
`getpid` and two atomic loads. `test_spawn_join_in_forked_child`
covers this path.

## Known limits

- If `Scheduler.drain` times out on a stuck worker, it detaches it.
  Under AsyncRT that task keeps its pool thread, and process exit
  waits for it.
- A handler that blocks inside `block_in_pool` work on AsyncRT holds
  a pool thread for the duration. A reactor thread that donates while
  joining can also run someone else's queued `block_in_pool` work
  before it gets back to its own connections.
- The fork check counts threads. A forked child that creates
  `parallelism_level()` threads of its own before its first flare
  spawn is mistaken for a live pool. If the OS won't report a thread
  count, flare assumes the pool is alive.
- The AsyncRT C entry points are internal to Mojo. A Mojo upgrade can
  break the build or the behaviour, so rerun `pixi run tests-asyncrt`
  after every upgrade.

## Comparing the engines

```bash
pixi run bench-threads               # spawn/join, fan-out, block_in_pool; any OS
pixi run -e bench bench-ab-threads   # flare_mc under wrk2, pthread (A) vs AsyncRT (B); Linux
```

`bench-ab-threads` builds `benchmark/baselines/flare_mc` twice and
alternates the two binaries through `ab_interleaved.sh`, which runs 4
workers. The AsyncRT pool therefore needs at least 5 threads on the
benchmark box. The pthread build pins its workers; for a pinned
comparison, set `MODULAR_ENABLE_AFFINITY=1`.
