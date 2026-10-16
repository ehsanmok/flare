# Threading: the AsyncRT thread engine

flare runs its threads on AsyncRT, the work-queue runtime that the Mojo
stdlib and the rest of the Modular stack use. Every Mojo binary already
links AsyncRT and creates its pool before `main`, so flare's work goes
on that same pool and the process has a single thread engine.
`ThreadHandle.spawn` enqueues a task; on Linux the pool's workers are
pthreads, on macOS they are native threads behind libdispatch.

AsyncRT is internal to Mojo. flare reaches it through the
`KGEN_CompilerRT_AsyncRT_*` C entry points (`Execute`, plus the
`InitializeChain` / `Complete` / `Wait` / `DestroyChain` chain calls).
Those are the same shims the stdlib's private `std.runtime._asyncrt`
uses, and they can change in any Mojo release; `pixi run
test-thread-engine` is the first thing to rerun after an upgrade.

## Where each thread runs

| Spawned by | Runs on | Why |
|---|---|---|
| `Scheduler` workers (HTTP/1, HTTP/2, static), WebSocket multicore workers | AsyncRT, while a serving lease is free; otherwise a dedicated OS thread | Long-lived but joined on shutdown. See [Serving leases](#serving-leases). |
| `block_in_pool`, `resolve_async`, the H3/H2 connect race | AsyncRT | Short tasks. Fine-grained work is where a task pool pays off. |
| `DeadlineWatchdog` / `spawn_leaked_watchdog` | OS thread (`spawn_os`) | Usually leaked for the life of the process. At exit AsyncRT waits for every running task, so a task that never returns would hang the exit. |
| WebSocket per-connection offload | OS thread (`spawn_os`) | Lives as long as its connection. The pool has a fixed size and doesn't grow when a task blocks, so one task per connection would starve it. |
| Anything in a forked child | OS thread | The child has no pool workers. See [Forked children](#forked-children). |

## Serving leases

Each serving worker holds its thread for as long as the server runs,
and the pool does not grow. So before a worker goes on the pool it
takes a lease. There are `parallelism_level() - 1` leases, counted
across the whole process, which always leaves one pool thread for
short tasks and for anything else in the process that uses AsyncRT. A
worker that finds no lease free runs on a dedicated OS thread, and the
lease comes back when its loop returns.

This means `num_workers` is never refused: on a 48-thread box,
`num_workers=48` runs 47 workers on the pool and one on its own thread,
and on a 3-core laptop `num_workers=4` runs two and two. Two servers
in one process share the same leases, so together they cannot take
every pool thread.

With `pin_cores` on, a worker pins the thread it runs on, as before. On
the pool that thread is shared, so the worker saves the thread's mask
first and puts it back when its loop returns.

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
pool is dead, that process uses OS threads for everything, and flare
prints one line to stderr:

```
flare: AsyncRT pool has no worker threads in pid N (forked child?); using OS threads in this process
```

The answer is cached per pid, so every later `spawn` costs one
`getpid` and two atomic loads. `test_spawn_join_in_forked_child`
covers this path.

## Known limits

- If `Scheduler.drain` times out on a stuck worker, it detaches it.
  On the pool that task keeps its thread and its lease, and process
  exit waits for it. `drain` leaves everything the detached worker may
  still touch (its context, stats cell, listeners and the shared stop
  flag) allocated for the life of the process; the rest is freed.
- A handler that blocks inside `block_in_pool` work holds a pool
  thread for the duration. A reactor thread that donates while joining
  can also run someone else's queued `block_in_pool` work before it
  gets back to its own connections.
- The fork check counts threads. A forked child that creates
  `parallelism_level()` threads of its own before its first flare
  spawn is mistaken for a live pool. If the OS won't report a thread
  count, flare assumes the pool is alive.
- No environment variable resizes the pool; it is sized from the core
  count. AsyncRT's own `MODULAR_ENABLE_AFFINITY=1` pins its workers.

## Measuring it

```bash
pixi run bench-threads   # spawn/join and fan-out, AsyncRT task vs OS thread; block_in_pool
```

To compare a server build against an older one, build both and hand
them to `ab_interleaved.sh` (`A_BIN=... B_BIN=... pixi run -e bench
bench-ab`), which alternates them under wrk2.
