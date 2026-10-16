# L5: Concurrency (`flare/runtime/`)

This layer covers the code in `flare/runtime/` that coordinates threads through shared memory:

- the deadline watchdog's slot protocol (`watchdog.mojo`);
- the AsyncRT task cell (`_asyncrt.mojo`);
- the `ThreadHandle` join/detach discipline (`_thread.mojo`);
- the multi-worker `Scheduler` lifecycle: start state, worker loop, stop flag, `drain` and `shutdown` teardown (`scheduler.mojo`, `_worker.mojo`, `scheduler_stats.mojo`);
- the shared-listener mode (`FLARE_REUSEPORT_WORKERS=0`): who may still use the listener's fd number during teardown;
- `start`'s rollback after a failed `pthread_create`, drain's stuck-worker index bookkeeping, and the POSIX error returns of `pthread_join` / `pthread_detach`;
- teardown timing: how long after the stop flag every worker is done and `shutdown` / `drain` return, against a clock;
- the io_uring buffer-ring worker (`http/_server_reactor_uring.mojo`, `runtime/uring_reactor.mojo`): whether it can run on the shared listener, how it uses the fd number, and how it waits.

Each component is an interleaving small-step semantics over a shared heap. Threads are program counters. Every atomic operation (load, store, CAS, a free) is one step, and the scheduler is an unconstrained choice of label with no fairness assumption. The one exception is the timing model, `Flare.L5.Timed`, where OS fairness, the kernel's timeout and handler time are explicit hypotheses.

The models are the shipped code. Safety properties are proved as general inductive invariants, so they hold for every trace length and, for the scheduler, for every number of workers. The scheduler also has an executable state-space explorer with a soundness proof. It is checked exhaustively with `decide` for one and two workers; those results are labelled "bounded".

Not modelled:

- the frontends' serve loops, beyond "load the stop flag, else one iteration touching the context, listener and stats cell" (and, for the shared-listener model, "register the fd number, then accept on it for each polled listener event");
- `runtime/blocking.mojo`, which belongs to L2;
- AsyncRT internals, beyond three stated assumptions.

Modules: `Flare.L5_Concurrency.{Watchdog, AsyncRT, Thread, Scheduler, SharedListener, Lifecycle, Timed, UringShared}`, aggregate `Flare.L5_Concurrency`, audit `Flare/Audit/L5.lean`. There are 153 theorems in total. No `sorry`, `admit`, `axiom` or `native_decide` appears anywhere.

## Components

### DeadlineWatchdog slot protocol (`flare/runtime/watchdog.mojo`)

**Model** (`Flare.L5.Watchdog`). Each slot has two shared words:

- the deadline: `0` means disarmed, `d > 0` means armed, and `-1` (`_FIRING`) means the poller is writing the cell;
- the cancel-cell address.

There is also a clock and the cancel cells. Two threads act on a slot:

- **The poller** (`PPc`, `_watchdog_main`): read the clock, load the deadline, CAS `d → FIRING` when `0 < d ≤ now`, load the address, store `TIMEOUT` into the cell, then store `0`.
- **The worker** (`WPc`, `watchdog_arm` and `watchdog_disarm`) runs requests. Each request is:
  - `arm`: the disarm loop (settle, then CAS a held deadline to `0`), store the address, compute the deadline with `_deadline_after` (`deadlineOf`: `now + budget` saturated at `Int64.MAX`, then raised to at least 1), then settle-and-CAS `0 → deadline`;
  - then the handler;
  - then `disarm`: settle, then CAS `v → 0`, or return `True` if the slot is already `0`.

The label `rearm` lets a caller re-arm without disarming, and the budget is arbitrary. Ghost fields record which request owns which deadline and claim.

Slots are independent words, so one slot is modelled. **Memory model:** sequential consistency. Every slot access is atomic (acquire loads, release stores, default-ordering CAS). The one cross-location dependency is that the poller reads `addr` after its claim. It is ordered by the worker's release store of `addr`, which is sequenced before the CAS the poller reads from. This argument is written in the module docstring, not proved in Lean.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.Watchdog.inv_inductive` | The program-counter-indexed invariant is inductive, for every budget and with re-arming allowed | proved |
| `Flare.L5.Watchdog.shipped_safe` | Every reachable state satisfies `Safe` (a cell write targets the current request, with that request's own expired deadline, before its disarm returned), `DisarmCorrect` (disarm returns `True` iff the cell was cancelled) and `FiringOwned` (FIRING is only ever held by the poller inside its claim window) | proved |
| `Flare.L5.Watchdog.deadlineOf_pos` | The stored deadline is positive for every clock reading and budget | proved |

Assumptions: the monotonic clock reads at least 1 ms (the `Init` predicate). Limitations: one slot and one worker per slot, as in flare (one slot per worker). `stop()` and the control-block lifetime are not modelled; the watchdog is leaked for the process lifetime by design.

### AsyncRT task cell (`flare/runtime/_asyncrt.mojo`)

**Model** (`Flare.L5.AsyncRT`). Two threads share one heap cell:

- **The trampoline** stores `started`, loads `arg`, runs `start` and CASes `RUNNING → DONE`. It then completes the chain, and also destroys the cell if the CAS lost to a detach.
- **The owner** does one of: `join` (wait on the chain, destroy, zero the handle), `detach` (CAS `RUNNING → DETACHED`, or wait and destroy if that fails), `wait_started`, or dropping the handle.

The model tracks `frees`, a ghost `uaf` flag, the chain-completed flag and the result. `stepFn` is executable and agrees with the step relation.

**Memory model:** sequential consistency.

- `compare_exchange` uses the stdlib default, which is `SEQUENTIAL` on CPU targets.
- Who frees the cell is decided only by RMWs on the single `state` word, whose modification order is total under any ordering.
- Data flows from task to owner through the chain: `Complete` is `copy().emplace()` (release) and `Wait` is `await` (acquire), in `Mojo/lib/CompilerRT/AsyncRT.cpp:67-76`.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.AsyncRT.inv_inductive` | `Inv` is inductive over every interleaving, by case split on every step including the CAS winner | proved |
| `Flare.L5.AsyncRT.free_at_most_once` | In every reachable state, `frees ≤ 1` | proved |
| `Flare.L5.AsyncRT.no_use_after_free` | No step dereferences a freed cell | proved |
| `Flare.L5.AsyncRT.chain_before_free` | If the cell was freed, the chain was completed and the result produced first | proved |
| `Flare.L5.AsyncRT.join_returns_after_done` | After `join` returns: state DONE, chain complete, result produced, freed once | proved |
| `Flare.L5.AsyncRT.no_leak`, `freed_exactly_once` | A terminal state not reached by a drop has `frees = 1` and no use after free | proved |
| `Flare.L5.AsyncRT.progress` | Every reachable non-terminal state has a non-stuttering step (deadlock freedom) | proved |
| `Flare.L5.AsyncRT.calls_after_zero_are_noops` | `join`, `detach` and `wait_started` on a zeroed handle are no-ops | proved |
| `Flare.L5.AsyncRT.step_iff_stepFn` | Relational and executable semantics agree | proved |
| `Flare.L5.AsyncRT.ar1_load_bearing` | If `Complete` touched the cell after publishing, a use after free would be reachable | counterexample (of the hypothetical variant) |
| `Flare.L5.AsyncRT.guard_load_bearing` | Without zeroing the handle, detach followed by join frees twice | counterexample (of the hypothetical variant) |
| `Flare.L5.AsyncRT.drop_leaks` | Dropping a live handle leaks the cell (the documented contract) | counterexample (by design) |

Assumptions:

- **AR-1:** `Complete` reads the cell only before publishing.
- **AR-2:** `Wait` returns only after `Complete`.
- **AR-3:** the start routine does not touch the cell.

All three are encoded in the step relation and taken from the AsyncRT source as read, not from the shipped binary. Limitations: AsyncRT is otherwise a black box, work-stealing donation inside `Wait` is not modelled, and liveness is deadlock freedom rather than termination under fairness.

### ThreadHandle (`flare/runtime/_thread.mojo`)

**Model** (`Flare.L5.Thread`). One OS or AsyncRT thread and two handle slots of type `Option Handle`. The events are:

- `join` and `detach`, each with an environment-chosen return code;
- `waitStarted`, `pin` and `drop`;
- `move` (Mojo `^`);
- `alias` (a bitwise copy, only under `Cfg.allowAlias`).

Counters record successful pthread operations, cell operations, POSIX undefined behaviour and bad `pin` calls. No memory model is needed: the handle is mutated only by its owner. The model discharges the AsyncRT model's guard premise.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.Thread.inv_inductive` | Inductive invariant on both platforms (single owner, no POSIX UB, at most one consuming effect) | proved |
| `Flare.L5.Thread.at_most_one_effect` | At most one of `pthread_join` / `pthread_detach` / `asyncrt_join` / `asyncrt_detach` takes effect, even with failures and retries | proved |
| `Flare.L5.Thread.no_posix_ub` | `pthread_join` / `pthread_detach` are never applied to a consumed thread | proved |
| `Flare.L5.Thread.zeroed_noop` | `join` and `detach` on a zeroed handle leave the state unchanged | proved |
| `Flare.L5.Thread.failed_call_keeps_handle` | A failed `pthread_join` / `pthread_detach` leaves the handle usable for a retry | proved |
| `Flare.L5.Thread.moved_from_inert` | Every operation on a moved-from slot is disabled (the Mojo move checker) | proved |
| `Flare.L5.Thread.drop_live_leaks` | Dropping the only live handle leaves the thread joinable, since there is no destructor | proved (by design) |
| `Flare.L5.Thread.alias_double_join` | A bitwise alias double-joins (`ub = 1`) | counterexample (outside Mojo's move semantics) |
| `Flare.L5.Thread.pin_after_join_hazard`, `pin_noop_macos` | On Linux, `pin_to_cpu` after `join` passes `pthread_t` 0; on macOS it is a no-op | counterexample (unreachable in flare) |

Limitations: one thread per handle and two slots. Handles stored in raw buffers (the scheduler's worker array) are outside this model; the scheduler model covers their single join or detach.

### Scheduler lifecycle (`flare/runtime/scheduler.mojo`, `_worker.mojo`, `scheduler_stats.mojo`)

**Model** (`Flare.L5.Scheduler`). The shared heap is:

- the stop flag (value `stop`, freed bit `stopF`);
- per worker, freed bits for its context, stats cell and per-worker listener;
- per worker, the `WORKER_STAT_DONE` slot.

The initial state (`init n`) is the one `Scheduler.start` returns: everything allocated and every worker at `start`.

A worker (`WPc`, `_worker_entry`) steps through:

1. `start`: reads the context.
2. `loop`: loads the stop flag; exits to `doneSt` if it is set, otherwise goes to `serve`.
3. `serve`: one reactor iteration or handler, touching the context (which holds the frontend), the listener and the stats cell; then back to `loop`.
4. `doneSt`: the release-store of `WORKER_STAT_DONE` through the context (`store_worker_stat`).
5. `ret`, then `term`.

The drain thread (`MPc`, `Scheduler.drain`) steps through:

1. `signal`: `_signal_stop`, which stores `stop := True`.
2. `wait`: any number of `sample i` steps reading `WORKER_STAT_DONE` into `done[i]`. The deadline may expire at any point (an over-approximation of the Mojo loop).
3. `sweep k` for `k = 0..n-1`: join worker `k` if `done[k]` (enabled only once it has terminated), otherwise detach it.
4. `report`: read every stats cell.
5. `free` (`freeAll`): the stuck-worker carve-out followed by `_free_resources`. The detached workers' contexts, stats cells and listeners are dropped from what gets freed, the stop flag is leaked when a worker was detached, and everything else is freed.
6. `fin`.

Every dereference ORs the cell's freed bit into the ghost flag `uaf`. `Cfg` has one flag, `hard`: `shutdown()` or `drain(timeout_ms <= 0)`, where every worker is joined. `cfgShutdown` and `cfgDrain` (`drain(timeout_ms > 0)`) name the two configurations.

**Memory model:** sequential consistency.

- The stop flag and each stats slot are single locations accessed by release stores and acquire loads (`store_stop_flag` / `load_stop_flag` and `store_worker_stat` / `load_worker_stat` in `scheduler_stats.mojo`), so their modification order is total.
- Freeing a joined worker's cells is ordered after all of that worker's accesses by `pthread_join`.
- Nothing a detached worker can reach is freed at all, so no ordering argument is needed for it.

**Environment assumption:** `pthread_join` and `pthread_detach` on a live, joinable handle succeed, so the `except: pass` branches in `_join_workers` and `drain` never run. This is no longer an assumption of the layer: `Flare.L5.Lifecycle.live_handle_calls` derives it from the POSIX error cases for every teardown that runs on a thread other than the workers, which every in-repo caller does. What flare does when a call does fail is `impl_freed_under_live_iff` (see "Lifecycle bookkeeping" below).

**Specification:**

- `MemSafe` (`uaf = false`).
- `LiveRefsAllocated`: a worker that has not terminated still has its context, stats cell and listener, and the stop flag is allocated. This is the property "nothing a live worker can reference is freed".
- `NoLeak`: after drain, every non-detached worker's cells are freed, and the stop flag is freed when nobody was detached. This follows the `drain` docstring.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.Scheduler.core_inductive` | The per-worker / per-phase invariant `Core` is inductive in both configurations and for every `n` | proved |
| `Flare.L5.Scheduler.coreSI_inductive` | `Core ∧ SI` (no use after free; stop freed only when all workers are joined) is inductive in both configurations | proved |
| `Flare.L5.Scheduler.safe_of_cfg` | In both configurations every reachable state is `MemSafe` and `LiveRefsAllocated`, for any number of workers | proved |
| `Flare.L5.Scheduler.noLeak_of_cfg` | In both configurations every reachable state satisfies `NoLeak` | proved |
| `Flare.L5.Scheduler.shutdown_safe` | `shutdown()` / `drain(<=0)` is memory safe and leak free | proved |
| `Flare.L5.Scheduler.drain_safe` | `drain(timeout_ms > 0)` is memory safe, frees nothing a live worker can reference, and leaks only the detached workers' resources (and then the stop flag) | proved |
| `Flare.L5.Scheduler.detached_sees_stop` | A worker still live after drain reads an allocated stop flag holding `True` | proved |
| `Flare.L5.Scheduler.soft_join_bounded` | In a soft drain, a worker seen DONE is at its final return or terminated, so the join waits at most one worker step | proved |
| `Flare.L5.Scheduler.check_sound` | If the explorer's certificate check returns `true`, the property holds on every reachable state | proved |
| `Flare.L5.Scheduler.bounded_drain` | `drain(timeout_ms > 0)` meets `specB` for 1 and 2 workers, all interleavings (`decide +kernel`; 47 and 389 states) | bounded (n ≤ 2) |
| `Flare.L5.Scheduler.bounded_shutdown` | `shutdown()` meets `specB` for 1 and 2 workers | bounded (n ≤ 2) |

Limitations:

- The serve loop is abstract.
- Freeing is one step. The frees are monotone, so splitting the step only adds interleavings with the same `uaf` outcome.
- The wait loop over-approximates the Mojo loop's sampling, which is sound for safety.
- This model's workers hold the heap listener of per-worker mode. The shared-listener mode, where workers hold only the fd number, is the separate model `Flare.L5.SharedListener`. `start`'s rollback and the stuck-worker pops are modelled in `Flare.L5.Lifecycle`.

### Shared-listener mode (`FLARE_REUSEPORT_WORKERS=0`; `runtime/scheduler.mojo`, `http/_server_reactor_epoll.mojo`)

**Model** (`Flare.L5.SharedListener`). The workers receive only the shared listener's fd number. A worker (`WPc`, `_run_handler_loop_impl`):

1. `reg`: registers the number with `register_exclusive`.
2. `check`: loads the stop flag.
3. `acc`: is past the check with a polled listener event, and calls `_accept_loop_fd(listener_fd, ...)`. A slow handler earlier in the same event batch just delays this step.
4. `done`.

The fd number's state (`Fd`) is the listener, closed, or `other`. The environment step `reuse` is an unrelated `open`/`socket`/`accept` taking the lowest free number. The teardown thread does `signal` (`_signal_stop`, which only stores the flag), `sweep k` (join if returned, else detach; with `hard` it waits), `free` (`freeFd`: `_free_resources` closes the number once when no worker was detached, and otherwise the shared listener is leaked), `fin`. The model takes `hard : Bool`, true for `shutdown()` / `drain(timeout_ms <= 0)`. A worker step that uses the number while it does not name the listener sets the ghost flag `stale`.

**Memory model:** the stop flag as in the scheduler model; `close`, `reuse` and `accept` are atomic system calls on the process fd table, so the interleaving is sequentially consistent.

**Specification:** `NoStaleUse` (no worker registers or accepts on the number after it stopped naming the listener). `ClosedAtEnd`: when teardown finished and no worker was detached, the listener is closed.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.SharedListener.inv_inductive` | The invariant (no stale use; a non-listener number implies every worker joined; sweep/free bookkeeping) is inductive for `shutdown` and `drain`, any `n` | proved |
| `Flare.L5.SharedListener.noStale` | `NoStaleUse` in every reachable state of `shutdown` and `drain`, any `n`, any interleaving with fd reuse | proved |
| `Flare.L5.SharedListener.closedAtEnd` | The listener is closed at the end unless a worker was detached | proved |
| `Flare.L5.SharedListener.stop_exits` | A worker leaves its loop without the fd being closed: from `check` or `acc` with the flag set it reaches `done` in at most two steps | proved |

Limitations: this model is untimed; `stop_exits` is only the step-level part of liveness. The time bound, from the 100 ms poll cap, is `Flare.L5.Timed` below. The io_uring worker on the shared fd is `Flare.L5.UringShared` below.

### Teardown timing (`http/_reactor/lifecycle.mojo`, `http/_server_reactor_epoll.mojo`, `http/_server_reactor_uring.mojo`, `runtime/scheduler.mojo`)

**Model** (`Flare.L5.Timed`). There is a discrete clock (`tick`, read as 1 ms) and one worker loop shared by every serve loop the scheduler runs:

1. `reg`: register or arm the listener.
2. `check`: load the stop flag.
3. `poll`: wait for events.
4. `ready`: the wait returned, but the thread may not be on a CPU.
5. `batch`: accepts, connection steps and handlers.
6. Back to `check`; or, once the flag is seen, `clean` (the worker's own teardown and the `WORKER_STAT_DONE` store), then `done`.

Each worker records the time it entered its phase. Only the kernel ends a `poll` (label `k i`), and it always can: every loop's wait has a timeout of at most the cap. The epoll/kqueue loops pass `_poll_timeout_ms(wheel)` (`pollTimeout_le_cap`), and both io_uring loops pass `URING_STOP_POLL_MS` (100 ms) to `poll`. The teardown thread is `shutdown` or `drain(D)` (`Cfg.drain`); closing the shared listener in `_free_resources` changes no timing:

- `sig`: store the flag;
- `wait` (drain only): until every worker returned or the deadline passed, taking the `done[]` snapshot;
- `pass k`: join worker `k`, or detach it when the snapshot says it was stuck;
- `free`, then `fin`.

**Hypotheses** (each a `Prop` on states; `Hyp` is their conjunction, required of every state of a run through `ltsH`):

- `PollReturns`: a wait returns within `cap + ε`.
- `FairW`, `FairM`: OS fairness; a runnable worker, or the teardown thread once its next step is enabled, runs within `σ`.
- `HandlerBound`: a batch takes at most `η`. This covers handlers and `_accept_loop_fd`, which accepts until `EAGAIN` with no per-call cap, so it also depends on the connection arrival rate.
- `TeardownBound`: a worker's post-loop teardown takes at most `τ`.

`bound P = cap + ε + σ + η + σ + τ`. That is the worst case: the flag lands just after a check, then a full wait, a CPU wait, a batch, the next check, and the teardown. `mBound P c n = bound P + (n + w + 2)·σ`, with `w = 1` for drain (its wait loop).

**Specification:** after the stop at `t0`, every worker is `done` by `t0 + bound P`; `shutdown` / `drain` reach `fin` by `t0 + mBound P c n`; a drain with `D > bound P` detaches nobody.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.Timed.pollTimeout_le_cap`, `pollTimeout_pos` | `_poll_timeout_ms` is always in `[1, cap]` (with an empty wheel `next_fire_ms` is the tick plus 2^32, so the difference stays positive and the cap applies) | proved |
| `Flare.L5.Timed.J_inductive` | The timed invariant (each worker's worst-case completion time is at most `t0 + bound P`; teardown phase times bounded; drain snapshot all-true when `D > bound P`) is inductive over runs meeting `Hyp`, any `n`, either teardown | proved |
| `Flare.L5.Timed.worker_done_by` | Under `Hyp`, every worker is `done` once more than `bound P` has passed since the stop | proved |
| `Flare.L5.Timed.teardown_done_by` | Under `Hyp`, `shutdown` / `drain` reach `fin` once more than `mBound P c n` has passed since the stop | proved |
| `Flare.L5.Timed.drain_joins_all` | Under `Hyp`, a drain with deadline `D > bound P` takes a snapshot in which every worker returned, so it joins all of them, detaches none, and frees (in shared mode: closes) the listener | proved |
| `Flare.L5.Timed.bound_epoll` | With the 100 ms cap the per-worker bound is `100 + ε + 2σ + η + τ` ms | proved |
| `Flare.L5.Timed.bound_tight` | A run meeting every hypothesis in which the worker finishes exactly at `t0 + bound P` (the bound is tight, and `Hyp` is satisfiable) | proved (by `decide`) |

The bound answers the 2 × cap + ε question with a tighter one: one full wait, not two, because the flag is re-read right after every wait. `σ` covers both the wake-up latency after the wait and the next check.

Limitations:

- The hypotheses are stated, not derived: the kernel honouring the timeout (`ε`), the OS scheduler (`σ`), the handler code and the arrival rate (`η`).
- Without `HandlerBound` no bound exists. That is by design: a handler that never returns is what drain's deadline and detach are for, and `shutdown` waits for it.
- The stop flag is visible to the first load after the store. That is the release/acquire pair, with cache-coherence latency folded into `σ`.
- The model has one listener per worker. Extra addresses do not change the loop's shape.

### io_uring buffer-ring worker (`http/frontend.mojo`, `http/_server_reactor_uring.mojo`, `runtime/uring_reactor.mojo`, `runtime/io_uring.mojo`)

**Model** (`Flare.L5.UringShared`) has two parts.

1. **Listener choice.** `requiresPerWorker` and `uringDispatch` mirror the frontend's two predicates (`HttpFrontend.requires_per_worker_listener` and the dispatch in `HttpFrontend.run_worker`), and `prebind` mirrors `Scheduler.start`'s choice.
2. **fd use.** `uwStep` / `ustep` is the io_uring worker (`run_uring_bufring_reactor_loop_shared`) on `SharedListener`'s state, with the same `hard` flag. It uses the number once, when it arms the multishot accept (`arm_listener_multishot(listener_fd)`), before its first stop check. Later accepts are completions of that request, which holds its own reference to the socket. `R` relates an io_uring state to an epoll state that agrees on everything except having at least the same stale uses.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.UringShared.uring_never_shared` | If both threads get the same io_uring probe result, a worker that runs the io_uring loop was given a per-worker listener: the frontend's `requires_per_worker_listener` forces `prebind` | proved |
| `Flare.L5.UringShared.probe_skew_shared` | If the scheduler thread's probe fails and the worker's succeeds, with `FLARE_REUSEPORT_WORKERS=0`, the io_uring loop does run on the shared fd. `use_uring_backend` re-reads the env var and re-runs `io_uring_setup` on every call, with no cache | proved (reachable only through a transient probe failure or an env change) |
| `Flare.L5.UringShared.sim_step`, `sim_reachable` | Forward simulation: every io_uring step is an epoll `SharedListener` step with the same label, and every stale use on the io_uring side is one on the epoll side | proved |
| `Flare.L5.UringShared.uring_fixed_noStale`, `uring_fixed_closedAtEnd` | So the teardown is also safe for an io_uring worker on the shared fd, `shutdown` or `drain`, any `n` | proved |

The result is that the shared-listener path reduces to the existing model, with a simulation and in a weaker form for fd use. The io_uring loop differs only in how it waits: its ring is built with `enable_wakeup=False`, so it sees the stop flag only because its `poll` is bounded by `URING_STOP_POLL_MS` (CONC-07). With that bound it is one of the loops of `Flare.L5.Timed`, with `cap = 100`.

Limitations:

- The kernel's multishot accept is abstracted to "completions keep coming from the armed request". Its termination (`!has_more`, never re-armed by the loop) is not modelled; that loop can then accept nothing more, which is not a safety issue.
- The probe-skew case is shown reachable at the level of the two predicates. Forcing a transient `io_uring_setup` failure on one thread was not attempted, so it has not been reproduced.

### Lifecycle bookkeeping (`runtime/scheduler.mojo`, `runtime/_thread.mojo`)

**Model** (`Flare.L5.Lifecycle`), three sequential parts.

1. **`start` and its rollback.** The heap is a count per resource: stop flag, shared listener, worker array, stats cell `i`, per-worker listener `i`, context `i`, plus a count of running worker threads. `free` of a resource with count 0 sets `dbl`; freeing anything a worker can reach while a worker thread runs sets `uaf`. In `Scheduler.start`, `startAlloc` mirrors the allocation order, `spawnR` the successful spawns, and `startFail` the failure of spawn `k` followed by the rollback, which also frees the per-worker listeners. `abandon` is `_abandon_start` after a failed bind.
2. **Drain's stuck-worker branch.** In `Scheduler.drain`, `sweepStuck` is the sweep's `stuck.append(i)`, `eraseAt` is Mojo `List.pop(idx)`, and `popStuck` is the descending pop loop with its `idx < len` guard.
3. **POSIX return codes.** `pjoin` / `pdetach` give `ESRCH` (thread reaped), `EINVAL` (not joinable, or already being joined) and `EDEADLK` (self-join). `WOut` is one worker's sweep outcome; `keptImpl` is flare's rule (append to `stuck` only when `detach` returned; a raising call falls into `except: pass` and the worker's resources are freed); `liveAfter` says whether the thread may still run.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.Lifecycle.rollback_clean` | For every worker count, listener count and failing spawn index, in both listener modes: the rollback joins every spawned worker, frees nothing twice, frees nothing under a running worker, and leaves nothing allocated (`startFail … = H.empty`) | proved |
| `Flare.L5.Lifecycle.abandon_clean` | `_abandon_start` after a failed per-worker bind leaves nothing | proved |
| `Flare.L5.Lifecycle.popStuck_keeps_joined` | For any `n`, any set of detached workers and any per-worker list, the pops leave exactly the entries at non-detached indices, in order; the same predicate applies to `_ctx_addrs` and `_stats_addrs`, so they stay aligned | proved |
| `Flare.L5.Lifecycle.freed_iff_not_detached` | An entry is freed by `_free_resources` iff it belongs to a worker that was not detached | proved |
| `Flare.L5.Lifecycle.live_handle_calls` | On a live handle (from `Thread.inv_inductive`) `pthread_detach` returns 0, and `pthread_join` returns 0 unless the caller joins itself | proved |
| `Flare.L5.Lifecycle.impl_freed_under_live_iff` | flare's teardown frees resources of a possibly running thread iff some `join`/`detach` failed | proved |
| `Flare.L5.Lifecycle.impl_safe_of_external_caller` | If every call returns 0 (teardown on a non-worker thread), nothing is freed under a live thread | proved |
| `Flare.L5.Lifecycle.self_shutdown_frees_caller` | `shutdown()` / `drain(<=0)` called from a worker joins itself, gets `EDEADLK`, and flare frees that worker's resources under it | counterexample (API hazard, unreachable in flare) |
| `Flare.L5.Lifecycle.self_drain_keeps_caller` | `drain(>0)` from a worker detaches itself, which succeeds, and keeps its resources | proved |
| `Flare.L5.Lifecycle.fixed_never_frees_live` | Treating a failed call like a detach never frees under a live thread | proved |

Assumptions: the POSIX error cases as listed in IEEE 1003.1 for `pthread_join` / `pthread_detach`; "another thread is already joining" is excluded by the single owner (`Thread.at_most_one_effect`). That the teardown runs on a thread other than the workers is a property of the callers (`HttpServer.serve*` in `http/server.mojo`: the serving thread owns the `Scheduler` and calls `shutdown` after its wait loop). The Mojo type system does not enforce it; a Frontend would need an unsafe pointer to the `Scheduler` to violate it.

## Findings

### CONC-01: a non-positive deadline is stored unchecked; `-1` wedges the slot

- **Severity:** Low (latent). No flare code arms the watchdog at 59bda50. A caller passing an already-spent budget, or one that overflows `now + budget`, would hang that worker in `_settle` forever.
- **Clause violated:** the `_FIRING` contract at `watchdog.mojo:47-49` ("a fire that has begun always lands on the request it was meant for"; `arm` and `disarm` wait it out), and `FiringOwned` in the model.
- **What goes wrong:** `watchdog_arm` computes `Int64(monotonic_now_ms() + budget_ms)` at `watchdog.mojo:107` and CASes it in at :110 with no range check.
  - `budget_ms = -(now + 1)` stores `-1`, which is the FIRING sentinel. The poller skips it (`d > 0`, :162), and every later `arm` or `disarm` spins in `_settle` (:81-87).
  - Any deadline `≤ 0` never fires, and `0` reads as "disarmed".
- **Lean counterexample:** `Flare.Bugs.CONC_01.arm_firing_sentinel` (at tag `formal-audit-0.12`). It is a reachable state with `¬ FiringOwned`, from which no schedule lets `disarm` return; `stuck_closed` shows the state is closed under every step.
- **Fix:** clamp the deadline to at least 1. A saturating add would also keep a huge budget from wrapping into an immediate fire. With the clamp (and CONC-02's disarm-first), `Flare.L5.Watchdog.shipped_safe` holds for every budget.
- **Repro:** `formal/repro/CONC-01_watchdog_nonpositive_deadline.mojo` (at tag `formal-audit-0.12`). Observed:
  `BUG REPRODUCED: arm with an expired budget left slot 0 at the FIRING sentinel (-1) after 50 polls; the cell was never flipped and disarm(0) would spin forever`.
- **Flip:** with the clamp, `OK: arm with an expired budget fires at the next poll` and exit 0. Restored.

Status: resolved. `watchdog_arm` takes its deadline from the new `_deadline_after`: the sum saturates at `Int64.MAX` (a huge budget no longer wraps into the past, as the report suggested) and is raised to at least 1, so a spent budget fires at the next poll and the `-1` sentinel can no longer be stored. Tests: `tests/runtime/test_watchdog.mojo::test_arm_with_an_expired_budget_fires_at_the_next_poll` (failed before: the cell was never flipped) and `::test_arm_with_a_huge_budget_saturates_instead_of_wrapping`. The repro printed `OK:` after the fix (3 of 3 runs). The watchdog model is the shipped arm (`deadlineOf` is `_deadline_after`); `Flare.L5.Watchdog.shipped_safe` and `deadlineOf_pos` are stated about it. Decision: no test pins the exact `-1` deadline, since it depends on the clock reading at `arm`; the spent-budget test uses a budget far below `-now`, which stored a negative deadline before.

### CONC-02: re-arming a still-armed slot fires the old deadline into the new request's cell

- **Severity:** Low (latent). A grep of `flare/` finds no caller that re-arms without `disarm`. There is no production call site at all; only `tests/runtime/test_watchdog.mojo` uses the watchdog, and its re-arm happens after the fire has completed, which `_settle` makes safe. The `arm` docstring does not state the "disarm first" precondition.
- **Clause violated:** `watchdog.mojo:47-49` (the fire lands on the request it was meant for) and the `disarm` contract (:114-124). In the model these are `Safe` and `DisarmCorrect`.
- **What goes wrong:** `arm` stores the new cell's address (:106) before CASing the new deadline in (:110). While the slot still holds the previous, expired deadline, the poller can claim it (:161-165), load the new address (:166) and write `TIMEOUT` into the new cell. The new request is cancelled with its 60 s budget untouched, and its `disarm` returns `False`.
- **Lean counterexamples** (at tag `formal-audit-0.12`):
  - `Flare.Bugs.CONC_02.rearm_hits_new_cell`: an explicit 13-step trace reaching a poller write into cell 2 under request 1's claim (`¬ Safe`).
  - `Flare.Bugs.CONC_02.rearm_disarm_wrong`: the continuation ends with cell 2 cancelled, request 2's deadline at 60001 ms, and `disarm` reporting not fired (`¬ DisarmCorrect`).
- **Fix:** start `watchdog_arm` with the disarm loop (CAS the current deadline to 0, waiting out FIRING), then store the address and CAS `0 → deadline`. With it, `Flare.L5.Watchdog.shipped_safe` holds with re-arming allowed and any budget.
- **Repro:** `formal/repro/CONC-02_watchdog_rearm_fires_old_deadline_on_new_cell.mojo` (at tag `formal-audit-0.12`). It races the real `arm` against the real poller for up to 4 s, because the poll loop cannot be driven one iteration at a time. Observed:
  `BUG REPRODUCED: re-arming a still-armed slot cancelled the new request's cell (60 s budget) in round 33291 ; disarm reported fired = False`.
- **Flip:** with the disarm-first arm, `OK: no stale fire hit the new cell in 49483143 rounds` and exit 0. Restored. The repro is nondeterministic, so an OK result is evidence, not proof.

Status: resolved. `watchdog_arm` now begins with the disarm loop (CAS the held deadline to 0, waiting out FIRING) before it stores the new address, then CASes `0 -> deadline`. Test: `tests/runtime/test_watchdog.mojo::test_rearming_an_armed_slot_never_fires_the_old_deadline_into_the_new_cell`, which runs the real `arm` against the real poller for up to 1 000 000 rounds and checks the new cell after `disarm` (failed in 3 of 3 runs before the fix; passes in 3 of 3 after). The repro printed `OK:` after the fix (3 of 3 runs, about 48 million rounds each). The watchdog model is the shipped arm, with re-arming allowed (`Lbl.rearm`); `Flare.L5.Watchdog.shipped_safe` is stated about it. Decision: the window is a few instructions wide and the poller cannot be stepped from outside, so there is no deterministic unit test; the bounded stress test misses a pre-fix stale fire with negligible probability (the race showed up about once per 30 000 rounds) and cannot raise a false alarm, since the new cell's 60 s budget is far in the future. The `arm` docstring now states that a still-armed slot is released first.

### CONC-03: `Scheduler.drain` frees the stop flag under a detached worker

- **Severity:** High. This is a use-after-free on the public, documented `Scheduler.drain(timeout_ms > 0)` path (`docs/asyncrt.md:101`, `examples/intermediate/drain.mojo`). It is reached whenever a handler outlives the drain timeout. The observed consequence is a worker that keeps serving after `drain` returned, on a listener that drain deliberately left open.
- **Clause violated:** the drain docstring at `scheduler.mojo:799-803` says the detached worker's resources "are left allocated, since the thread may still be using them". In the model this is `MemSafe` / `LiveRefsAllocated`.
- **What goes wrong:** the stuck-worker branch (`scheduler.mojo:887-897`) pops the stuck worker's context and stats entries. `_free_resources` (:900, :741-744) then frees the shared stop-flag cell anyway. The detached worker re-reads that cell on every serve-loop iteration (`_worker.mojo:114-116,150-155`, via the frontend's `load_stop_flag`).
- **Lean counterexamples** (at tag `formal-audit-0.12`):
  - `Flare.Bugs.CONC_03.drain_frees_live_ref`: a 9-step trace with one worker in `serve` at `fin` and the stop flag freed (`¬ LiveRefsAllocated`).
  - `Flare.Bugs.CONC_03.drain_uaf`: two more worker steps dereference the freed flag (`¬ MemSafe`).
  - The explorer found the violation independently, for one and for two workers.
- **Fix:** in `if len(stuck) > 0:`, set `self._stopping_addr = 0` before `_free_resources`, which leaks the flag like the stuck worker's other cells. With it, `Flare.L5.Scheduler.drain_safe` holds for every `n`, and `detached_sees_stop` shows the detached worker then reads `True` and exits.
- **Repro:** `formal/repro/CONC-03_drain_frees_stop_flag_under_detached_worker.mojo` (at tag `formal-audit-0.12`). Observed in 5 of 5 runs, for example:
  `BUG REPRODUCED: drain freed the stop flag at 0x10a0c0008 under the detached worker (cell reissued: True; worker saw the stop: False)`.
- **Flip:** with the fix, `OK: drain left the stop flag allocated and the detached worker saw the stop` and exit 0, in 3 of 3 runs. Restored.
- **Determinism:** the verdict is "the flag cell was freed", observed as the cell being handed out again by one of the next 64 same-size allocations on the thread that called `drain`. A leaked cell can never come back. What the worker then reads is reported only as a consequence.
  - Mojo's allocator is the TCMalloc embedded in `libKGENCompilerRTShared` (not the system malloc, so `malloc_size` cannot be used). It hands a freed small cell back within the few same-class frees `drain` performs after it.
  - The repro calibrates that property first, with three same-size frees, and raises `setup:` instead of printing OK if it fails. It therefore cannot print OK while the cell is freed.
  - Two pitfalls make an earlier version of the check report "not reissued" falsely. The optimizer folds "fresh allocation == older address" to false, so the address goes through an atomic cell. A scratch cell in the same 8-byte size class consumes the freed cell, so the scratch is 64 bytes.

Status: resolved. `drain` sets `self._stopping_addr = 0` in the stuck-worker branch, so the stop flag is leaked with the detached worker's other cells. Test: `tests/runtime/test_scheduler.mojo::test_drain_keeps_the_stop_flag_allocated_for_a_detached_worker`; the repro printed `OK:` after the fix. The scheduler model's drain (`freeAll`) is the shipped one; `Flare.L5.Scheduler.drain_safe` and `detached_sees_stop` are stated about it.

### CONC-04: `Scheduler.drain` leaks the joined workers' listeners whenever one worker is detached

- **Severity:** Medium. Every non-stuck worker's `SO_REUSEPORT` listener stays open and bound for the process lifetime. If the process binds the port again (a restart in the same process), the kernel keeps hashing a share of new connections to listeners nobody accepts on. It is a resource leak, not memory corruption.
- **Clause violated:** the drain docstring at `scheduler.mojo:799-803` leaves only the stuck worker's "context, stats cell and listeners" allocated. In the model this is `NoLeak`.
- **What goes wrong:** the stuck-worker branch runs `self._per_worker_listener_addrs.clear()` (`scheduler.mojo:897`). That removes every per-worker listener from the list `_free_resources` frees (:726-733), not just the stuck worker's.
- **Lean counterexample:** `Flare.Bugs.CONC_04.drain_leaks_joined_listener` (at tag `formal-audit-0.12`). In a 15-step trace with two workers, worker 1 is joined (not detached) and its context and stats are freed, but its listener is not (`¬ NoLeak`).
- **Fix:** in that branch drop only the stuck workers' entries, meaning primary `i` and extras `n_workers + i*n_extra + j`. With it, `Flare.L5.Scheduler.noLeak_of_cfg` holds for every `n`; with both fixes, `drain_safe`.
- **Repro:** `formal/repro/CONC-04_drain_leaks_joined_worker_listeners.mojo` (at tag `formal-audit-0.12`). Observed:
  `BUG REPRODUCED: after drain, the joined worker's listener fd 10 is still open (only the stuck worker's fd 8 should be)`.
- **Flip:** with the fix (a `keep` list filtered by the stuck set), `OK: drain closed the joined worker's listener fd 10` and exit 0. Restored.

Status: resolved. The stuck-worker branch of `drain` now keeps every non-stuck worker's primary and extra listeners in the list `_free_resources` frees, and drops only the detached workers' (owner of entry `p` is `p` for the primaries, `(p - n) // n_extra` for the extras). Tests: `tests/runtime/test_scheduler.mojo::test_drain_closes_the_joined_workers_listeners` and `::test_drain_closes_the_joined_workers_extra_listeners` (deterministic: the stuck worker waits on a gate; the fds are checked with `fcntl(F_GETFD)`). The repro printed `OK:` after the fix (3 of 3 runs). The scheduler model's drain carries both the CONC-03 and CONC-04 fixes; `Flare.L5.Scheduler.noLeak_of_cfg` and `drain_safe` are stated about it.

### CONC-05: shared-listener teardown closes the listener's fd number while workers can still accept on it

- **Severity:** Medium. It affects only the opt-in shared-listener mode (`FLARE_REUSEPORT_WORKERS=0`).
  - In `drain(timeout_ms > 0)` with a detached worker the window is unbounded. The worker outlives `drain`, and `_free_resources` also frees the `TcpListener` under it. A listener event still pending in the worker's poll batch then makes it `accept` on whatever file the number names next, possibly another listening socket of the process, whose connection it steals.
  - In `shutdown()` the window is one poll batch.
  - A worker that is still starting up can also register the reused number in its epoll set.
- **Clause violated:**
  - The drain docstring at `scheduler.mojo:799-803` says a detached worker's listeners "are left allocated, since the thread may still be using them".
  - The listener field comment at :245-248 says workers never close the listener; that is "shutdown()'s job after every worker has joined".
  - In the model: `NoStaleUse`.
- **What goes wrong:** `_signal_and_close_listener` (:655-668) closes the shared fd right after storing the stop flag, before any worker has observed the flag or been joined. Workers hold the bare number (:550). They `accept` on it for every listener event of a batch polled before they saw the flag (`_server_reactor_epoll.mojo:163,184-193`), and they register it at start-up (:155-156). `drain` detaches stuck workers without protecting the shared listener (:886-900).
- **Lean counterexamples** (at tag `formal-audit-0.12`):
  - `Flare.Bugs.CONC_05.shutdown_stale_accept`: a 5-step `shutdown` trace (register, pass the check, close, reuse, accept).
  - `Flare.Bugs.CONC_05.drain_closes_live_listener`: an 8-step `drain` trace ending after `drain` returned, with the worker detached and its accept on the reused number.
- **Fix:** do not close in `_signal_and_close_listener`. Let `_free_resources` close the number once, after every worker joined. When a worker was detached, leak the shared listener (`self._shared_listener_addr = 0` in the stuck-worker branch). With it, `Flare.L5.SharedListener.noStale` holds for `shutdown` and `drain`, any `n`, any interleaving with fd reuse, and `closedAtEnd` shows the listener is still closed when no worker was detached. Liveness does not need the early close: with the 100 ms poll cap every worker is done within `bound P` of the stop (`Flare.L5.Timed.worker_done_by`) and the teardown returns within `mBound` (`teardown_done_by`). The io_uring loop had no cap (CONC-07), but the close never woke it either: the armed accept holds its own reference to the socket. The fix is also safe for an io_uring worker on the shared fd (`UringShared.uring_fixed_noStale`).
- **Repro:** `formal/repro/CONC-05_shared_listener_closed_under_live_worker.mojo` (at tag `formal-audit-0.12`). It sets `FLARE_REUSEPORT_WORKERS=0` with libc `setenv`; one worker records its listener fd and stays in a "handler"; `drain(50)` detaches it. Deterministic: the close is observed with `fcntl(F_GETFD)` and the reuse with one `open("/dev/null")`. Observed:
  `BUG REPRODUCED: drain closed the shared listener fd 8 while the detached worker still holds it (the next open() reused the number: True)`.
- **Flip:** with the fix (close removed from `_signal_and_close_listener`, `self._shared_listener_addr = 0` in the stuck branch), `OK: the detached worker's shared listener fd 8 is still open` and exit 0. Restored.

Status: resolved. `_signal_and_close_listener` is now `_signal_stop` and only stores the stop flag. `_free_resources` closes the shared listener once, after every worker joined, and the stuck-worker branch of `drain` leaks it (`_shared_listener_addr = 0`) together with the detached worker's other resources. The early close was never needed for liveness (the workers re-read the flag every poll, at most 100 ms). Tests: `tests/runtime/test_scheduler.mojo::test_shutdown_closes_the_shared_listener_after_the_workers_join` (replaces `test_shutdown_closes_the_shared_listener_once`, which pinned the early close: it reused the number between the signal and the free) and `::test_drain_keeps_the_shared_listener_open_for_a_detached_worker`. The repro printed `OK:` after the fix (3 of 3 runs). The shared-listener model's teardown is the shipped one; `Flare.L5.SharedListener.noStale` and `closedAtEnd` are stated about it. The io_uring worker that could hold the shared fd is covered by `UringShared.uring_fixed_noStale`.

### CONC-06: `Scheduler.start`'s rollback leaks every per-worker listener

- **Severity:** Medium. When `pthread_create` fails part-way through `start` in the default listener mode (per-worker `SO_REUSEPORT`, also forced by extra addresses or by a frontend that requires it), every pre-bound listener, including the extras, stays open and bound for the life of the process. The caller sees the `Error`, but the port stays held, and a retry binds next to sockets that keep receiving a share of new connections nobody accepts. `pthread_create` fails under thread or memory exhaustion, exactly when a caller is likely to retry.
- **Clause violated:** `start`'s docstring (:337-343): "partially-started workers are best-effort joined before re-raising"; a failed constructor leaves nothing behind. In the model: `startFail … = H.empty`.
- **What goes wrong:** the rollback (`scheduler.mojo:591-633`) frees the worker array, the contexts, the stats cells, the shared listener and the stop flag, but never `s._per_worker_listener_addrs` (filled at :511-543). `Scheduler` has no destructor, so nothing frees them once the error propagates.
- **Lean counterexample:** `Flare.Bugs.CONC_06.rollback_leaks_listeners` (at tag `formal-audit-0.12`). It holds in general: for every worker count, listener count and failing spawn index, each per-worker listener is still allocated. `repro_instance` is the repro's case; `rollback_rest_ok` shows everything else is released correctly.
- **Fix:** in the rollback, destroy and free every entry of `_per_worker_listener_addrs` and clear it, as `_free_resources` does. With it, `Flare.L5.Lifecycle.rollback_clean` holds: nothing allocated, nothing freed twice or under a running worker, every spawned worker joined.
- **Repro:** `formal/repro/CONC-06_start_rollback_leaks_per_worker_listeners.mojo` (at tag `formal-audit-0.12`). Deterministic: it fills the process thread table with parked threads until `spawn_os` raises, frees exactly one slot by joining one of them, and runs `start(num_workers=2)`. Worker 0 takes the slot and worker 1 fails; if anything else took the slot, worker 0 fails instead, with the same leak. The leak is the change in the number of open descriptors. Observed:
  `BUG REPRODUCED: the failed Scheduler.start left 2 listener fds open ( 10 open before, 12 after)`.
- **Flip:** with the fix, `OK: the failed Scheduler.start released every fd ( 10 open)` and exit 0. Restored.

Status: resolved. The `start` rollback now frees every pre-bound per-worker listener (primaries and extras) through `_free_per_worker_listeners`, the helper `_free_resources` also uses, after all started workers have joined. Test: `tests/runtime/test_scheduler_start_rollback.mojo::test_failed_start_releases_the_per_worker_listeners` (standalone: it fills the process thread table as the repro did, releases one slot, and compares the open-fd count; macOS only, since on Linux the fill would hit a system or cgroup limit shared with other processes, where the repro was the end-to-end check). The repro printed `OK:` after the fix (3 of 3 runs). The rollback model `Flare.L5.Lifecycle.startFail` is the shipped rollback; `rollback_clean` is stated about it.

### CONC-07: an idle io_uring worker never sees the stop flag, so `shutdown()` hangs and `drain` detaches it

- **Severity:** Medium. The io_uring buffer-ring loop is the production handler path when io_uring is available and `config.use_bufring` is set; `HttpServer` sets it from `FLARE_BUFRING_HANDLER` (`http/server.mojo:1302-1303`).
  - On a server with no traffic, `Scheduler.shutdown()` blocks in `pthread_join` until a client happens to connect. `HttpServer.serve(num_workers > 1)` therefore does not return after `close()` (`http/server.mojo:1330-1336`).
  - `drain(timeout_ms)` returns, but detaches every idle worker however large the deadline is. It reports them as not drained, and leaks their contexts, stats cells and listeners (CONC-03/04 territory).
  - The same cause, by code reading (not separately reproduced), hangs `start`'s rollback, which joins the started workers (`scheduler.mojo:591-600`), and the single-worker `run_uring_bufring_reactor_loop`, which runs the same body (`_server_reactor_uring.mojo:756-781`).
- **Clause violated:**
  - The scheduler module docstring (`scheduler.mojo:24-37`): the heap flag "every worker polls on each reactor iteration" "is what actually breaks the loop".
  - The `_poll_timeout_ms` docstring (`_reactor/lifecycle.mojo:34-37`): the cap "stays load-bearing for shutdown-flag responsiveness ... so idle workers still wake at most every `cap_ms`".
  - In the model: `PollReturns`, the hypothesis under which `Flare.L5.Timed.worker_done_by` holds.
- **What goes wrong:** the loop builds its ring with `enable_wakeup=False` (`_server_reactor_uring.mojo:820-824`) and waits with `ureactor.poll(1, completions, 64)` (:852). With nothing ready, `poll(1)` blocks in `io_uring_enter(min_complete=1)` with no timeout (`uring_reactor.mojo:834-836`), and no timeout SQE is ever armed. The stop flag is read only at the top of the loop (:848). `shutdown` stores the flag and joins (`scheduler.mojo:746-760`); nothing produces a completion on the worker's ring. RT-03 (a wakeup read that is not armed) is a different defect: this ring has no wakeup channel at all.
- **Lean counterexamples** (at tag `formal-audit-0.12`):
  - `Flare.Bugs.CONC_07.shutdown_never_returns`: for every `N`, a run in which every hypothesis but `PollReturns` holds throughout, and `N` ms after the stop the worker is still in its wait and `shutdown` is still at `pass 0`.
  - `not_pollReturns` shows these states violate the wait bound.
  - `drain_detaches_idle`: for every deadline `D`, a drain that ends with the idle worker detached (snapshot `[false]`). This includes `D > bound P`, where `Timed.drain_joins_all` rules it out for a loop whose wait is bounded.
- **Fix:** bound the wait. For example, keep one `IORING_OP_TIMEOUT` (100 ms, relative) armed on the ring and re-arm it when its completion arrives, so `poll(1)` returns at least every 100 ms as the epoll loop does. A timeout passed to `io_uring_enter` (`IORING_ENTER_EXT_ARG`) works too. With the fix the loop's wait is bounded, and `Flare.L5.Timed.worker_done_by`, `teardown_done_by` and `drain_joins_all` apply to it with `cap = 100`.
- **Repro:** `formal/repro/CONC-07_uring_worker_ignores_stop_while_idle.mojo` (at tag `formal-audit-0.12`), `# PLATFORM: linux`, run with `formal/repro/linux.sh` (Ubuntu 24.04 container, native arm64, seccomp unconfined).
  - Setup: a real `HttpFrontend` with `ServerConfig(use_bufring=True)`, one worker, no traffic, 300 ms for the worker to arm and block, then `drain(2000)`, which is 20 times the epoll cap.
  - If the worker was detached, the repro opens one TCP connection, to show that only traffic releases it and to let the process exit cleanly.
  - Without io_uring it stops as inconclusive instead of printing OK.
  - Observed in 4 of 4 runs (the last one after the flip was restored): `BUG REPRODUCED: the idle io_uring worker ignored the stop flag for 2000 ms; drain detached it (still running: True), and it returned only after a client connected (returned: True)`.
- **Flip:** in the container's copy of the repo, `run_uring_bufring_reactor_loop_shared` was changed to keep one 100 ms `IORING_OP_TIMEOUT` SQE armed and re-arm it on its completion. Result: `OK: the idle io_uring worker saw the stop and was joined after 14 ms` (then 111 ms and 3 ms) and exit 0, in 3 of 3 runs. The next synced run restored the copy, and the host's `flare/` was never edited.

Status: resolved. Both io_uring loops (`run_uring_bufring_reactor_loop_shared`, which the single-worker loop delegates to, and the static-response loop) now call `ureactor.poll(1, completions, 64, URING_STOP_POLL_MS)`. The new `timeout_ms` argument makes the blocking phase an `io_uring_enter` with `IORING_ENTER_EXT_ARG` and a 100 ms timeout (`io_uring_enter_timeout`, Linux 5.11+, older than the buffer-ring features this path already needs). A timed-out wait (`-ETIME`) is not an error. No SQE or CQE tag is added, so the SQ and the completion handling are unchanged. Tests: `tests/runtime/test_uring_worker_stop.mojo::test_idle_uring_worker_is_joined_by_drain` (real `HttpFrontend`, one idle worker, `drain(2000)` joins it) and `tests/runtime/test_uring_reactor.mojo::test_blocking_poll_with_a_timeout_returns_on_its_own` (Linux only). The repro printed `OK:` after the fix (3 of 3 runs). `Flare.L5.Timed` models the shipped io_uring loop with its bounded wait, so `worker_done_by`, `teardown_done_by` and `drain_joins_all` are stated about it.

## Checked, not a bug

- **Watchdog: `disarm` racing a fire in progress.** `_settle` waits out FIRING. `DisarmCorrect` and `Safe` (via `shipped_safe`) show that `disarm` returns `True` exactly when the cell was cancelled, and that the poller never writes a cell after that request's `disarm` returned.
- **Watchdog: `arm` while the slot is FIRING.** `arm` settles before storing, and `FiringOwned` shows FIRING is always held by a poller inside its three-step claim window. The test `test_rearm_right_after_a_fire_keeps_its_deadline` exercises exactly this case, and it is safe.
- **Watchdog: clock overflow.** `now + budget` could wrap only for budgets near `I64_MAX - now`, and the wrapped value was non-positive, which is CONC-01. `_deadline_after` now saturates the sum at `Int64.MAX`, and `deadlineOf_pos` shows the stored deadline is always positive.
- **AsyncRT: double free or use after free when join or detach races the trampoline's CAS.** Refuted by `free_at_most_once` and `no_use_after_free`. Exactly one side frees.
- **AsyncRT: the trampoline touching the cell after waking the joiner.** Not a bug, given AR-1 (`ar1_load_bearing` shows AR-1 is the one fact the protocol depends on).
- **AsyncRT: join twice, detach after join, and similar sequences.** Refuted by `calls_after_zero_are_noops` and `zeroed_noop`. The zeroing is load-bearing (`guard_load_bearing`).
- **ThreadHandle: `pthread_join` / `pthread_detach` called twice.** Refuted by `at_most_one_effect` and `no_posix_ub`, including retries after failures.
- **ThreadHandle: a moved-from handle.** Rejected by the Mojo move checker (`moved_from_inert`). A bitwise alias would defeat the defence (`alias_double_join`), but flare's only second handle to a running thread (in `_worker_entry`) calls only `pin_to_cpu`.
- **ThreadHandle: no destructor.** By design (the `_thread.mojo` module docstring): dropping a live handle leaks (`drop_live_leaks`, `AsyncRT.drop_leaks`).
- **ThreadHandle: `pin_to_cpu` on a zeroed handle.** On Linux this passes `pthread_t` 0 (`pin_after_join_hazard`), but flare only pins fresh handles, so it is unreachable. Suggested hardening: return early when `_thread_id == 0`.
- **Scheduler: `shutdown()` / `drain(timeout_ms <= 0)` freeing under a live worker.** Refuted. `shutdown_safe` proves memory safety and no leaks for every `n`: every worker is joined before anything is freed.
- **Scheduler: a joined worker touching its context or stats after the DONE store.** Not possible. After its `WORKER_STAT_DONE` store the worker only returns. The join waits for termination, and in a soft drain it waits at most that one step (`soft_join_bounded`).
- **Scheduler: the stuck worker's context, stats cell and listeners staying allocated.** By design (the `drain` docstring). `drain` also leaks the stop flag in that case; this is the price of CONC-03's fix.
- **Scheduler: stop-flag visibility.** The release store / acquire load pair gives workers the happens-before edge, and the model's SC abstraction is justified for this single location.
- **Scheduler: drain's stuck-worker index bookkeeping.** Proved correct: `popStuck_keeps_joined` and `freed_iff_not_detached`, for any `n` and any set of detached workers. `stuck` is built in increasing order (`sweepStuck_sorted`), the pops run in decreasing order, so no pop shifts an index still to be popped. The same predicate applies to `_ctx_addrs` and `_stats_addrs`, so exactly the joined workers' contexts and stats cells are freed and the two lists stay aligned. The `idx < len` guards never skip a pop (both lists have one entry per worker).
- **Scheduler: `start` rollback.** Proved by `rollback_clean`, in both listener modes: every spawned worker is joined before anything is freed, nothing is freed twice, the context of the failed spawn is freed, and nothing is left allocated. In shared mode the rollback frees the shared listener with its destructor, closing the fd once. `_abandon_start` after a failed bind is clean (`abandon_clean`), as are the probe-bind and `set_nonblocking` failure paths, which free only the stop flag (the local `bound` listener is dropped by Mojo).
- **Serve loops: liveness of the teardown.** Proved under stated hypotheses: every worker is done within `cap + ε + 2σ + η + τ` of the stop, and `shutdown` / `drain` return within that plus `(n + 2)σ` (one more `σ` for drain). A drain whose deadline exceeds the per-worker bound detaches nobody (`Timed.worker_done_by`, `teardown_done_by`, `drain_joins_all`). Every epoll/kqueue loop the scheduler runs passes `_poll_timeout_ms(wheel)` (in `_server_reactor_epoll.mojo` and `_unified_reactor_impl.mojo`), whose result is in `[1, 100]` (`pollTimeout_le_cap`); the streaming loop (`_stream_reactor_impl.mojo`) passes a fixed 100 ms default, and the io_uring loops pass `URING_STOP_POLL_MS` (100 ms). The bound fails in no interleaving that meets the hypotheses. It needs a bounded batch: `_accept_loop_fd` accepts until `EAGAIN` with no per-call cap, so a sustained connection storm stretches one iteration. That is an arrival-rate assumption, not a defect.
- **io_uring loop on the shared listener.** Not reachable while both io_uring probes agree (`uring_never_shared`). If they disagree (`probe_skew_shared`), the fd-use behaviour simulates the epoll model's, so the shared-listener teardown's safety covers it (`uring_fixed_noStale`, `uring_fixed_closedAtEnd`). Its timing (CONC-07) is independent of the listener mode.
- **Scheduler: `pthread_join` / `pthread_detach` failing.** On a live handle, `pthread_detach` cannot fail, and `pthread_join` fails only for a self-join (`live_handle_calls`; `ESRCH`/`EINVAL` need a reaped or detached thread, which `Thread.inv_inductive` excludes). Every in-repo teardown runs on the thread that owns the `Scheduler`, so the `except: pass` branches are dead (`impl_safe_of_external_caller`). If a call did fail, flare would free the worker's resources under it (`impl_freed_under_live_iff`). The one way to get there is an **API hazard**, not a reachable bug: `shutdown()` or `drain(timeout_ms <= 0)` called from inside a worker joins itself, gets `EDEADLK`, and frees that worker's context, stats cell and stop flag while it runs (`self_shutdown_frees_caller`). `drain(timeout_ms > 0)` from a worker is fine; it detaches itself (`self_drain_keeps_caller`). A worker can only reach its `Scheduler` through an unsafe pointer, so no ID and no repro. Suggested hardening: on a raising `join`/`detach`, treat the worker as stuck (`fixed_never_frees_live`), and document that teardown must not run on a worker thread.

## Traceability

| Lean definition | Mojo code | Theorems | Status |
|---|---|---|---|
| `Flare.L5.Watchdog.FIRING` | `runtime/watchdog.mojo#_FIRING` | `FIRING_neg` | proved |
| `Flare.L5.Watchdog.PPc`, `pStep` | `runtime/watchdog.mojo#_watchdog_main` | `inv_step_p`, `shipped_safe` | proved |
| `Flare.L5.Watchdog.WPc`, `wStep` | `runtime/watchdog.mojo#watchdog_arm`, `watchdog_disarm` | `inv_step_w`, `shipped_safe` | proved |
| `Flare.L5.Watchdog.deadlineOf` | `runtime/watchdog.mojo#_deadline_after` | `deadlineOf_pos` | proved |
| `Flare.L5.AsyncRT.CS`, `St`, `init` | `runtime/_asyncrt.mojo#asyncrt_spawn` | `inv_inductive` | proved |
| `Flare.L5.AsyncRT.Step` (trampoline) | `runtime/_asyncrt.mojo#_asyncrt_trampoline` | `free_at_most_once`, `no_use_after_free`, `chain_before_free` | proved |
| `Flare.L5.AsyncRT.Step` (owner) | `runtime/_asyncrt.mojo#asyncrt_join+asyncrt_detach+asyncrt_wait_started` | `join_returns_after_done`, `progress`, `calls_after_zero_are_noops` | proved |
| `Flare.L5.Thread.Handle`, `join`, `detach`, `pin` | `runtime/_thread.mojo#ThreadHandle`, `ThreadHandle.join`, `ThreadHandle.detach`, `ThreadHandle.pin_to_cpu` | `inv_inductive`, `at_most_one_effect`, `no_posix_ub`, `zeroed_noop` | proved |
| `Flare.L5.Scheduler.WPc`, `wStep` | `runtime/_worker.mojo#_worker_entry` | `core_inductive`, `safe_of_cfg`, `soft_join_bounded` | proved |
| `Flare.L5.Scheduler.WS`, `St` | `runtime/scheduler.mojo#Scheduler`, `runtime/scheduler_stats.mojo` (`WORKER_STAT_*`) | `core_inductive` | proved |
| `Flare.L5.Scheduler.init` | `runtime/scheduler.mojo#Scheduler.start` | `core_init` | proved |
| `Flare.L5.Scheduler.MPc`, `mStep`, `step` | `runtime/scheduler.mojo#Scheduler.drain` (`shutdown` as `hard`) | `core_step_m`, `shutdown_safe`, `drain_safe` | proved |
| `Flare.L5.Scheduler.freeAll` | `runtime/scheduler.mojo#Scheduler.drain+Scheduler._free_resources` | `safe_of_cfg`, `noLeak_of_cfg` | proved |
| `Flare.L5.Scheduler.explore`, `check` | (checker, no Mojo counterpart) | `check_sound`, `bounded_drain`, `bounded_shutdown` | proved / bounded |
| `Flare.L5.SharedListener.WPc`, `wStep` | `http/_server_reactor_epoll.mojo#_run_handler_loop_impl` | `inv_inductive`, `stop_exits` | proved |
| `Flare.L5.SharedListener.freeFd`, `mStep`, `step` | `runtime/scheduler.mojo#Scheduler._signal_stop+Scheduler._join_workers`, `Scheduler._signal_stop+Scheduler.drain`, `Scheduler._free_resources` | `noStale`, `closedAtEnd` | proved |
| `Flare.L5.Lifecycle.startAlloc`, `spawnR` | `runtime/scheduler.mojo#Scheduler.start` | `rollback_clean` | proved |
| `Flare.L5.Lifecycle.startFail` | `runtime/scheduler.mojo#Scheduler.start` | `rollback_clean` | proved |
| `Flare.L5.Lifecycle.abandon` | `runtime/scheduler.mojo#Scheduler.start+Scheduler._abandon_start+Scheduler._free_resources` | `abandon_clean` | proved |
| `Flare.L5.Lifecycle.sweepStuck`, `eraseAt`, `popStuck` | `runtime/scheduler.mojo#Scheduler.drain` | `popStuck_keeps_joined`, `freed_iff_not_detached` | proved |
| `Flare.L5.Lifecycle.pjoin`, `pdetach`, `keptImpl` | `runtime/_thread.mojo#ThreadHandle.join+ThreadHandle.detach`, `runtime/scheduler.mojo#Scheduler._join_workers+Scheduler.drain` | `live_handle_calls`, `impl_freed_under_live_iff`, `impl_safe_of_external_caller` | proved |
| `Flare.L5.Timed.pollTimeout` | `http/_reactor/lifecycle.mojo#_poll_timeout_ms` | `pollTimeout_le_cap`, `pollTimeout_pos` | proved |
| `Flare.L5.Timed.TPc`, `wNext`, `step` | `http/_server_reactor_epoll.mojo#_run_handler_loop_impl`, `http/_server_reactor_uring.mojo#run_uring_bufring_reactor_loop_shared` | `J_inductive`, `worker_done_by` | proved |
| `Flare.L5.Timed.MPc`, `mStep` | `runtime/scheduler.mojo#Scheduler._signal_stop+Scheduler.shutdown+Scheduler.drain` | `teardown_done_by`, `drain_joins_all` | proved |
| `Flare.L5.Timed.PollReturns`, `FairW`, `FairM`, `HandlerBound`, `TeardownBound` | (hypotheses, no Mojo counterpart) | `worker_done_by`, `bound_tight` | proved |
| `Flare.L5.UringShared.requiresPerWorker`, `uringDispatch`, `prebind` | `http/frontend.mojo#HttpFrontend.requires_per_worker_listener`, `HttpFrontend.run_worker`, `runtime/scheduler.mojo#Scheduler.start` | `uring_never_shared`, `probe_skew_shared` | proved |
| `Flare.L5.UringShared.uwStep`, `ustep` | `http/_server_reactor_uring.mojo#run_uring_bufring_reactor_loop_shared`, `runtime/scheduler.mojo#Scheduler._signal_stop+Scheduler.drain` | `sim_step`, `uring_fixed_noStale`, `uring_fixed_closedAtEnd` | proved |
