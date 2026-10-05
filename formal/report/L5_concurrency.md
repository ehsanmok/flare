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

Safety properties are proved as general inductive invariants, so they hold for every trace length and, for the scheduler, for every number of workers. The scheduler also has an executable state-space explorer with a soundness proof. It is checked exhaustively with `decide` for one and two workers and with `native_decide` for three; those results are labelled "bounded".

Not modelled:

- the frontends' serve loops, beyond "load the stop flag, else one iteration touching the context, listener and stats cell" (and, for the shared-listener model, "register the fd number, then accept on it for each polled listener event");
- `runtime/blocking.mojo`, which belongs to L2;
- AsyncRT internals, beyond three stated assumptions.

Modules: `Flare.L5_Concurrency.{Watchdog, AsyncRT, Thread, Scheduler, SharedListener, Lifecycle, Timed, UringShared}`, aggregate `Flare.L5_Concurrency`, bug files `Flare.Bugs.CONC_01` to `CONC_07`, audit `Flare/Audit/L5.lean`. There are 209 theorems in total. No `sorry`, `admit` or `axiom` appears anywhere, and `native_decide` is used only in `Flare.Bugs.CONC_03` (two bounded checks).

## Components

### DeadlineWatchdog slot protocol (`flare/runtime/watchdog.mojo`)

**Model** (`Flare.L5.Watchdog`). Each slot has two shared words:

- the deadline: `0` means disarmed, `d > 0` means armed, and `-1` (`_FIRING`) means the poller is writing the cell;
- the cancel-cell address.

There is also a clock and the cancel cells. Two threads act on a slot:

- **The poller** (`PPc`, `watchdog.mojo:154-177`): read the clock, load the deadline, CAS `d → FIRING` when `0 < d ≤ now`, load the address, store `TIMEOUT` into the cell, then store `0`.
- **The worker** (`WPc`, `watchdog.mojo:98-132`) runs requests. Each request is:
  - `arm`: settle, store the address, compute `deadline = now + budget` with a 64-bit wrap, then settle-and-CAS;
  - then the handler;
  - then `disarm`: settle, then CAS `v → 0`, or return `True` if the slot is already `0`.

The label `rearm` lets a caller re-arm without disarming. Ghost fields record which request owns which deadline and claim.

`Cfg` selects:

- the code at 59bda50, or the fix (`disarmFirst`: `arm` first CASes the old deadline to `0`; `clamp`: deadline ≥ 1);
- whether re-arming is allowed;
- the admissible budgets.

Slots are independent words, so one slot is modelled. **Memory model:** sequential consistency. Every slot access is atomic (acquire loads, release stores, default-ordering CAS). The one cross-location dependency is that the poller reads `addr` after its claim. It is ordered by the worker's release store of `addr`, which is sequenced before the CAS the poller reads from. This argument is written in the module docstring, not proved in Lean.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.Watchdog.inv_inductive` | The program-counter-indexed invariant is inductive for any config that re-arms only with disarm-first and stores positive deadlines | proved |
| `Flare.L5.Watchdog.safe_of_cfg` | For such configs, every reachable state satisfies `Safe` (a cell write targets the current request, with that request's own expired deadline, before its disarm returned), `DisarmCorrect` (disarm returns `True` iff the cell was cancelled) and `FiringOwned` (FIRING is only ever held by the poller inside its claim window) | proved |
| `Flare.L5.Watchdog.impl_safe` | The code at 59bda50 is safe under "arm only after disarm" with budgets giving a deadline in `1..I64_MAX` | proved |
| `Flare.L5.Watchdog.fixed_safe` | The fixed arm (disarm-first plus clamp) is safe for every budget, even when callers re-arm without disarm | proved |
| `Flare.L5.Watchdog.deadlinePos_impl`, `deadlinePos_fixed` | The stored deadline is positive (impl: for admissible budgets; fix: always) | proved |
| `Flare.L5.Watchdog.run_of_exec` | The executable trace function yields valid runs | proved |

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

The initial state (`init n`) is the one `Scheduler.start` returns (`scheduler.mojo:361-641`): everything allocated and every worker at `start`.

A worker (`WPc`, `_worker.mojo:99-162`) steps through:

1. `start`: reads the context.
2. `loop`: loads the stop flag; exits to `doneSt` if it is set, otherwise goes to `serve`.
3. `serve`: one reactor iteration or handler, touching the context (which holds the frontend), the listener and the stats cell; then back to `loop`.
4. `doneSt`: the release-store of `WORKER_STAT_DONE` through the context (`_worker.mojo:156`).
5. `ret`, then `term`.

The drain thread (`MPc`, `scheduler.mojo:815-901`) steps through:

1. `signal`: store `stop := True`.
2. `wait`: any number of `sample i` steps reading `WORKER_STAT_DONE` into `done[i]`. The deadline may expire at any point (an over-approximation of the Mojo loop).
3. `sweep k` for `k = 0..n-1`: join worker `k` if `done[k]` (enabled only once it has terminated), otherwise detach it.
4. `report`: read every stats cell.
5. `free`: the stuck-worker carve-out followed by `_free_resources`.
6. `fin`.

Every dereference ORs the cell's freed bit into the ghost flag `uaf`. `Cfg` has three flags:

- `hard`: `shutdown()` or `drain(timeout_ms <= 0)`, where every worker is joined;
- `fixStop`: the CONC-03 fix;
- `fixLis`: the CONC-04 fix.

`cfgImpl`, `cfgShutdown` and `cfgFixed` name the configurations used below.

**Memory model:** sequential consistency.

- The stop flag and each stats slot are single locations accessed by release stores and acquire loads (`scheduler_stats.mojo:26-46,76-95`), so their modification order is total.
- Freeing a joined worker's cells is ordered after all of that worker's accesses by `pthread_join`.
- In the fixed configuration, nothing a detached worker can reach is freed at all, so no ordering argument is needed for it.

**Environment assumption:** `pthread_join` and `pthread_detach` on a live, joinable handle succeed, so the `except: pass` at `scheduler.mojo:680,853` never runs. This is no longer an assumption of the layer: `Flare.L5.Lifecycle.live_handle_calls` derives it from the POSIX error cases for every teardown that runs on a thread other than the workers, which every in-repo caller does. What flare does when a call does fail is `impl_freed_under_live_iff` (see "Lifecycle bookkeeping" below).

**Specification:**

- `MemSafe` (`uaf = false`).
- `LiveRefsAllocated`: a worker that has not terminated still has its context, stats cell and listener, and the stop flag is allocated. This is the property "nothing a live worker can reference is freed".
- `NoLeak`: after drain, every non-detached worker's cells are freed, and the stop flag is freed when nobody was detached. This follows the drain docstring at `scheduler.mojo:799-803`.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.Scheduler.core_inductive` | The per-worker / per-phase invariant `Core` is inductive for every config and every `n` | proved |
| `Flare.L5.Scheduler.coreSI_inductive` | `Core ∧ SI` (no use after free; stop freed only when all workers are joined) is inductive when `fixStop ∨ hard` | proved |
| `Flare.L5.Scheduler.safe_of_cfg` | When `fixStop ∨ hard`, every reachable state is `MemSafe` and `LiveRefsAllocated`, for any number of workers | proved |
| `Flare.L5.Scheduler.noLeak_of_cfg` | When `fixLis ∨ hard`, every reachable state satisfies `NoLeak` | proved |
| `Flare.L5.Scheduler.shutdown_safe` | The code at 59bda50 in `shutdown()` / `drain(<=0)` is memory safe and leak free | proved |
| `Flare.L5.Scheduler.fixed_safe` | The fixed `drain(timeout_ms > 0)` is memory safe and leak free | proved |
| `Flare.L5.Scheduler.detached_sees_stop` | With the fix, a worker still live after drain reads an allocated stop flag holding `True` | proved |
| `Flare.L5.Scheduler.soft_join_bounded` | In a soft drain, a worker seen DONE is at its final return or terminated, so the join waits at most one worker step | proved |
| `Flare.L5.Scheduler.check_sound` | If the explorer's certificate check returns `true`, the property holds on every reachable state | proved |
| `Flare.L5.Scheduler.bounded_fixed` | The fixed drain meets `specB` for 1 and 2 workers, all interleavings (`decide +kernel`; 47 and 389 states) | bounded (n ≤ 2) |
| `Flare.L5.Scheduler.bounded_shutdown` | `shutdown()` meets `specB` for 1 and 2 workers | bounded (n ≤ 2) |
| `Flare.L5.Scheduler.bounded_impl_fails` | The explorer reports a violation for the code at 59bda50 with 1 worker | bounded (n = 1) |
| `Flare.Bugs.CONC_03.bounded_fixed_3` | The fixed drain meets `specB` for 3 workers (3263 states; `native_decide`) | bounded (n = 3) |
| `Flare.L5.Scheduler.run_of_exec`, `reachable_of_exec` | Executable traces give valid runs / reachable states | proved |

Limitations:

- The serve loop is abstract.
- Freeing is one step. The frees are monotone, so splitting the step only adds interleavings with the same `uaf` outcome.
- The wait loop over-approximates the Mojo loop's sampling, which is sound for safety. The counterexamples sample every worker once, as the Mojo loop does.
- This model's workers hold the heap listener of per-worker mode. The shared-listener mode, where workers hold only the fd number, is the separate model `Flare.L5.SharedListener`. `start`'s rollback and the stuck-worker pops are modelled in `Flare.L5.Lifecycle`.

### Shared-listener mode (`FLARE_REUSEPORT_WORKERS=0`; `scheduler.mojo:407-474,655-744`, `http/_server_reactor_epoll.mojo:110-266`)

**Model** (`Flare.L5.SharedListener`). The workers receive only the shared listener's fd number. A worker (`WPc`):

1. `reg`: registers the number with `register_exclusive` (`_server_reactor_epoll.mojo:155-156`).
2. `check`: loads the stop flag (:163).
3. `acc`: is past the check with a polled listener event, and calls `_accept_loop_fd(listener_fd, ...)` (:184-193). A slow handler earlier in the same event batch just delays this step.
4. `done`.

The fd number's state (`Fd`) is the listener, closed, or `other`. The environment step `reuse` is an unrelated `open`/`socket`/`accept` taking the lowest free number. The teardown thread does `signal` (`_signal_and_close_listener`), `sweep k` (join if returned, else detach; `hard` waits), `free`, `fin`. A worker step that uses the number while it does not name the listener sets the ghost flag `stale`. `Cfg.fix` is the CONC-05 fix.

**Memory model:** the stop flag as in the scheduler model; `close`, `reuse` and `accept` are atomic system calls on the process fd table, so the interleaving is sequentially consistent.

**Specification:** `NoStaleUse` (no worker registers or accepts on the number after it stopped naming the listener). `ClosedAtEnd`: when teardown finished and no worker was detached, the listener is closed.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.SharedListener.inv_inductive` | The invariant (no stale use; a non-listener number implies every worker joined; sweep/free bookkeeping) is inductive for the fixed teardown, `shutdown` or `drain`, any `n` | proved |
| `Flare.L5.SharedListener.fixed_noStale` | Fixed teardown: `NoStaleUse` in every reachable state, any `n`, any interleaving with fd reuse | proved |
| `Flare.L5.SharedListener.fixed_closedAtEnd` | Fixed teardown: the listener is closed at the end unless a worker was detached | proved |
| `Flare.L5.SharedListener.stop_exits` | Without the early close a worker still leaves its loop: from `check` or `acc` with the flag set it reaches `done` in at most two steps | proved |
| `Flare.Bugs.CONC_05.shutdown_stale_accept`, `drain_closes_live_listener` | The code at 59bda50 reaches `¬ NoStaleUse` in `shutdown` and in `drain` | counterexample |

Limitations: this model is untimed; `stop_exits` is only the step-level part of liveness. The time bound, from the 100 ms poll cap, is `Flare.L5.Timed` below. The io_uring worker on the shared fd is `Flare.L5.UringShared` below.

### Teardown timing (`http/_reactor/lifecycle.mojo:31-47`, `http/_server_reactor_epoll.mojo:150-266`, `http/_server_reactor_uring.mojo:842-981`, `scheduler.mojo:655-668,746-760,815-901`)

**Model** (`Flare.L5.Timed`). There is a discrete clock (`tick`, read as 1 ms) and one worker loop shared by every serve loop the scheduler runs:

1. `reg`: register or arm the listener.
2. `check`: load the stop flag.
3. `poll`: wait for events.
4. `ready`: the wait returned, but the thread may not be on a CPU.
5. `batch`: accepts, connection steps and handlers.
6. Back to `check`; or, once the flag is seen, `clean` (the worker's own teardown and the `WORKER_STAT_DONE` store), then `done`.

Each worker records the time it entered its phase. Only the kernel ends a `poll` (label `k i`). With a capped wait it always can (`Cfg.capped`); with an uncapped one only a completion can, which needs traffic. The teardown thread is `shutdown` or `drain(D)` with the CONC-05 fix (the fix moves the close and changes no timing):

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
| `Flare.L5.Timed.teardown_done_by` | Under `Hyp`, `shutdown` / `drain` (fixed) reach `fin` once more than `mBound P c n` has passed since the stop | proved |
| `Flare.L5.Timed.drain_joins_all` | Under `Hyp`, a drain with deadline `D > bound P` takes a snapshot in which every worker returned, so it joins all of them, detaches none, and frees (with CONC-05's fix: closes) the listener | proved |
| `Flare.L5.Timed.bound_epoll` | With the epoll/kqueue cap the per-worker bound is `100 + ε + 2σ + η + τ` ms | proved |
| `Flare.L5.Timed.bound_tight` | A run meeting every hypothesis in which the worker finishes exactly at `t0 + bound P` (the bound is tight, and `Hyp` is satisfiable) | proved (by `decide`) |
| `Flare.Bugs.CONC_07.shutdown_never_returns`, `drain_detaches_idle` | The io_uring buffer-ring loop is not `capped`: with every hypothesis except `PollReturns`, `shutdown` is still joining an idle worker at any time `N`, and drain with any deadline detaches it | counterexample |

The bound answers the 2 × cap + ε question with a tighter one: one full wait, not two, because the flag is re-read right after every wait. `σ` covers both the wake-up latency after the wait and the next check.

Limitations:

- The hypotheses are stated, not derived: the kernel honouring the timeout (`ε`), the OS scheduler (`σ`), the handler code and the arrival rate (`η`).
- Without `HandlerBound` no bound exists. That is by design: a handler that never returns is what drain's deadline and detach are for, and `shutdown` waits for it.
- The stop flag is visible to the first load after the store. That is the release/acquire pair, with cache-coherence latency folded into `σ`.
- The model has one listener per worker. Extra addresses do not change the loop's shape.

### io_uring buffer-ring worker (`http/frontend.mojo:114-183`, `http/_server_reactor_uring.mojo:784-998`, `runtime/uring_reactor.mojo:739-846,953-979`, `runtime/io_uring.mojo:513-536`)

**Model** (`Flare.L5.UringShared`) has two parts.

1. **Listener choice.** `requiresPerWorker` and `uringDispatch` mirror the frontend's two predicates, and `prebind` mirrors `start`'s choice (`scheduler.mojo:388-430`).
2. **fd use.** `uwStep` / `ustep` is the io_uring worker on `SharedListener`'s state. It uses the number once, when it arms the multishot accept (`arm_listener_multishot(listener_fd)`, :843), before its first stop check. Later accepts are completions of that request, which holds its own reference to the socket. `R` relates an io_uring state to an epoll state that agrees on everything except having at least the same stale uses.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.UringShared.uring_never_shared` | If both threads get the same io_uring probe result, a worker that runs the io_uring loop was given a per-worker listener: the frontend's `requires_per_worker_listener` forces `prebind` | proved |
| `Flare.L5.UringShared.probe_skew_shared` | If the scheduler thread's probe fails and the worker's succeeds, with `FLARE_REUSEPORT_WORKERS=0`, the io_uring loop does run on the shared fd. `use_uring_backend` re-reads the env var and re-runs `io_uring_setup` on every call, with no cache | proved (reachable only through a transient probe failure or an env change) |
| `Flare.L5.UringShared.sim_step`, `sim_reachable` | Forward simulation: every io_uring step is an epoll `SharedListener` step with the same label, and every stale use on the io_uring side is one on the epoll side | proved |
| `Flare.L5.UringShared.uring_fixed_noStale`, `uring_fixed_closedAtEnd` | So the CONC-05 fix is also safe for an io_uring worker on the shared fd, `shutdown` or `drain`, any `n` | proved |
| `Flare.L5.UringShared.uring_trace_shutdown_safe` | CONC-05's shutdown trace is harmless for this loop: it does not touch the number after arming | proved |
| `Flare.L5.UringShared.uring_late_arm_stale` | Under the unfixed teardown, a worker that arms after the close arms on whatever file has the number (the registration half of CONC-05) | counterexample (covered by CONC-05) |

The result is that the shared-listener path reduces to the existing model, with a simulation and in a weaker form for fd use. The io_uring loop differs where it matters in timing: it waits with `poll(1)` on a ring built with `enable_wakeup=False`, so it is not `capped`. That is CONC-07, and it affects the per-worker-listener mode the scheduler normally gives this loop.

Limitations:

- The kernel's multishot accept is abstracted to "completions keep coming from the armed request". Its termination (`!has_more`, never re-armed by the loop) is not modelled; that loop can then accept nothing more, which is not a safety issue.
- The probe-skew case is shown reachable at the level of the two predicates. Forcing a transient `io_uring_setup` failure on one thread was not attempted, so there is no repro.

### Lifecycle bookkeeping (`scheduler.mojo:361-653,670-689,845-897`, `_thread.mojo:211-274`)

**Model** (`Flare.L5.Lifecycle`), three sequential parts.

1. **`start` and its rollback.** The heap is a count per resource: stop flag, shared listener, worker array, stats cell `i`, per-worker listener `i`, context `i`, plus a count of running worker threads. `free` of a resource with count 0 sets `dbl`; freeing anything a worker can reach while a worker thread runs sets `uaf`. `startAlloc` mirrors the allocation order (:361-543), `spawnR` the successful spawns (:545-590), `startFail` the failure of spawn `k` followed by the rollback (:591-633), and `abandon` `_abandon_start` after a failed bind (:511-543,643-653).
2. **Drain's stuck-worker branch.** `sweepStuck` is the sweep's `stuck.append(i)` (:845-855), `eraseAt` is Mojo `List.pop(idx)`, and `popStuck` is the descending pop loop with its `idx < len` guard (:890-896).
3. **POSIX return codes.** `pjoin` / `pdetach` give `ESRCH` (thread reaped), `EINVAL` (not joinable, or already being joined) and `EDEADLK` (self-join). `WOut` is one worker's sweep outcome; `keptImpl` is flare's rule (append to `stuck` only when `detach` returned; a raising call falls into `except: pass` and the worker's resources are freed); `liveAfter` says whether the thread may still run.

| Lean name | Statement (one line, English) | Status |
|---|---|---|
| `Flare.L5.Lifecycle.startFail_eq` | For every worker count, listener count and failing spawn index: the rollback joins every spawned worker, frees nothing twice, frees nothing under a running worker, and leaves allocated exactly the per-worker listeners (none with the fix or in shared mode) | proved |
| `Flare.L5.Lifecycle.impl_rollback_leaks` | flare's rollback in per-worker mode leaves every per-worker listener allocated (CONC-06) | counterexample (general) |
| `Flare.L5.Lifecycle.fixed_rollback_clean`, `impl_rollback_clean_shared` | With the fix (or in shared mode, already) the failed `start` leaves nothing | proved |
| `Flare.L5.Lifecycle.abandon_clean` | `_abandon_start` after a failed per-worker bind leaves nothing | proved |
| `Flare.L5.Lifecycle.popStuck_keeps_joined` | For any `n`, any set of detached workers and any per-worker list, the pops leave exactly the entries at non-detached indices, in order; the same predicate applies to `_ctx_addrs` and `_stats_addrs`, so they stay aligned | proved |
| `Flare.L5.Lifecycle.freed_iff_not_detached` | An entry is freed by `_free_resources` iff it belongs to a worker that was not detached | proved |
| `Flare.L5.Lifecycle.live_handle_calls` | On a live handle (from `Thread.inv_inductive`) `pthread_detach` returns 0, and `pthread_join` returns 0 unless the caller joins itself | proved |
| `Flare.L5.Lifecycle.impl_freed_under_live_iff` | flare's teardown frees resources of a possibly running thread iff some `join`/`detach` failed | proved |
| `Flare.L5.Lifecycle.impl_safe_of_external_caller` | If every call returns 0 (teardown on a non-worker thread), nothing is freed under a live thread | proved |
| `Flare.L5.Lifecycle.self_shutdown_frees_caller` | `shutdown()` / `drain(<=0)` called from a worker joins itself, gets `EDEADLK`, and flare frees that worker's resources under it | counterexample (API hazard, unreachable in flare) |
| `Flare.L5.Lifecycle.self_drain_keeps_caller` | `drain(>0)` from a worker detaches itself, which succeeds, and keeps its resources | proved |
| `Flare.L5.Lifecycle.fixed_never_frees_live` | Treating a failed call like a detach never frees under a live thread | proved |

Assumptions: the POSIX error cases as listed in IEEE 1003.1 for `pthread_join` / `pthread_detach`; "another thread is already joining" is excluded by the single owner (`Thread.at_most_one_effect`). That the teardown runs on a thread other than the workers is a property of the callers (`http/server.mojo:1173-1181,1312-1336,1614-1628`: the serving thread owns the `Scheduler` and calls `shutdown` after its wait loop). The Mojo type system does not enforce it; a Frontend would need an unsafe pointer to the `Scheduler` to violate it.

## Findings

### CONC-01: a non-positive deadline is stored unchecked; `-1` wedges the slot

- **Severity:** Low (latent). No flare code arms the watchdog at 59bda50. A caller passing an already-spent budget, or one that overflows `now + budget`, would hang that worker in `_settle` forever.
- **Clause violated:** the `_FIRING` contract at `watchdog.mojo:47-49` ("a fire that has begun always lands on the request it was meant for"; `arm` and `disarm` wait it out), and `FiringOwned` in the model.
- **What goes wrong:** `watchdog_arm` computes `Int64(monotonic_now_ms() + budget_ms)` at `watchdog.mojo:107` and CASes it in at :110 with no range check.
  - `budget_ms = -(now + 1)` stores `-1`, which is the FIRING sentinel. The poller skips it (`d > 0`, :162), and every later `arm` or `disarm` spins in `_settle` (:81-87).
  - Any deadline `≤ 0` never fires, and `0` reads as "disarmed".
- **Lean counterexample:** `Flare.Bugs.CONC_01.arm_firing_sentinel`. It is a reachable state with `¬ FiringOwned`, from which no schedule lets `disarm` return; `stuck_closed` shows the state is closed under every step.
- **Fix:** clamp the deadline to at least 1. Proved sufficient by `Flare.Bugs.CONC_01.clampOnly_safe` (under arm-after-disarm) and `Flare.L5.Watchdog.fixed_safe`. A saturating add would also keep a huge budget from wrapping into an immediate fire.
- **Repro:** `formal/repro/CONC-01_watchdog_nonpositive_deadline.mojo`. Observed:
  `BUG REPRODUCED: arm with an expired budget left slot 0 at the FIRING sentinel (-1) after 50 polls; the cell was never flipped and disarm(0) would spin forever`.
- **Flip:** with the clamp, `OK: arm with an expired budget fires at the next poll` and exit 0. Restored.

### CONC-02: re-arming a still-armed slot fires the old deadline into the new request's cell

- **Severity:** Low (latent). A grep of `flare/` finds no caller that re-arms without `disarm`. There is no production call site at all; only `tests/runtime/test_watchdog.mojo` uses the watchdog, and its re-arm happens after the fire has completed, which `_settle` makes safe. The `arm` docstring does not state the "disarm first" precondition.
- **Clause violated:** `watchdog.mojo:47-49` (the fire lands on the request it was meant for) and the `disarm` contract (:114-124). In the model these are `Safe` and `DisarmCorrect`.
- **What goes wrong:** `arm` stores the new cell's address (:106) before CASing the new deadline in (:110). While the slot still holds the previous, expired deadline, the poller can claim it (:161-165), load the new address (:166) and write `TIMEOUT` into the new cell. The new request is cancelled with its 60 s budget untouched, and its `disarm` returns `False`.
- **Lean counterexamples:**
  - `Flare.Bugs.CONC_02.rearm_hits_new_cell`: an explicit 13-step trace reaching a poller write into cell 2 under request 1's claim (`¬ Safe`).
  - `Flare.Bugs.CONC_02.rearm_disarm_wrong`: the continuation ends with cell 2 cancelled, request 2's deadline at 60001 ms, and `disarm` reporting not fired (`¬ DisarmCorrect`).
- **Fix:** start `watchdog_arm` with the disarm loop (CAS the current deadline to 0, waiting out FIRING), then store the address and CAS `0 → deadline`. Proved sufficient by `Flare.Bugs.CONC_02.disarmFirst_safe` (positive budgets, re-arm allowed) and `Flare.L5.Watchdog.fixed_safe` (any budget).
- **Repro:** `formal/repro/CONC-02_watchdog_rearm_fires_old_deadline_on_new_cell.mojo`. It races the real `arm` against the real poller for up to 4 s, because the poll loop cannot be driven one iteration at a time. Observed:
  `BUG REPRODUCED: re-arming a still-armed slot cancelled the new request's cell (60 s budget) in round 33291 ; disarm reported fired = False`.
- **Flip:** with the disarm-first arm, `OK: no stale fire hit the new cell in 49483143 rounds` and exit 0. Restored. The repro is nondeterministic, so an OK result is evidence, not proof.

### CONC-03: `Scheduler.drain` frees the stop flag under a detached worker

- **Severity:** High. This is a use-after-free on the public, documented `Scheduler.drain(timeout_ms > 0)` path (`docs/asyncrt.md:101`, `examples/intermediate/drain.mojo`). It is reached whenever a handler outlives the drain timeout. The observed consequence is a worker that keeps serving after `drain` returned, on a listener that drain deliberately left open.
- **Clause violated:** the drain docstring at `scheduler.mojo:799-803` says the detached worker's resources "are left allocated, since the thread may still be using them". In the model this is `MemSafe` / `LiveRefsAllocated`.
- **What goes wrong:** the stuck-worker branch (`scheduler.mojo:887-897`) pops the stuck worker's context and stats entries. `_free_resources` (:900, :741-744) then frees the shared stop-flag cell anyway. The detached worker re-reads that cell on every serve-loop iteration (`_worker.mojo:114-116,150-155`, via the frontend's `load_stop_flag`).
- **Lean counterexamples:**
  - `Flare.Bugs.CONC_03.drain_frees_live_ref`: a 9-step trace with one worker in `serve` at `fin` and the stop flag freed (`¬ LiveRefsAllocated`).
  - `Flare.Bugs.CONC_03.drain_uaf`: two more worker steps dereference the freed flag (`¬ MemSafe`).
  - The explorer finds the violation independently: `bounded_impl_fails` (n = 1) and `bounded_impl_2_fails` (n = 2).
- **Fix:** in `if len(stuck) > 0:`, set `self._stopping_addr = 0` before `_free_resources`, which leaks the flag like the stuck worker's other cells. Proved sufficient for every `n` by `Flare.Bugs.CONC_03.implFixed_safe`; `implFixed_detached_sees_stop` shows the detached worker then reads `True` and exits.
- **Repro:** `formal/repro/CONC-03_drain_frees_stop_flag_under_detached_worker.mojo`. Observed in 5 of 5 runs, for example:
  `BUG REPRODUCED: drain freed the stop flag at 0x10a0c0008 under the detached worker (cell reissued: True; worker saw the stop: False)`.
- **Flip:** with the fix, `OK: drain left the stop flag allocated and the detached worker saw the stop` and exit 0, in 3 of 3 runs. Restored.
- **Determinism:** the verdict is now "the flag cell was freed", observed as the cell being handed out again by one of the next 64 same-size allocations on the thread that called `drain`. A leaked cell can never come back. What the worker then reads is reported only as a consequence.
  - Mojo's allocator is the TCMalloc embedded in `libKGENCompilerRTShared` (not the system malloc, so `malloc_size` cannot be used). It hands a freed small cell back within the few same-class frees `drain` performs after it.
  - The repro calibrates that property first, with three same-size frees, and raises `setup:` instead of printing OK if it fails. It therefore cannot print OK while the cell is freed.
  - Two pitfalls make an earlier version of the check report "not reissued" falsely. The optimizer folds "fresh allocation == older address" to false, so the address goes through an atomic cell. A scratch cell in the same 8-byte size class consumes the freed cell, so the scratch is 64 bytes.

Status: resolved. `drain` sets `self._stopping_addr = 0` in the stuck-worker branch, so the stop flag is leaked with the detached worker's other cells. Test: `tests/runtime/test_scheduler.mojo::test_drain_keeps_the_stop_flag_allocated_for_a_detached_worker`; the repro now prints `OK:`. The shipped drain is `Flare.L5.Scheduler.cfgShipped` (`fixStop` only; the CONC-04 listener fix lands separately); `Bugs.CONC_03.implFixed_safe` is stated about it.

### CONC-04: `Scheduler.drain` leaks the joined workers' listeners whenever one worker is detached

- **Severity:** Medium. Every non-stuck worker's `SO_REUSEPORT` listener stays open and bound for the process lifetime. If the process binds the port again (a restart in the same process), the kernel keeps hashing a share of new connections to listeners nobody accepts on. It is a resource leak, not memory corruption.
- **Clause violated:** the drain docstring at `scheduler.mojo:799-803` leaves only the stuck worker's "context, stats cell and listeners" allocated. In the model this is `NoLeak`.
- **What goes wrong:** the stuck-worker branch runs `self._per_worker_listener_addrs.clear()` (`scheduler.mojo:897`). That removes every per-worker listener from the list `_free_resources` frees (:726-733), not just the stuck worker's.
- **Lean counterexample:** `Flare.Bugs.CONC_04.drain_leaks_joined_listener`. In a 15-step trace with two workers, worker 1 is joined (not detached) and its context and stats are freed, but its listener is not (`¬ NoLeak`).
- **Fix:** in that branch drop only the stuck workers' entries, meaning primary `i` and extras `n_workers + i*n_extra + j`. Proved sufficient for every `n` by `Flare.Bugs.CONC_04.implFixed_noLeak`; with both fixes, `implFixed_full`.
- **Repro:** `formal/repro/CONC-04_drain_leaks_joined_worker_listeners.mojo`. Observed:
  `BUG REPRODUCED: after drain, the joined worker's listener fd 10 is still open (only the stuck worker's fd 8 should be)`.
- **Flip:** with the fix (a `keep` list filtered by the stuck set), `OK: drain closed the joined worker's listener fd 10` and exit 0. Restored.

Status: resolved. The stuck-worker branch of `drain` now keeps every non-stuck worker's primary and extra listeners in the list `_free_resources` frees, and drops only the detached workers' (owner of entry `p` is `p` for the primaries, `(p - n) // n_extra` for the extras). Tests: `tests/runtime/test_scheduler.mojo::test_drain_closes_the_joined_workers_listeners` and `::test_drain_closes_the_joined_workers_extra_listeners` (deterministic: the stuck worker waits on a gate; the fds are checked with `fcntl(F_GETFD)`). The repro now prints `OK:` (3 of 3 runs). The shipped drain is `Flare.L5.Scheduler.cfgShipped` (both the CONC-03 and CONC-04 fixes); `Flare.Bugs.CONC_04.implFixed_noLeak` is stated about it.

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
- **Lean counterexamples:**
  - `Flare.Bugs.CONC_05.shutdown_stale_accept`: a 5-step `shutdown` trace (register, pass the check, close, reuse, accept).
  - `Flare.Bugs.CONC_05.drain_closes_live_listener`: an 8-step `drain` trace ending after `drain` returned, with the worker detached and its accept on the reused number.
- **Fix:** do not close in `_signal_and_close_listener`. Let `_free_resources` close the number once, after every worker joined. When a worker was detached, leak the shared listener (`self._shared_listener_addr = 0` in the stuck-worker branch). Proved sufficient for `shutdown` and `drain`, any `n`, any interleaving with fd reuse, by `Flare.Bugs.CONC_05.implFixed_safe`; `implFixed_noLeak` shows the listener is still closed when no worker was detached. Liveness does not need the early close: with the 100 ms poll cap every worker is done within `bound P` of the stop (`Flare.L5.Timed.worker_done_by`) and the fixed teardown returns within `mBound` (`teardown_done_by`). The io_uring loop has no cap (CONC-07), but the close never woke it either: the armed accept holds its own reference to the socket. The fix is also safe for an io_uring worker on the shared fd (`UringShared.uring_fixed_noStale`).
- **Repro:** `formal/repro/CONC-05_shared_listener_closed_under_live_worker.mojo`. It sets `FLARE_REUSEPORT_WORKERS=0` with libc `setenv`; one worker records its listener fd and stays in a "handler"; `drain(50)` detaches it. Deterministic: the close is observed with `fcntl(F_GETFD)` and the reuse with one `open("/dev/null")`. Observed:
  `BUG REPRODUCED: drain closed the shared listener fd 8 while the detached worker still holds it (the next open() reused the number: True)`.
- **Flip:** with the fix (close removed from `_signal_and_close_listener`, `self._shared_listener_addr = 0` in the stuck branch), `OK: the detached worker's shared listener fd 8 is still open` and exit 0. Restored.

### CONC-06: `Scheduler.start`'s rollback leaks every per-worker listener

- **Severity:** Medium. When `pthread_create` fails part-way through `start` in the default listener mode (per-worker `SO_REUSEPORT`, also forced by extra addresses or by a frontend that requires it), every pre-bound listener, including the extras, stays open and bound for the life of the process. The caller sees the `Error`, but the port stays held, and a retry binds next to sockets that keep receiving a share of new connections nobody accepts. `pthread_create` fails under thread or memory exhaustion, exactly when a caller is likely to retry.
- **Clause violated:** `start`'s docstring (:337-343): "partially-started workers are best-effort joined before re-raising"; a failed constructor leaves nothing behind. In the model: `startFail … = H.empty`.
- **What goes wrong:** the rollback (`scheduler.mojo:591-633`) frees the worker array, the contexts, the stats cells, the shared listener and the stop flag, but never `s._per_worker_listener_addrs` (filled at :511-543). `Scheduler` has no destructor, so nothing frees them once the error propagates.
- **Lean counterexample:** `Flare.Bugs.CONC_06.rollback_leaks_listeners`. It holds in general: for every worker count, listener count and failing spawn index, each per-worker listener is still allocated. `repro_instance` is the repro's case; `rollback_rest_ok` shows everything else is released correctly.
- **Fix:** in the rollback, destroy and free every entry of `_per_worker_listener_addrs` and clear it, as `_free_resources` does. Proved sufficient by `Flare.Bugs.CONC_06.fixed_rollback_clean`: nothing allocated, nothing freed twice or under a running worker, every spawned worker joined.
- **Repro:** `formal/repro/CONC-06_start_rollback_leaks_per_worker_listeners.mojo`. Deterministic: it fills the process thread table with parked threads until `spawn_os` raises, frees exactly one slot by joining one of them, and runs `start(num_workers=2)`. Worker 0 takes the slot and worker 1 fails; if anything else took the slot, worker 0 fails instead, with the same leak. The leak is the change in the number of open descriptors. Observed:
  `BUG REPRODUCED: the failed Scheduler.start left 2 listener fds open ( 10 open before, 12 after)`.
- **Flip:** with the fix, `OK: the failed Scheduler.start released every fd ( 10 open)` and exit 0. Restored.

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
- **Lean counterexamples:**
  - `Flare.Bugs.CONC_07.shutdown_never_returns`: for every `N`, a run in which every hypothesis but `PollReturns` holds throughout, and `N` ms after the stop the worker is still in its wait and `shutdown` is still at `pass 0`.
  - `not_pollReturns` shows these states violate the wait bound.
  - `drain_detaches_idle`: for every deadline `D`, a drain that ends with the idle worker detached (snapshot `[false]`). This includes `D > bound P`, where `Timed.drain_joins_all` rules it out for capped loops.
- **Fix:** bound the wait. For example, keep one `IORING_OP_TIMEOUT` (100 ms, relative) armed on the ring and re-arm it when its completion arrives, so `poll(1)` returns at least every 100 ms as the epoll loop does. A timeout passed to `io_uring_enter` (`IORING_ENTER_EXT_ARG`) works too. With the fix the loop is `capped`, and `Flare.Bugs.CONC_07.fixed_meets_spec` (that is, `Timed.worker_done_by`, `teardown_done_by` and `drain_joins_all`) applies with `cap = 100`.
- **Repro:** `formal/repro/CONC-07_uring_worker_ignores_stop_while_idle.mojo`, `# PLATFORM: linux`, run with `formal/repro/linux.sh` (Ubuntu 24.04 container, native arm64, seccomp unconfined).
  - Setup: a real `HttpFrontend` with `ServerConfig(use_bufring=True)`, one worker, no traffic, 300 ms for the worker to arm and block, then `drain(2000)`, which is 20 times the epoll cap.
  - If the worker was detached, the repro opens one TCP connection, to show that only traffic releases it and to let the process exit cleanly.
  - Without io_uring it stops as inconclusive instead of printing OK.
  - Observed in 4 of 4 runs (the last one after the flip was restored): `BUG REPRODUCED: the idle io_uring worker ignored the stop flag for 2000 ms; drain detached it (still running: True), and it returned only after a client connected (returned: True)`.
- **Flip:** in the container's copy of the repo, `run_uring_bufring_reactor_loop_shared` was changed to keep one 100 ms `IORING_OP_TIMEOUT` SQE armed and re-arm it on its completion. Result: `OK: the idle io_uring worker saw the stop and was joined after 14 ms` (then 111 ms and 3 ms) and exit 0, in 3 of 3 runs. The next synced run restored the copy, and the host's `flare/` was never edited.

## Checked, not a bug

- **Watchdog: `disarm` racing a fire in progress.** `_settle` waits out FIRING. `DisarmCorrect` and `Safe` (via `impl_safe`) show that `disarm` returns `True` exactly when the cell was cancelled, and that the poller never writes a cell after that request's `disarm` returned.
- **Watchdog: `arm` while the slot is FIRING.** `arm` settles before storing, and `FiringOwned` shows FIRING is always held by a poller inside its three-step claim window. The test `test_rearm_right_after_a_fire_keeps_its_deadline` exercises exactly this case, and it is safe.
- **Watchdog: clock overflow.** `now + budget` wraps only for budgets near `I64_MAX - now`. The wrapped value is non-positive, which is CONC-01, so its fix covers this case too.
- **AsyncRT: double free or use after free when join or detach races the trampoline's CAS.** Refuted by `free_at_most_once` and `no_use_after_free`. Exactly one side frees.
- **AsyncRT: the trampoline touching the cell after waking the joiner.** Not a bug, given AR-1 (`ar1_load_bearing` shows AR-1 is the one fact the protocol depends on).
- **AsyncRT: join twice, detach after join, and similar sequences.** Refuted by `calls_after_zero_are_noops` and `zeroed_noop`. The zeroing is load-bearing (`guard_load_bearing`).
- **ThreadHandle: `pthread_join` / `pthread_detach` called twice.** Refuted by `at_most_one_effect` and `no_posix_ub`, including retries after failures.
- **ThreadHandle: a moved-from handle.** Rejected by the Mojo move checker (`moved_from_inert`). A bitwise alias would defeat the defence (`alias_double_join`), but flare's only second handle to a running thread (`_worker.mojo:131-134`) calls only `pin_to_cpu`.
- **ThreadHandle: no destructor.** By design (`_thread.mojo:20-22`): dropping a live handle leaks (`drop_live_leaks`, `AsyncRT.drop_leaks`).
- **ThreadHandle: `pin_to_cpu` on a zeroed handle.** On Linux this passes `pthread_t` 0 (`pin_after_join_hazard`), but flare only pins fresh handles, so it is unreachable. Suggested hardening: return early when `_thread_id == 0`.
- **Scheduler: `shutdown()` / `drain(timeout_ms <= 0)` freeing under a live worker.** Refuted. `shutdown_safe` proves memory safety and no leaks for every `n`: every worker is joined before anything is freed.
- **Scheduler: a joined worker touching its context or stats after the DONE store.** Not possible. After `_worker.mojo:156` the worker only returns. The join waits for termination, and in a soft drain it waits at most that one step (`soft_join_bounded`).
- **Scheduler: the stuck worker's context, stats cell and listeners staying allocated.** By design (the drain docstring at `scheduler.mojo:799-803`). The fixed drain also leaks the stop flag in that case; this is the price of CONC-03's fix.
- **Scheduler: stop-flag visibility.** The release store / acquire load pair gives workers the happens-before edge, and the model's SC abstraction is justified for this single location.
- **Scheduler: drain's stuck-worker index bookkeeping.** Proved correct: `popStuck_keeps_joined` and `freed_iff_not_detached`, for any `n` and any set of detached workers. `stuck` is built in increasing order (`sweepStuck_sorted`), the pops run in decreasing order, so no pop shifts an index still to be popped. The same predicate applies to `_ctx_addrs` and `_stats_addrs`, so exactly the joined workers' contexts and stats cells are freed and the two lists stay aligned. The `idx < len` guards never skip a pop (both lists have one entry per worker).
- **Scheduler: `start` rollback, other than CONC-06.** Proved by `startFail_eq`: every spawned worker is joined before anything is freed, nothing is freed twice, and the context of the failed spawn is freed. In shared mode the rollback is already clean (`impl_rollback_clean_shared`); it frees the shared listener with its destructor, closing the fd once. `_abandon_start` after a failed bind is clean (`abandon_clean`), as are the probe-bind and `set_nonblocking` failure paths, which free only the stop flag (the local `bound` listener is dropped by Mojo).
- **epoll/kqueue loops: liveness of the fixed teardown.** Proved under stated hypotheses: every worker is done within `cap + ε + 2σ + η + τ` of the stop, and `shutdown` / `drain` return within that plus `(n + 2)σ` (one more `σ` for drain). A drain whose deadline exceeds the per-worker bound detaches nobody (`Timed.worker_done_by`, `teardown_done_by`, `drain_joins_all`). Every loop the scheduler runs passes `_poll_timeout_ms(wheel)` (`_server_reactor_epoll.mojo:167,389,608,754`, `_unified_reactor_impl.mojo:1107,1292`), whose result is in `[1, 100]` (`pollTimeout_le_cap`); the streaming loop passes a fixed 100 ms default (`_stream_reactor_impl.mojo:196-298`). The bound fails in no interleaving that meets the hypotheses. It needs a bounded batch: `_accept_loop_fd` accepts until `EAGAIN` with no per-call cap, so a sustained connection storm stretches one iteration. That is an arrival-rate assumption, not a defect.
- **io_uring loop on the shared listener.** Not reachable while both io_uring probes agree (`uring_never_shared`). If they disagree (`probe_skew_shared`), the fd-use behaviour simulates the epoll model's, so CONC-05's fix covers it (`uring_fixed_noStale`), and the unfixed teardown is stale only for a late arm (`uring_late_arm_stale`, part of CONC-05). The timing defect is CONC-07, independent of the listener mode.
- **Scheduler: `pthread_join` / `pthread_detach` failing.** On a live handle, `pthread_detach` cannot fail, and `pthread_join` fails only for a self-join (`live_handle_calls`; `ESRCH`/`EINVAL` need a reaped or detached thread, which `Thread.inv_inductive` excludes). Every in-repo teardown runs on the thread that owns the `Scheduler`, so the `except: pass` branches are dead (`impl_safe_of_external_caller`). If a call did fail, flare would free the worker's resources under it (`impl_freed_under_live_iff`). The one way to get there is an **API hazard**, not a reachable bug: `shutdown()` or `drain(timeout_ms <= 0)` called from inside a worker joins itself, gets `EDEADLK`, and frees that worker's context, stats cell and stop flag while it runs (`self_shutdown_frees_caller`). `drain(timeout_ms > 0)` from a worker is fine; it detaches itself (`self_drain_keeps_caller`). A worker can only reach its `Scheduler` through an unsafe pointer, so no ID and no repro. Suggested hardening: on a raising `join`/`detach`, treat the worker as stuck (`fixed_never_frees_live`), and document that teardown must not run on a worker thread.

## Traceability

| Lean definition | Mojo file:line @59bda50 | Theorems | Status |
|---|---|---|---|
| `Flare.L5.Watchdog.FIRING` | `runtime/watchdog.mojo:46` | `FIRING_neg` | proved |
| `Flare.L5.Watchdog.PPc`, `pStep` | `runtime/watchdog.mojo:154-177` | `inv_step_p`, `safe_of_cfg` | proved |
| `Flare.L5.Watchdog.WPc`, `wStep` | `runtime/watchdog.mojo:81-87,98-132` | `inv_step_w`, `safe_of_cfg`, CONC-01, CONC-02 | proved / counterexample |
| `Flare.L5.Watchdog.deadlineOf` | `runtime/watchdog.mojo:107` | `deadlinePos_impl`, `deadlinePos_fixed`, CONC-01 | proved / counterexample |
| `Flare.L5.AsyncRT.CS`, `St`, `init` | `runtime/_asyncrt.mojo:84-92,171-200` | `inv_inductive` | proved |
| `Flare.L5.AsyncRT.Step` (trampoline) | `runtime/_asyncrt.mojo:132-168` | `free_at_most_once`, `no_use_after_free`, `chain_before_free` | proved |
| `Flare.L5.AsyncRT.Step` (owner) | `runtime/_asyncrt.mojo:203-262` | `join_returns_after_done`, `progress`, `calls_after_zero_are_noops` | proved |
| `Flare.L5.Thread.Handle`, `join`, `detach`, `pin` | `runtime/_thread.mojo:93-128,211-274,289-346` | `inv_inductive`, `at_most_one_effect`, `no_posix_ub`, `zeroed_noop` | proved |
| `Flare.L5.Scheduler.WPc`, `wStep` | `runtime/_worker.mojo:99-162` | `core_inductive`, `safe_of_cfg`, `soft_join_bounded` | proved |
| `Flare.L5.Scheduler.WS`, `St` | `runtime/scheduler.mojo:243-277`, `runtime/scheduler_stats.mojo:57-73` | `core_inductive` | proved |
| `Flare.L5.Scheduler.init` | `runtime/scheduler.mojo:361-641` | `core_init` | proved |
| `Flare.L5.Scheduler.MPc`, `mStep`, `step` | `runtime/scheduler.mojo:815-885` (`drain`), `:746-760` (`shutdown`) | `core_step_m`, `shutdown_safe`, `fixed_safe` | proved |
| `Flare.L5.Scheduler.freeAll` | `runtime/scheduler.mojo:887-900,703-744` | `safe_of_cfg`, `noLeak_of_cfg`, CONC-03, CONC-04 | proved / counterexample |
| `Flare.L5.Scheduler.explore`, `check` | (checker, no Mojo counterpart) | `check_sound`, `bounded_fixed`, `bounded_shutdown`, `bounded_impl_fails` | proved / bounded |
| `Flare.Bugs.CONC_01.trace` | `runtime/watchdog.mojo:107,161-165,81-87` | `arm_firing_sentinel`, `stuck_closed` | counterexample |
| `Flare.Bugs.CONC_02.traceA`, `traceB` | `runtime/watchdog.mojo:106-110,161-175` | `rearm_hits_new_cell`, `rearm_disarm_wrong`, `disarmFirst_safe` | counterexample / proved |
| `Flare.Bugs.CONC_03.traceFree`, `traceUaf` | `runtime/scheduler.mojo:887-900,741-744`, `_worker.mojo:150-155` | `drain_frees_live_ref`, `drain_uaf`, `implFixed_safe` | counterexample / proved |
| `Flare.Bugs.CONC_04.trace` | `runtime/scheduler.mojo:897,726-733` | `drain_leaks_joined_listener`, `implFixed_noLeak` | counterexample / proved |
| `Flare.L5.SharedListener.WPc`, `wStep` | `http/_server_reactor_epoll.mojo:150-266` | `inv_inductive`, `stop_exits` | proved |
| `Flare.L5.SharedListener.signalFd`, `freeFd`, `mStep`, `step` | `runtime/scheduler.mojo:655-668,703-724,846-900` | `fixed_noStale`, `fixed_closedAtEnd`, CONC-05 | proved / counterexample |
| `Flare.Bugs.CONC_05.traceShutdown`, `traceDrain` | `runtime/scheduler.mojo:655-668`, `http/_server_reactor_epoll.mojo:163,184-193` | `shutdown_stale_accept`, `drain_closes_live_listener`, `implFixed_safe` | counterexample / proved |
| `Flare.L5.Lifecycle.startAlloc`, `spawnR` | `runtime/scheduler.mojo:361-590` | `startFail_eq` | proved |
| `Flare.L5.Lifecycle.startFail` | `runtime/scheduler.mojo:572-633` | `startFail_eq`, `fixed_rollback_clean`, CONC-06 | proved / counterexample |
| `Flare.L5.Lifecycle.abandon` | `runtime/scheduler.mojo:511-543,643-653,703-744` | `abandon_clean` | proved |
| `Flare.L5.Lifecycle.sweepStuck`, `eraseAt`, `popStuck` | `runtime/scheduler.mojo:845-855,890-896` | `popStuck_keeps_joined`, `freed_iff_not_detached` | proved |
| `Flare.L5.Lifecycle.pjoin`, `pdetach`, `keptImpl` | `runtime/_thread.mojo:211-274`, `runtime/scheduler.mojo:670-689,846-855` | `live_handle_calls`, `impl_freed_under_live_iff`, `impl_safe_of_external_caller` | proved |
| `Flare.Bugs.CONC_06` | `runtime/scheduler.mojo:511-543,591-633` | `rollback_leaks_listeners`, `fixed_rollback_clean` | counterexample / proved |
| `Flare.L5.Timed.pollTimeout` | `http/_reactor/lifecycle.mojo:31-47` | `pollTimeout_le_cap`, `pollTimeout_pos` | proved |
| `Flare.L5.Timed.TPc`, `wNext`, `step` | `http/_server_reactor_epoll.mojo:150-266`, `http/_server_reactor_uring.mojo:842-981` | `J_inductive`, `worker_done_by` | proved |
| `Flare.L5.Timed.MPc`, `mStep` | `runtime/scheduler.mojo:655-668,746-760,815-901` | `teardown_done_by`, `drain_joins_all` | proved |
| `Flare.L5.Timed.PollReturns`, `FairW`, `FairM`, `HandlerBound`, `TeardownBound` | (hypotheses, no Mojo counterpart) | `worker_done_by`, `bound_tight` | proved |
| `Flare.L5.UringShared.requiresPerWorker`, `uringDispatch`, `prebind` | `http/frontend.mojo:114-162`, `runtime/scheduler.mojo:388-430` | `uring_never_shared`, `probe_skew_shared` | proved |
| `Flare.L5.UringShared.uwStep`, `ustep` | `http/_server_reactor_uring.mojo:843-981`, `runtime/scheduler.mojo:655-668,846-900` | `sim_step`, `uring_fixed_noStale`, `uring_fixed_closedAtEnd` | proved |
| `Flare.Bugs.CONC_07` | `http/_server_reactor_uring.mojo:820-852`, `runtime/uring_reactor.mojo:834-836`, `runtime/scheduler.mojo:746-760,829-852` | `shutdown_never_returns`, `drain_detaches_idle`, `fixed_meets_spec` | counterexample / proved |
