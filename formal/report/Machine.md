# Worker-loop machine

Scope: the event loop that composes the layers inside one reactor worker. The
model follows the handler loop in flare/http/_server_reactor_epoll.mojo
(`_run_handler_loop_impl`) and the bookkeeping in
flare/http/_reactor/lifecycle.mojo (`_apply_step`, `_cleanup_conn`,
`_accept_loop`). The loop that `HttpServer.serve(handler)` runs,
`_run_unified_loop_for_fd` in `_unified_reactor_impl.mojo`, has the same
structure (`_cleanup_conn_unified` also cancels the timer before freeing), so
the results apply to both. The file is `Flare/Machine.lean`.

Modelled: the `conns` and `timers` dictionaries, the timer wheel at the level
of its spec (`advance now` fires exactly the active timers due by `now`; a
cancelled timer never fires), the batch of tokens returned by one
`reactor.poll`, the order "fire timers, then walk the batch", accept with
lowest-fd reuse, and the listener token versus client token = fd. Per-connection
behaviour is a parameter `ConnModel` (state, `onEvent : S → I → S ×
StepResult`, idle timeout), so any connection model, including
`Flare.L4.ConnSM`, plugs in.

Not yet re-modelled: since 861d3367 the loop collects the fired timers right
after `poll` but reaps their connections only after the batch
(`_expired_idle_conns`), so a connection that the batch served and re-armed is
spared. The model still reaps before the batch. Its anchor on
`_run_handler_loop_impl` is stale for this reason.

Abstractions: the kernel may put any live token in a batch (spurious readiness
is allowed, so no readiness semantics is assumed); write back-pressure and TLS
interest are part of the per-connection model (`ConnSM`, L4); the multi-worker
reuseport mode is `Flare/MachineWorkers.lean`, the shared-listener mode is the
L5 scheduler model. Time is `Nat`: flare's `UInt64` monotonic milliseconds
wrap after about 584 million years, which the model does not represent.

## Components

### Configuration and steps

`Cfg S` holds `now`, `conns : Fd → Option (Live S)` (state, ghost incarnation
number `gen`, interest), `timers : Fd → Option Nat`, the active `wheel`, the
pending `batch`, and a ghost log `kills` of idle closes (victim incarnation,
arming incarnation, due time, close time). Labels: `poll now toks`,
`accept fd regOk`, `acceptDone`, `dispatch i`. `step` is a partial function;
`lts M P := LTS.ofFn (· = initCfg) (step M P)`. The listener's reactor token
is the constant `listenerToken` (2^40, flare's `LISTENER_TOKEN`), and
`fdLimit_le_listenerToken` shows it is above every fd. `Params` fixes the
listener fd, whether fd 0 is in use (stdin open), and whether cleanup cancels
the connection's timer (flare: yes).

| Lean name | Statement | Status |
|---|---|---|
| `inv_reachable` | With cancel-on-cleanup, every reachable state satisfies `Inv`: each wheel timer belongs to a live connection on its fd with the same incarnation and is that fd's `timers` entry; timer ids are fresh and distinct; every logged close hit the incarnation that armed it, at or after the deadline. | proved |
| `no_stale_timer` | In every reachable state, every idle close so far closed the incarnation that armed its timer, even across fd reuse. | proved |
| `no_early_close` | No idle close happens before its deadline. | proved |
| `no_late_close` | A poll at time `now` leaves no live connection whose timer was due at or before `now`. | proved |
| `dispatch_isolated` | A dispatch on fd `f` changes no other connection and no other `timers` entry. | proved |
| `conn_invariant_lifts` | Any property of every state reachable in the per-connection model holds of every live connection in every reachable machine state. | proved |
| `routing_ok` | No reachable state has a connection on the listener's token, whether or not stdin is open, so that token only ever means the listener. | proved |
| `fd0_served` | Stdin closed: the client accepted on fd 0 gets its event dispatched and its connection advances. | proved (concrete trace) |
| `stale_timer_without_cancel` | Without the cancel in cleanup, a reachable state has an idle close of a connection the timer was not armed for. | counterexample (shows the cancel is necessary; flare has it) |
| `reuse_with_cancel` | On the same fd-reuse trace, flare's loop closes nothing early. | proved (concrete trace) |
| `stale_event_redelivered` | A readiness event harvested for one incarnation of fd 5 can be dispatched to the next incarnation on fd 5 within one batch. | counterexample (benign, see below) |

### The worker loop running `ConnHandle`

`Flare/MachineHttp.lean` instantiates the machine with `Flare.L4.ConnSM`
(input = `ConnSM.Ev`, the `StepResult` read off the handle's phase: reading
arms the idle timer, writing the write timer, done cancels). The theorems
hold for any framing oracle satisfying `ConnSM.Oracle.WF` and every worker
parameter set.

| Lean name | Statement | Status |
|---|---|---|
| `server_conns_inv` | In every reachable worker state, every live connection satisfies the `ConnSM` invariant. | proved |
| `server_responses_fifo` | On every live connection, responses answer exactly the dispatched requests in order, each request is the framing of exactly its own bytes, and the wire is a prefix of the queued responses. | proved |
| `server_ka_bound` | On every live connection the keep-alive count stays within `max_keepalive_requests`. | proved |
| `server_no_stale_timer` | With HTTP connections, every idle close hits the connection that armed the timer. | proved |

### Progress and several workers

`Flare/MachineWorkers.lean`. `Sys` interleaves `n` workers (one per thread,
`Scheduler.start` in flare/runtime/scheduler.mojo) under the one global
constraint that they share the process's fd table: `accept` in any worker
returns an fd that is neither a live connection of any worker nor any
worker's listener.

| Lean name | Statement | Status |
|---|---|---|
| `step_dom` | A worker step adds a live connection on fd `x` only by accepting `x`. | proved |
| `poll_needs_empty_batch` | `reactor.poll` runs only after every token of the previous batch was handled. | proved |
| `batch_progress` | While tokens remain, some step handles the head token and shortens the batch. | proved |
| `no_deadlock` | A worker always has an enabled step. | proved |
| `sys_component_reachable` | Every worker of a reachable multi-worker system is a reachable single-worker machine, so all single-worker theorems hold per worker. | proved |
| `sys_disjoint` | No fd is a live connection of two workers at once. | proved |
| `sys_no_stale_timer`, `sys_conn_invariant_lifts`, `sys_routing_ok` | The single-worker results, per worker of the system. | proved |

### The machine on the real timer wheel

`Flare/MachineWheel.lean`. The machine's wheel is a list of active timers that
`advance` fires in scheduling order. The real wheel
(`Flare.L2.TimerWheel`, flare/runtime/timer_wheel.mojo) fires in slot order.
Two results close that gap.

| Lean name | Statement | Status |
|---|---|---|
| `inv_any` | In the worker where each poll fires the due timers in any order (`ltsAny`), the bookkeeping invariant is inductive. | proved |
| `no_stale_timer_any` | In `ltsAny`, every idle close hits the incarnation that armed the timer. | proved |
| `reachable_le_any` | Every reachable state of the scheduling-order machine is reachable in `ltsAny`. | proved |
| `R_init`, `R_schedule`, `R_cancel`, `R_advance` | The relation "the real wheel's active timers are the machine wheel's timers (id, fd, fire time)" holds initially and is preserved by `schedule` (wheel advanced to `now`, delay at least 1 ms), `cancel` and `advance`; `advance` fires exactly the timers due by `now`, each once. | proved |
| `real_wheel_poll` | Under that relation, the timers the real wheel fires, in its own order, are an allowed firing of `ltsAny`, so the poll preserves the invariant and the relation. | proved |

Assumptions and limitations: the per-connection model is total and sees only
its own state and input. `R_schedule` assumes the wheel's `tick` equals the
machine's `now` when the worker schedules, which holds because the loop
advances the wheel to `now` at the top of every iteration
(`_collect_fired_timers`, called right after `poll`). Axiom audit (`Flare/Audit/Machine.lean`):
`propext` and `Quot.sound` at most for `Flare.Machine`, plus
`Classical.choice` for the `MachineHttp` theorems (inherited from `ConnSM`);
some theorems use no axioms.

## Findings

### MACH-01: a client accepted on fd 0 is never served

Severity: Low. It needs fd 0 to be free while the server runs (stdin closed at
runtime by the application, a library, or a daemonisation helper); when it
happens, that client hangs until its idle timeout, and the worker spins at
full CPU until then because the client's unread data keeps waking the
listener branch: about 450 ms of server CPU in the 500 ms default idle
window, against about 5 ms for an idle connection without the bug. With a
long idle timeout the spin and the hang last that long.

Clause: the loop's own contract, that each readiness event reaches its
connection; nothing in the docs says fd 0 must stay open.

What goes wrong (at 59bda50): the listener is registered with token 0
(`_unified_reactor_impl.mojo:1086-1089`, and the four loops in
`_server_reactor_epoll.mojo`), every token-0 event goes to the accept drainer
(:1119), and each client is registered with token = its fd (:722). `accept`
returns the lowest free fd, so once fd 0 is free the next client gets token
0. Its request is never read.

Lean: on the pre-fix machine (listener token 0, stdin closed) a reachable
state has a live connection on fd 0, no dispatch step exists for its event,
and its state never changes (`Flare.Machine.fd0_reachable_old`,
`fd0_event_not_dispatched_old`, `fd0_never_served_old` and
`Flare.Bugs.MACH_01`, at tag `formal-audit-0.12`).

Fix: give the listener a token no fd can take. `LISTENER_TOKEN` (2^40,
`flare/runtime/event.mojo`, exported from `flare.runtime`) replaces the
literal 0 in the registration and the accept branch of the unified loop and of
the four loops in `_server_reactor_epoll.mojo`. `routing_ok` shows that no
reachable state has a connection on the listener's token, with or without
stdin, and `fd0_served` that the fd-0 client is dispatched.

Repro (at tag `formal-audit-0.12`):
`formal/repro/MACH-01_client_on_fd0_never_served.mojo`. A forked
`HttpServer` whose handler closes fd 0 on `/close-stdin`; a second client then
gets no response. Observed: `BUG REPRODUCED: after fd 0 was freed, the next
client got no response ( 0 bytes before the idle timer closed it); its token 0
routes its events to the accept drainer; server CPU 469 ms over its life, of
which 502 ms were spent waiting on that client`. After the fix:
`OK: the client after fd 0 was freed was served`, exit 0 (macOS and the Linux
container).

Status: resolved. Tests: `tests/http/test_listener_token_fd0.mojo`
(`test_client_on_freed_fd0_is_served_unified`, `_cancellable`, `_view`, `_pool`,
and `test_listener_token_is_not_a_possible_fd`); the first four fail on the
unfixed code. The static and shared-handler loops in
`_server_reactor_epoll.mojo` use the same constant but cannot be driven to
fd 0 from a handler.

## Checked, not a bug

- Stale idle timer after fd reuse. `_cleanup_conn` cancels the timer before
  freeing the connection, and `no_stale_timer` proves no timer ever closes a
  later connection on the same fd. `stale_timer_without_cancel` shows this
  cancel is load-bearing.
- Event redelivery within a batch (`stale_event_redelivered`). When the fired
  loop closes fd 5 and the accept drainer reuses fd 5 in the same iteration,
  the event harvested for the old connection is dispatched to the new one.
  The new connection's `recv` returns EAGAIN and the loop breaks, which is the
  same path as any spurious level-triggered wakeup. `conn_invariant_lifts`
  shows connection invariants hold regardless.
- Cross-connection interference: `dispatch_isolated` rules it out.

## Traceability

| Lean definition | Mojo code | Theorems | Status |
|---|---|---|---|
| `StepResult`, `ConnModel` | flare/http/_reactor/keepalive_scan.mojo (`StepResult`) | `conn_invariant_lifts` | proved |
| `cleanup` | flare/http/_reactor/lifecycle.mojo (`_cleanup_conn`); _unified_reactor_impl.mojo (`_cleanup_conn_unified`) | `cleanup_inv`, `no_stale_timer` | proved |
| `applyStep` | flare/http/_reactor/lifecycle.mojo (`_apply_step`) | `applyStep_inv`, `dispatch_isolated` | proved |
| `pollStep`, `fireAll` | flare/http/_reactor/lifecycle.mojo (`_collect_fired_timers`); the poll branch of `_run_handler_loop_impl` and `_run_unified_loop_for_fd` | `pollStep_inv`, `no_early_close`, `no_late_close` | proved |
| `acceptStep`, `step` (accept) | flare/http/_reactor/lifecycle.mojo (`_accept_loop`); _unified_reactor_impl.mojo (`_accept_loop_unified_fd`) | `acceptStep_inv`, `routing_ok`, `fd0_served` | proved |
| `listenerToken` | flare/runtime/event.mojo (`LISTENER_TOKEN`) | `fdLimit_le_listenerToken`, `routing_ok` | proved |
| `pollStepWith`, `ltsAny`, `R` | flare/runtime/timer_wheel.mojo (via `Flare.L2.TimerWheel`) | `inv_any`, `R_*`, `real_wheel_poll` | proved |
| `Sys`, `sysStep`, `fdFree` | flare/runtime/scheduler.mojo (`Scheduler.start`, one reactor loop per worker thread) | `sys_component_reachable`, `sys_disjoint` | proved |
| `step` (batch walk) | flare/http/_unified_reactor_impl.mojo (`_run_unified_loop_for_fd`) | `batch_progress`, `no_deadlock`, `poll_needs_empty_batch` | proved |
