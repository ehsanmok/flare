# Concurrency in flare — what is sound, what is the user's job

## What this means for your handlers

flare uses a thread-per-core reactor with **synchronous** handlers.
Mojo doesn't have async / await yet, so `def serve(req) raises ->
Response` runs on a pthread worker and *blocks that worker until it
returns*. This is the nginx model, not the async-tokio model.

Three practical implications you need to design around:

1. **Long blocking I/O blocks one worker.** A 30 ms DB call holds
   one worker for 30 ms, preventing that worker from accepting
   other connections during the call. With `num_workers=N` you
   have *N concurrently in-flight requests*, full stop. There is
   no per-connection task that can yield back to a runtime while
   waiting on I/O — that's an async-runtime thing flare doesn't
   have.
2. **Size `num_workers` to your handler latency profile.** For
   compute-bound or fast-I/O workloads (cache hits, in-process
   computation, small DB queries), `num_workers=num_cpus()` is
   the right starting point. For workloads with long blocking
   calls, you want larger — pick `num_workers` such that
   `num_workers ÷ p99_handler_latency_seconds` exceeds your
   target req/s. Bench your real handler before you ship.
3. **Use `block_in_pool` for genuinely-blocking C calls.** When
   you have to call a synchronous C library (an old database
   driver, a compute-heavy native function), wrap the call in
   `flare.runtime.block_in_pool(...)` so it runs on a fresh
   kernel thread (per-call `pthread_create`). The handler frame
   that called `block_in_pool` still blocks until the work
   returns — the synchronous signature requires it — but the
   *other* reactor workers stay free, and a crash inside `work()`
   only kills its own pthread instead of the reactor's. The
   submitter polls `cancel` and joins via `pthread_join`. See
   [`flare/runtime/blocking.mojo`](../flare/runtime/blocking.mojo)
   for the full cancel + crash-isolation contract.

If you're coming from axum/tokio, fastapi, asyncio, or any other
async-first framework, the mental shift is: "one in-flight request
per worker, not thousands." The throughput numbers in
[`benchmark.md`](benchmark.md) reflect non-blocking
"Hello, World!" workloads where the handler returns in microseconds;
real-app throughput depends on your handler latency × `num_workers`.

When Mojo grows async / await, flare will adopt it additively (the
`Handler` trait already takes `req` by borrow, which is the only
shape that composes cleanly with both sync and async dispatch).
Until then, plan around the sync model.

## Cross-thread primitives

flare's reactor is single-threaded per worker. The expensive shared
state lives in three places: per-connection state machines (owned by
one reactor thread), per-worker pools (`Pool[T]`, `Pool[BufferHandle]`,
`Pool[Response]`, etc., scoped to one worker), and a small set of
cross-thread primitives (`Cancel`, `HandoffQueue`, `block_in_pool`'s
heap-handoff) that are explicitly designed for cross-thread use.

The rest of this doc is about the third bucket — the cross-thread
primitives — and about the closure / `def`-binding rules in the
pinned Mojo release (see [`pixi.toml`](../pixi.toml) for the exact
version) you need to know to use them safely.

## The Mojo closure-binding rules flare relies on

The pinned Mojo release distinguishes three function-type annotations:

| Annotation | Meaning | What flare uses it for |
|---|---|---|
| `thin` | No captures. Function-pointer-shaped. Materialises as a runtime value. | Every public `def(Request) raises thin -> Response` in [`flare/http/handler.mojo`](../flare/http/handler.mojo) — `FnHandler`, `FnHandlerCT[F]`. The work argument to [`block_in_pool`](../flare/runtime/blocking.mojo) (`work: def() raises thin -> T`). The pthread `start_routine` thunk shape in [`flare/runtime/_thread.mojo`](../flare/runtime/_thread.mojo). |
| `capturing` | Captures local state. **Cannot be materialised as a runtime value on the pinned release** (the compiler emits `"TODO: capturing closures cannot be materialized as runtime values"` if you try). Usable only as a comptime parameter (`[F: def(...) capturing -> ...]`), and even then a method body that calls `F(...)` is silently promoted to `capturing`, which can't satisfy a `Handler` trait method declared without that annotation. | Not used by the public surface. |
| `unified` | Universal closure type (per [Mojo Closures 2026 forum thread](https://forum.modular.com/t/mojo-closures-2026/3013)). The keyword is accepted in function-type position (`def(Int) raises unified -> Int`), but the conversion machinery is incomplete — `def f(...) raises unified -> Int:` on a declaration site fails with `"use of unknown declaration 'unified'"`. | Not used by the public surface. |

The practical consequence: **every callable flare's public API
accepts is a `thin` closure or a `Handler`-trait struct.** Inline
closures with captures are not yet a runtime-bindable shape; the
canonical workaround is a `Handler` struct that owns the captured
state as fields.

The forum's [Formal proposal for closures](https://forum.modular.com/t/formal-proposal-for-closures/2989)
thread is explicit that closures are work-in-progress. The
[Discussing closure capture syntax](https://forum.modular.com/t/discussing-closure-capture-syntax/2475)
thread proposes signature-level capture annotations
(`fn do(*args, +var, mut a, read z, mov x)`) — neither shipped.

## Owned-by-one-thread is the default

Connections are owned by one reactor worker for their entire
lifetime. There is no implicit work-stealing on the hot path;
opt-in cross-worker handoff is available via `WorkerHandoffPool`
behind `FLARE_SOAK_WORKERS=on` for skewed-keepalive workloads
(see [`examples/advanced/work_stealing.mojo`](../examples/advanced/work_stealing.mojo)).
The per-connection state machine in [`flare/http/_server_reactor_impl.mojo`](../flare/http/_server_reactor_impl.mojo)
mutates without locks because nothing else can reach it. The same
applies to `Pool[T]` instances and the per-worker scheduler state in
[`flare/runtime/scheduler.mojo`](../flare/runtime/scheduler.mojo).

The cross-thread surfaces are an explicit, narrow list:

1. **`Cancel`** — see [`flare/http/cancel.mojo`](../flare/http/cancel.mojo).
   The cell flips from any thread via an `Atomic[DType.int64]`
   release-store; readers see the flip via the paired acquire load,
   so a reader that observes the flip also observes every write the
   flipper made before it. Lowers to a plain `mov` on x86-64 (TSO)
   and to `stlr` / `ldar` on ARM64. The reactor flips it on
   `PEER_CLOSED` / `TIMEOUT` / `SHUTDOWN`; handlers poll. No lock.
   The multicore scheduler's stopping flag uses the same
   release-store / acquire-load pair
   ([`store_stop_flag`](../flare/runtime/scheduler.mojo) /
   `load_stop_flag`).

2. **`HandoffQueue` / `WorkerHandoffPool`** — see
   [`flare/runtime/handoff.mojo`](../flare/runtime/handoff.mojo).
   Bounded MPSC of opaque `Int` tokens (file descriptors or scheduler
   tokens). The producer side (any worker) and consumer side (one
   worker) coordinate through an atomic head / tail. The token itself
   carries no Mojo-managed memory across the boundary; ownership of
   any heap allocations referenced by the token is the caller's job.

3. **`block_in_pool[T]`** — see
   [`flare/runtime/blocking.mojo`](../flare/runtime/blocking.mojo).
   Runs `work: def() raises thin -> T` on a fresh pthread; the
   submitter polls `Cancel` then joins. This is the only public
   API that crosses pthread boundaries with a user-supplied callable.

## The Send-discipline obligation (pthread-bound work)

The pinned Mojo release has no compiler-checked notion of state
that is safe to share across threads (no `Send` / `Sync` traits).
The same point is called out in the
[Mojo Closures 2026](https://forum.modular.com/t/mojo-closures-2026/3013)
forum thread:

> There is no compiler checked notion of state that is safe to share
> across threads. The best option is to use the copy/move capture
> convention or `register_passable` convention to create
> self-contained closures, but that alone is not sufficient as it
> depends on the type copied into the closure.

For flare specifically, the only cross-thread callable surface is
`block_in_pool[T]`'s `work` argument (a `thin` closure). Because the
closure is `thin`, it has no Mojo-managed captures by construction —
state shared with the worker thread must travel through:

- **Heap-allocated `_Task[T]` struct** with `Int`-typed addresses
  (the [`flare/runtime/blocking.mojo`](../flare/runtime/blocking.mojo)
  pattern). Addresses cross the pthread boundary as integer values;
  ownership of the underlying allocation passes from submitter to
  worker on `pthread_create` and back on `pthread_join`.
- **Module-level `comptime` constants** (read-only, no mutation
  hazard).
- **Atomic byte cells** (the `Cancel` cell shape — single-byte loads
  and stores are atomic on x86_64 and arm64, so the cell can be read
  from any thread without a lock).

What is NOT safe to share, even though Mojo doesn't refuse to compile
it:

- A `String` / `List[T]` / `Dict[K, V]` value captured by a thin
  closure — the stdlib's reference-count for these types is not
  multi-thread safe. Pass an `UnsafePointer` and own the
  lifetime explicitly, or convert to `Span[UInt8]` over a
  comptime-stable buffer.
- A `Pool[T]` instance — pools are explicitly per-worker.
- An `UnsafePointer[T, MutUntrackedOrigin]` reconstructed in the
  worker thread from an `Int` address that points into another
  thread's stack. The pointer arithmetic is fine; the pointed-at
  memory is not (the source thread can unwind and the storage
  becomes invalid). Use heap allocations for any cross-thread
  payload.

`block_in_pool[T]` itself owns all three of these correctly: the
`_Task[T]` allocation is heap-owned, the result / err / success
buffers are heap-owned, and the `done_flag` is a heap-allocated
single-byte atomic. The user-supplied `work()` only needs to be
careful about what *it* captures — and since it is `thin`, the
language gives you nothing to capture by reference in the first
place.

The closure-shape contract above is pinned by
[`tests/runtime/test_closure_send_contract.mojo`](../tests/runtime/test_closure_send_contract.mojo)
so a future Mojo release that lifts the materialisation restriction
trips the test instead of silently changing behaviour.

## Recommended patterns today

| You want to ... | Use ... |
|---|---|
| A handler that closes over per-app state | `Handler` struct with the state as fields — see [`tests/http/test_handler.mojo`](../tests/http/test_handler.mojo) `_Greeter` for the canonical shape. |
| A handler that closes over per-request derived state | A function chain with the state passed explicitly through `Request.params` / `Request.headers`, or a struct that re-builds the derived state on every call. |
| Background work outside the reactor | `block_in_pool[T](work, cancel)` with `work: def() raises thin -> T`. Capture-by-reference is impossible because the type is `thin`; data shared with the worker travels via heap-allocated structs whose addresses are read on the worker side. |
| Cross-worker connection migration | `WorkerHandoffPool[N]` — push the fd as an `Int` token, the receiving worker pops and adopts. |
| Cooperative cancellation across threads | `Cancel.cancelled()` — the cell is multi-thread safe. |

## When the closure story changes

When Mojo lifts the runtime-materialisation block on capturing
closures (and / or completes the `unified` path), flare will add
closure-flavored overloads to `Router.{get, post, ...}`, `App.use`,
and the extractor surface **alongside** the existing struct-based
shapes. Nothing existing breaks — the current API stays valid
indefinitely.
