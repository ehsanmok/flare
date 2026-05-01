# Concurrency in flare — what is sound, what is the user's job

flare's reactor is single-threaded per worker. The expensive shared
state lives in three places: per-connection state machines (owned by
one reactor thread), per-worker pools (`Pool[T]`, `Pool[BufferHandle]`,
`Pool[Response]`, etc., scoped to one worker), and a small set of
cross-thread primitives (`Cancel`, `HandoffQueue`, `block_in_pool`'s
heap-handoff) that are explicitly designed for cross-thread use.

This doc is about the third bucket — the cross-thread primitives —
and about the closure / `def`-binding rules in Mojo
`1.0.0b1.dev2026042717` you need to know to use them safely.

## The Mojo closure-binding rules flare relies on

The pinned Mojo nightly distinguishes three function-type annotations:

| Annotation | Meaning | What flare uses it for |
|---|---|---|
| `thin` | No captures. Function-pointer-shaped. Materialises as a runtime value. | Every public `def(Request) raises thin -> Response` in [`flare/http/handler.mojo`](../flare/http/handler.mojo) — `FnHandler`, `FnHandlerCT[F]`. The work argument to [`block_in_pool`](../flare/runtime/blocking.mojo) (`work: def() raises thin -> T`). The pthread `start_routine` thunk shape in [`flare/runtime/_thread.mojo`](../flare/runtime/_thread.mojo). |
| `capturing` | Captures local state. **Cannot be materialised as a runtime value on the pinned nightly** (the compiler emits `"TODO: capturing closures cannot be materialized as runtime values"` if you try). Usable only as a comptime parameter (`[F: def(...) capturing -> ...]`), and even then a method body that calls `F(...)` is silently promoted to `capturing`, which can't satisfy a `Handler` trait method declared without that annotation. | Not used by the v0.6 / v0.7 public surface. The probe entry in [`development.mdc`](../.cursor/rules/development.mdc) § "Mojo-blocked items remaining" tracks the v0.7 re-probe. |
| `unified` | Universal closure type (per [Mojo Closures 2026 forum thread](https://forum.modular.com/t/mojo-closures-2026/3013)). The keyword is accepted in function-type position (`def(Int) raises unified -> Int`), but the conversion machinery is incomplete — `def f(...) raises unified -> Int:` on a declaration site fails with `"use of unknown declaration 'unified'"`. | Not used today; same re-probe entry. |

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
lifetime. There is no work-stealing today. The per-connection state
machine in [`flare/http/_server_reactor_impl.mojo`](../flare/http/_server_reactor_impl.mojo)
mutates without locks because nothing else can reach it. The same
applies to `Pool[T]` instances and the per-worker scheduler state in
[`flare/runtime/scheduler.mojo`](../flare/runtime/scheduler.mojo).

The cross-thread surfaces are an explicit, narrow list:

1. **`Cancel`** — see [`flare/http/cancel.mojo`](../flare/http/cancel.mojo).
   The cell flips from any thread; readers see the flip via a relaxed
   atomic load. The reactor flips it on `PEER_CLOSED` / `TIMEOUT` /
   `SHUTDOWN`; handlers poll. No lock; the cell is a single-byte
   atomic.

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

Mojo `1.0.0b1.dev2026042717` has no compiler-checked notion of state
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
  closure — the v0.6 stdlib's reference-count for these types is
  not multi-thread safe. Pass an `UnsafePointer` and own the
  lifetime explicitly, or convert to `Span[UInt8]` over a
  comptime-stable buffer.
- A `Pool[T]` instance — pools are explicitly per-worker.
- An `UnsafePointer[T, MutExternalOrigin]` reconstructed in the
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

## Why this matters: the audit pattern

flare's release discipline is to **probe every "Mojo blocked"
classification before accepting it, and to write a postmortem in the
commit body when the probe demonstrates a previous classification
was wrong**. This pattern caught:

- v0.5 `block_in_pool` mis-classified as Mojo-blocked (it wasn't —
  pthread per-call works).
- v0.6 macOS `OwnedDLHandle` framed as a Mojo runtime flake (it
  wasn't — function-local handle was being reclaimed by ASAP-
  destruction before its returned function pointer was invoked).

The same audit ran in the other direction for v0.7 closures: the
design speculated that capturing closures had landed; the probe
falsified the claim. The result is the entry in
[`development.mdc`](../.cursor/rules/development.mdc) § "Mojo-blocked
items remaining" and this doc.

## Recommended patterns today

| You want to ... | Use ... |
|---|---|
| A handler that closes over per-app state | `Handler` struct with the state as fields — see [`tests/test_handler.mojo`](../tests/test_handler.mojo) `_Greeter` for the canonical shape. |
| A handler that closes over per-request derived state | A function chain with the state passed explicitly through `Request.params` / `Request.headers`, or a struct that re-builds the derived state on every call. |
| Background work outside the reactor | `block_in_pool[T](work, cancel)` with `work: def() raises thin -> T`. Capture-by-reference is impossible because the type is `thin`; data shared with the worker travels via heap-allocated structs whose addresses are read on the worker side. |
| Cross-worker connection migration | `WorkerHandoffPool[N]` — push the fd as an `Int` token, the receiving worker pops and adopts. |
| Cooperative cancellation across threads | `Cancel.cancelled()` — the cell is multi-thread safe. |

## When the closure story changes

When Mojo lifts the runtime-materialisation block on capturing
closures (and / or completes the `unified` path), flare will land a
v0.7.x patch that adds closure-flavored overloads to
`Router.{get, post, ...}`, `App.use`, and the extractor surface
**alongside** the existing struct-based shapes. Nothing existing
breaks — the v0.6 / v0.7 API stays valid indefinitely.

The re-probe target lives in
[`development.mdc`](../.cursor/rules/development.mdc) § "Mojo-blocked
items remaining"; re-probe on every pinned-nightly bump.
