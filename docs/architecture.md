# Architecture

flare is a layered library. Each module imports only from the layers
below it. No circular dependencies, no global state, no hidden runtime.

```
flare.io       BufReader (Readable trait, generic buffered reader)
flare.ws       WebSocket client + server (RFC 6455)
flare.h2       HTTP/2 (planned, v0.6 — h2 over TLS only)
flare.http     HTTP/1.1 client + reactor server + Handler / Router / App
               + extractors + ComptimeRouter + StaticResponse
               + Cancel / CancelHandler (v0.5.0 Step 1)
flare.tls      TLS 1.2/1.3 (OpenSSL); v0.5 adds TlsAcceptor + ALPN
flare.tcp      TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      UdpSocket (IPv4 + IPv6)
flare.dns      getaddrinfo (dual-stack)
flare.net      IpAddr, SocketAddr, RawSocket
flare.runtime  Reactor (kqueue/epoll), TimerWheel, Scheduler,
               num_cpus / default_worker_count, pthread + pinning,
               install_drain_on_sigterm (v0.5.0 Step 1)
```

---

## Reactor + per-connection state machine

A single event loop per worker drives every connection. No
thread-per-connection. No locks on the hot path. The reactor wraps
`kqueue` on macOS and `epoll` on Linux through a thin abstraction
in [`flare/runtime/reactor.mojo`](../flare/runtime/reactor.mojo).

Each accepted connection owns a small state machine in
[`flare/http/_server_reactor_impl.mojo`](../flare/http/_server_reactor_impl.mojo):

```mermaid
stateDiagram-v2
    [*] --> READING : accept + register
    READING --> WRITING : handler returned
    WRITING --> READING : flushed + keep-alive
    WRITING --> CLOSING : flushed + close
    READING --> CLOSING : peer FIN / error / timeout
    WRITING --> CLOSING : peer FIN / error / timeout
    CLOSING --> [*] : unregister + close fd
```

The state machine **does not own** the reactor or the timer wheel. It
exposes `on_readable`, `on_writable`, and `on_timeout` and returns a
small `StepResult` per call telling the reactor how to update its
interest mask, whether to re-arm the idle timer, and whether the
connection is finished. The reactor owns the lifecycle.

A 3-cycle inline fast path in `run_reactor_loop` lets a single
readable event drive the next writable + the next readable in
sequence (without going back through `kqueue.kevent` / `epoll_wait`)
when the buffers permit. This is the single biggest win on the
plaintext keep-alive workload — the syscall overhead is the
dominant per-request cost on flare's hot path.

---

## Request lifecycle

```mermaid
sequenceDiagram
    participant client
    participant kernel as kqueue/epoll
    participant accept as _accept_loop
    participant conn as ConnHandle
    participant cancel as Cancel cell
    participant timers as TimerWheel
    participant handler as Handler.serve

    client->>kernel: SYN
    kernel->>accept: readable on listener fd
    accept->>conn: stream.peer_addr() captured
    accept->>conn: heap-allocate ConnHandle, set_nonblocking
    accept->>kernel: register fd, INTEREST_READ

    client->>kernel: bytes
    kernel->>conn: on_readable
    conn->>conn: parse headers + body
    conn->>cancel: install fresh cell
    conn->>timers: arm request_timeout_ms
    conn->>handler: serve(req, cancel)

    Note over kernel,conn: if peer FIN before response: cancel.flag = PEER_CLOSED
    Note over timers,cancel: if deadline fires:    cancel.flag = TIMEOUT
    Note over conn,cancel: if drain():            cancel.flag = SHUTDOWN

    handler->>conn: Response
    conn->>conn: serialize to write_buf
    conn->>kernel: send (non-blocking)
    kernel->>conn: on_writable for any remainder
    conn->>kernel: keep-alive: re-arm idle, INTEREST_READ
    conn->>kernel: close: unregister, close fd
```

The Cancel cell is a single byte (`0` = live, `1..3` = reason) that
the reactor flips before the handler's next `cancel.cancelled()` poll.
We do not preempt — Mojo can't, and synchronous preemption would
defeat the per-thread invariant. Cooperation is the contract.

---

## Multicore: thread-per-core via SO_REUSEPORT

`HttpServer.serve(handler, num_workers=N)` with `N >= 2` opens N
`SO_REUSEPORT` listeners on N pthread workers. Each worker owns its
own reactor, its own timer wheel, its own per-connection state.
**Shared-nothing.** The kernel load-balances accepted connections
across the listeners.

`pin_cores=True` (default) pins worker `i` to core `i % num_cpus()`
on Linux via `pthread_setaffinity_np`. macOS does not expose CPU
affinity to userspace, so pinning is a no-op there. The upper
bound on `num_workers` is 256, enforced by `Scheduler.start`.

`Scheduler.shutdown` (v0.4.x) and `Scheduler.drain(timeout_ms)`
(v0.5.0 Step 1) coordinate across workers. Drain returns one
`ShutdownReport` per worker — see [`operational-guarantees.md`](operational-guarantees.md).

---

## Timer wheel

[`flare/runtime/timer_wheel.mojo`](../flare/runtime/timer_wheel.mojo)
is a hashed timing wheel with millisecond resolution and a fixed
slot count. Inserts and cancels are O(1) amortised; `advance(now_ms)`
fires every expired entry in slot order. It's the single source of
truth for `idle_timeout_ms`, `write_timeout_ms`, and (v0.5.0 Step 1)
`read_body_timeout_ms`, `handler_timeout_ms`, `request_timeout_ms`.

Resolution: 1 ms tick, 1024 slots, fixed memory. Deadlines below
1 ms round up. This is well below the noise floor of any HTTP
deadline a real service cares about.

---

## What stays out of the reactor

flare deliberately keeps a few things on the application thread, not
the reactor thread:

- **TLS handshake** (today, client only). Handled inline by
  `TlsStream.connect`. v0.5.0 Step 3 adds a non-blocking
  server-side handshake state machine driven by the same
  `on_readable` / `on_writable` calls as HTTP.
- **DNS resolution.** `getaddrinfo` is a blocking call; the
  client uses it pre-connect. The reactor never blocks on it.
- **Long-running handler work.** The current contract is
  synchronous: a slow handler blocks its worker's reactor. v0.5.0
  Step 1 ships a `Cancel` so the *caller* doesn't pay for it; a
  blocking-pool escape hatch lands once the v0.5 story is
  complete (see `.cursor/rules/design-0.5.md` §2.5).

---

## Where to read the code

| Concern | Source |
|---|---|
| Reactor abstraction | [`flare/runtime/reactor.mojo`](../flare/runtime/reactor.mojo) |
| `kqueue` impl | [`flare/runtime/_kqueue.mojo`](../flare/runtime/_kqueue.mojo) |
| `epoll` impl | [`flare/runtime/_epoll.mojo`](../flare/runtime/_epoll.mojo) |
| Timer wheel | [`flare/runtime/timer_wheel.mojo`](../flare/runtime/timer_wheel.mojo) |
| Multicore scheduler | [`flare/runtime/scheduler.mojo`](../flare/runtime/scheduler.mojo) |
| HTTP request parsing | [`flare/http/server.mojo`](../flare/http/server.mojo) |
| HTTP per-conn state machine | [`flare/http/_server_reactor_impl.mojo`](../flare/http/_server_reactor_impl.mojo) |
| `Cancel` cell + `CancelHandler` | [`flare/http/cancel.mojo`](../flare/http/cancel.mojo) (v0.5.0 Step 1) |
| SIGTERM helper | [`flare/runtime/_signal.mojo`](../flare/runtime/_signal.mojo) (v0.5.0 Step 1) |

If you want a one-page tour of each, the layered docstrings on the
public types (`HttpServer`, `Router`, `Handler`, `App`) are the place
to start; they include "Failure modes" sections describing what
raises, what becomes a 4xx vs 5xx, what gets logged, and what never
returns.
