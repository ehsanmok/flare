# L2: OS-facing abstract machines (NET, RT)

Scope: the parts of flare that sit directly on the operating system. Sockets
and fd ownership, the read and write loops around `send`/`recv`/`writev`,
`BufReader`, `connect_timeout`, the epoll/kqueue reactor, the io_uring rings
and the `UringReactor` wakeup protocol, the timer wheel, the worker handoff
queues, the UDS frame multiplexer, UDP `recvfrom` address decoding, UDS
`sockaddr_un` encoding and decoding, the DNS cache, the buffer pool, and the
blocking-pool thread cap, Happy Eyeballs address ordering, hostname
validation in `resolve`, the UNIX listener's stale-socket takeover and
destructor guard, the batched-UDP wire layouts and receiver buffers
(`udp/batch.mojo`), and the timer wheel's `_jump` firing order and `UInt64`
clock arithmetic. All references are to commit 59bda50.

Every model lives in `Flare/L2_Machine/<Component>.lean` (namespace
`Flare.L2.<Component>`); the aggregate is `Flare/L2_Machine.lean`; the axiom
audit is `Flare/Audit/L2.lean`. The kernel and libc are environment inputs:
either an oracle function (the result of the k-th syscall) or an explicit
Prop hypothesis such as `Flare.Assumptions.SendContract` or
`Flare.L2.Udp.RecvfromFills`. Nothing is an `axiom`.

Totals: 20 model files with 307 theorems, 19 Bugs files (`NET_01`..`NET_11`,
`RT_01`..`RT_08`) with 58 theorems. No `sorry`, `admit` or `axiom`. The audit
prints 141 headline theorems; outside `Flare.Bugs` the footprint is at most
`propext`, `Quot.sound`, `Classical.choice`. Fourteen Bugs theorems use
`native_decide` for concrete traces; the ten audited theorems that rest on
one show the corresponding auxiliary axiom. No model file uses `native_decide` or
`bv_decide` (the io_uring and reactor bit-vector lemmas are proved by
translation to `Nat` and `decide`). Every module builds in a few seconds.

## Components

### Socket fd ownership (`Socket.lean`)

`RawSocket` (flare/net/socket.mojo:143-220) as an object-level machine (one
`fd` field, close count per method) and as an fd-level LTS over one fd
incarnation (number of holders, number of closes). Also the scheduler's
listener teardown (runtime/scheduler.mojo:655-668, 713-725), `_set_timeval_opt`
(net/socket.mojo:481-509) and the accept path (tcp/listener.mojo:165-201,
248-282).

| Lean name | Statement | Status |
|---|---|---|
| `close_idempotent` | A second `close()` issues no `close(2)` and leaves the fd field unchanged. | proved |
| `closes_then_deinit_exactly_once` | Any number of `close()` calls followed by the destructor closes a valid fd exactly once. | proved |
| `fd_closed_once` | In every reachable state each fd incarnation is closed at most once, and exactly once when no object holds it. | proved |
| `copy_would_double_close` | Without the non-`Copyable` restriction two destructors would close the fd twice. | counterexample (design check) |
| `sched_patch_closes_once` | With the scheduler's `fd = -1` patch, any number of stop signals plus teardown close the listener once. | proved |
| `sched_unpatched_double_close` | Without the patch the listener fd number is closed twice. | counterexample (shows the patch is needed; flare has it) |
| `timeval_exact`, `timeval_fits` | `_set_timeval_opt` produces a normalised timeval equal to the millisecond value, with no Int64 overflow. | proved |
| `timeval_negative` | A negative timeout gives a negative `tv_sec`. | proved (note) |
| `accept_nodelay_safe` | Once the accepted fd is wrapped, a `TCP_NODELAY` failure cannot leak it. | proved |

Assumptions: Mojo runs no destructor on a moved-from value. Limitations: one fd
incarnation at a time; kernel fd reuse is modelled as a new incarnation.

### Write and read loops (`WriteLoop.lean`)

`TcpStream.write`/`write_all`/`read_exact` (tcp/stream.mojo:429-519),
`UnixStream.write_all` (uds/stream.mojo:140-163) and `writev_buf_all`
(runtime/iovec.mojo:312-361), each a loop over a syscall oracle with explicit
fuel. `Strong` is the contract "`send` returns `1..len` or an error", `Weak`
(POSIX) also allows 0.

| Lean name | Statement | Status |
|---|---|---|
| `writeAll_terminates_strong` | Under `Strong`, with fuel `total - sent`, `write_all` sends exactly `total` bytes or raises. | proved |
| `writeAll_no_overshoot` | Under `Weak`, `write_all` never counts more than `total` bytes. | proved |
| `udsWriteAll_eq` | The UDS loop equals the TCP loop. | proved |
| `writeAll_livelock_weak` | Under `Weak` with a 0-returning `send`, the loop never terminates. | counterexample (NET-02) |
| `writeAllFixed_terminates_weak` | Raising on a 0 return terminates under `Weak`. | proved |
| `readExact_terminates` | Under `RecvContract`, `read_exact` returns exactly `size` bytes or raises. | proved |
| `writevAll_strong` | Under `Strong` and the caller precondition `total_bytes = Σ len_i`, `writev_buf_all` returns normally only with every byte written; `first` is monotone and bounded. | proved |
| `writevAll_understated`, `writevAll_overstated` | A wrong `total_bytes` makes the loop return early. | counterexample (caller precondition, not filed) |

Limitations: EINTR is folded into the oracle (it only re-asks). Timeouts are
errors.

### BufReader (`BufReader.lean`)

io/buf_reader.mojo:117-266. The `Readable` is a list of chunks; the trait
contract (each read returns `0..cap` bytes) is a hypothesis.

| Lean name | Statement | Status |
|---|---|---|
| `consume_inv` | Consuming one byte keeps `pos + len ≤ cap`. | proved |
| `consume_view` | A returned byte is the head of the remaining stream; EOF leaves it unchanged. | proved |
| `readExact_correct` | `read_exact n` returns the next `n` stream bytes and keeps the invariant. | proved |
| `overlong_read_breaks_inv`, `negative_read_runs_away` | A `Readable` that violates the contract breaks the invariant. | counterexample (outside contract) |

### connect_timeout (`ConnectTimeout.lean`)

tcp/stream.mojo:254-333 (Linux path) as a function of an oracle record of
syscall results.

| Lean name | Statement | Status |
|---|---|---|
| `flags_restored` | If `F_GETFL` succeeded, the flag writes are exactly set-nonblocking then restore, on every path. | proved |
| `never_left_nonblocking` | The socket never leaves `connect_timeout` in non-blocking mode. | proved |
| `poll_eintr_raises` | EINTR from `poll` is not retried; it raises. | proved (note) |
| `getsockopt_failure_is_success` | A failing `getsockopt(SO_ERROR)` is read as a successful connect. | proved (note) |

### Reactor bookkeeping and epoll/kqueue (`Reactor.lean`)

runtime/reactor.mojo:112-135, 290-479, 586-665. Bookkeeping map fd ↦ token
next to the kernel interest list; every kernel call has an environment-chosen
outcome.

| Lean name | Statement | Status |
|---|---|---|
| `register_refines`, `unregister_refines`, `modify_keeps_token` | The operations refine finite-map insert/erase/keep on success. | proved |
| `unregister_always_removes` | `unregister` removes the entry whatever the kernel returned. | proved |
| `agree_register`, `agree_unregister`, `agree_close` | Bookkeeping and kernel interest list stay in agreement. | proved |
| `fd_reuse_safe` | After close then unregister (DEL fails with EBADF), a reused fd number registers with the new token. | proved |
| `raising_unregister_rejects_reuse` | Had `unregister` raised on the failed DEL, the reused fd would be rejected as a duplicate. | counterexample (shows the design is needed) |
| `read_interest_has_rdhup`, `roundtrip_rw`, `readable_iff_in`, `writable_iff_out` | The interest/event bit translations are correct. | proved |
| `dispatch_rw_equiv` | When FIN marks a socket readable, OR-ing the events of a token gives the same readable/writable set on epoll and kqueue. | proved |
| `error_differs`, `kqueue_counts_filters` | An error-only condition is ERROR on epoll and invisible on kqueue; a socket ready both ways is one epoll event but two kqueue events. | proved (documented differences) |

### io_uring rings and provided-buffer ring (`IoUring.lean`)

runtime/io_uring_driver.mojo:297-671 and runtime/_pbuf_ring.mojo:61-97, with
`UInt32` wrapping counters exactly as in Mojo. `PowMask m` says the mask is
`2^k - 1` with `k ≤ 15` (`IORING_MAX_ENTRIES`); `powMask_bitwise` checks this
agrees with the bitwise test `m &&& (m + 1) = 0` for every such `k`. The
kernel is an interleaved second party (`sqLTS`).

| Lean name | Statement | Status |
|---|---|---|
| `ringDistance_true` | Wrapping `tail - head` is the true occupancy whenever the unbounded counters differ by less than 2^32. | proved |
| `oldDistance_wrong` | The earlier Int-widening distance was wrong after wrap (flare no longer uses it). | counterexample (history) |
| `sq_reachable_inv` | Every reachable SQ state satisfies `ktail - head ≤ ltail - head ≤ entries`. | proved |
| `live_slots_distinct`, `nextSqe_fresh` | Live SQEs occupy distinct slots and `next_sqe` never hands out a live slot, for all counter values. | proved |
| `submit_count` | `to_submit` is the number of committed-but-unsubmitted SQEs. | proved |
| `reap_count`, `reap_none_iff`, `reap_keeps_bound` | Reaping decrements the CQ count by one and keeps the kernel bound. | proved |
| `pbufIdx_wrap` | The u16 provided-buffer tail wraps consistently with the power-of-two ring mask. | proved |
| `pbuf_add_preserves_tail` | `_pbuf_ring_add` never writes the bytes where the shared tail lives. | proved |

Assumption: `KernelCQBound` (the kernel never posts more than `cq_entries`
unreaped CQEs).

### UringReactor wakeup (`UringWakeup.lean`)

runtime/uring_reactor.mojo:739-946: the lazy arming of the eventfd read and
the three poll phases. Assumption `KernelConsumesAll` (an `io_uring_enter`
consumes all submitted SQEs).

| Lean name | Statement | Status |
|---|---|---|
| `poll_inv` | Both the flare and the fixed `poll` keep the invariant. | proved |
| `pollFixed_never_blocks_unarmed` | With a re-arm after phase 1, `poll` never blocks without the wakeup read in flight. | proved |
| `Flare.Bugs.RT_03.poll_blocks_unarmed` | flare's `poll` can block unarmed with a wakeup pending. | counterexample (RT-03) |
| `minComplete_weakened` | `poll(min_complete = 2)` returns 1 CQE without blocking. | proved (note; all callers pass 1) |

### Timer wheel (`TimerWheel.lean`)

runtime/timer_wheel.mojo:102-333: 512 slots, overflow list, lazy cancel,
tick-by-tick `advance` and the `_jump` path. The spec is the set of active
timers (`Act s id e`). `Inv` says: slot < 512; every wheel entry is due within
the next rotation in the right slot; every overflow entry is due at or after
the next slot-0 boundary; every active entry is in the wheel or overflow; ids
are fresh.

| Lean name | Statement | Status |
|---|---|---|
| `inv_init`, `inv_schedule`, `inv_cancel`, `inv_run` | The invariant holds initially and after every operation sequence. | proved |
| `schedule_spec` | `schedule` returns id `nextId + 1 ≥ 1` and adds exactly that active timer, due at `tick + max(1, after)`. | proved |
| `cancel_spec` | `cancel` deactivates exactly the given timer and returns whether it was active. | proved |
| `advance_spec` | `advance now` fires exactly the active timers due by `now`, each once, leaves the rest active, and moves the tick to `max tick now`. | proved |
| `advance_no_early_fire`, `advance_no_late_fire` | No timer fires before its due time; none due by `now` survives `advance now`. | proved |
| `advance_backwards_noop` | `advance` to an earlier time fires nothing and changes nothing. | proved |
| `jump_equiv_ticks` | The `_jump` path fires a permutation of what ticking would fire and ends in the same active set. | proved |
| `cancel_never_fires`, `run_nodup` | A cancelled timer never fires; no timer fires twice over any run. | proved |
| `nextFire_lower_bound_no_overflow` | With an empty overflow list, `next_fire_ms` is a lower bound on every active timer. | proved |
| `nextFireFixed_lower_bound` | With the fix, `next_fire_ms` is a lower bound in every reachable state. | proved |
| `Flare.Bugs.RT_01.nextFire_not_lower_bound` | flare's hint exceeds a timer's fire time once the wheel has advanced. | counterexample (RT-01) |

Limitations: time is `Nat` here; `TimerWheelTime.lean` (below) relates it to
flare's `UInt64` and fixes the `_jump` firing order. Fired ids are recorded,
not tokens (tokens are carried unchanged).

### Timer wheel: `_jump` firing order and `UInt64` time (`TimerWheelTime.lean`)

runtime/timer_wheel.mojo:119-144, 169-333. The `…64` definitions redo every
time computation of `schedule`, `advance` (tick loop and `_jump`) and
`next_fire_ms` with wrapping `UInt64` arithmetic and `UInt64` comparisons,
over the same state shape. `ClockBound` is a Prop hypothesis on a trace:
every `now_ms` passed to `advance` is below 2^63 ms (about 292 million years
of `monotonic_ms()`), and every `after_ms` is a Mojo `Int`, so below 2^63.

| Lean name | Statement | Status |
|---|---|---|
| `jump_fire_order` | `_jump` reports `W ++ O`: `W` is a sublist of the wheel ids in slot order, sorted by fire time; `O` is a sublist of the overflow list in list order. This is the documented contract (timer_wheel.mojo:190-191). | proved |
| `jump_not_sorted` | From `init 700`, schedule 512, advance to 1000, schedule 400, advance to 2000: `_jump` reports `[2, 1]` although timer 1 is due at 1212 and timer 2 at 1400. | proved (note) |
| `ticks_order_example` | Ticking the same state one millisecond at a time reports `[1, 2]`. | proved (note) |
| `advance64_eq`, `jump64_eq`, `ticks64_eq` | With every stored time below 2^64, the `UInt64` `advance` equals the `Nat` one for every `UInt64` reading of `now`. | proved |
| `schedule64_eq`, `nextFire64_eq` | `schedule` and `next_fire_ms` agree when `tick + delay` (resp. `tick + 0xFFFFFFFF`) fits in 64 bits. | proved |
| `run64_eq`, `run64_init` | Under `ClockBound`, the `UInt64` and `Nat` machines produce the same state and fired list on every trace (from any state with clock below 2^63, in particular `init now`). | proved |
| `nextFire64_wraps` | Without a bound, at `tick = 2^64 - 1` with no timers the `UInt64` hint wraps to `0xFFFFFFFE`, below `now`. | proved (note; needs a clock near 2^64) |

### Worker handoff (`Handoff.lean`)

runtime/handoff.mojo:150-195 (`_HandoffQueue`) and 312-365
(`peek_idle_worker`, `choose_handoff_target`).

| Lean name | Statement | Status |
|---|---|---|
| `push_refines`, `pop_refines`, `drain_refines` | The ring buffer refines a bounded FIFO list. | proved |
| `cap_zero_safe` | A capacity-0 queue never divides by zero. | proved |
| `chooseTarget_spec` | The target is -1 or a peer other than the caller whose load is at least `steal_threshold` below the local load. | proved |
| `peekFixed_below_capacity` | With the fix, `peek_idle_worker` returns -1 or a peer strictly below capacity, and -1 only when every peer is full. | proved |
| `Flare.Bugs.RT_04.peek_returns_full_peer` | flare returns a full peer. | counterexample (RT-04) |

### UDS frame multiplexer (`FrameMux.lean`)

uds/frame_mux.mojo:97-280: the frame codec, `FrameDemux.feed` reassembly,
routing to per-stream inboxes, id allocation.

| Lean name | Statement | Status |
|---|---|---|
| `decode_encode` | Codec round trip for payloads up to `MAX_FRAME_PAYLOAD`. | proved |
| `drain_sound`, `drain_complete` | The parse loop splits its input into exactly the encoded frames plus an incomplete residual. | proved |
| `feed_chunking` | `feed` is chunking independent. | proved |
| `routeAll_eq`, `poll_fifo` | Each stream gets exactly its frames, in arrival order. | proved |
| `nextId_injective`, `nextId_wraps` | Ids are unique for the first 2^64 - 1 allocations; the next one wraps to 0. | proved |
| `feedM_error_keeps_routed` | After a protocol error the already routed bytes stay buffered. | proved (NET-04 mechanism) |
| `feedMFixed_error_stuck` | With the fix, every feed after a protocol error raises and routes nothing. | proved |

### UDP recvfrom address decoding (`Udp.lean`)

udp/socket.mojo:279-283, 330-334 and net/_libc.mojo:303-397. Hypothesis
`RecvfromFills bufLen saLen sa stack mem`: the kernel copies
`min(bufLen, saLen)` bytes of the sender sockaddr into the buffer and leaves
memory past the buffer untouched.

| Lean name | Statement | Status |
|---|---|---|
| `impl_reads_past_buffer` | The IPv6 decoder reads offsets 16..23 of a 16-byte buffer. | proved |
| `impl_addr6` | With the 16-byte buffer, the decoded IPv6 address is 8 bytes of the sender plus 8 bytes of stack. | proved |
| `fixed_addr6` | With a 28-byte buffer the decoded address and port are the sender's. | proved |
| `addr4_ok` | IPv4 senders decode correctly with any buffer of at least 16 bytes. | proved |

### UDS sockaddr_un (`Uds.lean`)

uds/_libc.mojo:43-133: `fill_sockaddr_un` and `read_path_from_sockaddr_un`,
for Linux (108-byte path) and macOS (104).

| Lean name | Statement | Status |
|---|---|---|
| `fill_len_le` | The returned `addrlen` fits `SOCKADDR_UN_SIZE` and equals the bytes written. | proved |
| `readPathFixed_fill` | Decoding the bytes as UTF-8 returns the bound path, whatever follows in the buffer. | proved |
| `readPath_fill_iff_ascii` | flare's Latin-1 decoding returns the bound path if and only if it is ASCII. | proved (NET-06) |

### DNS cache (`DnsCache.lean`)

dns/cache.mojo:69-142. The dictionary is an insertion-ordered association
list; host keys are abstracted to `Nat`; times are `Int64` with wrapping `+`;
the resolver always succeeds.

| Lean name | Statement | Status |
|---|---|---|
| `huge_ttl_expiry_wraps` | With `ttl = Int.MAX` and `now ≥ 1`, the stored expiry is below every non-negative time. | proved (NET-03) |
| `storeFixed_size_bound` | The fixed store keeps `size ≤ max_entries`. | proved |
| `storeFixed_hits_within_ttl` | After the fixed store at `now ≥ 0`, any lookup strictly inside the TTL window is a hit. | proved |
| `key_fqdn_case`, `key_not_idempotent` | `_key` merges case and one trailing dot, but is not idempotent (`a..` vs `a.`). | proved (note) |

### Buffer pool (`BufferPool.lean`)

runtime/buffer_pool.mojo:130-364. A handle is its capacity and class tag; the
caller may hand any handle to `release` (the fields and constructor are
public).

| Lean name | Statement | Status |
|---|---|---|
| `classIndex_fits`, `classIndex_least` | The class chosen is the smallest one that fits the request. | proved |
| `bounded_acquire`, `bounded_release` | No bucket ever holds more than `class_capacity` handles (flare and fix). | proved |
| `releaseFixed_preserves_capacity` | With the fixed release, `acquire n` returns capacity at least `n` after any history. | proved |
| `Flare.Bugs.RT_05.acquire_after_shrunk_release` | flare can return capacity 0 for `acquire(60000)`. | counterexample (RT-05) |

### Blocking-pool thread cap (`Blocking.lean`)

runtime/blocking.mojo:123-206: the named semaphore as `count` plus `held`
slots; whether each `sem_open` succeeds is an environment input. Releases are
paired with earlier successful acquires.

| Lean name | Statement | Status |
|---|---|---|
| `paired_cap_invariant` | If every `sem_open` succeeds, `count + held = 32` throughout, so at most 32 slots are held. | proved |
| `fixed_cap_invariant` | With a fail-closed acquire, `count + held ≤ 32` under any pattern of `sem_open` failures. | proved |
| `Flare.Bugs.RT_06.persistentFailOpen_unbounded` | If `sem_open` always fails, `n` acquires succeed for every `n`. | counterexample (RT-06) |
| `Flare.Bugs.RT_07.failOpen_breaks_cap` | One failed-`sem_open` acquire and its normal release let 33 slots be held. | counterexample (RT-07) |
| `Flare.Bugs.RT_08.linux_failure_crashes` | With glibc's `SEM_FAILED` (NULL), a failed `sem_open` passes the `== -1` test and both acquire and release crash. | counterexample (RT-08) |
| `Flare.Bugs.RT_08.fixed_never_crashes` | Testing against the platform's `SEM_FAILED` never crashes on either platform; `fixed_agrees`: it changes nothing on success or on macOS. | proved |

### Happy Eyeballs ordering (`HappyEyeballs.lean`)

dns/async_resolve.mojo:154-177, `order_happy_eyeballs`. Addresses are an
abstract type with a family test (`IpAddr.is_v6`).

| Lean name | Statement | Status |
|---|---|---|
| `order_eq` | The two Mojo loops compute the interleaving of the IPv6 and IPv4 sublists. | proved |
| `order_perm` | The output is a permutation of the input. | proved |
| `order_filter_v6`, `order_filter_v4` | Each family keeps its relative order. | proved |
| `order_get_even`, `order_get_odd` | Positions alternate IPv6, IPv4 over the first `2 * min n6 n4` slots. | proved |
| `orderFixed_head`, `orderFixed_perm` | The fix keeps the input's first address first and is still a permutation. | proved |
| `Flare.Bugs.NET_10.order_breaks_spec` | `[v4, v6, v4]` comes out as `[v6, v4, v4]`. | counterexample (NET-10) |

### Batched UDP layouts and receiver buffers (`UdpBatch.lean`)

udp/batch.mojo:66-92, 176-206, 399-414 (Linux only). A C struct layout
calculator (natural alignment, LP64) and a model of the kernel's control
message walk (`__CMSG_FIRSTHDR`, `__cmsg_nxthdr`, `CMSG_OK` in
include/linux/socket.h, consumed by `__udp_cmsg_send` in net/ipv4/udp.c).

| Lean name | Statement | Status |
|---|---|---|
| `layout_constants` | Every hard-coded size and offset (`iovec` 16, `msghdr` 56 with its field offsets, `mmsghdr` 64 with `msg_len` at 56, `cmsghdr` 16) is the C layout. | proved |
| `cmsg_constants` | `CMSG_LEN(2) = 18`, `CMSG_SPACE(2) = 24`, `CMSG_DATA` at 16; the 28-byte name slot fits `sockaddr_in6` and `sockaddr_in`. | proved |
| `gso_walk_18`, `gso_walk_24`, `gso_seg` | With `msg_controllen` 18 (flare) or 24, the kernel walk finds exactly one `(SOL_UDP, UDP_SEGMENT)` header and reads back the segment size. | proved |
| `slot_in_bounds`, `slots_disjoint` | With exact arithmetic every receive slot lies inside the `capacity * max_payload` region and slots are disjoint. | proved |
| `allocSize_fixed`, `covers_fixed` | With `capacity ≤ Int.MAX / max_payload`, the 64-bit size is exact and covers every slot. | proved |
| `Flare.Bugs.NET_11.allocSize_wraps` | `capacity = 16, max_payload = 2^60` passes the checks and the size wraps to 0. | counterexample (NET-11) |

### Hostname validation (`Hostname.lean`)

dns/resolver.mojo:68-107, the checks `resolve` runs before `getaddrinfo`.
The spec is the documented one (resolver.mojo:71-79): no NUL, CR, LF or `@`,
labels of at most 63 bytes, and at most 253 bytes not counting one trailing
root dot (RFC 1035 §2.3.4 bounds the wire form at 255 octets).

| Lean name | Statement | Status |
|---|---|---|
| `scan_ok_iff` | The per-byte loop accepts exactly when no forbidden byte occurs and every label is at most 63 bytes. | proved |
| `validate_sound` | flare never accepts a name that breaks the documented rules. | proved |
| `validate_gap` | The only valid names flare rejects are 254 bytes long and end in `.`. | proved (NET-08) |
| `validateFixed_iff` | The fixed check accepts exactly the valid names. | proved |
| `truncChars_wf`, `tooLongTailFixed_wf` | Cutting at a character boundary keeps the error text well-formed UTF-8 and quotes at most 20 bytes. | proved |
| `Flare.Bugs.NET_09.message_not_wf` | A well-formed 261-byte host gives an error text that is not well-formed. | counterexample (NET-09) |

### UNIX listener takeover and destructor guard (`UdsListener.lean`)

uds/listener.mojo:72-184. `bind_with_options(unlink_existing=True)` lstat's
the path, probes a socket with `UnixStream.connect` and unlinks it as stale
when the probe fails; `__deinit__` unlinks only if the path still names the
socket file whose `(dev, ino)` was recorded after `bind`. What `connect(2)`
may return is a hypothesis (`ConnectFacts`): `ECONNREFUSED` only when nobody
listens, success when somebody listens and the caller may write the file.

| Lean name | Statement | Status |
|---|---|---|
| `takeover_unlinks_live` | A live listener whose socket file the caller may not write (probe `EACCES`) is unlinked and taken over. | proved (NET-07) |
| `prep_agrees` | flare and the fix agree whenever the probe succeeds or is refused. | proved |
| `prepFixed_safe` | The fix unlinks only after a refusal, so never a live socket, and still takes over stale ones. | proved |
| `deinit_spec` | Without interleaving, the destructor unlinks exactly when the path still names its own socket. | proved |
| `deinit_no_record`, `deinit_no_cleanup` | No recorded inode, or `cleanup_path=False`: the destructor never unlinks. | proved |
| `deinit_race` | Another process binding the path between `close` and `lstat` and getting the freed inode passes the check. | proved (note) |

## Findings

Repro status below is from runs on macOS arm64 in this session, and, where
stated, in the Linux container of `formal/repro/linux.sh` (Ubuntu 24.04,
native arm64). Every repro was run at least three times per platform with the
same verdict. "Flip" means the minimal fix was applied to the single flare
file, the repro rerun, and the file restored: on the host with `git checkout`
(`git status --short flare/` empty after each), in the container by copying
the file back from the read-only host mount.

Three latent bugs (NET-02, NET-05, RT-02) need a libc call to return
something Linux and macOS never return on these sockets. Their repros inject
the result: each writes a small C interposer for the one call (`send`,
`inet_ntop`, `writev`), compiles it with `cc`, `mojo build`s itself and reruns
the binary with `DYLD_INSERT_LIBRARIES` (macOS, `__DATA,__interpose`) or
`LD_PRELOAD` (Linux, `dlsym(RTLD_NEXT)`). The fault is armed by an environment
variable that the repro sets only around the call under test, and the
interposer counts its hits, so a repro whose fault was never reached prints
`inconclusive:` and fails instead of passing. The `mojo` JIT did not route
these calls through the interposer on either platform (on Linux the preloaded
library is loaded but the JIT-bound `writev` bypasses it), hence the build
step. On Linux the conda linker's glibc stubs are older than the versions
Mojo's runtime libraries reference, so the build passes
`-Xlinker --allow-shlib-undefined`; the real glibc resolves them at run
time.

### NET-01: `UdpSocket.recv_from` reports the wrong sender for IPv6 peers

Severity: high. Every datagram from an IPv6 peer reports a wrong address, so a
server that replies to the sender replies to the wrong host, and the decoder
reads 8 bytes of stack beyond the buffer.
Spec: POSIX `recvfrom(2)` stores the sender in `src_addr`, truncated to
`*addrlen`; `recv_from` must return that sender.
What goes wrong: udp/socket.mojo:279-283 and 330-334 pass a 16-byte buffer
and `addrlen = 16` on every socket. The kernel writes only 16 of the 28 bytes
of a `sockaddr_in6`; `_read_ipv6_from_sockaddr` (net/_libc.mojo:366-397)
reads `sin6_addr` at offsets 8..23.
Lean: `Flare.Bugs.NET_01.recvFrom_ipv6_wrong_sender` (for the sender
`[::1]` and any stack byte 23 other than 1, the decoded address differs),
`reads_past_buffer`. Fix: allocate and pass `SOCKADDR_IN6_SIZE`;
`Flare.Bugs.NET_01.recvFromFixed_correct`.
Repro: `formal/repro/NET-01_udp_recvfrom_ipv6_sender.mojo`, observed
`BUG REPRODUCED: recv_from reported sender [::307:0:0:0]:52925 but the datagram came from [::1]:52925`
(the wrong half is stack contents and varies between runs).
Flip: `OK: recv_from reported the IPv6 sender [::1]:52884`, exit 0.

### NET-02: `write_all` livelocks if `send` returns 0

Severity: low (latent). POSIX allows `send` to return 0 for a non-empty
buffer; Linux and macOS do not do so on blocking TCP or Unix stream sockets,
so the repro injects it.
Spec: `write_all` writes every byte or raises.
What goes wrong: tcp/stream.mojo:497-519 and uds/stream.mojo:156-163 add the
return value to the progress counter without checking for 0.
Lean: `Flare.Bugs.NET_02.writeAll_livelock`. Fix: raise on a 0 return;
`writeAllFixed_terminates`.
Repro: `formal/repro/NET-02_write_all_zero_send_livelock.mojo` (PLATFORM any,
fault injection: `send` returns 0 for its first 1000 calls, then fails with
EIO), observed on macOS and Linux (3/3 each)
`BUG REPRODUCED: write_all of 100 bytes called send 1000 times while send returned 0 (no progress) and only stopped when the injected send failed with EIO: NetworkError(errno 5): Input/output error (send)`.
Flip (raise `NetworkError` when `write` returns 0 in `TcpStream.write_all`), on
macOS and Linux:
`OK: write_all raised after send returned 0 (send called 1 time(s)): NetworkError: send returned 0 (write_all)`, exit 0.

### NET-03: `DnsCache` with a very large TTL never serves a hit

Severity: low. Caching silently stops for the "cache forever" setting
(`ttl_ms = Int.MAX`, or any TTL with `now + ttl > Int.MAX`); answers stay
correct, every lookup goes to `getaddrinfo`.
Spec: an entry is served until `ttl_ms` has elapsed; the cache holds at most
`max_entries` hosts.
What goes wrong: dns/cache.mojo:117-119 computes `now + ttl_ms` with wrapping
`Int` addition, so the expiry is negative and every entry is born expired.
Saturating the expiry alone would expose a second defect: the eviction scan
(:99-106) starts at `oldest_at = Int.MAX` with a strict `<`, so entries
expiring at `Int.MAX` are never evicted and the cache grows past
`max_entries`. flare already reaches that when `now + ttl = Int.MAX` exactly
(`store_exceeds_max_at_INT_MAX`, at `now = 0`), and
`saturation_alone_exceeds_max` shows the half-fix makes it the common case.
Lean: `Flare.Bugs.NET_03.huge_ttl_never_hits` (all `now ≥ 1`, `now' ≥ 0`),
`huge_ttl_trace`. Fix: saturate the expiry and use `<=` in the scan;
`storeFixed_hits_within_ttl`, `storeFixed_size_bound`.
Repro: `formal/repro/NET-03_dns_cache_ttl_overflow.mojo`, observed
`BUG REPRODUCED: DnsCache(ttl_ms=Int.MAX) resolved 2 times with 0 hits for two lookups of the same host`.
Flip (both changes): `OK: second lookup served from cache`, exit 0.

### NET-04: `FrameDemux.feed` re-delivers frames after a protocol error

Severity: medium. A frame is delivered twice to its stream if a later frame in
the same feed is malformed and the caller feeds again (for example
`UpstreamChunkSource.next_chunk` retried after the error).
Spec: every complete frame on the wire reaches its inbox exactly once.
What goes wrong: uds/frame_mux.mojo:176-207 routes frames while advancing a
local `consumed` and compacts only after the loop; the oversize-header raise
skips the compaction.
Lean: `Flare.Bugs.NET_04.feed_after_error_duplicates`. Fix: compact before
raising; `feedFixed_no_duplicates`.
Repro: `formal/repro/NET-04_frame_demux_redelivers_after_error.mojo`, observed
`BUG REPRODUCED: one CHUNK frame on the wire, stream 5 has 2 queued frames after the protocol error and one more feed()`.
Flip: `OK: stream 5 has exactly one queued frame`, exit 0.

### NET-05: accepted fd leaks if the peer address fails to decode

Severity: info (latent; reproduced by fault injection). Spec: once
`accept(2)` returns an fd, a `TcpStream` owns it or it is closed before the
error propagates.
What goes wrong: tcp/listener.mojo:183-201 and 265-282 decode the peer
address before wrapping `client_fd`; a raise there leaks the fd. The decode
cannot raise in practice: unknown families fall through to the AF_INET branch
(net/socket.mojo:561-585) and `inet_ntop` does not fail for AF_INET/AF_INET6
with flare's buffers.
Lean: `Flare.Bugs.NET_05.accept_leaks_on_decode_error`. Fix: wrap first,
then decode; `acceptFixed_spec`, `acceptFixed_agrees` (unchanged success path).
Repro: `formal/repro/NET-05_accept_fd_leak_on_decode_error.mojo` (PLATFORM any,
fault injection: `inet_ntop` returns NULL with ENOSPC, armed only around
`accept()`; the repro learns the lowest free fd before `accept` and checks it
with `fcntl` and `getpeername` afterwards), observed on macOS (3/3)
`BUG REPRODUCED: accept raised ( inet_ntop failed: errno No space left on device ) but the accepted fd 8 is still open and connected to the client (peer port 60834 ); nothing owns it, so it leaks`
and on Linux (3/3) the same line with fd 7.
Flip (construct the `RawSocket` before decoding, then set its family), on
macOS and Linux:
`OK: accept raised ( inet_ntop failed: errno No space left on device ) and the accepted fd 8 was closed`
(fd 7 on Linux), exit 0.

### NET-06: `queried_local_path()` garbles non-ASCII Unix socket paths

Severity: low. `queried_local_path` is mainly a test helper; `local_path`
returns the stored string and is unaffected.
Spec: decoding the `sockaddr_un` written for `path` returns `path`.
What goes wrong: uds/_libc.mojo:128-133 appends `chr(Int(b))` per byte, i.e.
decodes Latin-1 and re-encodes every byte `≥ 0x80` as two UTF-8 bytes.
Lean: `Flare.Bugs.NET_06.decode_encode_not_id` ("é" reads back as "Ã©"),
`roundtrip_iff_ascii`. Fix: collect the bytes and build the `String` as UTF-8;
`decodeFixed_encode`.
Repro: `formal/repro/NET-06_uds_queried_path_latin1.mojo`, observed
`BUG REPRODUCED: bound /tmp/flare_net06_é.sock ( 24 bytes) but queried_local_path() returned /tmp/flare_net06_Ã©.sock ( 26 bytes)`.
Flip: `OK: queried_local_path() round-trips /tmp/flare_net06_é.sock`, exit 0.

### NET-07: `UnixListener.bind` unlinks a live socket when the probe fails with `EACCES`

Severity: medium. A second process that may not write the first server's
socket file (another user's mode-0600 socket in a shared, writable directory,
or a mode-0 socket) silently takes the path over; the first server keeps
running but stops receiving connections.
Spec (listener.mojo:146-153): `unlink_existing` removes "a stale socket at
`path` ...: one no process is listening on. A live socket raises
`AddressInUse`".
What goes wrong: listener.mojo:174-184 probes liveness with
`UnixStream.connect(path)` inside `try: ... except: pass`, so every probe
failure counts as stale, including `EACCES`, which says nothing about
liveness.
Lean: `Flare.Bugs.NET_07.takeover_unlinks_live`. Fix: unlink only after
`ConnectionRefused` (`ECONNREFUSED` or `ENOENT`) and raise `AddressInUse`
otherwise; `prepFixed_safe`.
Repro: `formal/repro/NET-07_uds_takeover_unlinks_live_socket.mojo` (macOS
only: on Linux the container runs as root, which bypasses the permission
check), observed
`BUG REPRODUCED: second bind() unlinked the live listener's socket file (its probe failed with EACCES) and bound the path itself`.
Flip: `OK: second bind() refused while the first listener is live: AddressInUse: /tmp/flare_net07.sock`, exit 0.

### NET-08: `resolve` rejects valid 254-byte absolute hostnames

Severity: low. Only the absolute spelling of a maximal-length name is
affected; the same name without the trailing dot resolves.
Spec: the rule flare cites, RFC 1035 §2.3.4, allows 253 text bytes plus an
optional root dot.
What goes wrong: resolver.mojo:80-82 compares the raw byte length with 253.
`validate_gap` shows this is the only valid input flare rejects.
Lean: `Flare.Bugs.NET_08.valid_but_rejected` (63+1+63+1+63+1+61+1 bytes).
Fix: compare the length without one trailing `.`; `validateFixed_spec`.
Repro: `formal/repro/NET-08_hostname_trailing_dot_too_long.mojo`, observed
`BUG REPRODUCED: 254-byte absolute name (253 + root dot) rejected: AddressParseError: invalid address 'hostname too long (max 253 chars): ...'`.
Flip: `OK: name passed validation; resolver said: DnsError(...)` (the name
reaches `getaddrinfo`, which then fails to resolve it), exit 0.

### NET-09: the "hostname too long" error cuts a UTF-8 character in half

Severity: low. The error text of a rejected over-long name can hold an
invalid UTF-8 sequence inside a Mojo `String`, which assumes well-formed
UTF-8.
Spec: an error built from a well-formed host is well-formed UTF-8.
What goes wrong: resolver.mojo:82-87 quotes
`String(unsafe_from_utf8=host_bytes[:20])`; byte 20 can fall inside a
multi-byte character.
Lean: `Flare.Bugs.NET_09.message_not_wf` (19 × `a`, `é`, 240 × `a`: the
text holds `C3` followed by the `E2 80 A6` of "…"). Fix: quote whole
characters only; `fixed_wf`.
Repro: `formal/repro/NET-09_hostname_error_splits_utf8.mojo`, observed
`BUG REPRODUCED: error text is not valid UTF-8; its non-ASCII bytes are C3 E2 80 A6`.
Flip (cut at the last character boundary at or before byte 20):
`OK: error text is valid UTF-8`, exit 0.

### NET-10: `order_happy_eyeballs` always tries IPv6 first

Severity: low. When the resolver ranks IPv4 first (RFC 6724 rules 1-2, for
example on a host without a usable IPv6 route), the first connection attempt
goes to an address the OS ranked lower, and the dialer pays one attempt
delay before trying the preferred one.
Spec: RFC 8305 §4, which the function's name and docstring cite: the
interleaving keeps the first address of the sorted list first ("Whichever
address family is first in the list should be followed by an address of the
other address family").
What goes wrong: async_resolve.mojo:162-177 splits by family and always
emits the IPv6 sublist first. The docstring itself documents
`v6[0], v4[0], ...`, so this is a gap between flare and the RFC it cites,
not between the code and its own docs. Order within each family and the
permutation property hold (`order_perm`, `order_filter_v6`,
`order_filter_v4`).
Lean: `Flare.Bugs.NET_10.order_breaks_spec`. Fix: start with the family of
`addrs[0]`; `orderFixed_spec`, `orderFixed_perm'`.
Repro: `formal/repro/NET-10_happy_eyeballs_ignores_preferred_family.mojo`,
observed
`BUG REPRODUCED: input starts with 192.0.2.1 but order_happy_eyeballs returned 2001:db8::1 192.0.2.1 192.0.2.2`.
Flip: `OK: preferred first address kept first: 192.0.2.1 2001:db8::1 192.0.2.2`, exit 0.

### RT-01: `TimerWheel.next_fire_ms` overshoots when only overflow timers remain

Severity: low. The reactor caps its poll at 100 ms
(http/_reactor/lifecycle.mojo:31-47), which bounds the lateness in flare's own
servers; other users of the hint can sleep up to 511 ms past a timer.
Spec (timer_wheel.mojo:320-323): the result "is never later than the true
next fire, so a timer can never be missed".
What goes wrong: with no wheel slot occupied and a non-empty overflow list the
hint is `tick + 512`, but overflow timers are promoted at the next slot-0
boundary `tick + (512 - slot)` and can fire there.
Lean: `Flare.Bugs.RT_01.nextFire_not_lower_bound` (timer due at 512, hint
1012 at t = 500). Fix: cap the scan and the fallback at `512 - slot` when
overflow is non-empty; `nextFireFixed_lower_bound` for every state satisfying
the wheel invariant. flare is correct when the overflow list is empty
(`nextFire_ok_without_overflow`).
Repro: `formal/repro/RT-01_timer_next_fire_overflow_hint.mojo`, observed
`BUG REPRODUCED: next_fire_ms() = 1012 at now=500 but the timer fires at 512`.
Flip: `OK: next_fire_ms() = 512 <= actual fire time 512`, exit 0.

### RT-02: `writev_buf_all` returns normally after a short write

Severity: low (latent). Spec: a normal return means every byte was written.
What goes wrong: runtime/iovec.mojo:340-341 returns on `sent <= 0`;
`writev_buf` already raises on -1, so this is `writev` returning 0 with bytes
queued, and the caller is told everything was sent. Linux and macOS do not
return 0 from `writev` on a socket with a non-empty iovec, so the repro
injects it.
Lean: `Flare.Bugs.RT_02.writev_silent_short_write`. Fix: raise on 0;
`writevAllFixed_spec` (for every oracle).
Repro: `formal/repro/RT-02_writev_all_silent_short_write.mojo` (PLATFORM any,
fault injection: `writev` returns 0), observed on macOS and Linux (3/3 each)
`BUG REPRODUCED: writev_buf_all(total_bytes=100) returned normally after writev returned 0; 0 of 100 bytes were written and iovec 0 still holds 100 bytes`.
Flip (raise `NetworkError` on `sent <= 0`), on macOS and Linux:
`OK: writev_buf_all raised after writev returned 0: NetworkError: writev returned 0 (writev_buf_all)`, exit 0.

### RT-03: `UringReactor.poll` can block with no wakeup read armed

Severity: medium (Linux io_uring backend only). A cross-thread `wakeup()` is
not seen until an unrelated completion arrives.
Spec: whenever `poll` may block in phase 3, the eventfd read is in flight.
What goes wrong: uring_reactor.mojo:790-804 swallows the arming failure when
the SQ is full and `_wake_armed` stays false; phase 1 frees the SQ but nothing
retries the arm before phase 3 (:739-846).
Lean: `Flare.Bugs.RT_03.poll_blocks_unarmed`. Fix: re-arm after phase 1;
`pollFixed_never_blocks_unarmed`.
Repro: `formal/repro/RT-03_uring_poll_blocks_unarmed.mojo`, PLATFORM linux,
run in the Linux container (seccomp unconfined so io_uring is available),
observed
`BUG REPRODUCED: after poll() flushed a full SQ ( 8 SQEs) no wakeup read is armed; a poll(1) here would block with wakeup() unable to release it`.
Where io_uring is unavailable (macOS) it prints
`inconclusive: io_uring not available on this host` and fails rather than
passing. Flip, in the container's copy: retrying `_arm_wakeup_recv()` right
after the phase-1 `submit_and_wait(0)` (the SQ is empty there) prints
`OK: wakeup read re-armed after the SQ was flushed` and exits 0.

### RT-04: `peek_idle_worker` returns a peer whose queue is full

Severity: low. `choose_handoff_target` can pick that peer; the following
`try_handoff` fails and the caller accepts locally, so the cost is a wasted
attempt.
Spec (handoff.mojo:315-317): "Returns -1 when the policy is disabled or no peer
queue is below capacity".
What goes wrong: the scan starts at `best_size = capacity + 1` (:326).
Lean: `Flare.Bugs.RT_04.peek_returns_full_peer`. Fix: start at `capacity`;
`peekFixed_below_capacity`.
Repro: `formal/repro/RT-04_handoff_peek_returns_full_peer.mojo`, observed
`BUG REPRODUCED: peek_idle_worker returned worker 1 whose queue is full; try_handoff to it returns False`.
Flip: `OK: no peer below capacity, peek_idle_worker returned -1`, exit 0.

### RT-05: `BufferPool.acquire` can return less capacity than requested

Severity: low. Appends still grow the list; only code that writes through
`unsafe_ptr()` trusting the contract is at risk, and `BufferPool` is not wired
into the server yet.
Spec (`acquire` docstring): returns a handle "with capacity ≥ `min_capacity`".
What goes wrong: `bytes` is public and `release` (buffer_pool.mojo:337-364)
checks only the class tag, so a shrunk buffer is recycled into its class.
Lean: `Flare.Bugs.RT_05.acquire_after_shrunk_release`. Fix: drop handles whose
capacity is below their class; `releaseFixed_preserves_capacity` (any history,
including forged handles).
Repro: `formal/repro/RT-05_buffer_pool_capacity_contract.mojo`, observed
`BUG REPRODUCED: acquire(60000) returned a handle with capacity 0`.
Flip: `OK: acquire(60000) capacity 65536`, exit 0.

### RT-06: the `MAX_POOL_SIZE` thread cap is never enforced on macOS arm64

Severity: medium. The cap exists to stop a fan-out from creating unbounded
threads; on macOS arm64 there is no cap.
Spec (blocking.mojo:116-122): at most 32 pool threads at once; the 33rd call
raises "pool saturated".
What goes wrong: `sem_open` is variadic; on Apple arm64 variadic arguments go
on the stack but `external_call` passes them in registers, so `sem_open` sees
a garbage initial value and fails with EINVAL; the acquire is fail-open
(:189-190), so every acquire succeeds. The platform behaviour is observed by
the repro, not derived in Lean.
Lean: `Flare.Bugs.RT_06.persistentFailOpen_unbounded`, `forty_slots`. Fix:
pass `mode` and `value` where the variadic callee reads them;
`Flare.Bugs.RT_06.fixed_cap` (from `Flare.L2.Blocking.paired_cap_invariant`).
Repro: `formal/repro/RT-06_pool_cap_not_enforced_macos.mojo` (PLATFORM macos),
observed `BUG REPRODUCED: 40 pool slots acquired at once; the cap is 32`.
Flip (six dummy register arguments before mode and value, in both
`_pool_try_acquire` and `_pool_release`): `OK: cap enforced, 32 slots acquired (cap 32 )`, exit 0.

### RT-07: one fail-open acquire raises the thread cap permanently

Severity: low. It needs `sem_open` to fail transiently (for example EMFILE
under fd exhaustion, the overload the cap is for); each occurrence raises the
cap by one for the rest of the process.
Spec: at most 32 slots held, whatever transient errors occur.
What goes wrong: `_pool_try_acquire` (blocking.mojo:177-193) returns `True`
without decrementing when `sem_open` fails, while the paired `_pool_release`
(:196-206) posts whenever its own `sem_open` succeeds.
Lean: `Flare.Bugs.RT_07.failOpen_breaks_cap`. Fix: fail closed;
`Flare.Bugs.RT_07.fixed_cap_invariant` (any failure pattern).
Repro: `formal/repro/RT-07_pool_semaphore_fail_open_drift.mojo`. The fd table
is filled in a forked child (under `mojo run` the parent's JIT threads would
need fds too), which reports the slot count through its exit status. On macOS
RT-06 masks it; observed
`BUG REPRODUCED: no cap at all on this platform ( 40 slots before any fault injection; RT-06 masks RT-07)`.
On Linux RT-08 masks it; observed
`BUG REPRODUCED: the failed sem_open crashed the process (SIGSEGV) before the fail-open branch; RT-08 masks RT-07`.
Flip on macOS: with the RT-06 fix only,
`BUG REPRODUCED: after one fail-open acquire/release pair, 33 pool slots could be held at once (cap is 32 )`;
with the RT-06 and RT-07 fixes, `OK: at most 32 slots held (cap 32 )`, exit 0.
Flip on Linux: the same two lines with the RT-08 fix alone, then with the
RT-08 and RT-07 fixes.

### RT-08: a failed `sem_open` crashes the process on Linux

Severity: medium. Any `block_in_pool` or `resolve_async` call made while the
fd table is full (a peer can get there by holding connections open) kills the
whole server with SIGSEGV, where the code meant to skip the cap.
Spec (`_pool_try_acquire` docstring, comment at blocking.mojo:130-132): if the
semaphore cannot be opened, the cap is skipped and the work runs.
What goes wrong: `_pool_try_acquire` (:185-190) and `_pool_release`
(:199-204) detect failure with `Int(sem) == -1`, which is Darwin's
`SEM_FAILED`. glibc's is `(sem_t *)0`, so on Linux a failed `sem_open` passes
the test and NULL goes to `sem_trywait` / `sem_post`. The platform constant is
a header fact taken as an input to the model.
Lean: `Flare.Bugs.RT_08.linux_failure_crashes` (and
`macos_failure_fails_open`: the same test is right on macOS). Fix: compare
against the platform's `SEM_FAILED`, or treat both 0 and -1 as failure;
`fixed_never_crashes` (both platforms, `sem_open` failing or not) and
`fixed_agrees` (no change on success or on macOS).
Repro: `formal/repro/RT-08_sem_open_failure_null_deref_linux.mojo` (PLATFORM
linux). A forked child restores the default SIGSEGV action (the Mojo
runtime's handler would turn the fault into `exit(1)`), fills its fd table
and calls `_pool_try_acquire`; observed
`BUG REPRODUCED: _pool_try_acquire with the fd table full (sem_open -> EMFILE, returns NULL) killed the process with SIGSEGV`.
Flip (`if Int(sem) == -1 or Int(sem) == 0:` in both functions):
`OK: _pool_try_acquire returned True with sem_open failing; no crash`, exit 0.

### NET-11: `BatchReceiver` sizes its data region with an unchecked `Int` product

Severity: low. It needs a caller misconfiguration (an absurd `max_payload` or
`capacity`, both caller-chosen; QUIC passes its configured
`max_udp_payload_size`), not a peer; then `recvmmsg` writes datagrams over
unrelated heap memory.
Spec: the data region covers every slot `[i * max_payload, (i + 1) *
max_payload)`, `i < capacity`, that the iovecs hand to `recvmmsg`.
What goes wrong: udp/batch.mojo:176-206 allocates
`capacity * max_payload` bytes with a wrapping 64-bit product and checks only
`capacity > 0 and max_payload > 0`; iovec `i` still announces `max_payload`
bytes at `data + i * max_payload`.
Lean: `Flare.Bugs.NET_11.allocSize_wraps` (`capacity = 16`,
`max_payload = 2^60`: accepted, size 0, slot 0 not covered). Fix: raise when
`capacity > Int.MAX // max_payload` (and likewise for `capacity * _MMSGHDR`);
`Flare.Bugs.NET_11.covers_fixed`.
Repro: `formal/repro/NET-11_batch_receiver_size_overflow.mojo` (PLATFORM any;
it allocates an 8-byte canary after the receiver and prints `inconclusive:`
unless the canary lands within 256 bytes of the data region), observed on
macOS (3/3)
`BUG REPRODUCED: data region is a wrapped capacity*max_payload = 0 byte allocation at 0x10b6dc000; iovec 0 announces 1152921504606846976 bytes there; a later 8-byte allocation sits at 0x10b6dc008 (inside iovec 0's span)`
and on Linux (3/3), where it also receives one 512-byte datagram,
`BUG REPRODUCED: ... a later 8-byte allocation sits at 0x70f27fe06040 ; recvmmsg of a 512-byte datagram overwrote all 8 of its bytes`.
Flip (make `__init__` raise on the overflowing product), on macOS and Linux:
`OK: BatchReceiver refused capacity=16, max_payload=2^60: BatchReceiver: capacity * max_payload overflows Int`, exit 0.

## Checked, not a bug

- Timer wheel: every property in the original suspicion list holds (no early
  or late fire, cancel semantics and return value, `_jump` equivalent to
  ticking up to fire order, backwards `advance` is a no-op, each timer fires at
  most once, ids start at 1 so 0 stays reserved). The only defect is the hint
  (RT-01).
- Reactor `unregister` swallowing a failed `EPOLL_CTL_DEL`: needed for fd-reuse
  safety (`fd_reuse_safe`); raising would reject the reused fd
  (`raising_unregister_rejects_reuse`).
- epoll versus kqueue: equivalent on readable/writable at dispatch level
  (`dispatch_rw_equiv`). The differences (error-only conditions, two kqueue
  events for a socket ready both ways) are behaviour differences, not defects
  (`error_differs`, `kqueue_counts_filters`).
- io_uring ring arithmetic: correct across the 2^32 wrap; the old
  Int-widening distance (`oldDistance_wrong`) is no longer in flare. The u16
  provided-buffer tail wraps consistently.
- `RawSocket` ownership and the scheduler's `fd = -1` patch: the fd is closed
  exactly once; the patch is load-bearing.
- `connect_timeout`: flags are restored on every path. Two behaviours are
  recorded as notes, not filed: EINTR from `poll` raises instead of retrying,
  and a failing `getsockopt(SO_ERROR)` is read as success (that call does not
  fail on a valid socket fd).
- `writev_buf_all` with a wrong `total_bytes`, and `BufReader` with a
  `Readable` returning more than requested or a negative count: outside the
  documented caller or trait contract.
- `UringReactor.poll(min_complete > 1)` can return fewer CQEs without blocking
  (`minComplete_weakened`); every in-tree caller passes 1.
- `_set_timeval_opt` with a negative timeout produces a negative `tv_sec`
  (`timeval_negative`); callers pass non-negative values.
- `DnsCache._key` strips only one trailing dot, so it is not idempotent
  (`key_not_idempotent`); names with two trailing dots just get their own
  entry.
- Handoff queue: refines a bounded FIFO, a capacity of 0 is safe, and
  `choose_handoff_target` meets its spec apart from RT-04.
- FrameMux id allocation wraps to 0 after 2^64 - 1 frames (`nextId_wraps`);
  unreachable in practice.
- Buffer pool buckets never exceed `class_capacity` (`bounded_release`).
- `UnixListener.__deinit__` unlinks only its own socket file when nothing
  interleaves (`deinit_spec`). With interleaving, another process can bind
  the path between `close` and `lstat` and receive the freed inode number,
  and the guard then unlinks the new socket (`deinit_race`). This is an
  inherent time-of-check/time-of-use window: POSIX has no "unlink if this
  inode" call, so no ordering of the existing calls closes it. Recorded as a
  note, not filed.
- `udp/batch.mojo` layouts: every hard-coded struct size and offset matches the
  C layout (`layout_constants`, `cmsg_constants`).
- GSO `msg_controllen = CMSG_LEN(2) = 18` instead of `CMSG_SPACE(2) = 24`: the
  kernel's cmsg walk accepts it and reads the same single `UDP_SEGMENT` header
  (`gso_walk_18`, `gso_walk_24`, `gso_seg`). Also checked live in the Linux
  container: `send_segmented` of 2500 bytes with segment size 1000 arrived as
  datagrams of 1000, 1000 and 500 bytes.
- Timer wheel `_jump` order: it is the documented one (`jump_fire_order`), but
  it differs from tick-by-tick order and from global fire-time order
  (`jump_not_sorted`, `ticks_order_example`). The callers do not depend on it:
  the HTTP reactors (`_server_reactor_epoll.mojo:174,396,615,761`,
  `_unified_reactor_impl.mojo:764`) treat each fired token as an independent
  close, and QUIC (`quic/server.mojo:2923-2939`) at most sends one extra PTO
  probe on a connection whose idle timer fired in the same jump.
- Timer wheel `UInt64` arithmetic: equal to the `Nat` model on every trace
  with clock readings below 2^63 ms (`run64_eq`). The only wrap
  (`nextFire64_wraps`) needs a monotonic clock within 2^32 ms of 2^64 ms.

## Not covered

Nothing from the original L2 scope. Two limits remain on what is shown: the
UNIX listener destructor guard is proved only for the sequential case (the
concurrent window is `deinit_race`, see above), and the timer wheel's fired
lists record ids, not tokens.

## Traceability

| Lean definition | Mojo file:line @59bda50 | Theorems | Status |
|---|---|---|---|
| `Flare.L2.Socket.close`, `deinit`, `fdStep` | flare/net/socket.mojo:143-220 | `close_idempotent`, `closes_then_deinit_exactly_once`, `fd_closed_once` | proved |
| `Flare.L2.Socket.signalAndClose`, `freeResources` | flare/runtime/scheduler.mojo:655-668, 713-725 | `sched_patch_closes_once`, `sched_unpatched_double_close` | proved |
| `Flare.L2.Socket.timeval` | flare/net/socket.mojo:481-509 | `timeval_exact`, `timeval_fits`, `timeval_negative` | proved |
| `Flare.L2.Socket.acceptImpl` | flare/tcp/listener.mojo:165-201, 248-282 | `accept_nodelay_safe`, `NET_05.accept_leaks_on_decode_error` | proved; counterexample (NET-05) |
| `Flare.L2.WriteLoop.write`, `writeAll` | flare/tcp/stream.mojo:458-519 | `writeAll_terminates_strong`, `writeAll_no_overshoot`, `writeAll_livelock_weak` | proved; counterexample (NET-02) |
| `Flare.L2.WriteLoop.udsWriteAll` | flare/uds/stream.mojo:140-163 | `udsWriteAll_eq` | proved |
| `Flare.L2.WriteLoop.readExact` | flare/tcp/stream.mojo:429-456 | `readExact_terminates` | proved |
| `Flare.L2.WriteLoop.writevAll`, `consume` | flare/runtime/iovec.mojo:312-361 | `writevAll_strong`, `RT_02.writev_silent_short_write` | proved; counterexample (RT-02) |
| `Flare.L2.BufReader.consume`, `readExact`, `fillInt` | flare/io/buf_reader.mojo:117-266 | `consume_view`, `readExact_correct` | proved |
| `Flare.L2.ConnectTimeout.run` | flare/tcp/stream.mojo:254-333 | `flags_restored`, `never_left_nonblocking` | proved |
| `Flare.L2.Reactor.interestToEpoll`, `epollToEventFlags` | flare/runtime/reactor.mojo:112-135 | `roundtrip_rw`, `read_interest_has_rdhup`, `readable_iff_in` | proved |
| `Flare.L2.Reactor.register`, `registerExclusive`, `modify`, `unregister` | flare/runtime/reactor.mojo:290-479, 646-665 | `register_refines`, `unregister_always_removes`, `agree_*`, `fd_reuse_safe` | proved |
| `Flare.L2.Reactor.kqueueEvents` | flare/runtime/reactor.mojo:586-604 | `dispatch_rw_equiv`, `error_differs` | proved |
| `Flare.L2.IoUring.ringDistance`, `nextSqe`, `commitSqe`, `submit` | flare/runtime/io_uring_driver.mojo:297-641 | `ringDistance_true`, `sq_reachable_inv`, `nextSqe_fresh` | proved |
| `Flare.L2.IoUring.cqeCount`, `reapCqe` | flare/runtime/io_uring_driver.mojo:645-671 | `reap_count`, `reap_keeps_bound` | proved |
| `Flare.L2.IoUring.pbufIdx` | flare/runtime/_pbuf_ring.mojo:61-97 | `pbufIdx_wrap`, `pbuf_add_preserves_tail` | proved |
| `Flare.L2.UringWakeup.lazyArm`, `drain`, `poll` | flare/runtime/uring_reactor.mojo:739-946 | `poll_inv`, `pollFixed_never_blocks_unarmed`, `RT_03.poll_blocks_unarmed` | proved; counterexample (RT-03) |
| `Flare.L2.TimerWheel.init`, `schedule`, `cancel` | flare/runtime/timer_wheel.mojo:102-167 | `inv_schedule`, `schedule_spec`, `cancel_spec` | proved |
| `Flare.L2.TimerWheel.stepTick`, `drainOne`, `jump`, `jumpIds`, `rebucketOne`, `advance` | flare/runtime/timer_wheel.mojo:169-293 | `advance_spec`, `jump_equiv_ticks`, `run_nodup` | proved |
| `Flare.L2.TimerWheel.nextFire` | flare/runtime/timer_wheel.mojo:310-333 | `nextFire_lower_bound_no_overflow`, `RT_01.nextFire_not_lower_bound` | proved; counterexample (RT-01) |
| `Flare.L2.Handoff.pushed`, `pop`, `drainGo` | flare/runtime/handoff.mojo:150-195 | `push_refines`, `pop_refines`, `drain_refines`, `cap_zero_safe` | proved |
| `Flare.L2.Handoff.peekWith` | flare/runtime/handoff.mojo:312-334 | `RT_04.peek_returns_full_peer`, `peekFixed_below_capacity` | counterexample (RT-04) |
| `Flare.L2.Handoff.chooseTarget` | flare/runtime/handoff.mojo:336-365 | `chooseTarget_spec` | proved |
| `Flare.L2.FrameMux.encodeFrame`, `decodeFrame` | flare/uds/frame_mux.mojo:97-130 | `decode_encode` | proved |
| `Flare.L2.FrameMux.feedLoop`, `feed`, `route`, `poll` | flare/uds/frame_mux.mojo:165-234 | `feed_chunking`, `drain_sound`, `drain_complete`, `routeAll_eq` | proved |
| `Flare.L2.FrameMux.feedM`, `feedLoopM` | flare/uds/frame_mux.mojo:176-207 | `NET_04.feed_after_error_duplicates`, `feedMFixed_error_stuck` | counterexample (NET-04) |
| `Flare.L2.FrameMux.nextId` | flare/uds/frame_mux.mojo:274-280 | `nextId_injective`, `nextId_wraps` | proved |
| `Flare.L2.Udp.readPort`, `readAddr4`, `readAddr6` | flare/net/_libc.mojo:303-397 | `impl_addr6`, `addr4_ok` | proved |
| `Flare.L2.Udp.implBufLen` | flare/udp/socket.mojo:279-283, 330-334 | `impl_reads_past_buffer`, `NET_01.recvFrom_ipv6_wrong_sender` | counterexample (NET-01) |
| `Flare.L2.Uds.fill` | flare/uds/_libc.mojo:55-107 | `fill_len_le` | proved |
| `Flare.L2.Uds.readPath` | flare/uds/_libc.mojo:110-133 | `readPath_fill_iff_ascii`, `NET_06.decode_encode_not_id` | counterexample (NET-06) |
| `Flare.L2.DnsCache.key` | flare/dns/cache.mojo:81-94 | `key_fqdn_case`, `key_not_idempotent` | proved |
| `Flare.L2.DnsCache.oldestGo`, `evict`, `store`, `resolveWith` | flare/dns/cache.mojo:96-142 | `huge_ttl_expiry_wraps`, `NET_03.huge_ttl_never_hits`, `storeFixed_size_bound` | counterexample (NET-03) |
| `Flare.L2.BufferPool.classIndex`, `capacityFor` | flare/runtime/buffer_pool.mojo:130-161 | `classIndex_fits`, `classIndex_least` | proved |
| `Flare.L2.BufferPool.acquire`, `releaseWith` | flare/runtime/buffer_pool.mojo:297-364 | `bounded_release`, `RT_05.acquire_after_shrunk_release` | counterexample (RT-05) |
| `Flare.L2.Blocking.tryAcquire`, `release` | flare/runtime/blocking.mojo:177-206 | `paired_cap_invariant`, `RT_06.persistentFailOpen_unbounded`, `RT_07.failOpen_breaks_cap`, `RT_08.linux_failure_crashes`, `RT_08.fixed_never_crashes` | counterexample (RT-06, RT-07, RT-08) |
| `Flare.L2.HappyEyeballs.order`, `orderFixed` | flare/dns/async_resolve.mojo:154-177 | `order_perm`, `order_filter_v6`, `NET_10.order_breaks_spec`, `orderFixed_head` | counterexample (NET-10) |
| `Flare.L2.Hostname.scan`, `validate`, `tooLongTail` | flare/dns/resolver.mojo:68-107 | `validate_sound`, `validate_gap`, `NET_08.valid_but_rejected`, `NET_09.message_not_wf` | counterexample (NET-08, NET-09) |
| `Flare.L2.UdsListener.prep`, `deinitUnlinks` | flare/uds/listener.mojo:72-184 | `takeover_unlinks_live`, `prepFixed_safe`, `deinit_spec`, `deinit_race` | counterexample (NET-07) |
| `Flare.L2.UdpBatch.IOVEC`, `MSGHDR`, `MMSGHDR`, `OFF_MSG`, `CMSG_LEN_GSO`, ... | flare/udp/batch.mojo:67-92 | `layout_constants`, `cmsg_constants` | proved |
| `Flare.L2.UdpBatch.gsoCtrl`, `cmsgs` | flare/udp/batch.mojo:400-408 | `gso_walk_18`, `gso_walk_24`, `gso_seg` | proved |
| `Flare.L2.UdpBatch.allocSize`, `accepts` | flare/udp/batch.mojo:185-195 | `slots_disjoint`, `NET_11.allocSize_wraps`, `covers_fixed` | counterexample (NET-11) |
| `Flare.L2.TimerWheel.jump` (order) | flare/runtime/timer_wheel.mojo:208-293 | `jump_fire_order`, `jump_not_sorted` | proved |
| `Flare.L2.TimerWheel.schedule64`, `advance64`, `jump64`, `ticks64`, `nextFire64` | flare/runtime/timer_wheel.mojo:119-144, 169-333 | `advance64_eq`, `run64_eq`, `nextFire64_eq`, `nextFire64_wraps` | proved |
