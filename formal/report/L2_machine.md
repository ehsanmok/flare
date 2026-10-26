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
clock arithmetic. The models describe the shipped code; each implementation
definition carries a symbol-based anchor to the Mojo code it mirrors, checked
by `formal/scripts/anchors.py`.

Every model lives in `Flare/L2_Machine/<Component>.lean` (namespace
`Flare.L2.<Component>`); the aggregate is `Flare/L2_Machine.lean`; the axiom
audit is `Flare/Audit/L2.lean`. The kernel and libc are environment inputs:
either an oracle function (the result of the k-th syscall) or an explicit
Prop hypothesis such as `Flare.Assumptions.SendContract` or
`Flare.L2.Udp.RecvfromFills`. Nothing is an `axiom`.

Totals: 20 model files with 304 theorems. No `sorry`, `admit` or `axiom`.
The audit prints the axioms of 98 headline theorems; the footprint is at most
`propext`, `Quot.sound`, `Classical.choice`. No model file uses
`native_decide` or `bv_decide` (the io_uring and reactor bit-vector lemmas
are proved by translation to `Nat` and `decide`). Every module builds in a
few seconds.

## Components

### Socket fd ownership (`Socket.lean`)

`RawSocket` (`net/socket.mojo`: `__init__`, `close`, `__deinit__`) as an
object-level machine (one `fd` field, close count per method) and as an
fd-level LTS over one fd incarnation (number of holders, number of closes).
Also `RawSocket._set_timeval_opt` and the accept path
(`tcp/listener.mojo`: `_adopt_accepted`, `TcpListener.accept`, `accept_fd`).

| Lean name | Statement | Status |
|---|---|---|
| `close_idempotent` | A second `close()` issues no `close(2)` and leaves the fd field unchanged. | proved |
| `closes_then_deinit_exactly_once` | Any number of `close()` calls followed by the destructor closes a valid fd exactly once. | proved |
| `fd_closed_once` | In every reachable state each fd incarnation is closed at most once, and exactly once when no object holds it. | proved |
| `copy_would_double_close` | Without the non-`Copyable` restriction two destructors would close the fd twice. | counterexample (design check) |
| `timeval_exact`, `timeval_fits` | `_set_timeval_opt` produces a normalised timeval equal to the millisecond value, with no Int64 overflow. | proved |
| `timeval_negative` | A negative timeout gives a negative `tv_sec`. | proved (note) |
| `accept_never_leaks` | The shipped accept (wrap, then decode) never leaks the fd, whatever the decode and `TCP_NODELAY` do. | proved |
| `accept_nodelay_safe` | Once the accepted fd is wrapped, a `TCP_NODELAY` failure cannot leak it. | proved |

Assumptions: Mojo runs no destructor on a moved-from value. Limitations: one fd
incarnation at a time; kernel fd reuse is modelled as a new incarnation.

### Write and read loops (`WriteLoop.lean`)

`TcpStream.write` and `TcpStream.read_exact` (`tcp/stream.mojo`), the shared
`write_all_chunks` loop (`net/_write_loop.mojo`) behind `TcpStream.write_all`
and `UnixStream.write_all` (`uds/stream.mojo`), and `writev_buf_all`
(`runtime/iovec.mojo`), each a loop over a syscall oracle with explicit
fuel. `Strong` is the contract "`send` returns `1..len` or an error", `Weak`
(POSIX) also allows 0.

| Lean name | Statement | Status |
|---|---|---|
| `writeAll_terminates_weak` | Under `Weak` (POSIX, `send` may return 0), with fuel `total - sent`, `write_all` sends exactly `total` bytes or raises. | proved |
| `writeAll_terminates_strong` | The same under `Strong` (special case). | proved |
| `writeAll_no_overshoot` | Under `Weak`, `write_all` never counts more than `total` bytes. | proved |
| `udsWriteAll_eq` | The UDS loop equals the TCP loop. | proved |
| `readExact_terminates` | Under `RecvContract`, `read_exact` returns exactly `size` bytes or raises. | proved |
| `writevAll_strong` | Under `Strong` and the caller precondition `total_bytes = Σ len_i`, `writev_buf_all` returns normally only with every byte written; `first` is monotone and bounded. | proved |
| `writevAll_done_complete` | For every oracle, even one breaking the POSIX contract, a normal return of `writev_buf_all` means nothing is left to write. | proved (RT-02) |
| `writevAll_understated` | A `total_bytes` that understates the cells makes the loop return early. | counterexample (caller precondition, not filed) |
| `writevAll_overstated` | A `total_bytes` that overstates the cells makes `writev` of zero cells return 0, and the loop raises. | proved (RT-02) |

Limitations: EINTR is folded into the oracle (it only re-asks). Timeouts are
errors.

### BufReader (`BufReader.lean`)

`io/buf_reader.mojo` (`BufReader._fill`, `_peek_byte`, `_consume_byte`,
`readline`, `read_exact`). The `Readable` is a list of chunks; the trait
contract (each read returns `0..cap` bytes) is a hypothesis.

| Lean name | Statement | Status |
|---|---|---|
| `consume_inv` | Consuming one byte keeps `pos + len ≤ cap`. | proved |
| `consume_view` | A returned byte is the head of the remaining stream; EOF leaves it unchanged. | proved |
| `readExact_correct` | `read_exact n` returns the next `n` stream bytes and keeps the invariant. | proved |
| `overlong_read_breaks_inv`, `negative_read_runs_away` | A `Readable` that violates the contract breaks the invariant. | counterexample (outside contract) |

### connect_timeout (`ConnectTimeout.lean`)

`TcpStream.connect_timeout` (`tcp/stream.mojo`, Linux path) as a function of
an oracle record of syscall results.

| Lean name | Statement | Status |
|---|---|---|
| `flags_restored` | If `F_GETFL` succeeded, the flag writes are exactly set-nonblocking then restore, on every path. | proved |
| `never_left_nonblocking` | The socket never leaves `connect_timeout` in non-blocking mode. | proved |
| `poll_eintr_raises` | EINTR from `poll` is not retried; it raises. | proved (note) |
| `getsockopt_failure_is_success` | A failing `getsockopt(SO_ERROR)` is read as a successful connect. | proved (note) |

### Reactor bookkeeping and epoll/kqueue (`Reactor.lean`)

`runtime/reactor.mojo` (`_interest_to_epoll`, `_epoll_to_event_flags`,
`Reactor.register`, `register_exclusive`, `modify`, `unregister`, `poll`).
Bookkeeping map fd ↦ token next to the kernel interest list; every kernel
call has an environment-chosen outcome.

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

`runtime/io_uring_driver.mojo` (`_ring_distance`, `IoUringDriver.commit_sqe`,
`submit_and_wait`, `cqe_count`, `reap_cqe`, `submit_nop`) and
`runtime/_pbuf_ring.mojo` (`_pbuf_ring_add`), with `UInt32` wrapping counters
exactly as in Mojo. `PowMask m` says the mask is `2^k - 1` with `k ≤ 15`
(`IORING_MAX_ENTRIES`); `powMask_bitwise` checks this agrees with the bitwise
test `m &&& (m + 1) = 0` for every such `k`. The kernel is an interleaved
second party (`sqLTS`).

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

Who gives provided buffers back is a separate verified kernel,
`Flare/Kernels/BufLedger.lean` (namespace `Flare.Kernels.BufLedger`), which
mirrors `http/_bufring_ledger.mojo` (`classify_recv`, `BufLedger`), the
decision the io_uring buffer-ring server loop in
`http/_server_reactor_uring.mojo` takes for every receive completion. The
spec defs are `RecvOk` (a buffer goes back exactly when the completion took
one; only completions of dead connections are dropped), `Conserved`
(`inRing + inCq = ringSize`), `Enabled` and `Valid` (the kernel only hands
back buffers it took out of the ring). `classify_ok` proves every decision
meets `RecvOk`; `run_conserved`, `run_inRing_le` and `run_drained` prove that
from a full ring every valid trace keeps every buffer accounted for, never
overfills the ring, and refills it once every held completion is processed.
The kernel is differential-tested against the Mojo code by the `formal/difftest`
target `bufring_ledger.trace`.

Strings flare hands C as NUL-terminated `char*` go through a second verified
kernel, `Flare/Kernels/CStr.lean` (namespace `Flare.Kernels.CStr`), which
mirrors `net/cstr.mojo` (`c_str_verdict`). It covers the TLS client and
server paths, `getaddrinfo`, `inet_pton` and `unlink`. The spec defs are
`cRead` (C reads the bytes before the first NUL) and `CrossOK` (pass exactly
the strings C reads back unchanged, NULL only for an empty value where the
parameter reads NULL as a default, `""` only where the parameter gives it a
meaning). `verdict_ok` proves every verdict meets `CrossOK`;
`cRead_append_nul`, `pass_exact` and `pass_complete` follow. That the
stdlib's `as_c_string_span` appends one NUL is outside the proof, so the
difftest target `cstr.cross` reads back what real libc sees (`strlen`,
`memcpy`), including the empty `TlsConfig().ca_bundle` of issue #42, and
`fuzz/fuzz_cstr.mojo` asserts the same properties under mozz.

### UringReactor wakeup (`UringWakeup.lean`)

`runtime/uring_reactor.mojo` (`UringReactor.poll`, `_try_arm_wakeup`,
`_arm_wakeup_recv`, `_drain_into_tracking`): the lazy arming of the eventfd
read and the three poll phases. Kernel assumption, built into `ksubmit`: an
`io_uring_enter` consumes all submitted SQEs.

| Lean name | Statement | Status |
|---|---|---|
| `poll_inv` | The shipped `poll` keeps the invariant (`_wake_armed` means the read is queued, in flight, or its CQE is waiting). | proved |
| `poll_never_blocks_unarmed` | The shipped `poll` (re-arm after phase 1) never blocks without the wakeup read in flight. | proved |
| `minComplete_weakened` | `poll(min_complete = 2)` returns 1 CQE without blocking. | proved (note; all callers pass 1) |

### Timer wheel (`TimerWheel.lean`)

`runtime/timer_wheel.mojo` (`TimerWheel.__init__`, `schedule`, `cancel`,
`advance`, `_jump`, `next_fire_ms`): 512 slots, overflow list, lazy cancel,
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
| `nextFire_lower_bound` | The shipped `next_fire_ms` is a lower bound on every active timer's fire time in every state satisfying `Inv`. | proved |

Limitations: time is `Nat` here; `TimerWheelTime.lean` (below) relates it to
flare's `UInt64` and fixes the `_jump` firing order. Fired ids are recorded,
not tokens (tokens are carried unchanged).

### Timer wheel: `_jump` firing order and `UInt64` time (`TimerWheelTime.lean`)

`runtime/timer_wheel.mojo` (`schedule`, `advance`, `_jump`, `next_fire_ms`).
The `…64` definitions redo every time computation of `schedule`, `advance`
(tick loop and `_jump`) and `next_fire_ms` with wrapping `UInt64` arithmetic
and `UInt64` comparisons, over the same state shape. `ClockBound` is a Prop
hypothesis on a trace: every `now_ms` passed to `advance` is below 2^63 ms
(about 292 million years of `monotonic_ms()`), and every `after_ms` is a Mojo
`Int`, so below 2^63.

| Lean name | Statement | Status |
|---|---|---|
| `jump_fire_order` | `_jump` reports `W ++ O`: `W` is a sublist of the wheel ids in slot order, sorted by fire time; `O` is a sublist of the overflow list in list order. This is the contract documented on `_jump`. | proved |
| `jump_not_sorted` | From `init 700`, schedule 512, advance to 1000, schedule 400, advance to 2000: `_jump` reports `[2, 1]` although timer 1 is due at 1212 and timer 2 at 1400. | proved (note) |
| `ticks_order_example` | Ticking the same state one millisecond at a time reports `[1, 2]`. | proved (note) |
| `advance64_eq`, `jump64_eq`, `ticks64_eq` | With every stored time below 2^64, the `UInt64` `advance` equals the `Nat` one for every `UInt64` reading of `now`. | proved |
| `schedule64_eq`, `nextFire64_eq` | `schedule` and `next_fire_ms` agree when `tick + delay` (resp. `tick + 0xFFFFFFFF`) fits in 64 bits. | proved |
| `run64_eq`, `run64_init` | Under `ClockBound`, the `UInt64` and `Nat` machines produce the same state and fired list on every trace (from any state with clock below 2^63, in particular `init now`). | proved |
| `nextFire64_wraps` | Without a bound, at `tick = 2^64 - 1` with no timers the `UInt64` hint wraps to `0xFFFFFFFE`, below `now`. | proved (note; needs a clock near 2^64) |

### Worker handoff (`Handoff.lean`)

`runtime/handoff.mojo` (`HandoffQueue.push`, `pop`, `drain`;
`WorkerHandoffPool.peek_idle_worker`, `choose_handoff_target`).

| Lean name | Statement | Status |
|---|---|---|
| `push_refines`, `pop_refines`, `drain_refines` | The ring buffer refines a bounded FIFO list. | proved |
| `cap_zero_safe` | A capacity-0 queue never divides by zero. | proved |
| `chooseTarget_spec` | The target is -1 or a peer other than the caller whose load is at least `steal_threshold` below the local load. | proved |
| `peek_below_capacity` | The shipped `peek_idle_worker` returns -1 or a peer strictly below capacity, and -1 only when every peer is full. | proved |

### UDS frame multiplexer (`FrameMux.lean`)

`uds/frame_mux.mojo` (`encode_frame`, `decode_frame`, `FrameDemux.feed`,
`_peek_len`, `_route`, `poll`, `FrameMux.next_id`): the frame codec,
`FrameDemux.feed` reassembly, routing to per-stream inboxes, id allocation.

| Lean name | Statement | Status |
|---|---|---|
| `decode_encode` | Codec round trip for payloads up to `MAX_FRAME_PAYLOAD`. | proved |
| `drain_sound`, `drain_complete` | The parse loop splits its input into exactly the encoded frames plus an incomplete residual. | proved |
| `feed_chunking` | `feed` is chunking independent. | proved |
| `routeAll_eq`, `poll_fifo` | Each stream gets exactly its frames, in arrival order. | proved |
| `nextId_injective`, `nextId_wraps` | Ids are unique for the first 2^64 - 1 allocations; the next one wraps to 0. | proved |
| `feedM_error_stuck` | After a protocol error the buffer starts at the bad header, so every later feed raises at once and routes nothing. | proved (NET-04) |
| `feedM_no_duplicates` | Once a feed raises, no sequence of later feeds routes anything, so no wire frame is routed twice. | proved (NET-04) |

### UDP recvfrom address decoding (`Udp.lean`)

`UdpSocket.recv_from` and `try_recv_from` (`udp/socket.mojo`), which pass a
28-byte `sockaddr_in6`-sized buffer (`implBufLen`), and the decoders
`_read_port_from_sockaddr`, `_read_ip_from_sockaddr`,
`_read_ipv6_from_sockaddr` (`net/_libc.mojo`). Hypothesis
`RecvfromFills bufLen saLen sa stack mem`: the kernel copies
`min(bufLen, saLen)` bytes of the sender sockaddr into the buffer and leaves
memory past the buffer untouched.

| Lean name | Statement | Status |
|---|---|---|
| `impl_addr6` | With the shipped 28-byte buffer the decoded IPv6 address and port are the sender's, whatever the stack holds. | proved |
| `addr4_ok` | IPv4 senders decode correctly with any buffer of at least 16 bytes. | proved |

### UDS sockaddr_un (`Uds.lean`)

`uds/_libc.mojo` (`fill_sockaddr_un`, `read_path_from_sockaddr_un`), for
Linux (108-byte path) and macOS (104).

| Lean name | Statement | Status |
|---|---|---|
| `fill_len_le` | The returned `addrlen` fits `SOCKADDR_UN_SIZE` and equals the bytes written. | proved |
| `readPath_fill` | The shipped decoder (bytes taken as UTF-8) returns the bound path, whatever follows in the buffer. | proved |

### DNS cache (`DnsCache.lean`)

`dns/cache.mojo` (`DnsCache.__init__`, `_key`, `_store`, `resolve`). The
dictionary is an insertion-ordered association list; host keys are
abstracted to `Nat`; times are `Int64` with wrapping `+`; the resolver
always succeeds. `_store` saturates the expiry at `Int.MAX` (`satAdd`) and
evicts with a `<=` scan.

| Lean name | Statement | Status |
|---|---|---|
| `satAdd_toInt` | For `now ≥ 0` the stored expiry is `min(now + ttl, Int.MAX)`. | proved |
| `store_size_bound` | The shipped store keeps `size ≤ max_entries`. | proved |
| `store_hits_within_ttl` | After the shipped store at `now ≥ 0`, any lookup strictly inside the TTL window is a hit. | proved |
| `key_fqdn_case`, `key_not_idempotent` | `_key` merges case and one trailing dot, but is not idempotent (`a..` vs `a.`). | proved (note) |

### Buffer pool (`BufferPool.lean`)

`runtime/buffer_pool.mojo` (`_class_index_for`, `_capacity_for_class`,
`BufferPool.acquire`, `release`). A handle is its capacity and class tag; the
caller may hand any handle to `release` (the fields and constructor are
public).

| Lean name | Statement | Status |
|---|---|---|
| `classIndex_fits`, `classIndex_least` | The class chosen is the smallest one that fits the request. | proved |
| `bounded_acquire`, `bounded_release` | No bucket ever holds more than `class_capacity` handles, whatever acceptance test `release` applies. | proved |
| `release_preserves_capacity` | With the shipped `release`, `acquire n` returns capacity at least `n` after any history. | proved |

### Blocking-pool thread cap (`Blocking.lean`)

`runtime/blocking.mojo` (`MAX_POOL_SIZE`, `_pool_sem_open`,
`_pool_try_acquire`, `_pool_release`, `_sem_open_failed`): the named
semaphore as `count` plus `held` slots; whether each `sem_open` succeeds is
an environment input. Releases are paired with earlier successful acquires.
The `SemOpen` section models the `SEM_FAILED` check per platform (glibc 0,
Darwin -1); its spec def `SemOpen.Valid` says a real semaphore handle is
neither 0 nor -1.

| Lean name | Statement | Status |
|---|---|---|
| `paired_cap_invariant` | If every `sem_open` succeeds, `count + held = 32` throughout, so at most 32 slots are held. | proved |
| `cap_invariant`, `cap_from_init` | The shipped fail-closed acquire keeps `count + held ≤ 32` under any pattern of `sem_open` failures; from the initial semaphore at most 32 slots are ever held. | proved |
| `SemOpen.never_crashes` | On Linux and macOS, whether `sem_open` fails or returns a `Valid` handle, neither acquire nor release crashes. | proved |
| `SemOpen.failure_fails_closed` | A failed `sem_open` on either platform refuses the slot and releases nothing. | proved |

### Happy Eyeballs ordering (`HappyEyeballs.lean`)

`order_happy_eyeballs` (`dns/async_resolve.mojo`). Addresses are an abstract
type with a family test (`IpAddr.is_v6`).

| Lean name | Statement | Status |
|---|---|---|
| `order_eq` | The Mojo loops compute the interleaving of the two family sublists, the family of `addrs[0]` first. | proved |
| `order_perm` | The output is a permutation of the input. | proved |
| `order_filter_v6`, `order_filter_v4` | Each family keeps its relative order. | proved |
| `order_get_even`, `order_get_odd`, `order_get_even_v4first`, `order_get_odd_v4first` | Positions alternate the two families over the first `2 * min n6 n4` slots, starting with the first address's family. | proved |
| `order_head` | The input's first address stays first (RFC 8305 §4). | proved |

### Batched UDP layouts and receiver buffers (`UdpBatch.lean`)

`udp/batch.mojo` (the layout constants, `send_segmented`,
`BatchReceiver.__init__`; Linux only). A C struct layout calculator (natural
alignment, LP64) and a model of the kernel's control message walk
(`__CMSG_FIRSTHDR`, `__cmsg_nxthdr`, `CMSG_OK` in include/linux/socket.h,
consumed by `__udp_cmsg_send` in net/ipv4/udp.c).

| Lean name | Statement | Status |
|---|---|---|
| `layout_constants` | Every hard-coded size and offset (`iovec` 16, `msghdr` 56 with its field offsets, `mmsghdr` 64 with `msg_len` at 56, `cmsghdr` 16) is the C layout. | proved |
| `cmsg_constants` | `CMSG_LEN(2) = 18`, `CMSG_SPACE(2) = 24`, `CMSG_DATA` at 16; the 28-byte name slot fits `sockaddr_in6` and `sockaddr_in`. | proved |
| `gso_walk_18`, `gso_walk_24`, `gso_seg` | With `msg_controllen` 18 (flare) or 24, the kernel walk finds exactly one `(SOL_UDP, UDP_SEGMENT)` header and reads back the segment size. | proved |
| `slot_in_bounds`, `slots_disjoint` | With exact arithmetic every receive slot lies inside the `capacity * max_payload` region and slots are disjoint. | proved |
| `allocSize_fixed`, `covers_fixed` | For every argument pair the shipped constructor accepts (`accepts`: positive, `capacity ≤ Int.MAX / max_payload`, `capacity ≤ Int.MAX / 64`), the 64-bit size is exact and covers every slot. | proved |
| `accepts_refuses_wrap` | The shipped checks refuse `capacity = 16, max_payload = 2^60`. | proved |

### Hostname validation (`Hostname.lean`)

The checks `resolve` (`dns/resolver.mojo`) runs before `getaddrinfo`. The
spec is the one documented on `resolve`: no NUL, CR, LF or `@`, labels of at
most 63 bytes, and at most 253 bytes not counting one trailing root dot
(RFC 1035 §2.3.4 bounds the wire form at 255 octets).

| Lean name | Statement | Status |
|---|---|---|
| `scan_ok_iff` | The per-byte loop accepts exactly when no forbidden byte occurs and every label is at most 63 bytes. | proved |
| `validate_sound` | flare never accepts a name that breaks the documented rules. | proved |
| `validate_iff` | The shipped check accepts exactly the valid names. | proved |
| `truncChars_wf`, `tooLongTail_wf` | The shipped error text (cut at a character boundary) is well-formed UTF-8 and quotes at most 20 bytes. | proved |

### UNIX listener takeover and destructor guard (`UdsListener.lean`)

`uds/listener.mojo` (`UnixListener.bind_with_options`, `__init__`,
`__deinit__`). `bind_with_options(unlink_existing=True)` lstat's the path,
probes a socket with a throwaway `connect(2)` (`_socket_path_is_stale`) and
unlinks it as stale only when the probe is refused; `__deinit__` unlinks only
if the path still names the socket file whose `(dev, ino)` was recorded after
`bind`. What `connect(2)` may return is a hypothesis (`ConnectFacts`):
`ECONNREFUSED` only when nobody listens, success when somebody listens and
the caller may write the file.

| Lean name | Statement | Status |
|---|---|---|
| `prep_safe` | The shipped `prep` unlinks only after a refusal, so never a live socket, and still takes over stale ones. | proved |
| `deinit_spec` | Without interleaving, the destructor unlinks exactly when the path still names its own socket. | proved |
| `deinit_no_record`, `deinit_no_cleanup` | No recorded inode, or `cleanup_path=False`: the destructor never unlinks. | proved |
| `deinit_race` | Another process binding the path between `close` and `lstat` and getting the freed inode passes the check. | proved (note) |

## Findings

Line numbers in the writeups below refer to the code at 59bda50. Repro
status is from runs on macOS arm64 in this session, and, where stated, in
the Linux container of `formal/repro/linux.sh` (at tag `formal-audit-0.12`,
like every repro and `Flare.Bugs` name cited below; Ubuntu 24.04, native
arm64). Every repro was run at least three times per platform with the
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
Lean (at the tag): `Flare.Bugs.NET_01.recvFrom_ipv6_wrong_sender` (for the
sender `[::1]` and any stack byte 23 other than 1, the decoded address
differs), `reads_past_buffer`. Fix: allocate and pass `SOCKADDR_IN6_SIZE`;
`Flare.L2.Udp.impl_addr6` proves the shipped decoding correct.
Repro (at the tag): `formal/repro/NET-01_udp_recvfrom_ipv6_sender.mojo`, observed
`BUG REPRODUCED: recv_from reported sender [::307:0:0:0]:52925 but the datagram came from [::1]:52925`
(the wrong half is stack contents and varies between runs).
Flip: `OK: recv_from reported the IPv6 sender [::1]:52884`, exit 0.
Status: resolved. `recv_from` and `try_recv_from` allocate and pass `SOCKADDR_IN6_SIZE`; the model's `implBufLen` is 28 and `impl_addr6` proves the sender is decoded exactly. Tests: `tests/udp/test_udp.mojo::test_recv_from_reports_ipv6_sender`, `::test_try_recv_from_reports_ipv6_sender`.

### NET-02: `write_all` livelocks if `send` returns 0

Severity: low (latent). POSIX allows `send` to return 0 for a non-empty
buffer; Linux and macOS do not do so on blocking TCP or Unix stream sockets,
so the repro injects it.
Spec: `write_all` writes every byte or raises.
What goes wrong: tcp/stream.mojo:497-519 and uds/stream.mojo:156-163 add the
return value to the progress counter without checking for 0.
Lean (at the tag): `Flare.Bugs.NET_02.writeAll_livelock`.
Fix: raise on a 0 return; `Flare.L2.WriteLoop.writeAll_terminates_weak` (the
shipped `writeAll` terminates under `Weak`).
Repro (at the tag): `formal/repro/NET-02_write_all_zero_send_livelock.mojo` (PLATFORM any,
fault injection: `send` returns 0 for its first 1000 calls, then fails with
EIO), observed on macOS and Linux (3/3 each)
`BUG REPRODUCED: write_all of 100 bytes called send 1000 times while send returned 0 (no progress) and only stopped when the injected send failed with EIO: NetworkError(errno 5): Input/output error (send)`.
Flip (raise `NetworkError` when `write` returns 0 in `TcpStream.write_all`), on
macOS and Linux:
`OK: write_all raised after send returned 0 (send called 1 time(s)): NetworkError: send returned 0 (write_all)`, exit 0.
Status: resolved. `TcpStream.write_all` and `UnixStream.write_all` now share `write_all_chunks` (`flare/net/_write_loop.mojo`), which raises `NetworkError("write_all: send returned 0 after n/total bytes")` when a chunk write makes no progress; the model's `writeAll` / `udsWriteAll` mirror it. Tests (the loop is driven through a scripted `_ChunkWriter`, since no kernel returns 0 here): `tests/net/test_write_loop.mojo::test_write_all_raises_when_send_returns_zero`, `::test_write_all_raises_after_partial_progress_then_zero`, `::test_write_all_completes_through_partial_writes`, `::test_write_all_empty_data_makes_no_call`, `::test_write_all_propagates_writer_errors`.

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
Lean (at the tag): `Flare.Bugs.NET_03.huge_ttl_never_hits` (all `now ≥ 1`,
`now' ≥ 0`), `huge_ttl_trace`, and the two theorems above. Fix: saturate the
expiry and use `<=` in the scan; `Flare.L2.DnsCache.store_hits_within_ttl`,
`store_size_bound` (the shipped `store`).
Repro (at the tag): `formal/repro/NET-03_dns_cache_ttl_overflow.mojo`, observed
`BUG REPRODUCED: DnsCache(ttl_ms=Int.MAX) resolved 2 times with 0 hits for two lookups of the same host`.
Flip (both changes): `OK: second lookup served from cache`, exit 0.
Status: resolved. `DnsCache._store` saturates the expiry (`Int.MAX` when `ttl_ms > Int.MAX - now`) and the eviction scan uses `<=`; the model's `store` / `resolve` mirror it (`satAdd_toInt`, `store_size_bound`, `store_hits_within_ttl`). Tests: `tests/dns/test_dns_cache.mojo::test_int_max_ttl_means_cache_forever`, `::test_ttl_that_overflows_the_expiry_still_caches`, `::test_saturated_expiries_are_still_evicted`.

### NET-04: `FrameDemux.feed` re-delivers frames after a protocol error

Severity: medium. A frame is delivered twice to its stream if a later frame in
the same feed is malformed and the caller feeds again (for example
`UpstreamChunkSource.next_chunk` retried after the error).
Spec: every complete frame on the wire reaches its inbox exactly once.
What goes wrong: uds/frame_mux.mojo:176-207 routes frames while advancing a
local `consumed` and compacts only after the loop; the oversize-header raise
skips the compaction.
Lean (at the tag): `Flare.Bugs.NET_04.feed_after_error_duplicates`. Fix:
compact before raising; `Flare.L2.FrameMux.feedM_no_duplicates` (no later
feed routes anything, so no frame is routed twice).
Repro (at the tag): `formal/repro/NET-04_frame_demux_redelivers_after_error.mojo`, observed
`BUG REPRODUCED: one CHUNK frame on the wire, stream 5 has 2 queued frames after the protocol error and one more feed()`.
Flip: `OK: stream 5 has exactly one queued frame`, exit 0.
Status: resolved. `FrameDemux.feed` compacts the consumed prefix before raising on an oversize header (the bad header stays at the front, so later feeds keep raising and route nothing); the model's `feedM` mirrors it (`feedM_error_stuck`, `feedM_no_duplicates`). Test: `tests/uds/test_frame_mux.mojo::test_demux_error_does_not_redeliver_routed_frames`.

### NET-05: accepted fd leaks if the peer address fails to decode

Severity: info (latent; reproduced by fault injection). Spec: once
`accept(2)` returns an fd, a `TcpStream` owns it or it is closed before the
error propagates.
What goes wrong: tcp/listener.mojo:183-201 and 265-282 decode the peer
address before wrapping `client_fd`; a raise there leaks the fd. The decode
cannot raise in practice: unknown families fall through to the AF_INET branch
(net/socket.mojo:561-585) and `inet_ntop` does not fail for AF_INET/AF_INET6
with flare's buffers.
Lean (at the tag): `Flare.Bugs.NET_05.accept_leaks_on_decode_error`. Fix:
wrap first, then decode; `Flare.L2.Socket.accept_never_leaks`.
Repro (at the tag): `formal/repro/NET-05_accept_fd_leak_on_decode_error.mojo` (PLATFORM any,
fault injection: `inet_ntop` returns NULL with ENOSPC, armed only around
`accept()`; the repro learns the lowest free fd before `accept` and checks it
with `fcntl` and `getpeername` afterwards), observed on macOS (3/3)
`BUG REPRODUCED: accept raised ( inet_ntop failed: errno No space left on device ) but the accepted fd 8 is still open and connected to the client (peer port 60834 ); nothing owns it, so it leaks`
and on Linux (3/3) the same line with fd 7.
Flip (construct the `RawSocket` before decoding, then set its family), on
macOS and Linux:
`OK: accept raised ( inet_ntop failed: errno No space left on device ) and the accepted fd 8 was closed`
(fd 7 on Linux), exit 0.
Status: resolved. `accept` and `accept_fd` call `_adopt_accepted`, which builds the `RawSocket` first and decodes the peer address afterwards, so a raise runs the destructor and closes the fd; the model's `acceptImpl` mirrors it (`accept_never_leaks`). Deterministic tests use a one-method internal seam (`_PeerDecoder`, not public API): `tests/tcp/test_tcp.mojo::test_accept_closes_fd_when_peer_decode_fails`, `::test_accept_hands_fd_to_the_stream_on_success`; the repro exercised the real `accept` through the `inet_ntop` interposer.

### NET-06: `queried_local_path()` garbles non-ASCII Unix socket paths

Severity: low. `queried_local_path` is mainly a test helper; `local_path`
returns the stored string and is unaffected.
Spec: decoding the `sockaddr_un` written for `path` returns `path`.
What goes wrong: uds/_libc.mojo:128-133 appends `chr(Int(b))` per byte, i.e.
decodes Latin-1 and re-encodes every byte `≥ 0x80` as two UTF-8 bytes.
Lean (at the tag): `Flare.Bugs.NET_06.decode_encode_not_id` ("é" reads back
as "Ã©"), `roundtrip_iff_ascii`. Fix: collect the bytes and build the
`String` as UTF-8; `Flare.L2.Uds.readPath_fill`.
Repro (at the tag): `formal/repro/NET-06_uds_queried_path_latin1.mojo`, observed
`BUG REPRODUCED: bound /tmp/flare_net06_é.sock ( 24 bytes) but queried_local_path() returned /tmp/flare_net06_Ã©.sock ( 26 bytes)`.
Flip: `OK: queried_local_path() round-trips /tmp/flare_net06_é.sock`, exit 0.
Status: resolved. `read_path_from_sockaddr_un` collects the bytes up to the NUL and builds the `String` from them as UTF-8; the model's `readPath` mirrors it (`readPath_fill`). Tests: `tests/uds/test_uds_listener.mojo::test_queried_local_path_round_trips_non_ascii`, `::test_sockaddr_un_round_trips_utf8`.

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
Lean (at the tag): `Flare.Bugs.NET_07.takeover_unlinks_live`. Fix: unlink
only after `ConnectionRefused` (`ECONNREFUSED` or `ENOENT`) and raise
`AddressInUse` otherwise; `Flare.L2.UdsListener.prep_safe` (about the shipped
`prep`).
Repro (at the tag): `formal/repro/NET-07_uds_takeover_unlinks_live_socket.mojo` (macOS
only: on Linux the container runs as root, which bypasses the permission
check), observed
`BUG REPRODUCED: second bind() unlinked the live listener's socket file (its probe failed with EACCES) and bound the path itself`.
Flip: `OK: second bind() refused while the first listener is live: AddressInUse: /tmp/flare_net07.sock`, exit 0.
Status: resolved. `bind_with_options` probes with the new `_socket_path_is_stale` (a throwaway `connect(2)`): only `ECONNREFUSED`/`ENOENT` mark the socket stale, any other outcome raises `AddressInUse` and leaves the file; the model's `prep` mirrors it (`prep_safe`). Tests: `tests/uds/test_uds_listener.mojo::test_bind_refuses_when_liveness_probe_is_inconclusive` (a live datagram socket, `EPROTOTYPE`, runs for any user) and `::test_bind_refuses_unwritable_live_listener` (the EACCES trigger, non-root only).

### NET-08: `resolve` rejects valid 254-byte absolute hostnames

Severity: low. Only the absolute spelling of a maximal-length name is
affected; the same name without the trailing dot resolves.
Spec: the rule flare cites, RFC 1035 §2.3.4, allows 253 text bytes plus an
optional root dot.
What goes wrong: resolver.mojo:80-82 compares the raw byte length with 253.
This was the only valid input flare rejected.
Lean (at the tag): `Flare.Bugs.NET_08.valid_but_rejected`
(63+1+63+1+63+1+61+1 bytes), `validateOld_gap` (the only gap). Fix: compare the length
without one trailing `.`; `Flare.L2.Hostname.validate_iff` (the shipped
`validate` accepts exactly the valid names).
Repro (at the tag): `formal/repro/NET-08_hostname_trailing_dot_too_long.mojo`, observed
`BUG REPRODUCED: 254-byte absolute name (253 + root dot) rejected: AddressParseError: invalid address 'hostname too long (max 253 chars): ...'`.
Flip: `OK: name passed validation; resolver said: DnsError(...)` (the name
reaches `getaddrinfo`, which then fails to resolve it), exit 0.
Status: resolved. `resolve` compares the length without one trailing root dot against 253; the model's `validate` mirrors it (`validate_iff`, `validate_sound`). Tests: `tests/dns/test_dns.mojo::test_resolve_accepts_253_byte_absolute_name`, `::test_resolve_accepts_253_byte_name`, `::test_resolve_rejects_254_byte_name_without_root_dot`.

### NET-09: the "hostname too long" error cuts a UTF-8 character in half

Severity: low. The error text of a rejected over-long name can hold an
invalid UTF-8 sequence inside a Mojo `String`, which assumes well-formed
UTF-8.
Spec: an error built from a well-formed host is well-formed UTF-8.
What goes wrong: resolver.mojo:82-87 quotes
`String(unsafe_from_utf8=host_bytes[:20])`; byte 20 can fall inside a
multi-byte character.
Lean (at the tag): `Flare.Bugs.NET_09.message_not_wf` (19 × `a`, `é`, 240 ×
`a`: the text holds `C3` followed by the `E2 80 A6` of "…"). Fix: quote whole
characters only; `Flare.L2.Hostname.tooLongTail_wf`.
Repro (at the tag): `formal/repro/NET-09_hostname_error_splits_utf8.mojo`, observed
`BUG REPRODUCED: error text is not valid UTF-8; its non-ASCII bytes are C3 E2 80 A6`.
Flip (cut at the last character boundary at or before byte 20):
`OK: error text is valid UTF-8`, exit 0.
Status: resolved. The too-long message steps its cut at byte 20 back to a lead byte, so only whole characters are quoted; the model's `tooLongTail` (`truncChars 20`) mirrors it (`tooLongTail_wf`). Tests: `tests/dns/test_dns.mojo::test_too_long_message_does_not_split_a_two_byte_char`, `::test_too_long_message_does_not_split_a_four_byte_char`, `::test_too_long_message_keeps_a_char_that_ends_at_byte_20`, `::test_too_long_message_quotes_20_ascii_bytes`.

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
emits the IPv6 sublist first. The docstring itself documented
`v6[0], v4[0], ...`, so this is a gap between flare and the RFC it cites,
not between the code and its own docs. Order within each family and the
permutation property held.
Lean (at the tag): `Flare.Bugs.NET_10.order_breaks_spec`. Fix: start with the
family of `addrs[0]`; `Flare.L2.HappyEyeballs.order_head`, `order_perm`,
`order_filter_v6`, `order_filter_v4`.
Repro (at the tag): `formal/repro/NET-10_happy_eyeballs_ignores_preferred_family.mojo`,
observed
`BUG REPRODUCED: input starts with 192.0.2.1 but order_happy_eyeballs returned 2001:db8::1 192.0.2.1 192.0.2.2`.
Flip: `OK: preferred first address kept first: 192.0.2.1 2001:db8::1 192.0.2.2`, exit 0.
Status: resolved. `order_happy_eyeballs` now starts the interleave with the family of `addrs[0]`; the model's `order` mirrors it (`order_head`). Tests: `tests/dns/test_async_resolve.mojo::test_happy_eyeballs_keeps_preferred_ipv4_first`, `::test_happy_eyeballs_ipv4_first_alternates_and_keeps_family_order`, `::test_happy_eyeballs_uneven_families` (updated: it asserted the old IPv6-first result), `::test_happy_eyeballs_empty_and_single`.

### RT-01: `TimerWheel.next_fire_ms` overshoots when only overflow timers remain

Severity: low. The reactor caps its poll at 100 ms
(http/_reactor/lifecycle.mojo:31-47), which bounds the lateness in flare's own
servers; other users of the hint can sleep up to 511 ms past a timer.
Spec (timer_wheel.mojo:320-323): the result "is never later than the true
next fire, so a timer can never be missed".
What goes wrong: with no wheel slot occupied and a non-empty overflow list the
hint is `tick + 512`, but overflow timers are promoted at the next slot-0
boundary `tick + (512 - slot)` and can fire there.
Lean (at the tag): `Flare.Bugs.RT_01.nextFire_not_lower_bound` (timer due at
512, hint 1012 at t = 500). Fix: cap the scan and the fallback at
`512 - slot` when overflow is non-empty; `Flare.L2.TimerWheel.nextFire_lower_bound`
for every state satisfying the wheel invariant. The pre-fix hint was correct
when the overflow list is empty (`nextFire_ok_without_overflow`, at the tag).
Repro (at the tag): `formal/repro/RT-01_timer_next_fire_overflow_hint.mojo`, observed before
the fix `BUG REPRODUCED: next_fire_ms() = 1012 at now=500 but the timer fires at 512`.
After the fix: `OK: next_fire_ms() = 512 <= actual fire time 512`, exit 0.

Status: resolved. `next_fire_ms` caps its scan and fallback at the next slot-0
boundary while overflow is non-empty; tests
`tests/runtime/test_timer_wheel.mojo::test_next_fire_ms_overflow_only_is_lower_bound_after_advance`,
`::test_next_fire_ms_wheel_hint_capped_at_promotion_boundary`,
`::test_next_fire_ms_overflow_hint_at_slot_zero`.

### RT-02: `writev_buf_all` returns normally after a short write

Severity: low (latent). Spec: a normal return means every byte was written.
What goes wrong: runtime/iovec.mojo:340-341 returns on `sent <= 0`;
`writev_buf` already raises on -1, so this is `writev` returning 0 with bytes
queued, and the caller is told everything was sent. Linux and macOS do not
return 0 from `writev` on a socket with a non-empty iovec, so the repro
injects it (libc also returns 0 for an iovec whose cells are all empty, e.g.
when `total_bytes` overstates the cells; the unit tests use that).
Lean (at the tag): `Flare.Bugs.RT_02.writev_silent_short_write`. Fix: raise
on 0; `Flare.L2.WriteLoop.writevAll_done_complete` for the shipped loop (for
every oracle).
Repro (at the tag): `formal/repro/RT-02_writev_all_silent_short_write.mojo` (PLATFORM any,
fault injection: `writev` returns 0), observed before the fix on macOS and
Linux (3/3 each)
`BUG REPRODUCED: writev_buf_all(total_bytes=100) returned normally after writev returned 0; 0 of 100 bytes were written and iovec 0 still holds 100 bytes`.
After the fix (`NetworkError` on `sent <= 0`):
`OK: writev_buf_all raised after writev returned 0: NetworkError: writev returned 0 with 100 bytes unsent (writev_buf_all)`, exit 0 (macOS 3/3, Linux container).

Status: resolved. `writev_buf_all` raises `NetworkError` when `writev` returns 0
with bytes owed; tests
`tests/runtime/test_iovec.mojo::test_writev_buf_all_raises_when_writev_makes_no_progress`
and `::test_writev_buf_all_raises_when_total_exceeds_cells` (deterministic: an
all-empty iovec makes real libc return 0, no interposer needed).

### RT-03: `UringReactor.poll` can block with no wakeup read armed

Severity: medium (Linux io_uring backend only). A cross-thread `wakeup()` is
not seen until an unrelated completion arrives.
Spec: whenever `poll` may block in phase 3, the eventfd read is in flight.
What goes wrong: uring_reactor.mojo:790-804 swallows the arming failure when
the SQ is full and `_wake_armed` stays false; phase 1 frees the SQ but nothing
retries the arm before phase 3 (:739-846).
Lean (at the tag): `Flare.Bugs.RT_03.poll_blocks_unarmed`.
Fix: re-arm after phase 1; `Flare.L2.UringWakeup.poll_never_blocks_unarmed`
for the shipped `poll`.
Repro (at the tag): `formal/repro/RT-03_uring_poll_blocks_unarmed.mojo`, PLATFORM linux,
run in the Linux container (seccomp unconfined so io_uring is available),
observed before the fix
`BUG REPRODUCED: after poll() flushed a full SQ ( 8 SQEs) no wakeup read is armed; a poll(1) here would block with wakeup() unable to release it`.
Where io_uring is unavailable (macOS) it prints
`inconclusive: io_uring not available on this host` and fails rather than
passing. After the fix: `OK: wakeup read re-armed after the SQ was flushed`, exit 0.

Status: resolved. `poll` now calls the new `_try_arm_wakeup()` again right
after the phase-1 `submit_and_wait(0)`, where the SQ is empty; test
`tests/runtime/test_uring_reactor.mojo::test_wakeup_rearmed_after_full_sq_flushed`.

### RT-04: `peek_idle_worker` returns a peer whose queue is full

Severity: low. `choose_handoff_target` can pick that peer; the following
`try_handoff` fails and the caller accepts locally, so the cost is a wasted
attempt.
Spec (handoff.mojo:315-317): "Returns -1 when the policy is disabled or no peer
queue is below capacity".
What goes wrong: the scan starts at `best_size = capacity + 1` (:326).
Lean (at the tag): `Flare.Bugs.RT_04.peek_returns_full_peer`. Fix: start at
`capacity`; `Flare.L2.Handoff.peek_below_capacity` for the shipped
`peek_idle_worker`.
Repro (at the tag): `formal/repro/RT-04_handoff_peek_returns_full_peer.mojo`, observed before
the fix
`BUG REPRODUCED: peek_idle_worker returned worker 1 whose queue is full; try_handoff to it returns False`.
After the fix: `OK: no peer below capacity, peek_idle_worker returned -1`, exit 0.

Status: resolved. `peek_idle_worker` starts its scan at `best_size = capacity`;
tests `tests/runtime/test_handoff.mojo::test_peek_idle_skips_peer_whose_queue_is_full`,
`::test_peek_idle_prefers_non_full_peer_over_full_one` and
`::test_choose_target_never_picks_full_peer`.

### RT-05: `BufferPool.acquire` can return less capacity than requested

Severity: low. Appends still grow the list; only code that writes through
`unsafe_ptr()` trusting the contract is at risk, and `BufferPool` is not wired
into the server yet.
Spec (`acquire` docstring): returns a handle "with capacity ≥ `min_capacity`".
What goes wrong: `bytes` is public and `release` (buffer_pool.mojo:337-364)
checks only the class tag, so a shrunk buffer is recycled into its class.
Lean (at the tag): `Flare.Bugs.RT_05.acquire_after_shrunk_release`. Fix: drop
handles whose capacity is below their class;
`Flare.L2.BufferPool.release_preserves_capacity` for the shipped `release`
(any history, including forged handles).
Repro (at the tag): `formal/repro/RT-05_buffer_pool_capacity_contract.mojo`, observed before
the fix `BUG REPRODUCED: acquire(60000) returned a handle with capacity 0`.
After the fix: `OK: acquire(60000) capacity 65536`, exit 0.

Status: resolved. `BufferPool.release` drops a handle whose `bytes.capacity()`
is below `_capacity_for_class(class_index)` (handles that grew are kept); tests
`tests/runtime/test_buffer_pool.mojo::test_pool_release_drops_handle_with_shrunk_capacity`,
`::test_pool_release_drops_forged_undersized_handle` and
`::test_pool_release_keeps_grown_handle`.

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
Lean (at the tag): `Flare.Bugs.RT_06.persistentFailOpen_unbounded`,
`forty_slots`. Fix: pass `mode` and `value` where the variadic callee reads
them; `Flare.L2.Blocking.paired_cap_invariant`.
Repro (at the tag): `formal/repro/RT-06_pool_cap_not_enforced_macos.mojo` (PLATFORM macos),
observed `BUG REPRODUCED: 40 pool slots acquired at once; the cap is 32`.
After the fix (six dummy register arguments before mode and value, in the new
`_pool_sem_open` used by `_pool_try_acquire` and `_pool_release`):
`OK: cap enforced, 32 slots acquired (cap 32 )`, exit 0.

Status: resolved. `_pool_sem_open` pads the variadic call on macOS (mode and
value as 64-bit values, one per stack slot); tests
`tests/runtime/test_block_in_pool.mojo::test_pool_cap_is_exactly_max_pool_size`
and `::test_pool_cap_enforced_and_recovers`. Decision: fix the code, not the
docs, since the cap is a documented thread-bomb protection.

### RT-07: one fail-open acquire raises the thread cap permanently

Severity: low. It needs `sem_open` to fail transiently (for example EMFILE
under fd exhaustion, the overload the cap is for); each occurrence raises the
cap by one for the rest of the process.
Spec: at most 32 slots held, whatever transient errors occur.
What goes wrong: `_pool_try_acquire` (blocking.mojo:177-193) returns `True`
without decrementing when `sem_open` fails, while the paired `_pool_release`
(:196-206) posts whenever its own `sem_open` succeeds.
Lean (at the tag): `Flare.Bugs.RT_07.failOpen_breaks_cap`. Fix: fail closed;
`Flare.L2.Blocking.cap_invariant` (any failure pattern).
Repro (at the tag): `formal/repro/RT-07_pool_semaphore_fail_open_drift.mojo`. The fd table
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

Status: resolved. `_pool_try_acquire` returns `False` when `sem_open` fails, so
a `True` result always means a slot was really taken; a failed release open can
only tighten the cap. Tests:
`tests/runtime/test_block_in_pool.mojo::test_failed_sem_open_does_not_raise_the_cap`
and `::test_acquire_survives_sem_open_failure` (the RT-08 test, updated because
it asserted the old fail-open `True`).

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
Lean (at the tag): `Flare.Bugs.RT_08.linux_failure_crashes` (and
`macos_failure_fails_open`: the same test is right on macOS). Fix: treat both
0 and -1 as failure; `Flare.L2.Blocking.SemOpen.never_crashes` (both
platforms, `sem_open` failing or returning a `Valid` handle) and
`SemOpen.failure_fails_closed`.
Repro (at the tag): `formal/repro/RT-08_sem_open_failure_null_deref_linux.mojo` (PLATFORM
linux). A forked child restores the default SIGSEGV action (the Mojo
runtime's handler would turn the fault into `exit(1)`), fills its fd table
and calls `_pool_try_acquire`; observed before the fix
`BUG REPRODUCED: _pool_try_acquire with the fd table full (sem_open -> EMFILE, returns NULL) killed the process with SIGSEGV`.
After the fix (`_sem_open_failed`: `0` or `-1`, in both functions):
`OK: _pool_try_acquire returned False with sem_open failing; no crash`, exit 0
(RT-07 later made the failed open refuse the slot).

Status: resolved. New `_sem_open_failed` helper used by `_pool_try_acquire` and
`_pool_release`; tests
`tests/runtime/test_block_in_pool.mojo::test_acquire_survives_sem_open_failure`
and `::test_release_survives_sem_open_failure` (forked child, fd table full).

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
Lean (at the tag): `Flare.Bugs.NET_11.allocSize_wraps` (`capacity = 16`,
`max_payload = 2^60`: accepted, size 0, slot 0 not covered). Fix: raise when
`capacity > Int.MAX // max_payload` (and likewise for `capacity * _MMSGHDR`);
`Flare.L2.UdpBatch.covers_fixed`.
Repro (at the tag): `formal/repro/NET-11_batch_receiver_size_overflow.mojo` (PLATFORM any;
it allocates an 8-byte canary after the receiver and prints `inconclusive:`
unless the canary lands within 256 bytes of the data region), observed on
macOS (3/3)
`BUG REPRODUCED: data region is a wrapped capacity*max_payload = 0 byte allocation at 0x10b6dc000; iovec 0 announces 1152921504606846976 bytes there; a later 8-byte allocation sits at 0x10b6dc008 (inside iovec 0's span)`
and on Linux (3/3), where it also receives one 512-byte datagram,
`BUG REPRODUCED: ... a later 8-byte allocation sits at 0x70f27fe06040 ; recvmmsg of a 512-byte datagram overwrote all 8 of its bytes`.
Flip (make `__init__` raise on the overflowing product), on macOS and Linux:
`OK: BatchReceiver refused capacity=16, max_payload=2^60: BatchReceiver: capacity * max_payload overflows Int`, exit 0.
Status: resolved. `BatchReceiver.__init__` (now `raises`) refuses non-positive arguments and products that overflow `Int` (data region and `mmsghdr` array); `accepts` mirrors it (`accepts_refuses_wrap`, `covers_fixed`). Tests: `tests/udp/test_udp_batch.mojo::test_batch_receiver_refuses_overflowing_data_region`, `::test_batch_receiver_refuses_overflowing_header_arrays`, `::test_batch_receiver_refuses_non_positive_arguments`, `::test_batch_receiver_accepts_sane_arguments`.

## Checked, not a bug

- Timer wheel: every property in the original suspicion list holds (no early
  or late fire, cancel semantics and return value, `_jump` equivalent to
  ticking up to fire order, backwards `advance` is a no-op, each timer fires at
  most once, ids start at 1 so 0 stays reserved). The only defect was the hint
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
- `RawSocket` ownership: the fd is closed exactly once (`fd_closed_once`).
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
  `choose_handoff_target` meets its spec (`chooseTarget_spec`).
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
  the HTTP reactors (`_server_reactor_epoll.mojo`, `_unified_reactor_impl.mojo`)
  treat each fired token as an independent close, and QUIC
  (`quic/server.mojo`) at most sends one extra PTO probe on a connection whose
  idle timer fired in the same jump.
- Timer wheel `UInt64` arithmetic: equal to the `Nat` model on every trace
  with clock readings below 2^63 ms (`run64_eq`). The only wrap
  (`nextFire64_wraps`) needs a monotonic clock within 2^32 ms of 2^64 ms.

## Not covered

Nothing from the original L2 scope apart from the scheduler's listener
teardown (`runtime/scheduler.mojo`), which no model covers. Two limits remain
on what is shown: the UNIX listener destructor guard is proved only for the
sequential case (the concurrent window is `deinit_race`, see above), and the
timer wheel's fired lists record ids, not tokens.

## Traceability

| Lean definition | Mojo symbols | Theorems | Status |
|---|---|---|---|
| `Flare.L2.Socket.close`, `deinit`, `fdStep` | flare/net/socket.mojo `RawSocket.__init__`, `close`, `__deinit__` | `close_idempotent`, `closes_then_deinit_exactly_once`, `fd_closed_once` | proved |
| `Flare.L2.Socket.timeval` | flare/net/socket.mojo `RawSocket._set_timeval_opt` | `timeval_exact`, `timeval_fits`, `timeval_negative` | proved |
| `Flare.L2.Socket.acceptImpl` | flare/tcp/listener.mojo `_adopt_accepted`, `TcpListener.accept`, `accept_fd` | `accept_never_leaks`, `accept_nodelay_safe` | proved (NET-05, resolved) |
| `Flare.L2.WriteLoop.write` | flare/tcp/stream.mojo `TcpStream.write` | `writeAll_terminates_weak` | proved |
| `Flare.L2.WriteLoop.writeAll` | flare/net/_write_loop.mojo `write_all_chunks` | `writeAll_terminates_weak`, `writeAll_terminates_strong`, `writeAll_no_overshoot` | proved (NET-02, resolved) |
| `Flare.L2.WriteLoop.udsWriteAll` | flare/uds/stream.mojo `UnixStream.write`, `write_all`, `_write_chunk` | `udsWriteAll_eq` | proved |
| `Flare.L2.WriteLoop.readExact` | flare/tcp/stream.mojo `TcpStream.read`, `read_exact` | `readExact_terminates` | proved |
| `Flare.L2.WriteLoop.writevAll`, `consume` | flare/runtime/iovec.mojo `writev_buf_all` | `writevAll_strong`, `writevAll_done_complete`, `writevAll_overstated` | proved (RT-02, resolved) |
| `Flare.L2.BufReader.consume`, `readExact`, `fillInt` | flare/io/buf_reader.mojo `BufReader._fill`, `_peek_byte`, `_consume_byte`, `readline`, `read_exact` | `consume_view`, `readExact_correct` | proved |
| `Flare.L2.ConnectTimeout.run` | flare/tcp/stream.mojo `TcpStream.connect_timeout` | `flags_restored`, `never_left_nonblocking` | proved |
| `Flare.L2.Reactor.interestToEpoll`, `epollToEventFlags` | flare/runtime/reactor.mojo `_interest_to_epoll`, `_epoll_to_event_flags` | `roundtrip_rw`, `read_interest_has_rdhup`, `readable_iff_in` | proved |
| `Flare.L2.Reactor.register`, `registerExclusive`, `modify`, `unregister` | flare/runtime/reactor.mojo `Reactor.register`, `register_exclusive`, `modify`, `unregister` | `register_refines`, `unregister_always_removes`, `agree_*`, `fd_reuse_safe` | proved |
| `Flare.L2.Reactor.kqueueEvents` | flare/runtime/reactor.mojo `Reactor.poll` | `dispatch_rw_equiv`, `error_differs` | proved |
| `Flare.L2.IoUring.ringDistance`, `nextSqe`, `commitSqe`, `submit` | flare/runtime/io_uring_driver.mojo `_ring_distance`, `IoUringDriver.commit_sqe`, `submit_and_wait` | `ringDistance_true`, `sq_reachable_inv`, `nextSqe_fresh` | proved |
| `Flare.L2.IoUring.cqeCount`, `reapCqe` | flare/runtime/io_uring_driver.mojo `IoUringDriver.cqe_count`, `reap_cqe` | `reap_count`, `reap_keeps_bound` | proved |
| `Flare.L2.IoUring.pbufIdx` | flare/runtime/_pbuf_ring.mojo `_pbuf_ring_add` | `pbufIdx_wrap`, `pbuf_add_preserves_tail` | proved |
| `Flare.Kernels.BufLedger.classify`, `Ledger.onFill`, `Ledger.onComplete` | flare/http/_bufring_ledger.mojo `classify_recv`, `BufLedger.on_fill`, `on_complete` | `classify_ok`, `run_conserved`, `run_inRing_le`, `run_drained` | proved; difftest `bufring_ledger.trace` |
| `Flare.Kernels.CStr.verdict` | flare/net/cstr.mojo `c_str_verdict` | `verdict_ok`, `cRead_append_nul`, `pass_exact`, `pass_complete` | proved; difftest `cstr.cross`, fuzz `fuzz-cstr` |
| `Flare.L2.UringWakeup.lazyArm`, `drain`, `poll` | flare/runtime/uring_reactor.mojo `UringReactor.poll`, `_try_arm_wakeup`, `_arm_wakeup_recv`, `_drain_into_tracking` | `poll_inv`, `poll_never_blocks_unarmed` | proved (RT-03, resolved) |
| `Flare.L2.TimerWheel.init`, `schedule`, `cancel` | flare/runtime/timer_wheel.mojo `TimerWheel.__init__`, `schedule`, `cancel` | `inv_schedule`, `schedule_spec`, `cancel_spec` | proved |
| `Flare.L2.TimerWheel.stepTick`, `drainOne`, `jump`, `jumpIds`, `rebucketOne`, `advance` | flare/runtime/timer_wheel.mojo `TimerWheel.advance`, `_jump` | `advance_spec`, `jump_equiv_ticks`, `run_nodup` | proved |
| `Flare.L2.TimerWheel.nextFire`, `hintLimit` | flare/runtime/timer_wheel.mojo `TimerWheel.next_fire_ms` | `nextFire_lower_bound` | proved (RT-01, resolved) |
| `Flare.L2.Handoff.pushed`, `pop`, `drainGo` | flare/runtime/handoff.mojo `HandoffQueue.push`, `pop`, `drain` | `push_refines`, `pop_refines`, `drain_refines`, `cap_zero_safe` | proved |
| `Flare.L2.Handoff.peekWith`, `peekIdle` | flare/runtime/handoff.mojo `WorkerHandoffPool.peek_idle_worker` | `peek_below_capacity` | proved (RT-04, resolved) |
| `Flare.L2.Handoff.chooseTarget` | flare/runtime/handoff.mojo `WorkerHandoffPool.choose_handoff_target` | `chooseTarget_spec` | proved |
| `Flare.L2.FrameMux.encodeFrame`, `decodeFrame` | flare/uds/frame_mux.mojo `encode_frame`, `decode_frame` | `decode_encode` | proved |
| `Flare.L2.FrameMux.feedLoop`, `feed`, `route`, `poll` | flare/uds/frame_mux.mojo `FrameDemux.feed`, `_peek_len`, `_route`, `poll` | `feed_chunking`, `drain_sound`, `drain_complete`, `routeAll_eq` | proved |
| `Flare.L2.FrameMux.feedM`, `feedLoopM` | flare/uds/frame_mux.mojo `FrameDemux.feed` | `feedM_error_stuck`, `feedM_no_duplicates` | proved (NET-04, resolved) |
| `Flare.L2.FrameMux.nextId` | flare/uds/frame_mux.mojo `FrameMux.next_id` | `nextId_injective`, `nextId_wraps` | proved |
| `Flare.L2.Udp.readPort`, `readAddr4`, `readAddr6` | flare/net/_libc.mojo `_read_port_from_sockaddr`, `_read_ip_from_sockaddr`, `_read_ipv6_from_sockaddr` | `impl_addr6`, `addr4_ok` | proved |
| `Flare.L2.Udp.implBufLen` | flare/udp/socket.mojo `UdpSocket.recv_from`, `try_recv_from` | `impl_addr6` | proved (NET-01, resolved) |
| `Flare.L2.Uds.fill` | flare/uds/_libc.mojo `fill_sockaddr_un` | `fill_len_le` | proved |
| `Flare.L2.Uds.readPath` | flare/uds/_libc.mojo `read_path_from_sockaddr_un` | `readPath_fill` | proved (NET-06, resolved) |
| `Flare.L2.DnsCache.key` | flare/dns/cache.mojo `DnsCache._key` | `key_fqdn_case`, `key_not_idempotent` | proved |
| `Flare.L2.DnsCache.oldestGo`, `evict`, `satAdd`, `store`, `resolve` | flare/dns/cache.mojo `DnsCache._store`, `resolve` | `satAdd_toInt`, `store_size_bound`, `store_hits_within_ttl` | proved (NET-03, resolved) |
| `Flare.L2.BufferPool.classIndex`, `capacityFor` | flare/runtime/buffer_pool.mojo `_class_index_for`, `_capacity_for_class` | `classIndex_fits`, `classIndex_least` | proved |
| `Flare.L2.BufferPool.acquire`, `releaseWith`, `release` | flare/runtime/buffer_pool.mojo `BufferPool.acquire`, `release` | `bounded_release`, `release_preserves_capacity` | proved (RT-05, resolved) |
| `Flare.L2.Blocking.tryAcquire`, `release` | flare/runtime/blocking.mojo `_pool_try_acquire`, `_pool_release`, `_pool_sem_open` | `paired_cap_invariant`, `cap_invariant`, `cap_from_init` | proved (RT-06, RT-07, resolved) |
| `Flare.L2.Blocking.SemOpen.tryAcquire`, `release` | flare/runtime/blocking.mojo `_pool_try_acquire`, `_pool_release`, `_sem_open_failed` | `SemOpen.never_crashes`, `SemOpen.failure_fails_closed` | proved (RT-08, resolved) |
| `Flare.L2.HappyEyeballs.order` | flare/dns/async_resolve.mojo `order_happy_eyeballs` | `order_eq`, `order_perm`, `order_filter_v6`, `order_head` | proved (NET-10, resolved) |
| `Flare.L2.Hostname.scan`, `validate`, `tooLongTail` | flare/dns/resolver.mojo `resolve` | `validate_sound`, `validate_iff`, `tooLongTail_wf` | proved (NET-08, NET-09, resolved) |
| `Flare.L2.UdsListener.prep`, `record`, `deinitUnlinks` | flare/uds/listener.mojo `UnixListener.bind_with_options`, `__init__`, `__deinit__` | `prep_safe`, `deinit_spec`, `deinit_race` | proved (NET-07, resolved) |
| `Flare.L2.UdpBatch.IOVEC`, `MSGHDR`, `MMSGHDR`, `OFF_MSG`, `CMSG_LEN_GSO`, ... | flare/udp/batch.mojo `_IOVEC`, `_MSGHDR`, `_MMSGHDR`, `_OFF_*`, `_CMSG_*` | `layout_constants`, `cmsg_constants` | proved |
| `Flare.L2.UdpBatch.gsoCtrl`, `cmsgs` | flare/udp/batch.mojo `send_segmented` | `gso_walk_18`, `gso_walk_24`, `gso_seg` | proved |
| `Flare.L2.UdpBatch.allocSize`, `accepts` | flare/udp/batch.mojo `BatchReceiver.__init__` | `slots_disjoint`, `accepts_refuses_wrap`, `covers_fixed` | proved (NET-11, resolved) |
| `Flare.L2.TimerWheel.jump` (order) | flare/runtime/timer_wheel.mojo `TimerWheel._jump` | `jump_fire_order`, `jump_not_sorted` | proved |
| `Flare.L2.TimerWheel.schedule64`, `advance64`, `jump64`, `ticks64`, `nextFire64` | flare/runtime/timer_wheel.mojo `TimerWheel.schedule`, `advance`, `_jump`, `next_fire_ms` | `advance64_eq`, `run64_eq`, `nextFire64_eq`, `nextFire64_wraps` | proved |
