import Flare.L2_Machine
/-! L2 OS-facing machines: axiom footprint of the headline theorems. Expected:
`propext`, `Quot.sound`, `Classical.choice` (some use none). Counterexamples
in `Flare.Bugs.NET_*` / `Flare.Bugs.RT_*` proved by `native_decide` also show
the per-theorem auxiliary axiom `<thm>._native.native_decide.ax_1_1`. -/

-- Socket ownership, timeval, accept
#print axioms Flare.L2.Socket.close_idempotent
#print axioms Flare.L2.Socket.fd_closed_once
#print axioms Flare.L2.Socket.sched_patch_closes_once
#print axioms Flare.L2.Socket.timeval_exact
#print axioms Flare.L2.Socket.timeval_fits
#print axioms Flare.L2.Socket.accept_nodelay_safe
-- Write / read loops
#print axioms Flare.L2.WriteLoop.writeAll_terminates_weak
#print axioms Flare.L2.WriteLoop.writeAll_terminates_strong
#print axioms Flare.L2.WriteLoop.writeAll_no_overshoot
#print axioms Flare.L2.WriteLoop.udsWriteAll_eq
#print axioms Flare.L2.WriteLoop.readExact_terminates
#print axioms Flare.L2.WriteLoop.writevAll_strong
-- BufReader
#print axioms Flare.L2.BufReader.consume_view
#print axioms Flare.L2.BufReader.readExact_correct
-- connect_timeout
#print axioms Flare.L2.ConnectTimeout.flags_restored
#print axioms Flare.L2.ConnectTimeout.never_left_nonblocking
-- Reactor
#print axioms Flare.L2.Reactor.register_refines
#print axioms Flare.L2.Reactor.unregister_always_removes
#print axioms Flare.L2.Reactor.agree_register
#print axioms Flare.L2.Reactor.agree_unregister
#print axioms Flare.L2.Reactor.agree_close
#print axioms Flare.L2.Reactor.fd_reuse_safe
#print axioms Flare.L2.Reactor.roundtrip_rw
#print axioms Flare.L2.Reactor.dispatch_rw_equiv
-- io_uring rings
#print axioms Flare.L2.IoUring.ringDistance_true
#print axioms Flare.L2.IoUring.live_slots_distinct
#print axioms Flare.L2.IoUring.nextSqe_fresh
#print axioms Flare.L2.IoUring.sq_reachable_inv
#print axioms Flare.L2.IoUring.reap_count
#print axioms Flare.L2.IoUring.pbufIdx_wrap
#print axioms Flare.L2.IoUring.pbuf_add_preserves_tail
-- UringReactor wakeup
#print axioms Flare.L2.UringWakeup.pollWith_inv
#print axioms Flare.L2.UringWakeup.poll_inv
#print axioms Flare.L2.UringWakeup.poll_never_blocks_unarmed
-- Timer wheel
#print axioms Flare.L2.TimerWheel.inv_run
#print axioms Flare.L2.TimerWheel.schedule_spec
#print axioms Flare.L2.TimerWheel.cancel_spec
#print axioms Flare.L2.TimerWheel.advance_spec
#print axioms Flare.L2.TimerWheel.advance_no_early_fire
#print axioms Flare.L2.TimerWheel.advance_no_late_fire
#print axioms Flare.L2.TimerWheel.advance_backwards_noop
#print axioms Flare.L2.TimerWheel.jump_equiv_ticks
#print axioms Flare.L2.TimerWheel.cancel_never_fires
#print axioms Flare.L2.TimerWheel.run_nodup
#print axioms Flare.L2.TimerWheel.nextFireFixed_lower_bound
#print axioms Flare.L2.TimerWheel.nextFire_lower_bound_no_overflow
-- Handoff queue
#print axioms Flare.L2.Handoff.push_refines
#print axioms Flare.L2.Handoff.pop_refines
#print axioms Flare.L2.Handoff.drain_refines
#print axioms Flare.L2.Handoff.cap_zero_safe
#print axioms Flare.L2.Handoff.peekFixed_below_capacity
#print axioms Flare.L2.Handoff.chooseTarget_spec
-- FrameMux / FrameDemux
#print axioms Flare.L2.FrameMux.decode_encode
#print axioms Flare.L2.FrameMux.feed_chunking
#print axioms Flare.L2.FrameMux.drain_sound
#print axioms Flare.L2.FrameMux.drain_complete
#print axioms Flare.L2.FrameMux.routeAll_eq
#print axioms Flare.L2.FrameMux.nextId_injective
#print axioms Flare.L2.FrameMux.feedM_error_stuck
-- UDP recvfrom, UDS sockaddr_un
#print axioms Flare.L2.Udp.impl_addr6
#print axioms Flare.L2.Udp.addr4_ok
#print axioms Flare.L2.Uds.fill_len_le
#print axioms Flare.L2.Uds.readPath_fill
#print axioms Flare.L2.Uds.readPathOld_fill_iff_ascii
-- DnsCache
#print axioms Flare.L2.DnsCache.store_size_bound
#print axioms Flare.L2.DnsCache.store_hits_within_ttl
#print axioms Flare.L2.DnsCache.huge_ttl_expiry_wraps
-- BufferPool
#print axioms Flare.L2.BufferPool.classIndex_fits
#print axioms Flare.L2.BufferPool.classIndex_least
#print axioms Flare.L2.BufferPool.bounded_release
#print axioms Flare.L2.BufferPool.releaseFixed_preserves_capacity
-- Blocking pool cap
#print axioms Flare.L2.Blocking.paired_cap_invariant
#print axioms Flare.L2.Blocking.fixed_cap_invariant
-- Bugs: counterexamples and fixes
#print axioms Flare.Bugs.NET_01.recvFrom_ipv6_wrong_sender
#print axioms Flare.Bugs.NET_01.recvFromFixed_correct
#print axioms Flare.Bugs.NET_02.writeAll_livelock
#print axioms Flare.Bugs.NET_02.writeAllFixed_terminates
#print axioms Flare.Bugs.NET_02.writeAll_zero_raises
#print axioms Flare.Bugs.NET_03.huge_ttl_never_hits
#print axioms Flare.Bugs.NET_03.huge_ttl_trace
#print axioms Flare.Bugs.NET_03.store_exceeds_max_at_INT_MAX
#print axioms Flare.Bugs.NET_03.storeFixed_hits_within_ttl
#print axioms Flare.Bugs.NET_03.storeFixed_size_bound
#print axioms Flare.Bugs.NET_04.feed_after_error_duplicates
#print axioms Flare.Bugs.NET_04.feedFixed_no_duplicates
#print axioms Flare.Bugs.NET_05.accept_leaks_on_decode_error
#print axioms Flare.Bugs.NET_05.acceptFixed_spec
#print axioms Flare.Bugs.NET_06.decode_encode_not_id
#print axioms Flare.Bugs.NET_06.decodeFixed_encode
#print axioms Flare.Bugs.RT_01.nextFire_not_lower_bound
#print axioms Flare.Bugs.RT_01.nextFireFixed_lower_bound
#print axioms Flare.Bugs.RT_02.writev_silent_short_write
#print axioms Flare.Bugs.RT_02.writevAllFixed_spec
#print axioms Flare.Bugs.RT_03.poll_blocks_unarmed
#print axioms Flare.Bugs.RT_03.poll_never_blocks_unarmed
#print axioms Flare.Bugs.RT_04.peek_returns_full_peer
#print axioms Flare.Bugs.RT_04.peekFixed_below_capacity
#print axioms Flare.Bugs.RT_05.acquire_after_shrunk_release
#print axioms Flare.Bugs.RT_05.releaseFixed_preserves_capacity
#print axioms Flare.Bugs.RT_06.persistentFailOpen_unbounded
#print axioms Flare.Bugs.RT_06.fixed_cap
#print axioms Flare.Bugs.RT_07.failOpen_breaks_cap
#print axioms Flare.Bugs.RT_07.fixed_cap_invariant
#print axioms Flare.Bugs.RT_08.linux_failure_crashes
#print axioms Flare.Bugs.RT_08.macos_failure_fails_open
#print axioms Flare.Bugs.RT_08.never_crashes
#print axioms Flare.Bugs.RT_08.agrees_with_old

-- Happy Eyeballs ordering, hostname validation, UDS bind takeover
#print axioms Flare.L2.HappyEyeballs.order_perm
#print axioms Flare.L2.HappyEyeballs.order_filter_v6
#print axioms Flare.L2.HappyEyeballs.order_filter_v4
#print axioms Flare.L2.HappyEyeballs.orderFixed_head
#print axioms Flare.L2.HappyEyeballs.orderFixed_perm
#print axioms Flare.L2.Hostname.validate_sound
#print axioms Flare.L2.Hostname.validate_gap
#print axioms Flare.L2.Hostname.validateFixed_iff
#print axioms Flare.L2.Hostname.tooLongTailFixed_wf
#print axioms Flare.L2.UdsListener.prep_agrees
#print axioms Flare.L2.UdsListener.prep_safe
#print axioms Flare.L2.UdsListener.deinit_spec
#print axioms Flare.L2.UdsListener.deinit_race
#print axioms Flare.Bugs.NET_07.takeover_unlinks_live
#print axioms Flare.Bugs.NET_07.prep_safe
#print axioms Flare.Bugs.NET_08.valid_but_rejected
#print axioms Flare.Bugs.NET_08.validateFixed_spec
#print axioms Flare.Bugs.NET_09.message_not_wf
#print axioms Flare.Bugs.NET_09.fixed_wf
#print axioms Flare.Bugs.NET_10.order_breaks_spec
#print axioms Flare.Bugs.NET_10.orderFixed_spec

-- UDP batch layout / cmsg walk; timer wheel jump order and UInt64 clock
#print axioms Flare.L2.UdpBatch.layout_constants
#print axioms Flare.L2.UdpBatch.cmsg_constants
#print axioms Flare.L2.UdpBatch.gso_walk_18
#print axioms Flare.L2.UdpBatch.gso_seg
#print axioms Flare.L2.UdpBatch.slots_disjoint
#print axioms Flare.L2.UdpBatch.covers_fixed
#print axioms Flare.L2.TimerWheel.jump_fire_order
#print axioms Flare.L2.TimerWheel.jump_not_sorted
#print axioms Flare.L2.TimerWheel.ticks_order_example
#print axioms Flare.L2.TimerWheel.advance64_eq
#print axioms Flare.L2.TimerWheel.nextFire64_eq
#print axioms Flare.L2.TimerWheel.nextFire64_wraps
#print axioms Flare.L2.TimerWheel.run64_eq
#print axioms Flare.L2.TimerWheel.run64_init
#print axioms Flare.Bugs.NET_11.allocSize_wraps
#print axioms Flare.Bugs.NET_11.covers_fixed
