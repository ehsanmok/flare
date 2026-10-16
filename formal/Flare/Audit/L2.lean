import Flare.L2_Machine
/-! L2 OS-facing machines: axiom footprint of the headline theorems. Expected:
`propext`, `Quot.sound`, `Classical.choice` (some use none). -/

-- Socket ownership, timeval, accept
#print axioms Flare.L2.Socket.close_idempotent
#print axioms Flare.L2.Socket.fd_closed_once
#print axioms Flare.L2.Socket.timeval_exact
#print axioms Flare.L2.Socket.timeval_fits
#print axioms Flare.L2.Socket.accept_nodelay_safe
#print axioms Flare.L2.Socket.accept_never_leaks
-- Write / read loops
#print axioms Flare.L2.WriteLoop.writeAll_terminates_weak
#print axioms Flare.L2.WriteLoop.writeAll_terminates_strong
#print axioms Flare.L2.WriteLoop.writeAll_no_overshoot
#print axioms Flare.L2.WriteLoop.udsWriteAll_eq
#print axioms Flare.L2.WriteLoop.readExact_terminates
#print axioms Flare.L2.WriteLoop.writevAll_strong
#print axioms Flare.L2.WriteLoop.writevAll_done_complete
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
#print axioms Flare.L2.TimerWheel.nextFire_lower_bound
-- Handoff queue
#print axioms Flare.L2.Handoff.push_refines
#print axioms Flare.L2.Handoff.pop_refines
#print axioms Flare.L2.Handoff.drain_refines
#print axioms Flare.L2.Handoff.cap_zero_safe
#print axioms Flare.L2.Handoff.peek_below_capacity
#print axioms Flare.L2.Handoff.chooseTarget_spec
-- FrameMux / FrameDemux
#print axioms Flare.L2.FrameMux.decode_encode
#print axioms Flare.L2.FrameMux.feed_chunking
#print axioms Flare.L2.FrameMux.drain_sound
#print axioms Flare.L2.FrameMux.drain_complete
#print axioms Flare.L2.FrameMux.routeAll_eq
#print axioms Flare.L2.FrameMux.nextId_injective
#print axioms Flare.L2.FrameMux.feedM_error_stuck
#print axioms Flare.L2.FrameMux.feedM_no_duplicates
-- UDP recvfrom, UDS sockaddr_un
#print axioms Flare.L2.Udp.impl_addr6
#print axioms Flare.L2.Udp.addr4_ok
#print axioms Flare.L2.Uds.fill_len_le
#print axioms Flare.L2.Uds.readPath_fill
-- DnsCache
#print axioms Flare.L2.DnsCache.store_size_bound
#print axioms Flare.L2.DnsCache.store_hits_within_ttl
-- BufferPool
#print axioms Flare.L2.BufferPool.classIndex_fits
#print axioms Flare.L2.BufferPool.classIndex_least
#print axioms Flare.L2.BufferPool.bounded_release
#print axioms Flare.L2.BufferPool.release_preserves_capacity
-- Blocking pool cap
#print axioms Flare.L2.Blocking.paired_cap_invariant
#print axioms Flare.L2.Blocking.cap_invariant
#print axioms Flare.L2.Blocking.SemOpen.never_crashes
#print axioms Flare.L2.Blocking.SemOpen.failure_fails_closed
-- Fixed findings

-- Happy Eyeballs ordering, hostname validation, UDS bind takeover
#print axioms Flare.L2.HappyEyeballs.order_perm
#print axioms Flare.L2.HappyEyeballs.order_filter_v6
#print axioms Flare.L2.HappyEyeballs.order_filter_v4
#print axioms Flare.L2.HappyEyeballs.order_head
#print axioms Flare.L2.HappyEyeballs.order_get_even_v4first
#print axioms Flare.L2.Hostname.validate_sound
#print axioms Flare.L2.Hostname.validate_iff
#print axioms Flare.L2.Hostname.tooLongTail_wf
#print axioms Flare.L2.UdsListener.prep_safe
#print axioms Flare.L2.UdsListener.deinit_spec
#print axioms Flare.L2.UdsListener.deinit_race

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
