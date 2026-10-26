import Flare.L3_Protocol.H2

-- Frame codec
#print axioms Flare.L3.H2.parse_encode
#print axioms Flare.L3.H2.parse_short
#print axioms Flare.L3.H2.parse_never_raises
#print axioms Flare.L3.H2.parse_consumed
#print axioms Flare.L3.H2.precheck_bounds
-- HPACK dynamic table, synchronisation, decoder
#print axioms Flare.L3.H2.Hpack.evict_spec
#print axioms Flare.L3.H2.Hpack.insert_spec
#print axioms Flare.L3.H2.Hpack.lookup_spec
#print axioms Flare.L3.H2.Hpack.inv_insert
#print axioms Flare.L3.H2.Hpack.inv_sizeUpdate
#print axioms Flare.L3.H2.Hpack.utf8Lossy_length_ge
#print axioms Flare.L3.H2.Hpack.sync_exact_shipped
#print axioms Flare.L3.H2.Hpack.prefix_inv
#print axioms Flare.L3.H2.Hpack.prefix_inv_flare
#print axioms Flare.L3.H2.Hpack.lookup_sound
#print axioms Flare.L3.H2.Hpack.sync_exact
#print axioms Flare.L3.H2.Hpack.jinv_withConfig
#print axioms Flare.L3.H2.Hpack.decode_budget_fixed
#print axioms Flare.L3.H2.Hpack.decode_budget
#print axioms Flare.L3.H2.Hpack.decode_table_inv
#print axioms Flare.L3.H2.Hpack.decode_encode
-- Request header validation
#print axioms Flare.L3.H2.Validate.loop_iff
#print axioms Flare.L3.H2.Validate.fold_facts
#print axioms Flare.L3.H2.Validate.nameOK_iff
#print axioms Flare.L3.H2.Validate.validate_names
-- Connection state machine: invariants, flow control, per-clause theorems
#print axioms Flare.L3.H2.Conn.win_reachable
#print axioms Flare.L3.H2.Conn.run_live
#print axioms Flare.L3.H2.Conn.h2_01_fixed
#print axioms Flare.L3.H2.Conn.h2_09_fixed
#print axioms Flare.L3.H2.Conn.handle_headers0
#print axioms Flare.L3.H2.Conn.handle_goaway_short
#print axioms Flare.L3.H2.Conn.handle_reuse
#print axioms Flare.L3.H2.Conn.handle_client_unopened
#print axioms Flare.L3.H2.Conn.drive_first_not_settings
#print axioms Flare.L3.H2.Conn.handle_client_late_wu
#print axioms Flare.L3.H2.Conn.handle_client_late_rst
#print axioms Flare.L3.H2.Conn.refuse_at_limit
#print axioms Flare.L3.H2.Conn.endLocal_hcr
#print axioms Flare.L3.H2.Conn.endLocal_closed
#print axioms Flare.L3.H2.Conn.headersPre_hcr
#print axioms Flare.L3.H2.Conn.isIdleId_even
#print axioms Flare.L3.H2.Conn.shape_rst_even
#print axioms Flare.L3.H2.Conn.shape_priority_idle
#print axioms Flare.L3.H2.Conn.wuH_zero_idle
#print axioms Flare.L3.H2.Conn.client_oversize
#print axioms Flare.L3.H2.Conn.dataFinish_no_stream_wu
#print axioms Flare.L3.H2.Conn.dataH_closed
#print axioms Flare.L3.H2.Conn.dataH_stream_scoped
-- RFC 9110 §8.6 content-length
#print axioms Flare.L3.H2.ContentLength.clParse_sound
#print axioms Flare.L3.H2.ContentLength.clParse_complete
#print axioms Flare.L3.H2.ContentLength.declaredCL_sound
#print axioms Flare.L3.H2.ContentLength.declaredCL_complete
-- Connection sequencing (CONTINUATION, GOAWAY) and HPACK composition on the real codec
#print axioms Flare.L3.H2.Conn.seq_step
#print axioms Flare.L3.H2.Conn.seq_run
#print axioms Flare.L3.H2.Conn.hb_local
#print axioms Flare.L3.H2.Hpack.pinv_init
#print axioms Flare.L3.H2.Hpack.decodeOne_rep
#print axioms Flare.L3.H2.Hpack.decode_block
#print axioms Flare.L3.H2.Hpack.real_correct
#print axioms Flare.L3.H2.Hpack.real_huff
#print axioms Flare.L3.H2.Conn.decFold_blocks
#print axioms Flare.L3.H2.Conn.seq_runD
#print axioms Flare.L3.H2.Conn.lookup_sound_conn
#print axioms Flare.L3.H2.Conn.real_lookup_sound_conn
#print axioms Flare.L3.H2.Hpack.real_decode_encode
#print axioms Flare.L3.H2.Hpack.real_decode_block
-- RFC 9113 §5.1: spec LTS and the connection's refinement of it
#print axioms Flare.L3.H2.StreamSpec.closed_no_send_wu
#print axioms Flare.L3.H2.Refine.fixed_handleW
#print axioms Flare.L3.H2.Refine.fixed_frame
#print axioms Flare.L3.H2.Refine.fixed_local
#print axioms Flare.L3.H2.Refine.fixed_step
#print axioms Flare.L3.H2.Refine.fixed_run
#print axioms Flare.L3.H2.Refine.fixed_refines
-- Client streaming-body mode
#print axioms Flare.L3.H2.Streaming.step_rel
#print axioms Flare.L3.H2.Streaming.ti_step
#print axioms Flare.L3.H2.Streaming.ti_run
#print axioms Flare.L3.H2.Streaming.pending_le
#print axioms Flare.L3.H2.Streaming.fifo_run
#print axioms Flare.L3.H2.Streaming.data_credit
#print axioms Flare.L3.H2.Streaming.drain_credit
