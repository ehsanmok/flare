import Flare.L3_Protocol.QuicH3

-- QUIC: wire / frame parser
#print axioms Flare.L3.Quic.Frame.parseFrame_good
#print axioms Flare.L3.Quic.Frame.parseFrame_progress
#print axioms Flare.L3.Quic.Frame.ack_range_cap
#print axioms Flare.L3.Quic.Frame.newcid_checks
#print axioms Flare.L3.Quic.Frame.parseFrameFixed_ok
#print axioms Flare.L3.Quic.Frame.parsePayloadFixed_ok
-- QUIC: packet numbers, connection state, ACK expansion, loss recovery
#print axioms Flare.L3.Quic.PacketNumber.decodePnImpl_eq_rfc
#print axioms Flare.L3.Quic.PacketNumber.decodePnImpl_window
#print axioms Flare.L3.Quic.Conn.specRun_absorbing
#print axioms Flare.L3.Quic.Conn.runFixed_eq_spec
#print axioms Flare.L3.Quic.Conn.implStep_frame_spec
#print axioms Flare.L3.Quic.AckExpand.expand_sound
#print axioms Flare.L3.Quic.AckExpand.expand_len_le
#print axioms Flare.L3.Quic.LossRecovery.inv_run
#print axioms Flare.L3.Quic.LossRecovery.retire_noUnderflow
#print axioms Flare.L3.Quic.LossRecovery.firePto_noUnderflow
-- QPACK
#print axioms Flare.L3.Qpack.Ric.implDecode_eq_spec
#print axioms Flare.L3.Qpack.Ric.implDecode_encode
#print axioms Flare.L3.Qpack.Table.inv_insert
#print axioms Flare.L3.Qpack.Table.inv_setCapacity
#print axioms Flare.L3.Qpack.Table.getAbs_insert
#print axioms Flare.L3.Qpack.FieldSection.decodeInt_offset_le
#print axioms Flare.L3.Qpack.FieldSection.implFixedResolve_eq_spec
#print axioms Flare.L3.Qpack.FieldSection.spec_imp_impl
#print axioms Flare.L3.Qpack.FieldSection.implFixedSignReadIndex_inBounds
#print axioms Flare.L3.Qpack.FieldSection.implFixedLiteral_ok
#print axioms Flare.L3.Qpack.FieldSection.implFixedDynRef_eq_spec
#print axioms Flare.L3.Qpack.FieldSection.implLiteral_eq_spec
#print axioms Flare.L3.Qpack.FieldSection.implLiteral_huffman
#print axioms Flare.L3.Qpack.Encoder.findBy_some
#print axioms Flare.L3.Qpack.Encoder.findBy_none
#print axioms Flare.L3.Qpack.Encoder.ric_bound
-- HTTP/3
#print axioms Flare.L3.H3.decodeFrame_encode
#print axioms Flare.L3.H3.decodeSettings_encode
#print axioms Flare.L3.H3.feedChunks_chunking_independent
#print axioms Flare.L3.H3.run_accept_impl
#print axioms Flare.L3.H3.run_reject_impl
#print axioms Flare.L3.H3.Control.applySettingsFixed_eq_spec
#print axioms Flare.L3.H3.Control.dispatchControlFixed_eq_spec
#print axioms Flare.L3.H3.Control.classifyFixed_eq_spec
#print axioms Flare.L3.H3.Control.runClassifyFixed_unique
-- Bugs: counterexamples and fixes
#print axioms Flare.Bugs.QUIC_01.violates_spec
#print axioms Flare.Bugs.QUIC_01.fixed_meets_spec
#print axioms Flare.Bugs.QUIC_02.violates_spec
#print axioms Flare.Bugs.QUIC_02.fixed_meets_spec
#print axioms Flare.Bugs.QUIC_03.violates_spec
#print axioms Flare.Bugs.QUIC_03.fixed_meets_spec
#print axioms Flare.Bugs.QUIC_04.violates_spec
#print axioms Flare.Bugs.QUIC_04.fixed_refines
#print axioms Flare.Bugs.QUIC_09.violates_spec
#print axioms Flare.Bugs.QUIC_09.fixed_meets_spec
#print axioms Flare.Bugs.QPACK_01.violates_safety
#print axioms Flare.Bugs.QPACK_01.fixed_meets_spec
#print axioms Flare.Bugs.QPACK_02.out_of_bounds
#print axioms Flare.Bugs.QPACK_02.fixed_inBounds
#print axioms Flare.Bugs.QPACK_03.not_string_ok
#print axioms Flare.Bugs.QPACK_03.fixed_ok
#print axioms Flare.Bugs.QPACK_04.counterexample
#print axioms Flare.Bugs.QPACK_04.fixed_meets_spec
#print axioms Flare.Bugs.QPACK_03.huffman_counterexample
#print axioms Flare.Bugs.QPACK_05.impl_never_connErr
#print axioms Flare.Bugs.QPACK_05.shipped_rejects
#print axioms Flare.Bugs.QPACK_05.impl_counterexample
#print axioms Flare.Bugs.QPACK_05.impl_drops_blockable
#print axioms Flare.Bugs.QPACK_05.fixed_spec
#print axioms Flare.Bugs.QPACK_06.impl_references_unacked
#print axioms Flare.Bugs.QPACK_06.impl_evicts_unacked
#print axioms Flare.Bugs.QPACK_06.fixedInsert_noEvict
#print axioms Flare.Bugs.QPACK_06.fixed_spec
#print axioms Flare.Bugs.H3_01.violates_spec
#print axioms Flare.Bugs.H3_01.feedFixed_bounded
#print axioms Flare.Bugs.H3_02.violates_spec
#print axioms Flare.Bugs.H3_02.runFixed_spec
#print axioms Flare.Bugs.H3_03.spec_rejects
#print axioms Flare.Bugs.H3_03.dispatchFixed_spec
#print axioms Flare.Bugs.H3_04.spec_rejects
#print axioms Flare.Bugs.H3_04.applyFixed_spec
#print axioms Flare.Bugs.H3_05.violates_spec
#print axioms Flare.Bugs.H3_05.classifyFixed_spec

-- QUIC transport parameters and peer-parameter checks
#print axioms Flare.L3.Quic.TransportParams.decodeFixed_eq_spec
#print axioms Flare.L3.Quic.TransportParams.specFrom_eq
#print axioms Flare.L3.Quic.PeerParams.clientCheckFixed_spec
#print axioms Flare.L3.Quic.PeerParams.serverCheck_spec
#print axioms Flare.Bugs.QUIC_10.impl_accepts
#print axioms Flare.Bugs.QUIC_10.decodeFixed_spec
#print axioms Flare.Bugs.QUIC_11.impl_accepts
#print axioms Flare.Bugs.QUIC_11.serverCheck_spec
#print axioms Flare.Bugs.QUIC_12.impl_accepts_absent_iscid
#print axioms Flare.Bugs.QUIC_12.impl_accepts_empty_rscid
#print axioms Flare.Bugs.QUIC_12.impl_accepts_pa_with_empty_cid
#print axioms Flare.Bugs.QUIC_12.checkFixed_spec
#print axioms Flare.Bugs.QUIC_13.impl_accepts
#print axioms Flare.Bugs.QUIC_13.decodeFixed_spec

-- H3 GOAWAY payload
#print axioms Flare.Bugs.H3_06.impl_accepts_trailing
#print axioms Flare.Bugs.H3_06.spec_rejects_trailing
#print axioms Flare.Bugs.H3_06.trace_impl
#print axioms Flare.Bugs.H3_06.goawayFixed_spec
#print axioms Flare.Bugs.H3_06.dispatchFixed_spec

-- H3 server control stream
#print axioms Flare.Bugs.H3_07.impl_no_control
#print axioms Flare.Bugs.H3_07.impl_observed
#print axioms Flare.Bugs.H3_07.emit_control_start
#print axioms Flare.Bugs.H3_07.fixed_spec
#print axioms Flare.Bugs.H3_07.fixed_stream_sendable
#print axioms Flare.Bugs.H3_07.fixed_classified

-- ACK expansion completeness and ACK generation
#print axioms Flare.L3.Quic.AckExpand.expand_eq_take
#print axioms Flare.L3.Quic.AckExpand.expand_complete
#print axioms Flare.L3.Quic.AckExpand.expand_length
#print axioms Flare.L3.Quic.AckGen.record_canon
#print axioms Flare.L3.Quic.AckGen.record_exact
#print axioms Flare.L3.Quic.AckGen.record_sound
#print axioms Flare.L3.Quic.AckGen.record_drops_lowest
#print axioms Flare.L3.Quic.AckGen.fromRanges_claimed
#print axioms Flare.L3.Quic.AckGen.fromRanges_wellFormed
#print axioms Flare.L3.Quic.AckGen.ack_roundtrip
#print axioms Flare.L3.Quic.AckGen.drain_after_recv
#print axioms Flare.Bugs.QUIC_14.impl_reaccepts
#print axioms Flare.Bugs.QUIC_14.fixed_never_reaccepts

-- Stream states
#print axioms Flare.L3.Quic.Streams.checked_eq_spec
#print axioms Flare.L3.Quic.Streams.server_stream_conforms
#print axioms Flare.L3.Quic.Streams.serverFixed_eq_spec
#print axioms Flare.L3.Quic.Streams.clientFixed_eq_spec
#print axioms Flare.L3.Quic.Streams.halves_reset_iff
#print axioms Flare.L3.Quic.Streams.halves_stop_iff
#print axioms Flare.Bugs.QUIC_15.impl_accepts
#print axioms Flare.Bugs.QUIC_15.fixed_spec
#print axioms Flare.Bugs.QUIC_16.impl_accepts
#print axioms Flare.Bugs.QUIC_16.fixed_spec
#print axioms Flare.Bugs.QUIC_17.impl_accepts
#print axioms Flare.Bugs.QUIC_17.fixed_spec
#print axioms Flare.Bugs.QUIC_18.impl_loses
#print axioms Flare.Bugs.QUIC_18.fixed_spec
#print axioms Flare.Bugs.QUIC_19.impl_silent
#print axioms Flare.Bugs.QUIC_19.fixed_spec

-- QUIC timers: idle timeout and closing/draining
#print axioms Flare.L3.Quic.Timers.fixed_closed_eq_spec
#print axioms Flare.L3.Quic.Timers.init_R
#print axioms Flare.L3.Quic.Timers.spec_none_never
#print axioms Flare.L3.Quic.Timers.client_never
#print axioms Flare.L3.Quic.Timers.spec_cc_on_close
#print axioms Flare.L3.Quic.Timers.spec_draining_silent
#print axioms Flare.L3.Quic.Timers.spec_closing_only_cc
#print axioms Flare.L3.Quic.Timers.spec_tick_before
#print axioms Flare.L3.Quic.Timers.cli_close_ok
#print axioms Flare.Bugs.QUIC_20.impl_unauth_restarts
#print axioms Flare.Bugs.QUIC_20.impl_ignores_peer
#print axioms Flare.Bugs.QUIC_20.impl_zero_closes
#print axioms Flare.Bugs.QUIC_20.impl_no_send_restart
#print axioms Flare.Bugs.QUIC_20.impl_no_pto_floor
#print axioms Flare.Bugs.QUIC_20.fixed_spec
#print axioms Flare.Bugs.QUIC_21.impl_never_closes
#print axioms Flare.Bugs.QUIC_21.impl_counterexample
#print axioms Flare.Bugs.QUIC_21.fixed_spec
#print axioms Flare.Bugs.QUIC_22.impl_no_cc
#print axioms Flare.Bugs.QUIC_22.spec_answers
#print axioms Flare.Bugs.QUIC_22.impl_short_period
#print axioms Flare.Bugs.QUIC_22.fixed_spec
#print axioms Flare.Bugs.QUIC_23.impl_sends_draining
#print axioms Flare.Bugs.QUIC_23.impl_trace
#print axioms Flare.Bugs.QUIC_23.fixed_spec
#print axioms Flare.Bugs.QUIC_24.impl_sends_draining
#print axioms Flare.Bugs.QUIC_24.impl_trace
#print axioms Flare.Bugs.QUIC_24.fixed_spec
#print axioms Flare.Bugs.QUIC_24.close_ok

-- Transport-parameter encoder
#print axioms Flare.L3.Quic.TransportParams.tlvs_wire
#print axioms Flare.L3.Quic.TransportParams.encode_roundtrip
