import Flare.L3_Protocol.QuicH3

-- QUIC: wire / frame parser
#print axioms Flare.L3.Quic.Frame.parseFrame_good
#print axioms Flare.L3.Quic.Frame.parseFrame_progress
#print axioms Flare.L3.Quic.Frame.ack_range_cap
#print axioms Flare.L3.Quic.Frame.newcid_checks
#print axioms Flare.L3.Quic.Frame.parseFrame_not_unknown
#print axioms Flare.L3.Quic.Frame.parsePayload_not_unknown
#print axioms Flare.L3.Quic.Frame.parseFrameFixed_ok
#print axioms Flare.L3.Quic.Frame.parsePayloadFixed_ok
-- QUIC: packet numbers, connection state, ACK expansion, loss recovery
#print axioms Flare.L3.Quic.PacketNumber.decodePnImpl_eq_rfc
#print axioms Flare.L3.Quic.PacketNumber.decodePnImpl_window
#print axioms Flare.L3.Quic.Conn.specRun_absorbing
#print axioms Flare.L3.Quic.Conn.run_eq_spec
#print axioms Flare.L3.Quic.Conn.implStep_eq_spec
#print axioms Flare.L3.Quic.Conn.implStep_frame_spec
#print axioms Flare.L3.Quic.Conn.implStep_client_eq_spec
#print axioms Flare.L3.Quic.Conn.implStep_absorbing
#print axioms Flare.L3.Quic.AckExpand.expand_sound
#print axioms Flare.L3.Quic.AckExpand.expand_len_le
#print axioms Flare.L3.Quic.LossRecovery.inv_run
#print axioms Flare.L3.Quic.LossRecovery.retire_noUnderflow
#print axioms Flare.L3.Quic.LossRecovery.firePto_noUnderflow
-- QPACK
#print axioms Flare.L3.Qpack.Ric.implDecode_eq_spec
#print axioms Flare.L3.Qpack.Ric.implDecode_encode
#print axioms Flare.L3.Qpack.Ric.implDecode_cap0
#print axioms Flare.L3.Qpack.Ric.sectionImpl_spec
#print axioms Flare.L3.Qpack.Table.inv_insert
#print axioms Flare.L3.Qpack.Table.inv_setCapacity
#print axioms Flare.L3.Qpack.Table.getAbs_insert
#print axioms Flare.L3.Qpack.FieldSection.decodeInt_offset_le
#print axioms Flare.L3.Qpack.FieldSection.implResolve_eq_spec
#print axioms Flare.L3.Qpack.FieldSection.implSignReadIndex_inBounds
#print axioms Flare.L3.Qpack.FieldSection.implLiteral_ok
#print axioms Flare.L3.Qpack.FieldSection.implDynRef_eq_spec
#print axioms Flare.L3.Qpack.FieldSection.implLiteralRaw_eq_spec
#print axioms Flare.L3.Qpack.FieldSection.implLiteralRaw_huffman
#print axioms Flare.L3.Qpack.FieldSection.implLiteral_eq_spec_of_ok
#print axioms Flare.L3.Qpack.Encoder.findBy_some
#print axioms Flare.L3.Qpack.Encoder.findBy_none
#print axioms Flare.L3.Qpack.Encoder.ric_bound
#print axioms Flare.L3.Qpack.Encoder.implInsert_noEvict
#print axioms Flare.L3.Qpack.Encoder.encoder_spec
-- HTTP/3
#print axioms Flare.L3.H3.decodeFrame_encode
#print axioms Flare.L3.H3.decodeSettings_encode
#print axioms Flare.L3.H3.decVarint_eq
#print axioms Flare.L3.H3.realEnc_codec
#print axioms Flare.L3.H3.realEnc_pos
#print axioms Flare.L3.H3.real_decodeFrame_encode
#print axioms Flare.L3.H3.real_decodeSettings_encode
#print axioms Flare.L3.H3.feedChunks_chunking_independent
#print axioms Flare.L3.H3.run_accept_impl
#print axioms Flare.L3.H3.feed_bounded
#print axioms Flare.L3.H3.spec_rejects
#print axioms Flare.L3.H3.implRejects_reserved
#print axioms Flare.L3.H3.run_reject_impl
#print axioms Flare.L3.H3.Control.applySettingsFixed_eq_spec
#print axioms Flare.L3.H3.Control.dispatchControlFixed_eq_spec
#print axioms Flare.L3.H3.Control.classifyFixed_eq_spec
#print axioms Flare.L3.H3.Control.runClassifyFixed_unique
#print axioms Flare.L3.H3.ControlStart.emit_control_start
#print axioms Flare.L3.H3.ControlStart.implOut_spec
#print axioms Flare.L3.H3.ControlStart.real_emit_control_start
#print axioms Flare.L3.H3.ControlStart.real_implOut_spec
#print axioms Flare.L3.H3.ControlStart.control_stream_sendable
#print axioms Flare.L3.H3.ControlStart.control_classified
-- Fixed findings

-- QUIC transport parameters and peer-parameter checks
#print axioms Flare.L3.Quic.TransportParams.decodeFixed_eq_spec
#print axioms Flare.L3.Quic.TransportParams.specFrom_eq
#print axioms Flare.L3.Quic.PeerParams.clientCheckFixed_spec
#print axioms Flare.L3.Quic.PeerParams.serverCheck_spec
#print axioms Flare.L3.Quic.PeerParams.serverCheck_sound

-- H3 GOAWAY payload

-- H3 server control stream

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
#print axioms Flare.L3.Quic.AckGen.never_reaccepts

-- Stream states
#print axioms Flare.L3.Quic.Streams.checked_eq_spec
#print axioms Flare.L3.Quic.Streams.serverFixed_eq_spec
#print axioms Flare.L3.Quic.Streams.clientFixed_eq_spec
#print axioms Flare.L3.Quic.Streams.halves_reset_iff
#print axioms Flare.L3.Quic.Streams.halves_stop_iff

-- QUIC timers: idle timeout and closing/draining
#print axioms Flare.L3.Quic.Timers.fixed_closed_eq_spec
#print axioms Flare.L3.Quic.Timers.init_R
#print axioms Flare.L3.Quic.Timers.spec_none_never
#print axioms Flare.L3.Quic.Timers.spec_cc_on_close
#print axioms Flare.L3.Quic.Timers.spec_draining_silent
#print axioms Flare.L3.Quic.Timers.spec_closing_only_cc
#print axioms Flare.L3.Quic.Timers.spec_tick_before
#print axioms Flare.L3.Quic.Timers.cli_close_ok
#print axioms Flare.L3.Quic.Timers.effectiveMs_spec
#print axioms Flare.L3.Quic.Timers.srvFix_refines

-- Transport-parameter encoder
#print axioms Flare.L3.Quic.TransportParams.tlvs_wire
#print axioms Flare.L3.Quic.TransportParams.encode_roundtrip
#print axioms Flare.L3.Quic.TransportParams.real_tlvs_wire
#print axioms Flare.L3.Quic.TransportParams.real_encode_roundtrip
