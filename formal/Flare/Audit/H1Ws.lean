import Flare.L3_Protocol.H1Ws

-- Chunked transfer coding
#print axioms Flare.L3.H1.Chunked.scanL_done_append
#print axioms Flare.L3.H1.Chunked.scanL_resume
#print axioms Flare.L3.H1.Chunked.scanL_malformed_append
#print axioms Flare.L3.H1.Chunked.scanEnd_range
#print axioms Flare.L3.H1.Chunked.decL_of_scanL
#print axioms Flare.L3.H1.Chunked.scanL_total_le
#print axioms Flare.L3.H1.Chunked.parseSize_le
#print axioms Flare.L3.H1.Chunked.parseSize_fits
#print axioms Flare.L3.H1.Chunked.parseSize_wraps_unbounded
#print axioms Flare.L3.H1.Chunked.scanEnd_decode
#print axioms Flare.L3.H1.Chunked.scanResume_resume
#print axioms Flare.L3.H1.Chunked.scanEnd_segmentation_independent
#print axioms Flare.L3.H1.Chunked.poll_eq_oneShot
#print axioms Flare.L3.H1.Chunked.impl_poll_eq_oneShot
#print axioms Flare.L3.H1.Chunked.impl_done_stable
#print axioms Flare.L3.H1.Chunked.scanEnd_lfSafe
#print axioms Flare.L3.H1.Chunked.impl_agrees_lfTolerant
-- Header text and Content-Length grammar
#print axioms Flare.L3.H1.Text.tokens_strip
#print axioms Flare.L3.H1.Text.classify_strip
#print axioms Flare.L3.H1.Text.parseCL_strip
#print axioms Flare.L3.H1.Text.parseCL_append_term
#print axioms Flare.L3.H1.ContentLength.parseCL_complete
#print axioms Flare.L3.H1.ContentLength.parseCL_sound
#print axioms Flare.L3.H1.ContentLength.parseCL_invalid
#print axioms Flare.L3.H1.ContentLength.parseCL_fits
#print axioms Flare.L3.H1.ContentLength.parseCL_fitsI64
-- Request framing: reactor vs parser
#print axioms Flare.L3.H1.Framing.scan_of_shape
#print axioms Flare.L3.H1.Framing.scan_map_strip
#print axioms Flare.L3.H1.Framing.classify_join
#print axioms Flare.L3.H1.Framing.framing_agrees
#print axioms Flare.L3.H1.Framing.no_smuggling_strict
#print axioms Flare.L3.H1.Framing.lf_fixed_agrees
-- Field values and the String invariant
#print axioms Flare.L3.H1.FieldValue.strict_value_ascii
#print axioms Flare.L3.H1.FieldValue.strict_value_utf8
#print axioms Flare.L3.H1.FieldValue.fixed_value_utf8
-- WebSocket frame codec
#print axioms Flare.L3.Ws.maskFrom_involutive
#print axioms Flare.L3.Ws.appendMasked_eq
#print axioms Flare.L3.Ws.parseLen_extLen
#print axioms Flare.L3.Ws.decode_encode
#print axioms Flare.L3.Ws.decode_encode_len
#print axioms Flare.L3.Ws.lenCode_125
#print axioms Flare.L3.Ws.lenCode_126
#print axioms Flare.L3.Ws.lenCode_65535
#print axioms Flare.L3.Ws.lenCode_65536
#print axioms Flare.L3.Ws.decode_ok_shape
-- WebSocket receive paths
#print axioms Flare.L3.Ws.decodeKnown_safe
#print axioms Flare.L3.Ws.decodeKnown_encode
#print axioms Flare.L3.Ws.server_safe
#print axioms Flare.L3.Ws.clientAccept_safe
#print axioms Flare.L3.Ws.collect_spec
#print axioms Flare.L3.Ws.nextMessage_delivered
#print axioms Flare.L3.Ws.textPayload_ok_iff
-- obs-fold
#print axioms Flare.L3.H1.ObsFold.fieldsOld_fold_unfold
#print axioms Flare.L3.H1.ObsFold.fieldsOld_strict_no_fold
#print axioms Flare.L3.H1.ObsFold.strict_no_fold
#print axioms Flare.L3.H1.ObsFold.valueOk_join
#print axioms Flare.L3.H1.ObsFold.fieldsOld_ok_strict
#print axioms Flare.L3.H1.ObsFold.fields_valid
#print axioms Flare.L3.H1.ObsFold.fold_unfold
-- Client chunked body
#print axioms Flare.L3.H1.ClientChunked.cDec_agree
#print axioms Flare.L3.H1.ClientChunked.framed_chunked_agrees
#print axioms Flare.L3.H1.ClientChunked.cRead_complete
-- Client response: framing, status line, head, reuse, TLS EOF
#print axioms Flare.L3.H1.ClientResponse.framing_bodyless
#print axioms Flare.L3.H1.ClientResponse.framing_te_cl_reject
#print axioms Flare.L3.H1.ClientResponse.framing_dup_cl
#print axioms Flare.L3.H1.ClientResponse.framing_chunked_iff
#print axioms Flare.L3.H1.ClientResponse.framing_length_iff
#print axioms Flare.L3.H1.ClientResponse.framing_close_iff
#print axioms Flare.L3.H1.ClientResponse.parseStatus_delimited
#print axioms Flare.L3.H1.ClientResponse.canReuse_ok
#print axioms Flare.L3.H1.ClientResponse.splitGo_join
#print axioms Flare.L3.H1.ClientResponse.lfGo_join
#print axioms Flare.L3.H1.ClientResponse.headImpl_agrees
#print axioms Flare.L3.H1.ClientResponse.bufferedClose_safe
-- Chunked encoder round trip
#print axioms Flare.L3.H1.ChunkedEncode.hexAcc_hexLower
#print axioms Flare.L3.H1.ChunkedEncode.decL_roundtrip
#print axioms Flare.L3.H1.ChunkedEncode.decodeBody_roundtrip
#print axioms Flare.L3.H1.ChunkedEncode.scan_roundtrip
#print axioms Flare.L3.H1.ChunkedEncode.cDec_roundtrip
#print axioms Flare.L3.H1.ChunkedEncode.upload_roundtrip
-- WebSocket opening handshake
#print axioms Flare.L3.Ws.Handshake.keyOk_iff
#print axioms Flare.L3.Ws.Handshake.genKey_valid
#print axioms Flare.L3.Ws.Handshake.clientAccepts_ok
#print axioms Flare.L3.Ws.Handshake.clientAccepts_le_old
#print axioms Flare.L3.Ws.Handshake.srvFixed_ok
#print axioms Flare.L3.Ws.Handshake.reactor_upgrade_v13
#print axioms Flare.L3.Ws.Handshake.reactorFixed_ok
#print axioms Flare.L3.Ws.Handshake.handshake_complete
-- WebSocket closing handshake
#print axioms Flare.L3.Ws.Close.fix_state
#print axioms Flare.L3.Ws.Close.fixed_good
#print axioms Flare.L3.Ws.Close.fixed_closeOK
-- Findings (native_decide allowed here)
#print axioms Flare.Bugs.H1_01.counterexample
#print axioms Flare.Bugs.H1_01.fixed_segmentation_independent
#print axioms Flare.Bugs.H1_02.counterexample
#print axioms Flare.Bugs.H1_02.fixed_agrees_lfTolerant
#print axioms Flare.Bugs.H1_03.counterexample
#print axioms Flare.Bugs.H1_03.fixed_agrees
#print axioms Flare.Bugs.H1_04.counterexample
#print axioms Flare.Bugs.H1_04.fixed_agrees
#print axioms Flare.Bugs.H1_05.counterexample
#print axioms Flare.Bugs.H1_05.fixed_utf8
#print axioms Flare.Bugs.H1_06.counterexample
#print axioms Flare.Bugs.H1_06.fixed_complete
#print axioms Flare.Bugs.H1_06.fixed_rejects
#print axioms Flare.Bugs.H1_07.counterexample
#print axioms Flare.Bugs.H1_07.fixed_agrees
#print axioms Flare.Bugs.H1_07.fixed_rejects
#print axioms Flare.Bugs.H1_08.not_delimited
#print axioms Flare.Bugs.H1_08.counterexample
#print axioms Flare.Bugs.H1_08.fixed_delimited
#print axioms Flare.Bugs.H1_08.fixed_rejects
#print axioms Flare.Bugs.H1_09.counterexample
#print axioms Flare.Bugs.H1_09.fixed_ok
#print axioms Flare.Bugs.H1_09.fixed_closes
#print axioms Flare.Bugs.H1_10.counterexample
#print axioms Flare.Bugs.H1_10.fixed_valid
#print axioms Flare.Bugs.H1_10.fixed_rejects
#print axioms Flare.Bugs.H1_11.counterexample
#print axioms Flare.Bugs.H1_11.fixed_safe
#print axioms Flare.Bugs.WS_01.counterexample
#print axioms Flare.Bugs.WS_01.fixed_known_opcode
#print axioms Flare.Bugs.WS_02.counterexample_fragment
#print axioms Flare.Bugs.WS_02.counterexample_pong
#print axioms Flare.Bugs.WS_02.fixed_meets_spec
#print axioms Flare.Bugs.WS_03.counterexample
#print axioms Flare.Bugs.WS_03.fixed_client_safe
#print axioms Flare.Bugs.WS_04.counterexample
#print axioms Flare.Bugs.WS_04.fixed_refuses
#print axioms Flare.Bugs.WS_04.fixed_ok
#print axioms Flare.Bugs.WS_05.counterexample
#print axioms Flare.Bugs.WS_05.key_invalid
#print axioms Flare.Bugs.WS_05.fixed_refuses
#print axioms Flare.Bugs.WS_05.fixed_ok
#print axioms Flare.Bugs.WS_06.counterexample_no_echo
#print axioms Flare.Bugs.WS_06.counterexample_invalid_payload
#print axioms Flare.Bugs.WS_06.counterexample_data_after_close
#print axioms Flare.Bugs.WS_06.reply_1002
#print axioms Flare.Bugs.WS_06.fixed_ok
#print axioms Flare.Bugs.WS_07.counterexample
#print axioms Flare.Bugs.WS_07.fixed_refuses
#print axioms Flare.Bugs.WS_07.fixed_ok
