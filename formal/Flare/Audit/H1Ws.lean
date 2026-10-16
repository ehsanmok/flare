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
#print axioms Flare.L3.Ws.serverRecv_utf8
#print axioms Flare.L3.Ws.serverRecv_mask
#print axioms Flare.L3.Ws.serverRecv_keeps
#print axioms Flare.L3.Ws.serverRecv_safe
#print axioms Flare.L3.Ws.clientAccept_safe
#print axioms Flare.L3.Ws.collect_spec
#print axioms Flare.L3.Ws.nextMessage_delivered
#print axioms Flare.L3.Ws.textPayload_ok_iff
-- obs-fold
#print axioms Flare.L3.H1.ObsFold.strict_no_fold
#print axioms Flare.L3.H1.ObsFold.valueOk_join
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
#print axioms Flare.L3.Ws.Handshake.srv_ok
#print axioms Flare.L3.Ws.Handshake.reactor_ok
#print axioms Flare.L3.Ws.Handshake.handshake_complete
-- WebSocket closing handshake
#print axioms Flare.L3.Ws.Close.fix_state
#print axioms Flare.L3.Ws.Close.fixed_good
#print axioms Flare.L3.Ws.Close.fixed_closeOK
