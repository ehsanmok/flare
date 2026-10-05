import Flare.L1_Encoding
/-! L1 encodings: axiom footprint of the headline theorems. Expected:
`propext`, `Quot.sound`, `Classical.choice` everywhere outside
`Flare.Bugs`; bit-level goals use the kernel-checked `bit_blast` macro, not
`bv_decide`. The concrete traces in `Flare.Bugs.ENC_01/03/04` use
`native_decide`, reported as a per-theorem auxiliary axiom
`<thm>._native.native_decide.ax_*`. -/

-- Raw buffers, byte order, decimal
#print axioms Flare.L1.Buf.readBytes_writeBytes
#print axioms Flare.L1.Buf.fromLE64_le64
#print axioms Flare.L1.ByteOrder.htons_involutive
#print axioms Flare.L1.ByteOrder.htonl_involutive
#print axioms Flare.L1.Decimal.decVal_dec
-- Addresses and sockaddr
#print axioms Flare.L1.Address.parsePortStrict_eq_spec
#print axioms Flare.L1.Address.parseSock_render
#print axioms Flare.L1.IpPredicates.isPrivate_dotted
#print axioms Flare.L1.IpPredicates.isMulticast_dotted
#print axioms Flare.L1.Sockaddr.readPort_fillIn
#print axioms Flare.L1.Sockaddr.readPort_fillIn6
#print axioms Flare.L1.Sockaddr.getFamily_eq_kFamily
-- UTF-8
#print axioms Flare.L1.Utf8.decode_encode
#print axioms Flare.L1.Utf8.seqOK_iff_encode
#print axioms Flare.L1.Utf8.isValidUtf8_iff
#print axioms Flare.L1.Utf8.scan_none_iff_valid
#print axioms Flare.L1.Utf8.lossy_wf
#print axioms Flare.L1.Utf8.lossy_of_wf
-- ByteReader / ByteWriter / ProtoReader
#print axioms Flare.L1.ByteCursor.guard_iff
#print axioms Flare.L1.ByteCursor.guard_iff_of_small
#print axioms Flare.L1.ByteCursor.guardFixed_iff
#print axioms Flare.L1.ByteCursor.readU16be_write
#print axioms Flare.L1.ByteCursor.readU32le_write
#print axioms Flare.L1.ByteCursor.readU64be_write
#print axioms Flare.L1.ByteCursor.readU64le_write
#print axioms Flare.L1.ByteCursor.skip_inv_of_small
#print axioms Flare.L1.ByteCursor.skipFixed_inv
#print axioms Flare.L1.ByteCursor.readBytesFixed_spec
#print axioms Flare.L1.ByteCursor.readUtf8_wf
#print axioms Flare.L1.ByteCursor.skipLen_inv
#print axioms Flare.L1.ByteCursor.readBytes_inv
-- Civil time
#print axioms Flare.L1.CivilTime.daysFloor_spec
#print axioms Flare.L1.CivilTime.civilFloor_daysFloor
#print axioms Flare.L1.CivilTime.daysFloor_civilFloor
#print axioms Flare.L1.CivilTime.civilFloor_valid
#print axioms Flare.L1.CivilTime.daysFromCivil_next
#print axioms Flare.L1.CivilTime.civilFromDays_daysFromCivil
#print axioms Flare.L1.CivilTime.daysFromCivil_civilFromDays
#print axioms Flare.L1.CivilTime.civilToUnix_unixToCivil
#print axioms Flare.L1.CivilTime.unixToCivil_civilToUnix
-- QUIC varint
#print axioms Flare.L1.QuicVarint.decode_encode
#print axioms Flare.L1.QuicVarint.encode_none_iff
#print axioms Flare.L1.QuicVarint.encode_minimal
#print axioms Flare.L1.QuicVarint.decode_bound
#print axioms Flare.L1.QuicVarint.decode_le_max
-- HPACK integer
#print axioms Flare.L1.HpackInt.decode_encode
#print axioms Flare.L1.HpackInt.encode_flags
#print axioms Flare.L1.HpackInt.decode_bounds
-- io_uring tags and CQE fields
#print axioms Flare.L1.UringTag.unpack_pack
#print axioms Flare.L1.UringTag.pack_unpack
#print axioms Flare.L1.UringTag.pack_inj
#print axioms Flare.L1.UringTag.cqeRes_eq_toInt32
#print axioms Flare.L1.UringTag.errno_range
#print axioms Flare.L1.UringTag.bufferId_range
-- HttpStatusError
#print axioms Flare.L1.StatusError.parse_render
#print axioms Flare.L1.StatusError.parse_render_mojo
#print axioms Flare.L1.MojoAtol.atol10_dec
#print axioms Flare.L1.MojoAtol.atol10_rejects
#print axioms Flare.L1.StatusError.parse_status_range
-- Base64
#print axioms Flare.L1.Base64.decode_encodeStd
#print axioms Flare.L1.Base64.decode_encodeUrl
#print axioms Flare.L1.Base64.decode_canonical
#print axioms Flare.L1.Base64.decode_padding
-- Huffman (RFC 7541 §5.2, Appendix B)
#print axioms Flare.L1.Huffman.kraft
#print axioms Flare.L1.Huffman.prefix_free
#print axioms Flare.L1.Huffman.padding_not_code
#print axioms Flare.L1.Huffman.TBL_eq_rfc
#print axioms Flare.L1.Huffman.canon_covers
#print axioms Flare.L1.Huffman.tableLengthImpl_eq
#print axioms Flare.L1.Huffman.lookupImpl_spec
#print axioms Flare.L1.Huffman.encodeImpl_eq
#print axioms Flare.L1.Huffman.encodedLengthImpl_eq
#print axioms Flare.L1.Huffman.decodeImpl_eq
#print axioms Flare.L1.Huffman.decodeSimdImpl_eq
#print axioms Flare.L1.Huffman.decodeSimdImpl_eq_decodeImpl
#print axioms Flare.L1.Huffman.decodeDispatch_eq
#print axioms Flare.L1.Huffman.okOnly_decodeSimdImpl
#print axioms Flare.L1.Huffman.okOnly_decodeDispatch
#print axioms Flare.L1.Huffman.decode_eq_some_iff
#print axioms Flare.L1.Huffman.decode_encode
#print axioms Flare.L1.Huffman.decodeImpl_encodeImpl
#print axioms Flare.L1.Huffman.decodeBits_eos
#print axioms Flare.L1.Huffman.decodeBits_padding_too_long
#print axioms Flare.L1.Huffman.decodeBits_padding_eos
#print axioms Flare.L1.Huffman.decodeBits_invalid_padding
-- UTF-8 maximal subparts (Unicode 15 §3.9)
#print axioms Flare.L1.Utf8.pfx_iff
#print axioms Flare.L1.Utf8.step_maxSub
#print axioms Flare.L1.Utf8.Subst.unique
#print axioms Flare.L1.Utf8.lossy_subst
#print axioms Flare.L1.Utf8.lossy_eq_iff_subst
-- Civil time in Int64
#print axioms Flare.L1.CivilTime.civilToUnix64_eq
#print axioms Flare.L1.CivilTime.civilToUnix64_exact
#print axioms Flare.L1.CivilTime.jan1_inRange_iff
#print axioms Flare.L1.CivilTime.civilToUnix64_wraps
#print axioms Flare.L1.CivilTime.httpdate_exact
#print axioms Flare.L1.CivilTime.unixToCivil64_eq
#print axioms Flare.L1.CivilTime.daysFromCivil_eq_floor_of_year_nonneg
#print axioms Flare.L1.CivilTime.parseDigits_four
-- Protobuf varint
#print axioms Flare.L1.ProtoVarint.writeVarint_length
#print axioms Flare.L1.ProtoVarint.writeVarint_canonical
#print axioms Flare.L1.ProtoVarint.rawVarint_writeVarint
#print axioms Flare.L1.ProtoVarint.rawVarint_eleven
#print axioms Flare.L1.ProtoVarint.tenth_byte_truncates
-- Findings
#print axioms Flare.Bugs.ENC_01.counterexample
#print axioms Flare.Bugs.ENC_01.isMulticast6Fixed_correct
#print axioms Flare.Bugs.ENC_02.counterexample
#print axioms Flare.Bugs.ENC_02.inverse_counterexample
#print axioms Flare.Bugs.ENC_02.fixed_spec
#print axioms Flare.Bugs.ENC_03.counterexample
#print axioms Flare.Bugs.ENC_03.fixed_preserves_inv
#print axioms Flare.Bugs.ENC_03.fixed_read_bytes_preserves_inv
#print axioms Flare.Bugs.ENC_04.counterexample
#print axioms Flare.Bugs.ENC_04.fixed_preserves_inv
