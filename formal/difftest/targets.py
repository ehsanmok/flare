"""Difftest targets: which Mojo symbols each oracle target exercises.

Every target named in formal/Oracle/Registry.lean has a row here:

  driver    formal/difftest/drivers/<driver>.mojo answers the target
  symbols   anchors (`flare/x.mojo#Sym[+Sym]`) of the Mojo code under test;
            a change to any of them makes the target "affected"
  models    Lean files whose edits also make it affected
  fuzz      fuzz/ harnesses whose `_bytes("...")` seeds are mutated into inputs
  gen       input generator in run.py
  max_len   longest generated input
  derive    run this oracle target on generated inputs first and feed its
            `OK:` payloads (mutated) to this target, e.g. Huffman decode
            inputs from Huffman encode outputs
"""

TARGETS = {
    "hpack_int.decode": dict(
        driver="dt_hpack_int",
        symbols=["flare/http2/hpack.mojo#decode_integer"],
        models=["Flare/L1_Encoding/HpackInt.lean"],
        fuzz=["fuzz_hpack_decoder.mojo"],
        gen="hpack_int_decode",
        max_len=10,
    ),
    "hpack_int.encode": dict(
        driver="dt_hpack_int",
        symbols=["flare/http2/hpack.mojo#encode_integer"],
        models=["Flare/L1_Encoding/HpackInt.lean"],
        fuzz=[],
        gen="hpack_int_encode",
        max_len=6,
    ),
    "quic_varint.decode": dict(
        driver="dt_quic_varint",
        symbols=["flare/quic/varint.mojo#decode_varint"],
        models=["Flare/L1_Encoding/QuicVarint.lean"],
        fuzz=["fuzz_quic_varint.mojo"],
        gen="quic_decode",
        max_len=10,
    ),
    "quic_varint.encode": dict(
        driver="dt_quic_varint",
        symbols=["flare/quic/varint.mojo#encode_varint+encode_varint_into+varint_encoded_length+VARINT_MAX"],
        models=["Flare/L1_Encoding/QuicVarint.lean"],
        fuzz=[],
        gen="quic_encode",
        max_len=8,
    ),
    "utf8.valid": dict(
        driver="dt_utf8",
        symbols=["flare/io/byte_cursor.mojo#_is_valid_utf8"],
        models=["Flare/L1_Encoding/Utf8.lean"],
        fuzz=["fuzz_ws_frame.mojo"],
        gen="utf8",
        max_len=16,
    ),
    "utf8.lossy": dict(
        driver="dt_utf8",
        symbols=["flare/http/proto/utf8.mojo#utf8_lossy_string+_step+_is_cont"],
        models=["Flare/L1_Encoding/Utf8.lean"],
        fuzz=[],
        gen="utf8",
        max_len=16,
    ),
    "huffman.decode": dict(
        driver="dt_huffman",
        symbols=["flare/http/hpack_huffman.mojo#huffman_decode"],
        models=["Flare/L1_Encoding/Huffman.lean", "Flare/L1_Encoding/HuffmanTable.lean"],
        fuzz=["fuzz_huffman_simd.mojo"],
        gen="bytes",
        max_len=512,
        derive="huffman.encode",
    ),
    "huffman.decode_simd": dict(
        driver="dt_huffman",
        symbols=["flare/http/hpack_huffman_simd.mojo#huffman_decode_simd"],
        models=["Flare/L1_Encoding/Huffman.lean", "Flare/L1_Encoding/HuffmanTable.lean"],
        fuzz=["fuzz_huffman_simd.mojo"],
        gen="bytes",
        max_len=512,
        derive="huffman.encode",
    ),
    "huffman.encode": dict(
        driver="dt_huffman",
        symbols=["flare/http/hpack_huffman.mojo#huffman_encode"],
        models=["Flare/L1_Encoding/Huffman.lean", "Flare/L1_Encoding/HuffmanTable.lean"],
        fuzz=[],
        gen="text",
        max_len=512,
    ),
    "huffman.length": dict(
        driver="dt_huffman",
        symbols=["flare/http/hpack_huffman.mojo#huffman_encoded_length"],
        models=["Flare/L1_Encoding/Huffman.lean", "Flare/L1_Encoding/HuffmanTable.lean"],
        fuzz=[],
        gen="text",
        max_len=512,
    ),
    "bufring_ledger.trace": dict(
        driver="dt_bufring_ledger",
        symbols=[
            "flare/http/_bufring_ledger.mojo#classify_recv+RecvDecision+RECV_STAGE+RECV_DROP+RECV_CLOSE",
            "flare/http/_bufring_ledger.mojo#BufLedger.__init__+BufLedger.on_fill+BufLedger.on_complete",
        ],
        models=["Flare/Kernels/BufLedger.lean"],
        fuzz=[],
        gen="bytes",
        max_len=48,
    ),
    "ws_protocol.trace": dict(
        driver="dt_ws",
        symbols=[
            "flare/ws/protocol.mojo#WsProtocol.next_event+WsProtocol._on_frame+WsProtocol._message+WsProtocol._fail+WsProtocol.close+WsProtocol._send+_close_reply_payload+_valid_close_code",
        ],
        models=["Flare/Kernels/WsProtocol.lean"],
        fuzz=["fuzz_ws_protocol.mojo"],
        gen="bytes",
        max_len=32,
    ),
    "h1_chunked.resume": dict(
        driver="dt_h1",
        symbols=["flare/http/proto/chunked.mojo#scan_chunked_resume+_hex_val+_has_lf+CHUNK_LINE_MAX"],
        models=["Flare/L3_Protocol/H1/Chunked.lean"],
        fuzz=[],
        gen="chunked",
        max_len=4400,
    ),
    "h2_conn.frames": dict(
        driver="dt_h2",
        symbols=[
            "flare/http2/state.mojo#Connection.handle_frame+Connection._conn_window_update",
            "flare/http2/state.mojo#Connection._commit_header_block+Connection._strip_pad_and_priority",
            "flare/http2/state.mojo#Connection._idle_id+Connection._ensure_stream+Connection._validate_request_headers",
            "flare/http2/hpack.mojo#HpackDecoder.decode",
        ],
        models=[
            "Flare/L3_Protocol/H2/Conn.lean",
            "Flare/L3_Protocol/H2/Hpack.lean",
            "Flare/L3_Protocol/H2/Validate.lean",
        ],
        fuzz=[],
        gen="h2",
        max_len=700,
    ),
}
