# L3 protocol: HTTP/1.1 and WebSocket

This report covers flare's HTTP/1.1 server framing and its WebSocket frame layer. On the HTTP/1.1 side it covers:
- the chunked body scanner the reactor polls after every read (`scan_chunked_resume` and `scan_chunked_end` in `flare/http/proto/chunked.mojo`, polled by `ConnHandle._check_request_complete` in `flare/http/_reactor/conn_handle.mojo`) and the chunked decoder (`decode_chunked_body`);
- the Content-Length grammar (`parse_content_length_bytes` in `flare/http/_scan.mojo`);
- the two components that must agree on where a request ends: the reactor's framing (`request_te_framing` and `scan_content_length`) and the request parser (`_parse_http_request_bytes` in `flare/http/_server/parse.mojo`), including the lenient `H1LeniencyConfig` options;
- header-value validation (`_check_field_value`) and obs-fold unfolding (the field loop of `_parse_http_request_bytes`);
- the client's response reader (`flare/http/_client/parse.mojo`, `download.mojo`, `h2_transport.mojo`): status line, head lines, RFC 9112 §6.3 framing, the chunked decoder, connection reuse and the TLS end of stream;
- the two chunked encoders (`flare/http/streaming_serialize.mojo`, `flare/http/client.mojo`).

On the WebSocket side it covers:
- masking, the frame encoder and the decoder (`_append_masked`, `WsFrame.encode_with_key` and `WsFrame.decode_one` in `flare/ws/frame.mojo`);
- the server's and the client's frame acceptance (`WsConnection._recv_one` in `flare/ws/server.mojo`, `WsClient._recv_one` in `flare/ws/client.mojo`) and the server's `WsConnection.recv`;
- the client's message reassembly (`WsClient.recv_message` and `_recv_data_frame`);
- the opening handshake on all three paths: `WsClient._connect_impl`, the standalone `WsServer` (`_parse_ws_upgrade_bytes`, `_read_upgrade_request` and `_ws_handshake_problem`) and the reactor upgrade (`_is_ws_version_mismatch` and `ConnHandle._handle_ws_upgrade` in `flare/http/_reactor/conn_handle.mojo`);
- the closing handshake of `WsConnection` (`server.mojo`).

Each model is a transliteration of the shipped Mojo code, and every implementation definition carries a fidelity anchor naming the Mojo symbols it mirrors, checked by `formal/scripts/anchors.py`. Specifications are written separately, from RFC 9112, RFC 9110, RFC 6455 and RFC 3629. The aggregate module is `Flare/L3_Protocol/H1Ws.lean`, and `Flare/Audit/H1Ws.lean` prints the axioms of 90 headline theorems. The keep-alive decision (`_wants_close`, `_compute_close_after`) is covered by `L4_App/KeepAlive.lean` (APP-02, APP-03) and is not repeated here.

Build and audit status:
- Every module builds on its own. There is no `maxHeartbeats` option.
- There are no `sorry`, `admit` or `axiom` declarations, no `native_decide` and no `bv_decide`.
- Every audited theorem depends only on `propext`, `Quot.sound` and `Classical.choice`.
- The modules contain 277 theorems.

## Components

### Chunked body scanner and decoder

Files: `H1/Chunked.lean`, `H1/ChunkedSpec.lean`.

**Model.**
- `scanL`/`scanTr`/`scanResume`/`scanEnd` mirror `scan_chunked_resume`/`scan_chunked_end`, including the 4096-byte line cap `CAP` (`CHUNK_LINE_MAX`) and the resume cursor. The model is the shipped scanner: both incomplete-line tests allow one byte of slack for a pending CR, complete trailer lines are capped (H1-01), and a size or trailer line containing LF is malformed (H1-02). `scanImpl` is another name for `scanEnd`.
- `poll` mirrors the reactor's loop in `ConnHandle._check_request_complete`: rescan from the saved cursor after each read.
- `decodeBody` mirrors `decode_chunked_body`.

| Lean name | Statement | Status |
|---|---|---|
| `scanEnd_range` | The verdict is -1 (incomplete), -2 (malformed) or `done e` with `start ≤ e ≤ buf.length`. | proved |
| `scanL_total_le`, `parseSize_le` | On acceptance the decoded total is ≤ `max_body`, and every chunk size is ≤ `max_body`. | proved |
| `parseSize_fits` | If `16·max_body + 15 < 2^63`, every chunk-size accumulator fits in Int64. | proved |
| `parseSize_wraps_unbounded` | Without that bound the accumulator wraps (`2^59·16` becomes `-2^63`). | counterexample (needs `max_body ≥ 2^59`; see "Checked") |
| `scanL_resume`, `scanResume_resume` | Resuming from the saved cursor on `b ++ m` gives the same result as rescanning `b ++ m` from the original cursor. | proved |
| `scanEnd_done_stable`, `scanEnd_malformed_stable`, `impl_done_stable` | A `done` or `malformed` verdict is never revoked by more bytes. | proved |
| `scanEnd_segmentation_independent` | A definite verdict on a prefix equals the verdict on every extension. | proved |
| `poll_eq_oneShot`, `impl_poll_eq_oneShot` | Polling any segmentation equals one scan of the concatenation (H1-01). | proved |
| `decL_of_scanL`, `scanEnd_decode` | Termination and agreement: if the scanner accepts at `e`, `decode_chunked_body` succeeds on the same buffer, consumes exactly to `e` and produces at most `max_body` bytes. | proved |
| `scanEnd_lfSafe`, `impl_agrees_lfTolerant` | An accepting scan agrees with an LF-tolerant recipient (`lfScan`) on both the body and its end (H1-02). | proved |

`scanL`, `scanTr` and `decL` are structurally recursive, so termination is by construction.

### Content-Length grammar

Files: `H1/HeaderText.lean`, `H1/ContentLength.lean`.

**Model.** `parseCL` mirrors `parse_content_length_bytes`: skip OWS, take at most 18 digits, skip OWS, then require the end of the value or CR/LF.

| Lean name | Statement | Status |
|---|---|---|
| `parseCL_complete` | For OWS `p`, 1-18 digits `ds`, OWS `q` and a tail that is empty or starts with CR/LF, `parseCL (p++ds++q++t) = decVal ds`. | proved |
| `parseCL_sound` | Every non-negative result comes from exactly such a decomposition. | proved |
| `parseCL_invalid`, `parseCL_fits`, `parseCL_fitsI64` | The result is -1 or a value in `[0, 10^18)`, so it fits in Int64. | proved |
| `parseCL_strip`, `tokens_strip`, `classify_strip` | Surrounding OWS does not change the Content-Length value, the Transfer-Encoding tokens or the chunked classification. | proved |

### Reactor-vs-parser framing (request smuggling)

File: `H1/Framing.lean`.

**Model.**
- `reactorFraming allowCL maxBody lines` is the shipped reactor's decision: `request_te_framing` and `scan_content_length` over the header lines, with SP/HTAB between the field name and the colon skipped (`_colon_after_name`, `_match_content_length_prefix`; the H1-03 fix). It returns `chunked`, `length n` or `reject`.
- `parserFraming ows allowCL maxBody lines` mirrors the parser's acceptance and framing (`_parse_http_request_bytes`). Its acceptance is a superset of the real parser's, since it checks only line shape, field syntax and Content-Length consistency. Any statement of the form "parser accepts ⇒ same framing" therefore carries over to the real parser.
- `ows` is `allow_ows_around_colon`.
- `linesLF` mirrors the lenient parser's LF line reader (`_read_line_buf_lenient`); the shipped reactor splits lines the same way (`reactorLines`, the H1-04 fix).

| Lean name | Statement | Status |
|---|---|---|
| `framing_agrees` | For either `ows`, any `allowCL` and `maxBody`: if the parser accepts, the shipped reactor frames the request the same way. | proved |
| `no_smuggling_strict` | Strict mode (`ows = false`): parser acceptance implies the same framing as the shipped reactor. | proved |
| `lf_fixed_agrees` | The shipped reactor splits lines with the parser's LF splitter (`reactorLines`), so the two agree whenever the parser accepts. | proved |
| `classify_chunked` | A Transfer-Encoding value whose list elements, stripped and lowercased with empty elements dropped, are exactly `chunked` is accepted (RFC 9110 §5.6.1). | proved |
| `parserFraming_chunked`, `reactorFraming_chunked` | Completeness: well-formed field lines with a Transfer-Encoding that classifies as `chunked` and no Content-Length are framed as chunked, by the parser and the reactor. | proved |
| `parserFraming_length`, `reactorFraming_length` | Completeness: well-formed field lines with no Transfer-Encoding and Content-Length values that all equal one `n` with `0 ≤ n ≤ maxBody` are framed by `n`, by both. | proved |

### Header values and the String invariant

File: `H1/FieldValue.lean`.

**Model.** `byteOk`/`valueOk` mirror the per-byte value check of `_check_field_value`; `valueAccepted` (= `valueOk` plus a UTF-8 check) is the shipped acceptance (the H1-05 fix).

| Lean name | Statement | Status |
|---|---|---|
| `strict_value_ascii`, `strict_value_utf8` | In strict mode every accepted value is ASCII, and hence valid UTF-8 (RFC 3629 `WF`). | proved |
| `fixed_value_utf8` | With the UTF-8 check (the shipped `valueAccepted`), every accepted value is valid UTF-8, with or without obs-text. | proved |
| `valueOk_complete`, `valueAccepted_complete` | Completeness: a value of field-vchars, SP and HTAB (RFC 9110 §5.5) passes the byte check, ASCII only in strict mode; with obs-text the shipped check accepts it whenever it is valid UTF-8. | proved |

### WebSocket frame codec

File: `Ws/Frame.lean`.

**Model.**
- `maskFrom` mirrors the scalar masking loop, and `appendMasked` mirrors the 32-byte-block masking with its scalar tail (`_append_masked`).
- `encode` mirrors `WsFrame.encode_with_key`, with minimal length encoding through `lenCode` and `extLen`.
- `decode` mirrors `WsFrame.decode_one` without its reserved-opcode check: RSV checks, length parsing, the control-frame rules and the `max_payload` limit. `decodeKnown` (`Ws/Recv.lean`) adds the opcode check and is the shipped decoder.

| Lean name | Statement | Status |
|---|---|---|
| `maskFrom_involutive` | Masking twice with the same key and offset is the identity. | proved |
| `maskFrom_append`, `maskFrom_zero_key` | Masking a concatenation equals masking the parts with the offset advanced. The all-zero key is the identity. | proved |
| `appendMasked_eq` | The blocked mask equals the scalar mask when the start offset is ≡ 0 (mod 4). | proved |
| `decode_encode`, `decode_encode_len` | For opcode < 16, a permitted RSV1, legal control frames, payload < 2^32 and payload ≤ `max_payload`: `decode (encode f mask k ++ rest)` returns `f` (with `masked := mask`) and consumes exactly the encoded length, for either mask flag and any key and trailing bytes. | proved |
| `lenCode_125`, `lenCode_126`, `lenCode_65535`, `lenCode_65536` | At the boundaries the encoder uses the 7-bit form (125), the 16-bit form (126 and 65535) and the 64-bit form (65536). Each is covered by `decode_encode`. | proved |
| `decode_ok_shape` | Every decoded frame satisfies the control-frame rules (FIN set, payload ≤ 125), the `max_payload` limit and the RSV1 setting. | proved |

### WebSocket receive path

File: `Ws/Recv.lean`.

**Model.**
- `decodeKnown` is `WsFrame.decode_one` with the reserved-opcode check (WS-01).
- `serverAccept` mirrors `WsConnection._recv_one` (an unmasked frame is refused), and `clientAccept` mirrors `WsClient._recv_one` (a masked frame is refused, WS-03).
- `serverRecv` mirrors `WsConnection.recv` together with `_recv_one`. Its result is a `Step`: `deliver f` hands the frame to the handler, `fail closes` fails the connection after a best-effort CLOSE with the listed codes, and `wait` asks for more bytes. The PING auto-reply loop and the 1009 close for an oversized frame are outside the model.
- `Utf8Spec` is RFC 6455 §8.1 and §7.4.1: a masked, final TEXT frame whose payload is not valid UTF-8 fails the connection with CLOSE 1007. `MaskSpec` is RFC 6455 §5.1 and §7.4.1: a decodable client frame without the MASK bit fails the connection with CLOSE 1002. These are the promises flare's documentation makes (DOC-01, DOC-02), stated about the shipped `recv`. An invalid close reason is answered with 1002 by the closing-handshake model (`Ws/Close.lean`).
- `nextMessage` mirrors `WsClient.recv_message` with `_recv_data_frame` (WS-02); `Delivered` is the RFC 6455 §5.4 meaning of "the next complete message".

| Lean name | Statement | Status |
|---|---|---|
| `server_safe` | Every frame the server accepts was masked (RFC 6455 §5.1). | proved |
| `serverRecv_utf8` | `serverRecv` meets `Utf8Spec`: a final TEXT frame that is not valid UTF-8 gives `fail [1007]`. | proved |
| `serverRecv_mask` | `serverRecv` meets `MaskSpec`: an unmasked frame gives `fail [1002]`. | proved |
| `serverRecv_keeps`, `serverRecv_safe` | Every other masked frame is delivered unchanged, and the handler only ever sees masked frames. | proved |
| `clientAccept_safe` | Every frame the client accepts is unmasked. | proved |
| `decodeKnown_safe`, `decodeKnown_encode` | The shipped decoder accepts only known opcodes, and the round trip still holds for them. | proved |
| `collect_spec`, `nextMessage_delivered` | `recv_message` returns exactly a TEXT/BINARY frame followed by CONTINUATION frames up to FIN, with the concatenated payload, skipping control frames (RFC 6455 §5.4). | proved |
| `textPayload_ok_iff` | The UTF-8 check on text payloads accepts exactly RFC 3629 `UTF8-octets` (from `L1.Utf8.isValidUtf8_iff`). | proved |

### obs-fold

File: `H1/ObsFold.lean`.

**Model.** `fields obsFold obsText prev lines` mirrors the field loop of `_parse_http_request_bytes` with `_check_field_value`: a field is committed only when the next line shows it is not continued; with `allow_obs_fold` a line starting with SP/HTAB is stripped (`aStrip`, `_ascii_strip_slice`), checked with `valueOk` like a first line (the H1-10 fix) and appended after one SP. The UTF-8 part of the value check (H1-05) is left out, so the model accepts a superset of what the code accepts.

| Lean name | Statement | Status |
|---|---|---|
| `strict_no_fold` | Without the flag a continuation line is an error. | proved |
| `fields_valid` | With or without folding, every stored value passes `valueOk`. | proved |
| `fold_unfold` | A run of valid continuation lines unfolds exactly as RFC 9112 §5.2 says: the value becomes `v ++ " " ++ strip c₁ ++ …` (`unfoldOnto`). | proved |

### Client response reader

Files: `H1/ClientChunked.lean`, `H1/ClientResponse.lean`.

**Model.**
- `respFraming` mirrors `_response_framing`, shared by the buffered, framed and streaming readers.
- `parseStatus` mirrors `_parse_status_line`, with the delimiter check after the three digits (H1-08).
- `san`, `findCRLF2` and `splitGo`/`splitLines` mirror `_bytes_to_str`, `_find_crlf2_from` and `_split_lines`. `headImpl` mirrors `_parse_response_head`, which refuses a head holding a bare LF or an empty line (H1-07). `lfHead` is an RFC 9112 §2.2 recipient that ends lines at LF.
- `cDec` mirrors `_decode_chunked`; `cHex` (`_parse_hex`), `cTr` and `trailerOk` (`_is_forbidden_trailer`) its size and trailer lines. `cRead` is the read-to-EOF path: `_require_complete_chunked`, then `_decode_chunked` (H1-06).
- `canReuse` mirrors the keep-alive decision of the pooled reader `_read_http_response_framed`, which pools only an HTTP/1.1 response (H1-09).
- `bufferedClose` mirrors the close_notify guard of the buffered readers (`_refuse_truncated_tls`). `dlClose` (= `bufferedClose`) is the streaming download, whose transport `_H2Transport.read` raises on a TLS end of stream without close_notify (H1-11).

| Lean name | Statement | Status |
|---|---|---|
| `framing_bodyless` | HEAD, 1xx, 204, 304 and a 2xx to CONNECT have no body, whatever the fields say (RFC 9112 §6.3 points 1-2). | proved |
| `framing_te_cl_reject`, `framing_dup_cl` | Transfer-Encoding together with Content-Length, or more than one Content-Length, is refused (stricter than §6.3 point 3-5, which allow recovery). | proved |
| `framing_chunked_iff`, `framing_length_iff`, `framing_close_iff` | Exactly: chunked iff a single TE value `chunked` and no CL; length n iff no TE and a single valid CL = n; close-delimited iff neither (§6.3 points 4-8). | proved |
| `cDec_agree`, `framed_chunked_agrees` | On any buffer the shipped scanner accepts at `e`, the client decoder either raises or returns exactly the server decoder's bytes, reading nothing past `e`. So the pooled reader's chunked path is right. | proved |
| `cRead_complete` | On the read-to-EOF path (`cRead`), a returned body is always a complete chunked body. | proved |
| `parseStatus_delimited` | The code is three digits followed by SP or the end of the line (`CodeDelimited`). | proved |
| `parseStatus_complete` | Completeness: `HTTP/<version> SP [whitespace] DIGIT{3}`, then SP or the end of the line, is accepted with that code, for any version without SP. | proved |
| `splitGo_join`, `lfGo_join`, `headImpl_agrees` | With bare LF and empty lines refused, the head lines and body start equal those of the LF-recognising recipient. | proved |
| `headImpl_complete` | Completeness: a head of nonempty lines without CR or LF, each ended by CRLF and closed by an empty line, is accepted with those lines and the body after it. | proved |
| `canReuse_ok` | Reuse implies HTTP/1.1 without `close` (RFC 9112 §9.3). | proved |
| `bufferedClose_safe` | The guard never returns a close-delimited TLS body that ended without close_notify, on the buffered and the streaming path. | proved |

### Chunked encoders

File: `H1/ChunkedEncode.lean`.

**Model.** `hexLower` mirrors the hex writer (`_hex_lower` in `streaming_serialize.mojo`, `_chunk_frame_prefix` in `client.mojo`). `encodeBody cs tr` is the output of `serialize_streaming_response`: each non-empty chunk as `hex CRLF data CRLF` (an empty write produces nothing), `0 CRLF`, one `name: value CRLF` per trailer, `CRLF`. `encodeUpload cs = encodeBody cs []` is the client upload (`HttpClient._send_chunked_tcp`).

| Lean name | Statement | Status |
|---|---|---|
| `hexAcc_hexLower` | The hex writer and every hex reader are inverse. | proved |
| `decL_roundtrip`, `decodeBody_roundtrip` | For any chunks (empty ones included), trailers whose lines hold no CR, and any following bytes, the server decoder returns `cs.flatten` and stops exactly at the end of the encoding. | proved |
| `scan_roundtrip` | The shipped scanner accepts the encoding at its end, when every chunk is < 2^60 bytes, every trailer line fits `CHUNK_LINE_MAX` (`TrailersCapped`) and the total ≤ `max_body`. | proved |
| `cDec_roundtrip` | The client decoder returns `cs.flatten` when the trailers pass its own checks (`ClientTrailersOK`). | proved |
| `upload_roundtrip` | The client upload encoding decodes to the uploaded bytes. | proved |

### WebSocket opening handshake

File: `Ws/Handshake.lean`.

**Model.** SHA-1 is a black box `Sha1 := Bytes → Bytes`; every theorem holds for every such function. `acceptOf sha1 key = encodeStd (sha1 (key ++ GUID))` mirrors `_compute_accept` and `_compute_accept_srv`, with base64 from `L1.Base64`. `genKey` mirrors `_generate_ws_key`. Fields are the stripped `(name, value)` pairs that each handshake loop builds; `lastVal` is the loops' "last wins", `firstVal` is `HeaderMap.get`.
- `clientAccepts` is the client's check in `WsClient._connect_impl` (`_UpgradeResponse.verify`, both branches); `ClientOK` is the RFC 6455 §4.1 list for a request that offered no subprotocol or extension (flare's request offers none, `clientRequest`).
- `srv` mirrors `_parse_ws_upgrade_bytes`/`_read_upgrade_request`, which apply `_ws_handshake_problem` (`qual`) to exactly one key; `ServerOK` is RFC 6455 §4.2.1 plus §11.3.1/§11.3.5 (key and version once).
- `reactor` mirrors `ConnHandle._handle_ws_upgrade`: the 426 branch (`versionMismatch`, `_is_ws_version_mismatch`) first, then `qual`.

| Lean name | Statement | Status |
|---|---|---|
| `genKey_valid` | The client's key, base64 of 16 nonce bytes, decodes to 16 bytes (`KeyOK`). | proved |
| `keyOk_iff` | The Boolean key check decides `KeyOK`. | proved |
| `clientAccepts_ok` | The client check decides exactly `ClientOK`. | proved |
| `srv_ok` | A request the standalone server accepts satisfies `ServerOK`. | proved |
| `reactor_ok` | A request the reactor upgrades satisfies `ServerOK`. | proved |
| `handshake_complete` | For every SHA-1 and valid key, flare's client request passes both servers, and the server's 101 passes the client. | proved |

### WebSocket closing handshake

File: `Ws/Close.lean`.

**Model.** An endpoint is a step function over what the application sees: a received frame, `send_text`/`send_binary`, `close(code)`; each step writes frames. `fixStep` is the shipped `WsConnection`, with a `close_sent` flag (`recv`, `close`, `send_text`, `send_binary`, `send_frame` and `_require_open`). `validPayload` is RFC 6455 §5.5.1/§7.4: empty, or a code in 1000-1003, 1007-1014, 3000-4999 followed by UTF-8. `closeReply p` is the received code, or 1002 for an invalid body. `CloseOK` (via `Good`) says, for every trace: a CLOSE received while none has been written is answered with `closeReply`, and once a CLOSE has been written no data frame follows.

| Lean name | Statement | Status |
|---|---|---|
| `fix_state`, `fixed_good`, `fixed_closeOK` | The shipped endpoint meets `CloseOK` on every trace. | proved |

### Assumptions and limitations

- **Framing is modelled at the level of header lines.** Both sides receive the same list of field lines. Detecting the end of the header block (CRLFCRLF in `ConnHandle._check_request_complete`) is outside the model, apart from the LF/CRLF line splitting of H1-04.
- **The parser model accepts more than the real parser** (it checks line shape, field syntax and Content-Length consistency only). The agreement theorems carry over to the real parser.
- **SHA-1 is a black box.** The handshake theorems quantify over every function `Bytes → Bytes`; SHA-1 itself is not modelled. Base64 and the key/GUID concatenation are.
- **Handshake fields are modelled after the line split.** The three handshake loops split lines (dropping CR, ending at LF) and then split each line at its first colon and strip both halves; the model starts from those pairs. The client's own response-head splitting is modelled separately (`ClientResponse.splitGo`).
- **The 101 status check** in `ClientOK` is flare's prefix test `HTTP/1.1 101`. A `HTTP/1.1 1010` status line is the H1-08 class and is not filed again.
- **Receive models and reserved opcodes.** `serverAccept`, `serverRecv` and `clientAccept` decode with the shipped `decodeKnown`, so a reserved opcode is a decode error before the mask and UTF-8 checks run. It fails the connection without a CLOSE, and `MaskSpec` and `Utf8Spec` are stated for frames with a defined opcode.
- **Server UTF-8 checking is per frame.** `WsConnection.recv` does not reassemble fragments, so `Utf8Spec` covers final TEXT frames; a fragmented text message is left to the application.
- **Encoder trailers.** The encoder does not filter forbidden trailer names; trailers are chosen by the application, and flare's own client refuses them. `cDec_roundtrip` therefore assumes `ClientTrailersOK`, and every round trip assumes trailer lines without CR or LF (which `HeaderMap` guarantees).
- **`scan_roundtrip`** assumes chunks below 2^60 bytes, because the scanner caps size lines at 16 hex digits (deliberate, see "Checked"), and trailer lines of at most `CHUNK_LINE_MAX` bytes (the H1-01 cap).
- **The close model** works at the level of the application API: frames are values, and their encoding is covered by `Ws/Frame.lean`. The peer is arbitrary, since `CloseOK` quantifies over every trace.
- **permessage-deflate is not modelled because flare does not implement it.** No handshake sends or accepts `Sec-WebSocket-Extensions`, and RSV1 is always refused, so there is no code to model.
- **WebSocket length bound.** `decode_encode` assumes payloads below 2^32. Larger payloads exceed any sane `max_payload`.
- **UInt8 header bit facts** (`byte0_bits_all`, `byte1_bits_all`) are checked by kernel `decide` over `Fin 16 × Bool × Bool` and `Fin 128 × Bool`, not over strings.

## Findings

### H1-01: the chunk-line cap gives a verdict that depends on TCP segmentation

Status: resolved. Both incomplete-line tests (size line and trailer line) now allow one byte of slack for a pending CR, and complete trailer lines are capped at `CHUNK_LINE_MAX`, so polling any segmentation gives the one-shot verdict (`impl_poll_eq_oneShot`, about the shipped scanner).

- **Severity:** Low. A legal request is answered with 400 or accepted depending on how TCP splits it, so behaviour is not deterministic. Separately, a complete trailer line is never capped while a partial one is. No framing desync results, because both outcomes either reject or agree with the decoder.
- **Spec:**
  - The reactor polls `scan_chunked_resume` after every read (`conn_handle.mojo:655-678`), so its verdict must equal a one-shot scan of the same bytes.
  - RFC 9112 §7.1 does not let the result depend on how the bytes were segmented.
- **What goes wrong:**
  - The complete-line test (`chunked.mojo:246-251`) is `line_end - pos > 4096`.
  - The incomplete-line test is `n - pos > 4096`, which also counts the pending CR. A size line of exactly 4096 bytes, cut after its CR, is therefore MALFORMED, while the same bytes in one read are accepted.
  - Trailer lines (270-290) have the opposite problem: a complete line has no cap at all.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_01.counterexample` (`¬ SegIndep preSegP`, about the scanner before the fix).
  - `counterexample_size_line`: polling `body1` cut at byte 4097 gives `malformed`, while a one-shot scan gives `done 4106`.
  - `counterexample_trailer`: the same with a 5000-byte trailer line gives `malformed` against `done 5007`.
- **Fix:** allow one byte of slack in both incomplete-line tests, and cap complete trailer lines. `impl_poll_eq_oneShot` proves that polling any segmentation of the shipped scanner's input equals a one-shot scan.
- **Repro:** `formal/repro/H1-01_chunk_line_cap_segmentation.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: chunked verdict depends on segmentation (size line one-shot=4106 split=-2; trailer one-shot=5007 split=-2)`
- **Flip:** `OK: chunked verdict is segmentation independent`; `flare/http/proto/chunked.mojo` restored.

### H1-02: a bare LF inside a chunk extension or trailer line is accepted

Status: resolved. Fixed in `scan_chunked_resume` (`flare/http/proto/chunked.mojo`): a size line or trailer line that contains an LF is `CHUNKED_MALFORMED` (new helper `_has_lf`). Regression test `tests/http/test_chunked_request.mojo::test_scan_rejects_bare_lf_in_chunk_lines`. Lean: `impl_agrees_lfTolerant` proves the shipped scanner LF-safe.

- **Severity:** Medium. Request smuggling becomes possible behind any front end that treats a bare LF as a line terminator, which RFC 9112 §2.2 allows. This applies in the default (strict) configuration.
- **RFC:**
  - RFC 9112 §7.1.1: `chunk-ext` is tokens and quoted strings, which never contain LF.
  - RFC 9112 §2.2: a recipient MAY treat a bare LF as a line terminator.
- **What goes wrong:** the scanner looks only for CRLF and skips everything after `;` (`chunked.mojo:239-266`, `270-290`). For `0;\n\r\nX: y\r\n\r\n`:
  - flare reads `0;\n` as the last-chunk line and `X: y` as a trailer, and ends the body at 13;
  - an LF-splitting front end ends the body at 5 and forwards the rest as the next request.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_02.counterexample` (`¬ LfSafe oldP`, the pre-fix scanner), with `old_accepts` (`done 13`) and `lf_recipient_ends_at_5`.
- **Fix:** a chunk line whose content contains LF is MALFORMED. `impl_agrees_lfTolerant` (from `scanEnd_lfSafe`) proves the shipped scanner agrees with an LF-tolerant recipient on both the body and its end.
- **Repro:** `formal/repro/H1-02_chunk_ext_bare_lf.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: scan_chunked_end accepted a chunk extension with a bare LF, body end 13 (an LF-splitting recipient ends the body at 5)`
- **Flip:** `OK: bare LF inside a chunk line is rejected`; `flare/http/proto/chunked.mojo` restored.

### H1-03: with `allow_ows_around_colon`, the reactor and the parser disagree on Transfer-Encoding

Status: resolved. Fixed in `flare/http/proto/chunked.mojo` (`request_te_framing`, new `_colon_after_name`) and `flare/http/_scan.mojo` (`_match_content_length_prefix`): SP/HTAB between the field name and the colon are skipped for both Transfer-Encoding and Content-Length (the latter had the same gap). Regression tests `tests/http/test_h1_smuggling.mojo::test_te_framing_skips_ows_before_the_colon`, `test_content_length_scan_skips_ows_before_the_colon` and `test_ows_before_colon_reactor_and_parser_agree`. Lean: `reactorFraming` is the shipped reactor (`framing_agrees`).

- **Severity:** Medium. It is a request desync: one request produces two responses, and the chunked body is parsed as a request. It needs a public, non-default leniency option, which is documented as safe behind an upstream that emits `Header :value`.
- **RFC:** RFC 9112 §6.3 and §11.2: the component that frames a message and the component that interprets it must use the same framing.
- **What goes wrong:**
  - `request_te_framing` (`chunked.mojo:139-148`) requires `:` immediately after the name.
  - The lenient parser strips SP/HTAB before the colon (`parse.mojo:249-255`).
  - For `Transfer-Encoding : chunked` the reactor sees no TE and Content-Length 0, while the parser accepts the request as chunked.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_03.counterexample`, on the lines `["Host: a", "Transfer-Encoding : chunked"]`:
  - `reactor_frames_by_length`: the pre-fix reactor gives `length 0`;
  - `parser_sees_chunked`: the parser gives `chunked`.
- **Fix:** skip SP/HTAB between the name and `:` in `request_te_framing` and in the Content-Length scan (`Content-Length : 5` had the same gap). Strict mode is unchanged, because the strict parser rejects such lines. `framing_agrees` with `ows = true` proves agreement of the shipped reactor on every request the parser accepts.
- **Repro:** `formal/repro/H1-03_te_ows_colon_framing_desync.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: reactor framed by Content-Length (TE verdict 0, body_total 63) while the parser accepted Transfer-Encoding: chunked; 15 body bytes are left to be parsed as the next request`
- **Flip:** `OK: reactor and parser agree on chunked framing`; `flare/http/proto/chunked.mojo` restored.

### H1-04: with `allow_lf_only_line_endings`, a Transfer-Encoding line after a bare LF is invisible to the reactor

Status: resolved. Fixed in `request_te_framing` (`flare/http/proto/chunked.mojo`): the request line and every header line now end at LF with a preceding CR dropped, the way the lenient parser reads them (`scan_content_length` already anchored on LF). Regression tests `tests/http/test_h1_smuggling.mojo::test_te_framing_ends_header_lines_at_a_bare_lf` and `test_bare_lf_reactor_and_parser_agree`. Lean: `reactorLines` is the shipped split (`lf_fixed_agrees`).

- **Severity:** Medium. It is the same desync as H1-03, triggered by a different non-default leniency option.
- **RFC:** RFC 9112 §2.2 and §6.3: a recipient that accepts a bare LF as a line terminator must do so for framing as well as for parsing.
- **What goes wrong:**
  - `request_te_framing` splits lines on CRLF only (`chunked.mojo:127-153`), so `Host: a\nTransfer-Encoding: chunked` is one line to the reactor.
  - The lenient parser (`parse_util.mojo:165-208`) reads it as two lines.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_04.counterexample`:
  - `reactor_lines`: the pre-fix CRLF split gives `linesCRLFOld blk = [blk]`;
  - the pre-fix reactor gives `length 0`, while the parser over `linesLF blk` gives `chunked`.
- **Fix:** end header lines at LF, dropping a preceding CR, in `request_te_framing`. `lf_fixed_agrees` proves the shipped reactor agrees on every block the parser accepts. The request line also ends at its first LF.
- **Repro:** `formal/repro/H1-04_te_lf_only_framing_desync.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: reactor framed by Content-Length (TE verdict 0, body_total 61) while the parser accepted Transfer-Encoding: chunked; 15 body bytes are left to be parsed as the next request`
- **Flip:** `OK: reactor and parser agree on chunked framing`; `flare/http/proto/chunked.mojo` restored.

### H1-05: obs-text header values become Strings that are not valid UTF-8

Status: resolved. The server parser now rejects an obs-text header value that is not valid UTF-8 (and an obs-fold continuation that is not), so every stored value is a valid `String` (`fixed_value_utf8`, about the shipped `valueAccepted`).

- **Severity:** Low. It needs the non-default `accept_obs_text_in_field_value`. The resulting `String` breaks Mojo's UTF-8 invariant, so any code that iterates its codepoints sees malformed data.
- **Spec:**
  - The contract of `_ascii_unchecked_string` (`flare/http/proto/ascii.mojo:63-70`): every byte is < 0x80.
  - Mojo `String` holds valid UTF-8.
  - RFC 9110 §5.5 admits obs-text only as opaque octets.
- **What goes wrong:** in the obs-text branch (`parse.mojo:277-285`) every byte ≥ 0x80 is accepted. The value is then built with `_ascii_unchecked_string` (`parse_util.mojo:65-89`), so `X: \xff` is stored as a String holding `0xFF`.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_05.counterexample` (`¬ Utf8Safe (valueAcceptedOld true)`, the byte check alone), with `lenient_accepts` and `not_utf8`.
- **Fix:** reject an obs-text value that is not valid UTF-8, or build it with a validating constructor. `fixed_value_utf8` proves every accepted value is then valid UTF-8. `strict_value_utf8` shows strict mode is already safe.
- **Repro:** `formal/repro/H1-05_obs_text_value_not_utf8.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: header value String holds bytes [ 255 ], which is not valid UTF-8`
- **Flip:** I added `if not _is_valid_utf8(v.as_bytes()): raise` after the byte loop, importing it from `flare/io/byte_cursor.mojo`. The repro printed `OK: obs-text value rejected or stored as valid UTF-8`, and `flare/http/_server/parse.mojo` was restored.

### H1-06: the client returns a truncated chunked body as complete

Status: resolved. The read-to-EOF readers now run `scan_chunked_end` first (`_require_complete_chunked`) in both `_parse_http_response` and `_extract_body_and_trailers`, and raise on an incomplete or malformed chunked body (`cRead_complete`, about the shipped `cRead`).

- **Severity:** Medium. The read-to-EOF readers hand the application a truncated body as a successful response. They serve unpooled HTTP/1.1 requests over TCP and TLS and the chunked uploads (`client.mojo:1283`, `1445`, `1495`, `2505`). On TLS, a peer or an on-path attacker that resets the connection mid-body (no close_notify) chooses where the body ends.
- **RFC:** RFC 9112 §7.1 (a chunked body ends with the last-chunk and the trailer section) and §8 (a message that ends before that is incomplete).
- **What goes wrong:** `_read_http_response_tcp`/`_tls` (`_client/parse.mojo:645-703`) read to EOF and call `_parse_http_response`, whose chunked branch (`205-212`) calls `_decode_chunked` (`497-578`). The decoder stops at the first line without CRLF and returns what it has. Nothing checks that the zero-size chunk arrived. The pooled framed reader is correct, because it scans first (`cDec_agree`).
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_06.counterexample` (`¬ Complete (2^20) cReadOld`): `old_accepts` gives `cReadOld "5\r\nhel" = ok "hel"`, while `scanner_incomplete` gives the shipped scanner's verdict `incomplete`.
- **Fix:** in the chunked branch, raise unless `scan_chunked_end(raw, body_start, MAX_BUFFERED_RESPONSE_BYTES) ≥ 0`. `cRead_complete` proves every returned body is then a complete chunked body.
- **Repro:** `formal/repro/H1-06_client_truncated_chunked_accepted.mojo` (at tag `formal-audit-0.12`; pure parser, and a forked TLS server that closes without close_notify)
- **Observed (3 runs):** `BUG REPRODUCED: truncated chunked body returned as complete (pure: accepted status=200 body=hel; TLS without close_notify: accepted status=200 body=hel)`
- **Flip:** with the scan added to `flare/http/_client/parse.mojo`: `OK: truncated chunked body refused (raised: NetworkError: HTTP response: incomplete chunked body; raised: NetworkError: HTTP response: incomplete chunked body)`; the file was restored.

### H1-07: a bare-LF response head skips the empty line that ends it

Status: resolved. `_parse_response_head` now refuses a head that holds a bare LF or an empty line before its end, for the buffered and the streaming readers alike (`headImpl_agrees`, about the shipped `headImpl`).

- **Severity:** Low. It needs a server, or an intermediary in front of one, that emits bare LF. Then a cache or proxy that ends lines at LF (RFC 9112 §2.2 allows it) sees body bytes that flare reads as header fields, for example a `Set-Cookie`.
- **RFC:** RFC 9112 §2.2 (a recipient MAY treat a bare LF as a line terminator) and §2.1 (the first empty line ends the head).
- **What goes wrong:** the head runs to the first CRLFCRLF (`_find_crlf2_from`, `_client/parse.mojo:233-245`). `_split_lines` (`283-306`) ends lines at a bare LF, and `_parse_response_head` (`106-110`) skips empty lines. So in `HTTP/1.1 200 OK\nX: a\n\nSet-Cookie: s=evil\r\n…\r\n\r\n` the empty line is ignored and `Set-Cookie` becomes a field.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_07.counterexample` (`¬ HeadAgrees headOld`): `old_head` gives fields `X: a`, `S: e` and body `b`, while `lf_head` ends the head at `\n\n`, with body `S: e\r\n\r\nb`.
- **Fix:** refuse a head with a bare LF or an empty line. `headImpl_agrees` proves the shipped head lines and body start equal the LF recipient's.
- **Repro:** `formal/repro/H1-07_response_bare_lf_blank_line_skipped.mojo` (at tag `formal-audit-0.12`)
- **Observed (3 runs):** `BUG REPRODUCED: header after an LF-terminated empty line was parsed (accepted status=200 set-cookie=s=evil)`
- **Flip:** `OK: bare-LF head is refused or ends at the empty line (raised: NetworkError: HTTP response: bare LF in head)`; `flare/http/_client/parse.mojo` restored.

### H1-08: the client takes the first three digits of a longer status code

Status: resolved. `_parse_status_line` now requires SP, or the end of the line, after the three status digits and raises otherwise (`parseStatus_delimited`, about the shipped `parseStatus`).

- **Severity:** Low. A malformed status line `HTTP/1.1 2041 OK` is read as 204. Status 204 has no body, so on a pooled connection the real body is parsed as the next response.
- **RFC:** RFC 9112 §4: `status-line = HTTP-version SP status-code SP [reason-phrase]`, with `status-code = 3DIGIT`.
- **What goes wrong:** `_parse_status_line` (`_client/parse.mojo:318-352`) checks three digits after the first SP and ignores the next byte.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_08.counterexample`: `old_parses` gives `parseStatusOld "HTTP/1.1 2041 OK" = some 204`, and `not_delimited` proves no decomposition of the line has 204 as a delimited three-digit code.
- **Fix:** require SP or the end of the line after the third digit. `parseStatus_delimited`.
- **Repro:** `formal/repro/H1-08_status_code_extra_digits.mojo` (at tag `formal-audit-0.12`)
- **Observed (3 runs):** `BUG REPRODUCED: four-digit status code accepted (accepted status=204 body_len=0)`
- **Flip:** `OK: four-digit status code refused (raised: NetworkError: HTTP status code not three digits: HTTP/1.1 2041 OK)`; `flare/http/_client/parse.mojo` restored.

### H1-09: an HTTP/1.0 response without keep-alive goes back to the pool

Status: resolved. The framed reader records whether the status line names exactly `HTTP/1.1` (`_ResponseHead.http11`) and pools the connection only then. An HTTP/1.0 response with `keep-alive` is not pooled either (stricter than RFC 9112 §9.3, still meets `PersistOK`). `canReuse` is the shipped decision (`canReuse_ok`). Test: `test_only_an_http11_response_keeps_the_connection`.

- **Severity:** Low. The next request on that connection goes to a socket the server is closing. It fails, or is retried, and the failure is timing-dependent. No cross-response desync results, because the server closes.
- **RFC:** RFC 9112 §9.3: an HTTP/1.0 response keeps the connection open only with `Connection: keep-alive`.
- **What goes wrong:** the pooled reader's reuse decision (`_client/parse.mojo:836-884`) checks `Connection: close` and close-delimited framing, but never the version.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_09.counterexample` (`¬ PersistOK canReuseOld`): `canReuseOld HTTP10 true [] (.length 2) = true`.
- **Fix:** reuse only an HTTP/1.1 response, or an HTTP/1.0 one with `keep-alive`; the minimal fix is HTTP/1.1 only. `canReuse_ok`.
- **Repro:** `formal/repro/H1-09_http10_response_pooled.mojo` (at tag `formal-audit-0.12`)
- **Observed (3 runs):** `BUG REPRODUCED: HTTP/1.0 response without keep-alive marked reusable (status=200 body=hi can_reuse=True)`
- **Flip:** `OK: HTTP/1.0 response closes the connection (status=200 body=hi can_reuse=False)`; `flare/http/_client/parse.mojo` restored.

### H1-10: obs-fold continuation lines are not validated

Status: resolved. The server parser now runs the same value check (`_check_field_value`: CR/LF/NUL, other control bytes, obs-text gate, UTF-8) on every obs-fold continuation as on a first line. `fields` is the shipped loop (`fields_valid`). Test: `test_obs_fold_continuation_gets_the_value_byte_check`.

- **Severity:** Low. It needs the non-default `allow_obs_fold`. Control bytes refused on a first line reach the application through a continuation line.
- **RFC:** RFC 9112 §5.2 (obs-fold is replaced by SP; the result is still a field value) and RFC 9110 §5.5 (no CTL except HTAB).
- **What goes wrong:** the continuation branch of the server field loop (`_server/parse.mojo:203-320`) appends the stripped line with no byte check. The first-line check (`277-285`) never sees it.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_10.counterexample`: `old_stores` (about the pre-fix loop `fieldsOld`) gives `X: a` + ` \x01\x7f` stored as `a \x01\x7f`, and `invalid` shows `valueOk` refuses it.
- **Fix:** run the value check on each continuation. `fields_valid` proves every stored value then passes `valueOk`; `fold_unfold` shows valid folds still unfold as RFC 9112 §5.2 says.
- **Repro:** `formal/repro/H1-10_obs_fold_continuation_unvalidated.mojo` (at tag `formal-audit-0.12`; controls: the same bytes on a first line are refused; a plain fold gives `a b`)
- **Observed (3 runs):** `BUG REPRODUCED: folded value accepted with control bytes, x = [ 97 32 1 127 ] (the same bytes on a first line are refused)`
- **Flip:** `OK: control bytes in a continuation line refused (raised: invalid control character in header value)`; `flare/http/_server/parse.mojo` restored.

### H1-11: a streamed TLS download that ends without close_notify is complete

Status: resolved. `_H2Transport.read` now raises `NetworkError` when a TLS read returns 0 and `eof_was_unclean()`, so `HttpDownload._read_close` never sees an unclean end (`bufferedClose_safe`; the shipped `dlClose` is `bufferedClose`).

- **Severity:** Medium. `HttpDownload` on a close-delimited TLS body reports success for a body cut at any point by a TCP reset, which is the truncation attack TLS close_notify exists to stop. The buffered readers have the guard.
- **RFC:** RFC 8446 §6.1 (a close without close_notify is a truncation) and RFC 9112 §8 (a close-delimited body ends at a clean close).
- **What goes wrong:** `HttpDownload._read_close` (`_client/download.mojo:215-220`) reads until `read` returns 0. The TLS transport's `read` (`_client/h2_transport.mojo`) returns 0 on an unclean EOF as well, and nobody calls `eof_was_unclean()`. Compare `_client/parse.mojo:665-683`.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.H1_11.counterexample` (`¬ TruncSafe dlCloseOld`).
- **Fix:** raise in the transport `read` when it returns 0 and `eof_was_unclean()`, as the buffered path does. `bufferedClose_safe` (`dlClose` = `bufferedClose`).
- **Repro:** `formal/repro/H1-11_download_tls_truncated_close_body.mojo` (at tag `formal-audit-0.12`; forked TLS server that writes `partial` and closes without close_notify)
- **Observed (3 runs):** `BUG REPRODUCED: close-delimited TLS body without close_notify returned as complete (status=200 body=partial)`
- **Flip:** `OK: truncated TLS download refused (raised: NetworkError: TLS connection closed without close_notify)`; `flare/http/_client/h2_transport.mojo` restored.

### WS-01: `decode_one` accepts reserved opcodes

Status: resolved. `WsFrame.decode_one` raises `WsProtocolError` for opcodes 0x3-0x7 and 0xB-0xF right after the RSV checks, so the server, client and h2 receive paths all fail the connection. `decodeKnown` is the shipped decoder (`decodeKnown_safe`). Test: `test_decode_reserved_opcode_raises`.

- **Severity:** Low. The application receives a frame with opcode 0x3-0x7 or 0xB-0xF where the connection must fail. This is a protocol-compliance gap with no memory or framing impact.
- **RFC:** RFC 6455 §5.2: "If an unknown opcode is received, the receiving endpoint MUST _Fail the WebSocket Connection_."
- **What goes wrong:** `opcode = byte0 & 0x0F` is never range-checked (`frame.mojo:395-508`), although RSV1-3 are. `WsConnection.recv` and `WsClient.recv` return the frame as decoded.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.WS_01.counterexample` (`¬ OpcodeSafe decode`):
  - `decodes_reserved`: `[0x83,0x00]` decodes to a frame with opcode 3;
  - `decodes_reserved_control`: `0x8B` decodes to opcode 11.
- **Fix:** after the RSV checks, raise unless the opcode is 0x0-0x2 or 0x8-0xA. `decodeKnown_safe` proves only known opcodes are then accepted, and `decodeKnown_encode` shows the round trip still holds.
- **Repro:** `formal/repro/WS-01_reserved_opcode_accepted.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: decode_one accepted reserved opcodes (0x3 -> opcode 3, 0xB -> opcode 11; -1 = rejected)`
- **Flip:** `OK: reserved opcodes 0x3 and 0xB are rejected`; `flare/ws/frame.mojo` restored.

### WS-02: `WsClient.recv_message` returns one fragment, not the message

Status: resolved. `WsClient.recv_message` now skips PONG, requires a TEXT/BINARY start, appends CONTINUATION payloads to FIN (PING/PONG may interleave), validates UTF-8 over the whole text message, and bounds the reassembled payload by `max_frame_size`. `nextMessage` is the shipped reader (`nextMessage_delivered`).

- **Severity:** Medium. Any server that fragments messages makes the client return truncated messages, then return continuation payloads as separate messages. An unsolicited PONG is returned as a text message. Data is silently corrupted at the application level. The function is documented as "Receive the next complete message".
- **RFC:**
  - RFC 6455 §5.4: a message is a TEXT or BINARY frame followed by CONTINUATION frames up to FIN, and its payload is the concatenation.
  - RFC 6455 §5.5.3: an unsolicited PONG is allowed and is not a message.
- **What goes wrong:** `client.mojo:765-794` returns the payload of whatever frame comes next ("TEXT or anything else: return as text").
- **Counterexample** (at tag `formal-audit-0.12`):
  - `Flare.Bugs.WS_02.counterexample_fragment` (about the pre-fix `recvMessageOld`): `[TEXT(fin=0,"hel"), CONT(fin=1,"lo")]` gives `"hel"`.
  - `counterexample_pong`: `[PONG "x", TEXT "a"]` gives `"x"`.
- **Fix:** skip PONG, require TEXT/BINARY to start a message, append CONTINUATION payloads until FIN, and validate UTF-8 over the whole text message. `nextMessage_delivered` proves the RFC 6455 §5.4 reassembly property.
- **Repro:** `formal/repro/WS-02_recv_message_returns_fragment.mojo` (at tag `formal-audit-0.12`; loopback TCP)
- **Observed:** `BUG REPRODUCED: recv_message returned 'hel', 'lo', 'x' (expected 'hello', 'a')`
- **Flip:** `OK: recv_message reassembles fragments and skips PONG`; `flare/ws/client.mojo` restored.

### WS-03: `WsClient` accepts masked frames from the server

Status: resolved. `WsClient._recv_one` raises `WsProtocolError` for a masked server frame, so `recv()` and `recv_message()` fail the connection. `clientAccept` is the shipped check (`clientAccept_safe`). Test: `test_client_refuses_a_masked_server_frame`.

- **Severity:** Low. It is a MUST violation with no direct exploit. The server side has the corresponding check (`server.mojo:558-562`).
- **RFC:** RFC 6455 §5.1: "A client MUST close a connection if it detects a masked frame."
- **What goes wrong:** `_recv_one` (`client.mojo:717-763`) unmasks the frame and returns it.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.WS_03.counterexample` (`¬ ClientSafe clientAcceptOld`), with `client_accepts_masked` (a masked TEXT "hi" is accepted).
- **Fix:** raise `WsProtocolError` if `result.frame.masked`. `clientAccept_safe` proves the client then accepts only unmasked frames.
- **Repro:** `formal/repro/WS-03_client_accepts_masked_server_frame.mojo` (at tag `formal-audit-0.12`; loopback TCP)
- **Observed:** `BUG REPRODUCED: client accepted a masked server frame (payload 'hi')`
- **Flip:** `OK: client rejects a masked server frame`; `flare/ws/client.mojo` restored.

### WS-04: `WsClient` accepts a 101 that is not a WebSocket handshake

Status: resolved. Both branches of `_connect_impl` record `Upgrade`, `Connection`, `Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions` next to the accept value (`_UpgradeResponse`), and `verify` raises `WsHandshakeError` unless the whole RFC 6455 §4.1 list holds. `clientAccepts` is the shipped check (`clientAccepts_ok`). Tests: `tests/ws/test_ws_client_handshake.mojo`.

- **Severity:** Low. The accept value is still checked, so only a server that read the key and computed the accept can trigger it. The client then treats a peer that never agreed to WebSocket (no `Upgrade`/`Connection`), or that selected a subprotocol the client never offered, as a WebSocket connection.
- **RFC:** RFC 6455 §4.1: the client MUST fail the connection if the 101 lacks `Upgrade: websocket` (case-insensitive), lacks a `Connection` token `upgrade`, has the wrong `Sec-WebSocket-Accept`, or names an extension or subprotocol that was not requested.
- **What goes wrong:** both branches of `_connect_impl` (`client.mojo:562-603`, `609-646`) check the status prefix and the last `Sec-WebSocket-Accept`, and read no other field.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.WS_04.counterexample` holds for every SHA-1: the 101 `[Sec-WebSocket-Accept: <right value>, Sec-WebSocket-Protocol: chat]` passes the pre-fix check `clientAcceptsOld` and violates `ClientOK`.
- **Fix:** check the whole list. `clientAccepts_ok`: the shipped check decides exactly `ClientOK`. `handshake_complete` shows flare's own server still passes.
- **Repro:** `formal/repro/WS-04_client_accepts_incomplete_101.mojo` (at tag `formal-audit-0.12`; forked raw server; control: a complete 101 connects)
- **Observed (3 runs):** `BUG REPRODUCED: WsClient accepted a 101 with no Upgrade or Connection field and an unrequested Sec-WebSocket-Protocol`
- **Flip:** with the field checks added to both branches of `flare/ws/client.mojo`: `OK: incomplete 101 refused (raised: WsHandshakeError: 101 lacks Upgrade/Connection or names an unrequested protocol)`; the file was restored.

### WS-05: the standalone `WsServer` handshake checks almost nothing

Status: resolved. Both standalone readers collect the request line and every handshake field (`_UpgradeFields`) and call `_ws_handshake_problem`: GET over HTTP/1.1, `Upgrade` and `Connection` as tokens, exactly one valid key (base64 of 16 bytes), exactly one version, 13. A refused handshake is answered 426 with `Sec-WebSocket-Version: 13` (version only) or 400. `srv` is the shipped check (`srv_ok`). Tests: `tests/ws/test_ws_handshake_request.mojo`.

- **Severity:** Low. Non-WebSocket requests are upgraded: POST, HTTP/1.0, `Connection: noupgrade`, a key that is not base64 of 16 bytes, and any version. Cross-protocol requests (for example a form POST carrying these fields) can open a WebSocket. A client speaking another version gets 101 instead of 426.
- **RFC:** RFC 6455 §4.2.1 (GET, HTTP/1.1 or higher, `Upgrade` containing `websocket`, a `Connection` token `upgrade`, a key that decodes to 16 bytes, version 13), §4.2.2 point 4 (otherwise 426 with `Sec-WebSocket-Version: 13`) and §11.3.1/§11.3.5 (those fields at most once).
- **What goes wrong:** `_parse_ws_upgrade_bytes` and `_read_upgrade_request` (`server.mojo:188-321`) drop the request line, test `Connection` by substring, test the key for being non-empty, keep the last repeated key, and never read `Sec-WebSocket-Version`.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.WS_05.counterexample`: the request above gives `srvOld = some "x"` but violates `ServerOK`. `key_invalid` shows `x` is not a valid key.
- **Fix:** check the request line, the Connection tokens, the decoded key length, single key/version fields and version 13. `srv_ok`. `handshake_complete` shows flare's own client request still passes.
- **Repro:** `formal/repro/WS-05_standalone_server_handshake_unchecked.mojo` (at tag `formal-audit-0.12`; control: the RFC 6455 §1.3 example request is accepted)
- **Observed (3 runs):** `BUG REPRODUCED: WsServer handshake accepted POST/HTTP/1.0 with Connection: noupgrade, key 'x' and version 8 (accepted key=x)`
- **Flip:** with the request-line, Connection-token, key and version checks added to `_parse_ws_upgrade_bytes` in `flare/ws/server.mojo`: `OK: invalid opening handshake refused (raised: NetworkError: not a GET HTTP/1.1 request)`; the file was restored. The flip did not add the single-field check, which the shipped fix and `srv` have. The repro's request does not depend on it.

### WS-06: `WsConnection` does not take part in the closing handshake

Status: resolved. `WsConnection` keeps a `_close_sent` flag. `recv` answers a received CLOSE (echoing the code, an empty CLOSE, or 1002 for an invalid body) unless one was sent, `close()` sends once and no longer claims to wait, and `send_text`/`send_binary`/`send_frame` raise once a CLOSE was sent. `fixStep` is the shipped endpoint (`fixed_closeOK`).

- **Severity:** Medium. Every connection that a client closes ends with EOF instead of a CLOSE reply, so clients see an abnormal closure (1006) and lose the close code. An invalid CLOSE body is not answered with 1002. After `close()` the server still puts data frames on the wire. `close()` is documented as "Send a CLOSE frame and wait for the client's CLOSE response", but it does not wait.
- **RFC:** RFC 6455 §5.5.1: an endpoint that receives a CLOSE and has not sent one MUST send a CLOSE in response, and after sending a CLOSE it MUST NOT send more data. Per §7.4.1 and §7.1.7, a 1-byte body, an invalid code or a non-UTF-8 reason is a protocol error (1002).
- **What goes wrong:**
  - `recv` (`server.mojo:514-536`) answers PING but hands CLOSE to the caller with no reply.
  - The documented handler (`660-671`) breaks on CLOSE, and `__deinit__` closes the socket.
  - `close()` (`600-616`) keeps no state.
  - `send_text`/`send_binary`/`send_frame` (`473-512`) never check.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.WS_06.counterexample_no_echo` (CLOSE 1000 gets no reply), `counterexample_invalid_payload` (a 1-byte body gets no 1002) and `counterexample_data_after_close` (`close(1000)` then `send_text` writes TEXT after CLOSE). All three are `¬ CloseOK oldStep ()`, about the pre-fix endpoint.
- **Fix:** add a `close_sent` flag. On a received CLOSE, reply with the code (or an empty CLOSE, or 1002 for an invalid body) unless one was already sent; set the flag in `close()`; make `send_*` raise once it is set. `fixed_closeOK` proves this on every trace.
- **Repro:** `formal/repro/WS-06_close_handshake_not_answered.mojo` (at tag `formal-audit-0.12`; forks `_handle_ws_connection` with the documented handler, and with a close-then-send handler)
- **Observed (3 runs):** `client CLOSE 1000 -> server sent: (nothing)`, `client CLOSE 1-byte payload -> server sent: (nothing)`, `close() then send_text -> server sent: [op=8 code=1000][op=1]`, then `BUG REPRODUCED: closing handshake violated (echo missing: True; 1002 missing: True; data after CLOSE: True)`
- **Flip:** with the flag, the reply and the checks added to `flare/ws/server.mojo`, the repro printed `[op=8 code=1000]`, `[op=8 code=1002]` and `[op=8 code=1000]`, then `OK: CLOSE echoed, invalid payload answered with 1002, no data after CLOSE`; the file was restored.

### WS-07: the reactor upgrade tests Connection by substring and never decodes the key

Status: resolved. `_handle_ws_upgrade` qualifies a request with `_ws_handshake_problem`, the rule the standalone server applies (WS-05): `Connection` and `Upgrade` as tokens, exactly one key that is base64 of 16 bytes, exactly one version 13. A request that fails it is served as ordinary HTTP. `reactor` is the shipped decision (`reactor_ok`). Test: `test_shared_listener_checks_the_whole_handshake`.

- **Severity:** Low. On the shared-listener path (`ServerConfig.ws`, once spelled `serve_ws_upgrade`), `Connection: noupgrade` (or any value containing `upgrade`) and a key such as `x` get 101. The version is enforced, because the 426 check (`versionMismatch`) runs first.
- **RFC:** RFC 6455 §4.2.1 points 4-5: a `Connection` token `upgrade`, and a key that is base64 of 16 bytes.
- **What goes wrong:** `_handle_ws_upgrade` (`conn_handle.mojo:1512-1523`) uses `"upgrade" in lower(connection)` and `key.byte_length() > 0`.
- **Counterexample** (at tag `formal-audit-0.12`): `Flare.Bugs.WS_07.counterexample`: GET, HTTP/1.1, `Upgrade: websocket`, `Connection: noupgrade`, `Sec-WebSocket-Key: x`, version 13 gives `reactorOld = upgrade "x"` and violates `ServerOK` (`no_conn_token`).
- **Fix:** test Connection tokens and decode the key, as in `qual`. `reactor_ok`.
- **Repro:** `formal/repro/WS-07_reactor_ws_key_and_connection_token.mojo` (at tag `formal-audit-0.12`; forked `HttpServer.serve` with `ServerConfig.ws` set; control: the valid handshake gets 101)
- **Observed (3 runs):** `BUG REPRODUCED: reactor upgraded a request with Connection: noupgrade and Sec-WebSocket-Key: x (HTTP/1.1 101 Switching Protocols)`
- **Flip:** with token matching and the base64 key-length check added to `flare/http/_reactor/conn_handle.mojo`: `OK: invalid handshake not upgraded (HTTP/1.1 200 OK)`; the file was restored.

After every flip, `git status --short flare/` showed none of my files. Other agents' flips can appear there briefly; one appeared once, on a file I did not touch. Every repro was run three times, with the same output each time.

## Checked, not a bug

**HTTP/1.1**
- **Strict-mode smuggling.** `no_smuggling_strict`: with the default leniency, whenever the parser accepts a request, the reactor frames it the same way (TE, CL, both, duplicates, OWS and case variations).
- **obs-fold framing.** Neither the reactor nor the parser takes TE or CL from continuation lines, so framing still agrees. The unvalidated continuation bytes were H1-10.
- **Truncated input to the full parser.** The parser accepts heads without CRLFCRLF, but the reactor only calls it after finding the terminator, so this is unreachable from the network.
- **`_parse_http_request` slicing past the end on early EOF.** This legacy path is reachable only from tests; `server.mojo` only re-exports it.
- **The minimal parser skips validation.** This is by design (it is the documented fast path) and does not affect framing.
- **The 18-digit Content-Length cap.** `parseCL_fits`: the value is < 10^18, so no Int64 overflow.
- **Chunk-size Int64 wrap.** `parseSize_fits` covers every `max_body < 2^59`. A wrap needs a configured body limit of at least 2^59 bytes, which is a misconfiguration.
- **Keep-alive.** `_wants_close` and the token-list issues are APP-02 and APP-03 in `L4_App/KeepAlive.lean`.
- **Client framing (RFC 9112 §6.3).** `respFraming` implements §6.3 exactly for the cases it accepts (`framing_*_iff`). It is stricter where §6.3 allows recovery: it refuses TE together with CL, a repeated CL, and any TE other than exactly `chunked`. HEAD, 1xx, 204 and 304 never read a body (`framing_bodyless`).
- **Response desync on a pooled keep-alive connection.** The pooled reader truncates the buffer at the scanner's end before parsing (`cDec_agree`, `framed_chunked_agrees`) and reads exactly n bytes for a length body (`framing_length_iff`), so bodies cannot spill into the next response. The ways to split a response in the head were filed as H1-07 (bare LF) and H1-08 (status code). The pooled chunked path uses the reactor's scanner, so it shared H1-01 and H1-02; those were not filed again.
- **A 101 on a pooled connection.** `_parse_http_response` treats 1xx other than 101 as interim. A 101 the client did not ask for would be a server MUST violation (RFC 9110 §15.2.2), so this is not a client bug.
- **A bare CR in a response field** is refused by `HeaderMap`.
- **The 16-hex-digit chunk-size cap** in both client readers is deliberate. It is what bounds the size accumulator.
- **Encoder trailers.** The streaming serializer writes application-chosen trailers without filtering forbidden names (RFC 9110 §6.5.1). flare's own client refuses them (`ClientTrailersOK`). This is an application responsibility, listed under limitations.
- **Buffered TLS reads** refuse a close-delimited body without close_notify (`bufferedClose_safe`). The streaming download has the same guard in `_H2Transport.read` (H1-11).

**WebSocket**
- **Close-code validation on receive** was an open question in the previous round. It is now part of WS-06, whose fix answers an invalid body with 1002.
- **`WsFrame.close` does not validate the code it sends.** Codes come from the application or from `WsCloseCode` constants. The MUST NOT on sending 1005/1006 binds the application that picks them.
- **`WsClient`'s closing handshake** is not part of WS-06. `recv` hands CLOSE to the application, which is told to call `close()`. `close()` writes CLOSE and closes the transport, so a reply exists (code 1000; RFC 6455 says the code is "typically" echoed), and nothing can be sent after it.
- **RSV1 is always rejected.** permessage-deflate is never negotiated, so this is correct (RFC 6455 §5.2).
- **Non-minimal length encodings are accepted.** The RFC's MUST binds the sender, and flare's encoder is minimal (`lenCode`, `decode_encode`).
- **Key generation.** The client key is base64 of 16 CSPRNG bytes, with no fallback (`genKey_valid`).
- **Accept computation.** The client and both servers compute `base64(SHA-1(key ++ GUID))` the same way, and every check accepts flare's own handshakes (`handshake_complete`).
- **Version 13 on the reactor path** is enforced: the 426 branch runs first, and `reactor_ok` shows every upgraded request carries exactly one `Sec-WebSocket-Version: 13`. The 426 response keeps the connection open, which is APP-01 in L4 and is not repeated here.
- **The server's exact `Upgrade == "websocket"` test** is stricter than RFC 6455's token list. That is an interoperability note, not a safety issue.
- **Subprotocol selection on the server.** No server path ever sends `Sec-WebSocket-Protocol`. RFC 6455 §4.2.2 lets a server select none, so this is allowed. The client offers none and, with the WS-04 fix, refuses one in the 101.
- **A WebSocket upgrade on TLS is served in cleartext.** This is APP-48 (`L4_App/ConnExt.lean`) and is not repeated here.
- **UTF-8 validation of text frames** is exactly RFC 3629 (`textPayload_ok_iff`, from L1). The server fails a final TEXT frame that is not UTF-8 with 1007 (`serverRecv_utf8`).
- **The server rejects unmasked client frames** (`server_safe`), with CLOSE 1002 (`serverRecv_mask`).
- **The encoder does not check opcode > 15.** Only internal constants reach it.
- **Server-side fragmentation.** `WsConnection.recv` is frame-level, and reassembly is left to the application by its API.

## Traceability

| Lean definition | Mojo symbol | Theorems | Status |
|---|---|---|---|
| `Chunked.hexVal`, `parseSize` | `http/proto/chunked.mojo#_hex_val`, `#scan_chunked_resume` | `parseSize_le`, `parseSize_fits`, `parseSize_wraps_unbounded` | proved / counterexample (misconfiguration only) |
| `Chunked.findCRLF`, `CAP`, `scanL`, `scanTr` | `chunked.mojo#scan_chunked_resume`, `#CHUNK_LINE_MAX` | `scanL_resume`, `scanL_total_le`, `scanL_done_append` | proved |
| `Chunked.scanResume`, `scanEnd` (`scanImpl`) | `chunked.mojo#scan_chunked_resume`, `#scan_chunked_end` | `scanEnd_range`, `scanResume_resume`, `scanEnd_segmentation_independent`, `scanEnd_lfSafe`, `impl_agrees_lfTolerant` | proved |
| `Chunked.poll` (`ChunkedSpec.lean`) | `http/_reactor/conn_handle.mojo#ConnHandle._check_request_complete` | `poll_eq_oneShot`, `impl_poll_eq_oneShot` | proved |
| `Chunked.decL`, `decTr`, `parseHexD`, `decodeBody` | `chunked.mojo#decode_chunked_body` | `decL_of_scanL`, `scanEnd_decode` | proved |
| `Text.isWS`, `isDigit`, `decVal`, `finCL`, `parseCL` | `http/_scan.mojo#parse_content_length_bytes` | `parseCL_complete`, `parseCL_sound`, `parseCL_fits` | proved |
| `Text.lower`, `ieqPrefix`, `ieq` | `chunked.mojo#_lower`, `#_matches_at`, `http/proto/ascii.mojo#ascii_eq_ignore_case` | `ieqPrefix_append_left`, `ieqPrefix_take` | proved |
| `Text.splitComma`, `normTok`, `tokens`, `classifyT`, `classify` | `chunked.mojo#classify_transfer_coding` | `tokens_strip`, `classify_strip`, `classify_join` | proved |
| `Text.isTchar`, `isFieldVchar`, `strip`, `findB` | `http/_server/parse_util.mojo#_is_token_char`, `#_is_field_value_char`, `#_ascii_strip_slice`, `http/_server/parse.mojo#_parse_http_request_bytes` | `strip_decomp`, `findB_spec` | proved |
| `Framing.scanField`, `joinR`, `reactorFraming`, `reactorLines` | `chunked.mojo#_colon_after_name`, `#request_te_framing`, `_scan.mojo#_match_content_length_prefix`, `#scan_content_length` | `framing_agrees`, `no_smuggling_strict`, `lf_fixed_agrees` | proved |
| `Framing.nameOf`, `wfB`, `field`, `parserField`, `joinP`, `parserFraming` | `parse.mojo#_parse_http_request_bytes` | `framing_agrees`, `shape_of_wf` | proved |
| `Framing.splitOn`, `dropCR`, `linesLF` | `parse_util.mojo#_read_line_buf_lenient` | `lf_fixed_agrees` | proved |
| `FieldValue.byteOk`, `valueOk`, `valueAccepted` | `parse.mojo#_check_field_value`, `#_parse_http_request_bytes` | `strict_value_utf8`, `fixed_value_utf8` | proved |
| `Ws.Key.at`, `maskFrom`, `appendMasked` | `ws/frame.mojo#WsFrame.decode_one`, `#_append_masked` | `maskFrom_involutive`, `maskFrom_append`, `appendMasked_eq` | proved |
| `Ws.Frame`, `isControl`, `byte0`, `lenCode`, `be16`, `be64`, `extLen`, `encode`, `encodeChecked` | `ws/frame.mojo#WsFrame`, `#WsFrame.is_control`, `#WsFrame.encode_with_key`, `#WsFrame.encode` | `decode_encode`, `lenCode_125`, `lenCode_126`, `lenCode_65535`, `lenCode_65536` | proved |
| `Ws.parseLen`, `finish`, `decode`, `decodeKnown` | `ws/frame.mojo#WsFrame.decode_one` | `decode_encode`, `decode_ok_shape`, `decodeKnown_safe`, `decodeKnown_encode` | proved |
| `Ws.serverAccept`, `serverRecv` | `ws/server.mojo#WsConnection._recv_one`, `#WsConnection.recv` | `server_safe`, `serverRecv_utf8`, `serverRecv_mask`, `serverRecv_keeps`, `serverRecv_safe` | proved |
| `Ws.clientAccept`, `recvFrame` | `ws/client.mojo#WsClient._recv_one`, `#WsClient.recv` | `clientAccept_safe` | proved |
| `Ws.collect`, `nextMessage` | `ws/client.mojo#WsClient._recv_data_frame`, `#WsClient.recv_message` | `collect_spec`, `nextMessage_delivered` | proved |
| UTF-8 check (`L1.Utf8.isValidUtf8`) | `ws/frame.mojo#WsFrame.text_payload` | `textPayload_ok_iff` | proved (in L1) |
| `ObsFold.isSPHT`, `aStrip`, `colonAt`, `fields` | `parse.mojo#_check_field_value`, `#_parse_http_request_bytes`, `parse_util.mojo#_ascii_strip_slice` | `fold_unfold`, `strict_no_fold`, `fields_valid` | proved |
| `ClientResponse.bodyless`, `respFraming` | `http/_client/parse.mojo#_response_framing` | `framing_bodyless`, `framing_te_cl_reject`, `framing_dup_cl`, `framing_*_iff` | proved |
| `ClientChunked.isSWS`, `pyStrip`, `hexAcc`, `cHex`, `trailerOk`, `cTr`, `cDec`, `cRead` | `_client/parse.mojo#_parse_hex`, `#_is_forbidden_trailer`, `#_decode_chunked`, `#_require_complete_chunked` | `cDec_agree`, `framed_chunked_agrees`, `cRead_complete` | proved |
| `ClientResponse.parseStatus` | `_client/parse.mojo#_parse_status_line` | `parseStatus_delimited` | proved |
| `ClientResponse.san`, `findCRLF2`, `splitGo`, `splitLines`, `headImpl` | `_client/parse.mojo#_bytes_to_str`, `#_find_crlf2_from`, `#_split_lines`, `#_parse_response_head` | `splitGo_join`, `lfGo_join`, `headImpl_agrees` | proved |
| `ClientResponse.canReuse` | `_client/parse.mojo#_read_http_response_framed` | `canReuse_ok` | proved |
| `ClientResponse.bufferedClose`, `dlClose` | `_client/parse.mojo#_refuse_truncated_tls`, `_client/h2_transport.mojo#_H2Transport.read` | `bufferedClose_safe` | proved |
| `ChunkedEncode.hexDigit`, `hexLower`, `encChunk`, `encChunks`, `trailerLine`, `encTrailers`, `encodeBody`, `encodeUpload` | `http/streaming_serialize.mojo#_hex_digit`, `#_hex_lower`, `#serialize_streaming_response`, `#_write_header_line`; `http/client.mojo#_chunk_frame_prefix`, `#HttpClient._send_chunked_tcp` | `decL_roundtrip`, `decodeBody_roundtrip`, `scan_roundtrip`, `cDec_roundtrip`, `upload_roundtrip` | proved |
| `Handshake.acceptOf`, `genKey` | `ws/client.mojo#_compute_accept`, `#_generate_ws_key`, `ws/server.mojo#_compute_accept_srv` | `genKey_valid`, `handshake_complete` | proved |
| `Handshake.clientAccepts`, `clientRequest` | `ws/client.mojo#WsClient._connect_impl` | `clientAccepts_ok`, `handshake_complete` | proved |
| `Handshake.qual`, `srv`, `srvResponse` | `ws/server.mojo#_parse_ws_upgrade_bytes`, `#_read_upgrade_request`, `#_ws_handshake_problem`, `#_send_upgrade_response` | `qual_ok`, `srv_ok`, `handshake_complete` | proved |
| `Handshake.firstVal`, `versionMismatch`, `reactor` | `http/headers.mojo#HeaderMap.get`, `http/_reactor/conn_handle.mojo#_is_ws_version_mismatch`, `#ConnHandle._handle_ws_upgrade` | `reactor_ok` | proved |
| `Close.fixStep` | `ws/server.mojo#WsConnection.recv`, `#WsConnection.close`, `#WsConnection.send_text`, `#WsConnection.send_binary`, `#WsConnection.send_frame`, `#WsConnection._require_open` | `fixed_closeOK` | proved |
