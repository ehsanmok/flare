# L3 protocol: HTTP/1.1 and WebSocket

This report covers flare's HTTP/1.1 server framing and its WebSocket frame layer. On the HTTP/1.1 side it covers:
- the chunked body scanner the reactor polls after every read (`flare/http/proto/chunked.mojo:183-303`, polled by `flare/http/_reactor/conn_handle.mojo:661-678`) and the chunked decoder (`chunked.mojo:306-360`);
- the Content-Length grammar (`flare/http/_scan.mojo:259-294`);
- the two components that must agree on where a request ends: the reactor's framing (`request_te_framing` and `scan_content_length`, `chunked.mojo:120-158`, `_scan.mojo:173-247`) and the request parser (`flare/http/_server/parse.mojo:234-353`), including the lenient `H1LeniencyConfig` options;
- header-value validation (`parse.mojo:277-285`) and obs-fold unfolding (`parse.mojo:203-320`);
- the client's response reader (`flare/http/_client/parse.mojo`, `download.mojo`): status line, head lines, RFC 9112 §6.3 framing, the chunked decoder, connection reuse and the TLS end of stream;
- the two chunked encoders (`flare/http/streaming_serialize.mojo`, `flare/http/client.mojo`).

On the WebSocket side it covers:
- masking, the frame encoder and the decoder (`flare/ws/frame.mojo:140-647`);
- the server's and the client's frame acceptance (`flare/ws/server.mojo:541-575`, `flare/ws/client.mojo:717-763`);
- the client's message reassembly (`client.mojo:765-794`);
- the opening handshake on all three paths: `WsClient` (`client.mojo:118-148`, `536-649`), the standalone `WsServer` (`server.mojo:100-111`, `188-340`) and the reactor upgrade (`flare/http/_reactor/conn_handle.mojo:143-152`, `835-860`, `1476-1560`);
- the closing handshake of `WsConnection` (`server.mojo:473-616`).

Each model is a transliteration of the Mojo code at commit 59bda50, and every implementation definition carries a `mirrors flare/<file>:<lines> @59bda50` comment. Specifications are written separately, from RFC 9112, RFC 9110, RFC 6455 and RFC 3629. The aggregate module is `Flare/L3_Protocol/H1Ws.lean`, and `Flare/Audit/H1Ws.lean` prints the axioms of 141 headline theorems. The keep-alive decision (`_wants_close`, `_compute_close_after`) is covered by `L4_App/KeepAlive.lean` (APP-02, APP-03) and is not repeated here.

Build and audit status:
- Every module builds on its own and elaborates in under 3 s (`lake env lean`, measured per file). There is no `maxHeartbeats` option.
- There are no `sorry`, `admit` or `axiom` declarations and no `bv_decide`.
- Outside `Flare/Bugs/`, every audited theorem depends only on `propext`, `Quot.sound` and `Classical.choice`.
- `native_decide` appears only in `Flare/Bugs/H1_*.lean` and `WS_*.lean`, where it evaluates concrete witnesses. Every `fixed` theorem is a general proof without it.
- The files contain 366 theorems: 276 in the model modules and 90 in the Bugs files.

## Components

### Chunked body scanner and decoder

Files: `H1/Chunked.lean`, `H1/ChunkedSpec.lean`.

**Model.**
- `scanL`/`scanTr`/`scanResume`/`scanEnd` mirror `scan_chunked_resume`/`scan_chunked_end` (`chunked.mojo:183-303`), including the 4096-byte line cap `CAP` and the resume cursor.
- `poll` mirrors the reactor's loop: rescan from the saved cursor after each read.
- `decodeBody` mirrors `decode_chunked` (`chunked.mojo:306-360`).
- A `Policy` parameterises the three places the fixes change (the shipped scanner is `implP`; `oldP` and `preSegP` are the pre-H1-02 and pre-H1-01 scanners kept for the counterexamples): the slack in the incomplete-line test, the cap on complete trailer lines, and rejection of LF inside a line. `oldP` is the scanner as it was at 59bda50, `implP` is the shipped code (it includes the H1-02 fix); `fixedP` and `fullFixP` are the H1-01 fix without and with the H1-02 check.

| Lean name | Statement | Status |
|---|---|---|
| `scanEnd_range` | The verdict is -1 (incomplete), -2 (malformed) or `done e` with `start ≤ e ≤ buf.length`. | proved |
| `scanL_total_le`, `parseSize_le` | On acceptance the decoded total is ≤ `max_body`, and every chunk size is ≤ `max_body`. | proved |
| `parseSize_fits` | If `16·max_body + 15 < 2^63`, every chunk-size accumulator fits in Int64. | proved |
| `parseSize_wraps_unbounded` | Without that bound the accumulator wraps (`2^59·16` becomes `-2^63`). | counterexample (needs `max_body ≥ 2^59`; see "Checked") |
| `scanL_resume`, `scanResume_resume` | Resuming from the saved cursor on `b ++ m` gives the same result as rescanning `b ++ m` from the original cursor. | proved |
| `scanEnd_done_stable`, `scanEnd_malformed_stable`, `impl_done_stable` | A `done` verdict is never revoked by more bytes (any policy). A `malformed` one is never revoked if the policy has slack ≥ 1 and caps complete trailer lines. | proved |
| `scanEnd_segmentation_independent` | With slack ≥ 1 and capped trailers, a definite verdict on a prefix equals the verdict on every extension. | proved |
| `poll_eq_oneShot`, `impl_poll_eq_oneShot` | Under the same conditions, polling any segmentation equals one scan of the concatenation. The shipped `implP` meets them (slack 1, capped trailers). | proved (the pre-fix `preSegP` fails, H1-01) |
| `decL_of_scanL`, `scanEnd_decode` | Termination and agreement: if the scanner accepts at `e`, `decode_chunked` succeeds on the same buffer, consumes exactly to `e` and produces at most `max_body` bytes. | proved |
| `scanEnd_lfSafe`, `impl_agrees_lfTolerant` | If the policy rejects LF inside lines, an accepting scan agrees with an LF-tolerant recipient (`lfScan`) on both the body and its end. The shipped `implP` rejects it. | proved (the pre-fix `oldP` fails, H1-02) |

`scanL`, `scanTr` and `decL` are structurally recursive, so termination is by construction.

### Content-Length grammar

Files: `H1/HeaderText.lean`, `H1/ContentLength.lean`.

**Model.** `parseCL` mirrors `parse_content_length` (`_scan.mojo:259-294`): skip OWS, take at most 18 digits, skip OWS, then require the end of the value or CR/LF.

| Lean name | Statement | Status |
|---|---|---|
| `parseCL_complete` | For OWS `p`, 1-18 digits `ds`, OWS `q` and a tail that is empty or starts with CR/LF, `parseCL (p++ds++q++t) = decVal ds`. | proved |
| `parseCL_sound` | Every non-negative result comes from exactly such a decomposition. | proved |
| `parseCL_invalid`, `parseCL_fits`, `parseCL_fitsI64` | The result is -1 or a value in `[0, 10^18)`, so it fits in Int64. | proved |
| `parseCL_strip`, `tokens_strip`, `classify_strip` | Surrounding OWS does not change the Content-Length value, the Transfer-Encoding tokens or the chunked classification. | proved |

### Reactor-vs-parser framing (request smuggling)

File: `H1/Framing.lean`.

**Model.**
- `reactorFraming allowCL maxBody lines` mirrors the shipped reactor's decision: `request_te_framing` and `scan_content_length` over the header lines, with SP/HTAB between the field name and the colon skipped (H1-03 fix). It returns `chunked`, `length n` or `reject`. `reactorFramingWith skip …` is the same function with the colon test as a parameter; `skip = false` is the pre-fix reactor.
- `parserFraming ows allowCL maxBody lines` mirrors the parser's acceptance and framing (`parse.mojo:234-353`). Its acceptance is a superset of the real parser's, since it checks only line shape, field syntax and Content-Length consistency. Any statement of the form "parser accepts ⇒ same framing" therefore carries over to the real parser.
- `ows` is `allow_ows_around_colon`.
- `linesLF` mirrors the lenient parser's LF line reader (`parse_util.mojo:165-208`); the shipped reactor splits lines the same way (`reactorLines`, the H1-04 fix), and `linesCRLFOld` is the pre-fix CRLF-only split.

| Lean name | Statement | Status |
|---|---|---|
| `framing_agrees` | For either `ows`, any `allowCL` and `maxBody`: if the parser accepts, the shipped reactor frames the request the same way. | proved |
| `no_smuggling_strict` | Strict mode (`ows = false`): parser acceptance implies the same framing as the shipped reactor. | proved |
| `lf_fixed_agrees` | The shipped reactor splits lines with the parser's LF splitter (`reactorLines`), so the two agree whenever the parser accepts. | proved |
| `Bugs.H1_03.counterexample` | With `allow_ows_around_colon` and the pre-fix reactor (`reactorFramingWith false`), they disagree on an accepted request. | counterexample |
| `Bugs.H1_04.counterexample` | With `allow_lf_only_line_endings` and the pre-fix CRLF splitter (`linesCRLFOld`), they disagree on an accepted request. | counterexample |

### Header values and the String invariant

File: `H1/FieldValue.lean`.

**Model.** `byteOk`/`valueOk` mirror the per-byte value check (`parse.mojo:277-285`).

| Lean name | Statement | Status |
|---|---|---|
| `strict_value_ascii`, `strict_value_utf8` | In strict mode every accepted value is ASCII, and hence valid UTF-8 (RFC 3629 `WF`). | proved |
| `fixed_value_utf8` | With a UTF-8 check added, every accepted value is valid UTF-8, with or without obs-text. | proved |
| `Bugs.H1_05.counterexample` | With obs-text accepted, `[0xFF]` passes the check. | counterexample |

### WebSocket frame codec

File: `Ws/Frame.lean`.

**Model.**
- `maskFrom` mirrors the scalar masking loop, and `appendMasked` mirrors the 32-byte-block masking with its scalar tail (`frame.mojo:483-488`, `612-647`).
- `encode` mirrors `_encode_into` (`frame.mojo:274-356`), with minimal length encoding through `lenCode` and `extLen`.
- `decode` mirrors `decode_one` (`frame.mojo:361-508`): RSV checks, length parsing, the control-frame rules and the `max_payload` limit.

| Lean name | Statement | Status |
|---|---|---|
| `maskFrom_involutive` | Masking twice with the same key and offset is the identity. | proved |
| `maskFrom_append`, `maskFrom_zero_key` | Masking a concatenation equals masking the parts with the offset advanced. The all-zero key is the identity. | proved |
| `appendMasked_eq` | The blocked mask equals the scalar mask when the start offset is ≡ 0 (mod 4). | proved |
| `decode_encode`, `decode_encode_len` | For opcode < 16, a permitted RSV1, legal control frames, payload < 2^32 and payload ≤ `max_payload`: `decode (encode f mask k ++ rest)` returns `f` (with `masked := mask`) and consumes exactly the encoded length, for either mask flag and any key and trailing bytes. | proved |
| `lenCode_125`, `lenCode_126`, `lenCode_65535`, `lenCode_65536` | At the boundaries the encoder uses the 7-bit form (125), the 16-bit form (126 and 65535) and the 64-bit form (65536). Each is covered by `decode_encode`. | proved |
| `decode_ok_shape` | Every decoded frame satisfies the control-frame rules (FIN set, payload ≤ 125), the `max_payload` limit and the RSV1 setting. | proved |
| `Bugs.WS_01.counterexample` | `decode` accepts reserved opcodes. | counterexample |

### WebSocket receive path

File: `Ws/Recv.lean`.

| Lean name | Statement | Status |
|---|---|---|
| `server_safe` | Every frame the server accepts was masked and passes `decode_ok_shape` (RFC 6455 §5.1). | proved |
| `clientFixed_safe` | With the WS-03 check, every frame the client accepts is unmasked. | proved |
| `decodeKnown_safe`, `decodeKnown_encode` | The WS-01 fix accepts only known opcodes, and the round trip still holds for them. | proved |
| `collect_spec`, `nextMessage_delivered` | The fixed `recv_message` returns exactly a TEXT/BINARY frame followed by CONTINUATION frames up to FIN, with the concatenated payload, skipping control frames (RFC 6455 §5.4). | proved |
| `textPayload_ok_iff` | The UTF-8 check on text payloads accepts exactly RFC 3629 `UTF8-octets` (from `L1.Utf8.isValidUtf8_iff`). | proved |
| `Bugs.WS_02.counterexample_fragment`, `counterexample_pong` | The pre-fix `recv_message` (`recvMessageOld`) returned a fragment, or a PONG payload, as a message. | counterexample |
| `Bugs.WS_03.counterexample` | The shipped client accepts a masked frame. | counterexample |

### obs-fold

File: `H1/ObsFold.lean`.

**Model.** `fields obsFold obsText prev lines` mirrors the field loop of `_parse_http_request_bytes` (`parse.mojo:203-320`): a field is committed only when the next line shows it is not continued; with `allow_obs_fold` a line starting with SP/HTAB is stripped (`aStrip`, `parse_util.mojo:65-90`) and appended after one SP. `fieldsFixed` also runs `valueOk` on the continuation.

| Lean name | Statement | Status |
|---|---|---|
| `fold_unfold` | A run of continuation lines is unfolded exactly as RFC 9112 §5.2 says: the value becomes `v ++ " " ++ strip c₁ ++ …` (`unfoldOnto`). | proved |
| `strict_no_fold` | Without the flag a continuation line is an error. | proved |
| `fields_ok_strict` | In strict mode every stored value passes `valueOk`. | proved |
| `fieldsFixed_valid`, `fixed_fold_unfold` | With the fix every stored value passes `valueOk`, and valid continuations still unfold as §5.2 says. | proved |
| `Bugs.H1_10.counterexample` | The shipped fold stores `a \x01\x7f`. | counterexample (H1-10) |

### Client response reader

Files: `H1/ClientChunked.lean`, `H1/ClientResponse.lean`.

**Model.**
- `respFraming` mirrors `_response_framing` (`_client/parse.mojo:128-170`), shared by the buffered, framed and streaming readers.
- `parseStatus` mirrors `_parse_status_line` (`318-352`).
- `san`, `findCRLF2`, `splitGo`/`splitLines` and `headImpl` mirror `_bytes_to_str`, `_find_crlf2_from`, `_split_lines` and the line loop of `_parse_response_head` (`89-125`, `233-306`). `lfHead` is an RFC 9112 §2.2 recipient that ends lines at LF.
- `cDec` mirrors `_decode_chunked` (`497-578`); `cHex`, `cTr`, `trailerOk` its size and trailer lines.
- `canReuse` mirrors the keep-alive decision of the pooled reader (`836-884`).
- `dlCloseOld` mirrors `HttpDownload._read_close` (`download.mojo:215-220`) over the pre-fix transport; `dlClose` (= `bufferedClose`) is the close_notify guard, in the buffered readers (`parse.mojo:665-683`) and now in `_H2Transport.read` (`h2_transport.mojo:69-96`).

| Lean name | Statement | Status |
|---|---|---|
| `framing_bodyless` | HEAD, 1xx, 204, 304 and a 2xx to CONNECT have no body, whatever the fields say (RFC 9112 §6.3 points 1-2). | proved |
| `framing_te_cl_reject`, `framing_dup_cl` | Transfer-Encoding together with Content-Length, or more than one Content-Length, is refused (stricter than §6.3 point 3-5, which allow recovery). | proved |
| `framing_chunked_iff`, `framing_length_iff`, `framing_close_iff` | Exactly: chunked iff a single TE value `chunked` and no CL; length n iff no TE and a single valid CL = n; close-delimited iff neither (§6.3 points 4-8). | proved |
| `cDec_agree`, `framed_chunked_agrees` | On any buffer the shipped scanner accepts at `e`, the client decoder either raises or returns exactly the server decoder's bytes, reading nothing past `e`. So the pooled reader's chunked path is right. | proved |
| `cRead_complete` | With the scan on the read-to-EOF path (`cRead`), a returned body is always a complete chunked body. | proved (H1-06 fix) |
| `parseStatusFixed_delimited` | With the delimiter check, the code is three digits followed by SP or the end of the line (`CodeDelimited`). | proved (H1-08 fix) |
| `splitGo_join`, `lfGo_join`, `headFixed_agrees` | With bare LF and empty lines refused, the head lines and body start equal those of the LF-recognising recipient. | proved (H1-07 fix) |
| `canReuseFixed_ok` | With the version check, reuse implies HTTP/1.1 without `close` (RFC 9112 §9.3). | proved (H1-09 fix) |
| `bufferedClose_safe` | The buffered guard never returns a close-delimited TLS body that ended without close_notify. | proved |
| `Bugs.H1_06/07/08/09/11.counterexample` | The shipped code violates each of the above. | counterexample |

### Chunked encoders

File: `H1/ChunkedEncode.lean`.

**Model.** `hexLower` mirrors the hex writer (`streaming_serialize.mojo:116-140`, `client.mojo:121-135`). `encodeBody cs tr` is the streaming serializer's output: each non-empty chunk as `hex CRLF data CRLF` (an empty write produces nothing), `0 CRLF`, one `name: value CRLF` per trailer, `CRLF` (`streaming_serialize.mojo:162-166`, `258-300`). `encodeUpload cs = encodeBody cs []` is the client upload (`client.mojo:1420-1445`, `1470-1495`).

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
- `clientAccepts` mirrors both branches of `_connect_impl` (`client.mojo:562-603`, `609-646`); `ClientOK` is the RFC 6455 §4.1 list for a request that offered no subprotocol or extension (flare's request offers none, `client.mojo:536-550`).
- `srvShipped` mirrors `_parse_ws_upgrade_bytes`/`_read_upgrade_request` (`server.mojo:188-321`); `ServerOK` is RFC 6455 §4.2.1 plus §11.3.1/§11.3.5 (key and version once).
- `reactor` mirrors `_is_ws_version_mismatch` (426), then `_handle_ws_upgrade` (`conn_handle.mojo:143-152`, `835-860`, `1512-1523`).

| Lean name | Statement | Status |
|---|---|---|
| `genKey_valid` | The client's key, base64 of 16 nonce bytes, decodes to 16 bytes (`KeyOK`). | proved |
| `keyOk_iff` | The Boolean key check decides `KeyOK`. | proved |
| `clientFixed_ok`, `clientFixed_accepts` | The fixed client check decides exactly `ClientOK`, and only adds conjuncts to the shipped one. | proved (WS-04 fix) |
| `srvFixed_ok` | A request the fixed standalone server accepts satisfies `ServerOK`. | proved (WS-05 fix) |
| `reactor_upgrade_v13` | The shipped reactor only upgrades `Sec-WebSocket-Version: 13`. | proved |
| `reactorFixed_ok` | A request the fixed reactor upgrades satisfies `ServerOK`. | proved (WS-07 fix) |
| `handshake_complete` | For every SHA-1 and valid key, flare's client request passes both fixed servers, and the server's 101 passes the fixed client. | proved |
| `Bugs.WS_04/05/07.counterexample` | The shipped checks accept handshakes that violate the spec. | counterexample |

### WebSocket closing handshake

File: `Ws/Close.lean`.

**Model.** An endpoint is a step function over what the application sees: a received frame, `send_text`/`send_binary`, `close(code)`; each step writes frames. `oldStep` mirrors `WsConnection` before the fix (`server.mojo:473-536`, `600-616`); `fixStep` is the shipped endpoint, with a `close_sent` flag. `validPayload` is RFC 6455 §5.5.1/§7.4: empty, or a code in 1000-1003, 1007-1014, 3000-4999 followed by UTF-8. `closeReply p` is the received code, or 1002 for an invalid body. `CloseOK` (via `Good`) says, for every trace: a CLOSE received while none has been written is answered with `closeReply`, and once a CLOSE has been written no data frame follows.

| Lean name | Statement | Status |
|---|---|---|
| `fix_state`, `fixed_good`, `fixed_closeOK` | The fixed endpoint meets `CloseOK` on every trace. | proved (WS-06 fix) |
| `Bugs.WS_06.counterexample_no_echo`, `counterexample_invalid_payload`, `counterexample_data_after_close` | The shipped endpoint violates `CloseOK` three ways. | counterexample |

### Assumptions and limitations

- **Framing is modelled at the level of header lines.** Both sides receive the same list of field lines. Detecting the end of the header block (CRLFCRLF in `conn_handle.mojo:622-654`) is outside the model, apart from the LF/CRLF line splitting in H1-04.
- **The parser model accepts more than the real parser** (it checks line shape, field syntax and Content-Length consistency only). The agreement theorems carry over to the real parser; the counterexamples were also confirmed against the real code by the repros.
- **SHA-1 is a black box.** The handshake theorems quantify over every function `Bytes → Bytes`; SHA-1 itself is not modelled. Base64 and the key/GUID concatenation are.
- **Handshake fields are modelled after the line split.** The three handshake loops split lines (dropping CR, ending at LF) and then split each line at its first colon and strip both halves; the model starts from those pairs. The client's own response-head splitting is modelled separately (`ClientResponse.splitGo`).
- **The 101 status check** in `ClientOK` is flare's prefix test `HTTP/1.1 101`. A `HTTP/1.1 1010` status line is the H1-08 class and is not filed again.
- **Encoder trailers.** The encoder does not filter forbidden trailer names; trailers are chosen by the application, and flare's own client refuses them. `cDec_roundtrip` therefore assumes `ClientTrailersOK`, and every round trip assumes trailer lines without CR or LF (which `HeaderMap` guarantees).
- **`scan_roundtrip`** assumes chunks below 2^60 bytes, because the scanner caps size lines at 16 hex digits (deliberate, see "Checked"), and trailer lines of at most `CHUNK_LINE_MAX` bytes (the H1-01 cap).
- **The close model** works at the level of the application API: frames are values, and their encoding is covered by `Ws/Frame.lean`. The peer is arbitrary, since `CloseOK` quantifies over every trace.
- **permessage-deflate is not modelled because flare does not implement it.** No handshake sends or accepts `Sec-WebSocket-Extensions`, and RSV1 is always refused, so there is no code to model.
- **WebSocket length bound.** `decode_encode` assumes payloads below 2^32. Larger payloads exceed any sane `max_payload`.
- **UInt8 header bit facts** (`byte0_bits_all`, `byte1_bits_all`) are checked by kernel `decide` over `Fin 16 × Bool × Bool` and `Fin 128 × Bool`, not over strings.

## Findings

### H1-01: the chunk-line cap gives a verdict that depends on TCP segmentation

Status: resolved. Both incomplete-line tests (size line and trailer line) now allow one byte of slack for a pending CR, and complete trailer lines are capped at `CHUNK_LINE_MAX`, so polling any segmentation gives the one-shot verdict. The counterexamples are about `preSegP` (the scanner before the fix); `Bugs.H1_01.fixed_segmentation_independent` is about the shipped `implP`.

- **Severity:** Low. A legal request is answered with 400 or accepted depending on how TCP splits it, so behaviour is not deterministic. Separately, a complete trailer line is never capped while a partial one is. No framing desync results, because both outcomes either reject or agree with the decoder.
- **Spec:**
  - The reactor polls `scan_chunked_resume` after every read (`conn_handle.mojo:655-678`), so its verdict must equal a one-shot scan of the same bytes.
  - RFC 9112 §7.1 does not let the result depend on how the bytes were segmented.
- **What goes wrong:**
  - The complete-line test (`chunked.mojo:246-251`) is `line_end - pos > 4096`.
  - The incomplete-line test is `n - pos > 4096`, which also counts the pending CR. A size line of exactly 4096 bytes, cut after its CR, is therefore MALFORMED, while the same bytes in one read are accepted.
  - Trailer lines (270-290) have the opposite problem: a complete line has no cap at all.
- **Counterexample:** `Bugs.H1_01.counterexample` (`¬ SegIndep preSegP`, about the scanner before the fix).
  - `counterexample_size_line`: polling `body1` cut at byte 4097 gives `malformed`, while a one-shot scan gives `done 4106`.
  - `counterexample_trailer`: the same with a 5000-byte trailer line gives `malformed` against `done 5007`.
- **Fix:** allow one byte of slack in both incomplete-line tests, and cap complete trailer lines. `Bugs.H1_01.fixed_segmentation_independent` (= `impl_poll_eq_oneShot`, `SegIndep implP`) proves that polling any segmentation of the shipped scanner's input equals a one-shot scan.
- **Repro:** `formal/repro/H1-01_chunk_line_cap_segmentation.mojo`
- **Observed:** `BUG REPRODUCED: chunked verdict depends on segmentation (size line one-shot=4106 split=-2; trailer one-shot=5007 split=-2)`
- **Flip:** `OK: chunked verdict is segmentation independent`; `flare/http/proto/chunked.mojo` restored.

### H1-02: a bare LF inside a chunk extension or trailer line is accepted

Status: resolved. Fixed in `scan_chunked_resume` (`flare/http/proto/chunked.mojo`): a size line or trailer line that contains an LF is `CHUNKED_MALFORMED` (new helper `_has_lf`). Regression test `tests/http/test_chunked_request.mojo::test_scan_rejects_bare_lf_in_chunk_lines`; the repro prints `OK:`. Lean: `oldP` keeps the counterexample, `implP` is the shipped policy and `impl_agrees_lfTolerant` proves it LF-safe.

- **Severity:** Medium. Request smuggling becomes possible behind any front end that treats a bare LF as a line terminator, which RFC 9112 §2.2 allows. This applies in the default (strict) configuration.
- **RFC:**
  - RFC 9112 §7.1.1: `chunk-ext` is tokens and quoted strings, which never contain LF.
  - RFC 9112 §2.2: a recipient MAY treat a bare LF as a line terminator.
- **What goes wrong:** the scanner looks only for CRLF and skips everything after `;` (`chunked.mojo:239-266`, `270-290`). For `0;\n\r\nX: y\r\n\r\n`:
  - flare reads `0;\n` as the last-chunk line and `X: y` as a trailer, and ends the body at 13;
  - an LF-splitting front end ends the body at 5 and forwards the rest as the next request.
- **Counterexample:** `Bugs.H1_02.counterexample` (`¬ LfSafe oldP`, the pre-fix scanner), with `old_accepts` (`done 13`) and `lf_recipient_ends_at_5`.
- **Fix:** a chunk line whose content contains LF is MALFORMED. `Bugs.H1_02.fixed_agrees_lfTolerant` (`LfSafe implP`, from `scanEnd_lfSafe`) proves the shipped scanner agrees with an LF-tolerant recipient on both the body and its end. `fixed_rejects` shows the shipped scanner rejects the witness.
- **Repro:** `formal/repro/H1-02_chunk_ext_bare_lf.mojo`
- **Observed:** `BUG REPRODUCED: scan_chunked_end accepted a chunk extension with a bare LF, body end 13 (an LF-splitting recipient ends the body at 5)`
- **Flip:** `OK: bare LF inside a chunk line is rejected`; `flare/http/proto/chunked.mojo` restored.

### H1-03: with `allow_ows_around_colon`, the reactor and the parser disagree on Transfer-Encoding

Status: resolved. Fixed in `flare/http/proto/chunked.mojo` (`request_te_framing`, new `_colon_after_name`) and `flare/http/_scan.mojo` (`_match_content_length_prefix`): SP/HTAB between the field name and the colon are skipped for both Transfer-Encoding and Content-Length (the latter had the same gap). Regression tests `tests/http/test_h1_smuggling.mojo::test_te_framing_skips_ows_before_the_colon`, `test_content_length_scan_skips_ows_before_the_colon` and `test_ows_before_colon_reactor_and_parser_agree`; the repro prints `OK:`. Lean: `reactorFraming` is now the shipped reactor, `reactorFramingWith false` keeps the counterexample.

- **Severity:** Medium. It is a request desync: one request produces two responses, and the chunked body is parsed as a request. It needs a public, non-default leniency option, which is documented as safe behind an upstream that emits `Header :value`.
- **RFC:** RFC 9112 §6.3 and §11.2: the component that frames a message and the component that interprets it must use the same framing.
- **What goes wrong:**
  - `request_te_framing` (`chunked.mojo:139-148`) requires `:` immediately after the name.
  - The lenient parser strips SP/HTAB before the colon (`parse.mojo:249-255`).
  - For `Transfer-Encoding : chunked` the reactor sees no TE and Content-Length 0, while the parser accepts the request as chunked.
- **Counterexample:** `Bugs.H1_03.counterexample`, on the lines `["Host: a", "Transfer-Encoding : chunked"]`:
  - `reactor_frames_by_length`: the pre-fix reactor (`reactorFramingWith false`) gives `length 0`;
  - `parser_sees_chunked`: the parser gives `chunked`.
- **Fix:** skip SP/HTAB between the name and `:` in `request_te_framing` and in the Content-Length scan (`Content-Length : 5` had the same gap). Strict mode is unchanged, because the strict parser rejects such lines. `Bugs.H1_03.fixed_agrees` (from `framing_agrees` with `ows = true`) proves agreement of the shipped reactor on every request the parser accepts.
- **Repro:** `formal/repro/H1-03_te_ows_colon_framing_desync.mojo`
- **Observed:** `BUG REPRODUCED: reactor framed by Content-Length (TE verdict 0, body_total 63) while the parser accepted Transfer-Encoding: chunked; 15 body bytes are left to be parsed as the next request`
- **Flip:** `OK: reactor and parser agree on chunked framing`; `flare/http/proto/chunked.mojo` restored.

### H1-04: with `allow_lf_only_line_endings`, a Transfer-Encoding line after a bare LF is invisible to the reactor

Status: resolved. Fixed in `request_te_framing` (`flare/http/proto/chunked.mojo`): the request line and every header line now end at LF with a preceding CR dropped, the way the lenient parser reads them (`scan_content_length` already anchored on LF). Regression tests `tests/http/test_h1_smuggling.mojo::test_te_framing_ends_header_lines_at_a_bare_lf` and `test_bare_lf_reactor_and_parser_agree`; the repro prints `OK:`. Lean: `reactorLines` is the shipped split, `linesCRLFOld` keeps the counterexample.

- **Severity:** Medium. It is the same desync as H1-03, triggered by a different non-default leniency option.
- **RFC:** RFC 9112 §2.2 and §6.3: a recipient that accepts a bare LF as a line terminator must do so for framing as well as for parsing.
- **What goes wrong:**
  - `request_te_framing` splits lines on CRLF only (`chunked.mojo:127-153`), so `Host: a\nTransfer-Encoding: chunked` is one line to the reactor.
  - The lenient parser (`parse_util.mojo:165-208`) reads it as two lines.
- **Counterexample:** `Bugs.H1_04.counterexample`:
  - `reactor_lines`: `linesCRLFOld blk = [blk]`;
  - the pre-fix reactor gives `length 0`, while the parser over `linesLF blk` gives `chunked`.
- **Fix:** end header lines at LF, dropping a preceding CR, in `request_te_framing`. `Bugs.H1_04.fixed_agrees` (from `lf_fixed_agrees`) proves the shipped reactor agrees on every block the parser accepts. The request line also ends at its first LF.
- **Repro:** `formal/repro/H1-04_te_lf_only_framing_desync.mojo`
- **Observed:** `BUG REPRODUCED: reactor framed by Content-Length (TE verdict 0, body_total 61) while the parser accepted Transfer-Encoding: chunked; 15 body bytes are left to be parsed as the next request`
- **Flip:** `OK: reactor and parser agree on chunked framing`; `flare/http/proto/chunked.mojo` restored.

### H1-05: obs-text header values become Strings that are not valid UTF-8

- **Severity:** Low. It needs the non-default `accept_obs_text_in_field_value`. The resulting `String` breaks Mojo's UTF-8 invariant, so any code that iterates its codepoints sees malformed data.
- **Spec:**
  - The contract of `_ascii_unchecked_string` (`flare/http/proto/ascii.mojo:63-70`): every byte is < 0x80.
  - Mojo `String` holds valid UTF-8.
  - RFC 9110 §5.5 admits obs-text only as opaque octets.
- **What goes wrong:** in the obs-text branch (`parse.mojo:277-285`) every byte ≥ 0x80 is accepted. The value is then built with `_ascii_unchecked_string` (`parse_util.mojo:65-89`), so `X: \xff` is stored as a String holding `0xFF`.
- **Counterexample:** `Bugs.H1_05.counterexample` (`¬ Utf8Safe (valueOk true)`), with `lenient_accepts` and `not_utf8`.
- **Fix:** reject an obs-text value that is not valid UTF-8, or build it with a validating constructor. `Bugs.H1_05.fixed_utf8` (= `fixed_value_utf8`) proves every accepted value is then valid UTF-8. `strict_value_utf8` shows strict mode is already safe.
- **Repro:** `formal/repro/H1-05_obs_text_value_not_utf8.mojo`
- **Observed:** `BUG REPRODUCED: header value String holds bytes [ 255 ], which is not valid UTF-8`
- **Flip:** I added `if not _is_valid_utf8(v.as_bytes()): raise` after the byte loop, importing it from `flare/io/byte_cursor.mojo`. The repro printed `OK: obs-text value rejected or stored as valid UTF-8`, and `flare/http/_server/parse.mojo` was restored.

### H1-06: the client returns a truncated chunked body as complete

Status: resolved. The read-to-EOF readers now run `scan_chunked_end` first (`_require_complete_chunked`) in both `_parse_http_response` and `_extract_body_and_trailers`, and raise on an incomplete or malformed chunked body. The counterexample is about `cReadOld`; `Bugs.H1_06.fixed_complete` is about the shipped `cRead`.

- **Severity:** Medium. The read-to-EOF readers hand the application a truncated body as a successful response. They serve unpooled HTTP/1.1 requests over TCP and TLS and the chunked uploads (`client.mojo:1283`, `1445`, `1495`, `2505`). On TLS, a peer or an on-path attacker that resets the connection mid-body (no close_notify) chooses where the body ends.
- **RFC:** RFC 9112 §7.1 (a chunked body ends with the last-chunk and the trailer section) and §8 (a message that ends before that is incomplete).
- **What goes wrong:** `_read_http_response_tcp`/`_tls` (`_client/parse.mojo:645-703`) read to EOF and call `_parse_http_response`, whose chunked branch (`205-212`) calls `_decode_chunked` (`497-578`). The decoder stops at the first line without CRLF and returns what it has. Nothing checks that the zero-size chunk arrived. The pooled framed reader is correct, because it scans first (`cDec_agree`).
- **Counterexample:** `Bugs.H1_06.counterexample` (`¬ Complete (2^20) cReadOld`): `old_accepts` gives `cReadOld "5\r\nhel" = ok "hel"`, while `scanner_incomplete` gives the shipped scanner's verdict `incomplete`.
- **Fix:** in the chunked branch, raise unless `scan_chunked_end(raw, body_start, MAX_BUFFERED_RESPONSE_BYTES) ≥ 0`. `Bugs.H1_06.fixed_complete` (from `cRead_complete`) proves every returned body is then a complete chunked body.
- **Repro:** `formal/repro/H1-06_client_truncated_chunked_accepted.mojo` (pure parser, and a forked TLS server that closes without close_notify)
- **Observed (3 runs):** `BUG REPRODUCED: truncated chunked body returned as complete (pure: accepted status=200 body=hel; TLS without close_notify: accepted status=200 body=hel)`
- **Flip:** with the scan added to `flare/http/_client/parse.mojo`: `OK: truncated chunked body refused (raised: NetworkError: HTTP response: incomplete chunked body; raised: NetworkError: HTTP response: incomplete chunked body)`; the file was restored.

### H1-07: a bare-LF response head skips the empty line that ends it

- **Severity:** Low. It needs a server, or an intermediary in front of one, that emits bare LF. Then a cache or proxy that ends lines at LF (RFC 9112 §2.2 allows it) sees body bytes that flare reads as header fields, for example a `Set-Cookie`.
- **RFC:** RFC 9112 §2.2 (a recipient MAY treat a bare LF as a line terminator) and §2.1 (the first empty line ends the head).
- **What goes wrong:** the head runs to the first CRLFCRLF (`_find_crlf2_from`, `_client/parse.mojo:233-245`). `_split_lines` (`283-306`) ends lines at a bare LF, and `_parse_response_head` (`106-110`) skips empty lines. So in `HTTP/1.1 200 OK\nX: a\n\nSet-Cookie: s=evil\r\n…\r\n\r\n` the empty line is ignored and `Set-Cookie` becomes a field.
- **Counterexample:** `Bugs.H1_07.counterexample` (`¬ HeadAgrees headImpl`): `shipped_head` gives fields `X: a`, `S: e` and body `b`, while `lf_head` ends the head at `\n\n`, with body `S: e\r\n\r\nb`.
- **Fix:** refuse a head with a bare LF or an empty line. `Bugs.H1_07.fixed_agrees` (= `headFixed_agrees`) proves the fixed lines and body start equal the LF recipient's.
- **Repro:** `formal/repro/H1-07_response_bare_lf_blank_line_skipped.mojo`
- **Observed (3 runs):** `BUG REPRODUCED: header after an LF-terminated empty line was parsed (accepted status=200 set-cookie=s=evil)`
- **Flip:** `OK: bare-LF head is refused or ends at the empty line (raised: NetworkError: HTTP response: bare LF in head)`; `flare/http/_client/parse.mojo` restored.

### H1-08: the client takes the first three digits of a longer status code

- **Severity:** Low. A malformed status line `HTTP/1.1 2041 OK` is read as 204. Status 204 has no body, so on a pooled connection the real body is parsed as the next response.
- **RFC:** RFC 9112 §4: `status-line = HTTP-version SP status-code SP [reason-phrase]`, with `status-code = 3DIGIT`.
- **What goes wrong:** `_parse_status_line` (`_client/parse.mojo:318-352`) checks three digits after the first SP and ignores the next byte.
- **Counterexample:** `Bugs.H1_08.counterexample`: `shipped_parses` gives `parseStatus "HTTP/1.1 2041 OK" = some 204`, and `not_delimited` proves no decomposition of the line has 204 as a delimited three-digit code.
- **Fix:** require SP or the end of the line after the third digit. `Bugs.H1_08.fixed_delimited` (= `parseStatusFixed_delimited`).
- **Repro:** `formal/repro/H1-08_status_code_extra_digits.mojo`
- **Observed (3 runs):** `BUG REPRODUCED: four-digit status code accepted (accepted status=204 body_len=0)`
- **Flip:** `OK: four-digit status code refused (raised: NetworkError: HTTP status code not three digits: HTTP/1.1 2041 OK)`; `flare/http/_client/parse.mojo` restored.

### H1-09: an HTTP/1.0 response without keep-alive goes back to the pool

- **Severity:** Low. The next request on that connection goes to a socket the server is closing. It fails, or is retried, and the failure is timing-dependent. No cross-response desync results, because the server closes.
- **RFC:** RFC 9112 §9.3: an HTTP/1.0 response keeps the connection open only with `Connection: keep-alive`.
- **What goes wrong:** the pooled reader's reuse decision (`_client/parse.mojo:836-884`) checks `Connection: close` and close-delimited framing, but never the version.
- **Counterexample:** `Bugs.H1_09.counterexample` (`¬ PersistOK canReuse`): `canReuse HTTP10 true [] (.length 2) = true`.
- **Fix:** reuse only an HTTP/1.1 response, or an HTTP/1.0 one with `keep-alive`; the minimal fix is HTTP/1.1 only. `Bugs.H1_09.fixed_ok` (= `canReuseFixed_ok`).
- **Repro:** `formal/repro/H1-09_http10_response_pooled.mojo`
- **Observed (3 runs):** `BUG REPRODUCED: HTTP/1.0 response without keep-alive marked reusable (status=200 body=hi can_reuse=True)`
- **Flip:** `OK: HTTP/1.0 response closes the connection (status=200 body=hi can_reuse=False)`; `flare/http/_client/parse.mojo` restored.

### H1-10: obs-fold continuation lines are not validated

- **Severity:** Low. It needs the non-default `allow_obs_fold`. Control bytes refused on a first line reach the application through a continuation line.
- **RFC:** RFC 9112 §5.2 (obs-fold is replaced by SP; the result is still a field value) and RFC 9110 §5.5 (no CTL except HTAB).
- **What goes wrong:** the continuation branch of the server field loop (`_server/parse.mojo:203-320`) appends the stripped line with no byte check. The first-line check (`277-285`) never sees it.
- **Counterexample:** `Bugs.H1_10.counterexample`: `shipped_stores` gives `X: a` + ` \x01\x7f` stored as `a \x01\x7f`, and `invalid` shows `valueOk` refuses it.
- **Fix:** run the value check on each continuation. `Bugs.H1_10.fixed_valid` (from `fieldsFixed_valid`); `fixed_fold_unfold` shows valid folds still unfold as RFC 9112 §5.2 says.
- **Repro:** `formal/repro/H1-10_obs_fold_continuation_unvalidated.mojo` (controls: the same bytes on a first line are refused; a plain fold gives `a b`)
- **Observed (3 runs):** `BUG REPRODUCED: folded value accepted with control bytes, x = [ 97 32 1 127 ] (the same bytes on a first line are refused)`
- **Flip:** `OK: control bytes in a continuation line refused (raised: invalid control character in header value)`; `flare/http/_server/parse.mojo` restored.

### H1-11: a streamed TLS download that ends without close_notify is complete

Status: resolved. `_H2Transport.read` now raises `NetworkError` when a TLS read returns 0 and `eof_was_unclean()`, so `HttpDownload._read_close` never sees an unclean end. The counterexample is about `dlCloseOld`; `Bugs.H1_11.fixed_safe` is about the shipped `dlClose`.

- **Severity:** Medium. `HttpDownload` on a close-delimited TLS body reports success for a body cut at any point by a TCP reset, which is the truncation attack TLS close_notify exists to stop. The buffered readers have the guard.
- **RFC:** RFC 8446 §6.1 (a close without close_notify is a truncation) and RFC 9112 §8 (a close-delimited body ends at a clean close).
- **What goes wrong:** `HttpDownload._read_close` (`_client/download.mojo:215-220`) reads until `read` returns 0. The TLS transport's `read` (`_client/h2_transport.mojo`) returns 0 on an unclean EOF as well, and nobody calls `eof_was_unclean()`. Compare `_client/parse.mojo:665-683`.
- **Counterexample:** `Bugs.H1_11.counterexample` (`¬ TruncSafe dlCloseOld`).
- **Fix:** raise in the transport `read` when it returns 0 and `eof_was_unclean()`, as the buffered path does. `Bugs.H1_11.fixed_safe` (= `bufferedClose_safe`).
- **Repro:** `formal/repro/H1-11_download_tls_truncated_close_body.mojo` (forked TLS server that writes `partial` and closes without close_notify)
- **Observed (3 runs):** `BUG REPRODUCED: close-delimited TLS body without close_notify returned as complete (status=200 body=partial)`
- **Flip:** `OK: truncated TLS download refused (raised: NetworkError: TLS connection closed without close_notify)`; `flare/http/_client/h2_transport.mojo` restored.

### WS-01: `decode_one` accepts reserved opcodes

- **Severity:** Low. The application receives a frame with opcode 0x3-0x7 or 0xB-0xF where the connection must fail. This is a protocol-compliance gap with no memory or framing impact.
- **RFC:** RFC 6455 §5.2: "If an unknown opcode is received, the receiving endpoint MUST _Fail the WebSocket Connection_."
- **What goes wrong:** `opcode = byte0 & 0x0F` is never range-checked (`frame.mojo:395-508`), although RSV1-3 are. `WsConnection.recv` and `WsClient.recv` return the frame as decoded.
- **Counterexample:** `Bugs.WS_01.counterexample` (`¬ OpcodeSafe decode`):
  - `decodes_reserved`: `[0x83,0x00]` decodes to a frame with opcode 3;
  - `decodes_reserved_control`: `0x8B` decodes to opcode 11.
- **Fix:** after the RSV checks, raise unless the opcode is 0x0-0x2 or 0x8-0xA. `Bugs.WS_01.fixed_known_opcode` proves only known opcodes are then accepted, and `decodeKnown_encode` shows the round trip still holds.
- **Repro:** `formal/repro/WS-01_reserved_opcode_accepted.mojo`
- **Observed:** `BUG REPRODUCED: decode_one accepted reserved opcodes (0x3 -> opcode 3, 0xB -> opcode 11; -1 = rejected)`
- **Flip:** `OK: reserved opcodes 0x3 and 0xB are rejected`; `flare/ws/frame.mojo` restored.

### WS-02: `WsClient.recv_message` returns one fragment, not the message

Status: resolved. `WsClient.recv_message` now skips PONG, requires a TEXT/BINARY start, appends CONTINUATION payloads to FIN (PING/PONG may interleave), validates UTF-8 over the whole text message, and bounds the reassembled payload by `max_frame_size`. The counterexamples are about `recvMessageOld`; `Bugs.WS_02.fixed_meets_spec` is about the shipped `nextMessage`.

- **Severity:** Medium. Any server that fragments messages makes the client return truncated messages, then return continuation payloads as separate messages. An unsolicited PONG is returned as a text message. Data is silently corrupted at the application level. The function is documented as "Receive the next complete message".
- **RFC:**
  - RFC 6455 §5.4: a message is a TEXT or BINARY frame followed by CONTINUATION frames up to FIN, and its payload is the concatenation.
  - RFC 6455 §5.5.3: an unsolicited PONG is allowed and is not a message.
- **What goes wrong:** `client.mojo:765-794` returns the payload of whatever frame comes next ("TEXT or anything else: return as text").
- **Counterexample:**
  - `Bugs.WS_02.counterexample_fragment` (about `recvMessageOld`): `[TEXT(fin=0,"hel"), CONT(fin=1,"lo")]` gives `"hel"`.
  - `counterexample_pong`: `[PONG "x", TEXT "a"]` gives `"x"`.
- **Fix:** skip PONG, require TEXT/BINARY to start a message, append CONTINUATION payloads until FIN, and validate UTF-8 over the whole text message. `Bugs.WS_02.fixed_meets_spec` (= `nextMessage_delivered`) proves the RFC 6455 §5.4 reassembly property. `fixed_fragment` and `fixed_pong` give `"hello"` and `"a"`.
- **Repro:** `formal/repro/WS-02_recv_message_returns_fragment.mojo` (loopback TCP)
- **Observed:** `BUG REPRODUCED: recv_message returned 'hel', 'lo', 'x' (expected 'hello', 'a')`
- **Flip:** `OK: recv_message reassembles fragments and skips PONG`; `flare/ws/client.mojo` restored.

### WS-03: `WsClient` accepts masked frames from the server

- **Severity:** Low. It is a MUST violation with no direct exploit. The server side has the corresponding check (`server.mojo:558-562`).
- **RFC:** RFC 6455 §5.1: "A client MUST close a connection if it detects a masked frame."
- **What goes wrong:** `_recv_one` (`client.mojo:717-763`) unmasks the frame and returns it.
- **Counterexample:** `Bugs.WS_03.counterexample` (`¬ ClientSafe clientAccept`), with `client_accepts_masked` (a masked TEXT "hi" is accepted).
- **Fix:** raise `WsProtocolError` if `result.frame.masked`. `Bugs.WS_03.fixed_client_safe` proves the client then accepts only unmasked frames.
- **Repro:** `formal/repro/WS-03_client_accepts_masked_server_frame.mojo` (loopback TCP)
- **Observed:** `BUG REPRODUCED: client accepted a masked server frame (payload 'hi')`
- **Flip:** `OK: client rejects a masked server frame`; `flare/ws/client.mojo` restored.

### WS-04: `WsClient` accepts a 101 that is not a WebSocket handshake

- **Severity:** Low. The accept value is still checked, so only a server that read the key and computed the accept can trigger it. The client then treats a peer that never agreed to WebSocket (no `Upgrade`/`Connection`), or that selected a subprotocol the client never offered, as a WebSocket connection.
- **RFC:** RFC 6455 §4.1: the client MUST fail the connection if the 101 lacks `Upgrade: websocket` (case-insensitive), lacks a `Connection` token `upgrade`, has the wrong `Sec-WebSocket-Accept`, or names an extension or subprotocol that was not requested.
- **What goes wrong:** both branches of `_connect_impl` (`client.mojo:562-603`, `609-646`) check the status prefix and the last `Sec-WebSocket-Accept`, and read no other field.
- **Counterexample:** `Bugs.WS_04.counterexample` holds for every SHA-1: the 101 `[Sec-WebSocket-Accept: <right value>, Sec-WebSocket-Protocol: chat]` passes `clientAccepts` and violates `ClientOK`.
- **Fix:** check the whole list. `Bugs.WS_04.fixed_ok` (= `clientFixed_ok`: the fix decides exactly `ClientOK`). `handshake_complete` shows flare's own server still passes.
- **Repro:** `formal/repro/WS-04_client_accepts_incomplete_101.mojo` (forked raw server; control: a complete 101 connects)
- **Observed (3 runs):** `BUG REPRODUCED: WsClient accepted a 101 with no Upgrade or Connection field and an unrequested Sec-WebSocket-Protocol`
- **Flip:** with the field checks added to both branches of `flare/ws/client.mojo`: `OK: incomplete 101 refused (raised: WsHandshakeError: 101 lacks Upgrade/Connection or names an unrequested protocol)`; the file was restored.

### WS-05: the standalone `WsServer` handshake checks almost nothing

- **Severity:** Low. Non-WebSocket requests are upgraded: POST, HTTP/1.0, `Connection: noupgrade`, a key that is not base64 of 16 bytes, and any version. Cross-protocol requests (for example a form POST carrying these fields) can open a WebSocket. A client speaking another version gets 101 instead of 426.
- **RFC:** RFC 6455 §4.2.1 (GET, HTTP/1.1 or higher, `Upgrade` containing `websocket`, a `Connection` token `upgrade`, a key that decodes to 16 bytes, version 13), §4.2.2 point 4 (otherwise 426 with `Sec-WebSocket-Version: 13`) and §11.3.1/§11.3.5 (those fields at most once).
- **What goes wrong:** `_parse_ws_upgrade_bytes` and `_read_upgrade_request` (`server.mojo:188-321`) drop the request line, test `Connection` by substring, test the key for being non-empty, keep the last repeated key, and never read `Sec-WebSocket-Version`.
- **Counterexample:** `Bugs.WS_05.counterexample`: the request above gives `srvShipped = some "x"` but violates `ServerOK`. `key_invalid` shows `x` is not a valid key.
- **Fix:** check the request line, the Connection tokens, the decoded key length, single key/version fields and version 13. `Bugs.WS_05.fixed_ok` (= `srvFixed_ok`). `handshake_complete` shows flare's own client request still passes.
- **Repro:** `formal/repro/WS-05_standalone_server_handshake_unchecked.mojo` (control: the RFC 6455 §1.3 example request is accepted)
- **Observed (3 runs):** `BUG REPRODUCED: WsServer handshake accepted POST/HTTP/1.0 with Connection: noupgrade, key 'x' and version 8 (accepted key=x)`
- **Flip:** with the request-line, Connection-token, key and version checks added to `_parse_ws_upgrade_bytes` in `flare/ws/server.mojo`: `OK: invalid opening handshake refused (raised: NetworkError: not a GET HTTP/1.1 request)`; the file was restored. The flip did not add the single-field check, which the Lean fix has. The repro's request does not depend on it.

### WS-06: `WsConnection` does not take part in the closing handshake

Status: resolved. `WsConnection` keeps a `_close_sent` flag. `recv` answers a received CLOSE (echoing the code, an empty CLOSE, or 1002 for an invalid body) unless one was sent, `close()` sends once and no longer claims to wait, and `send_text`/`send_binary`/`send_frame` raise once a CLOSE was sent. The counterexamples are about `oldStep`; `Bugs.WS_06.fixed_ok` is about the shipped `fixStep`.

- **Severity:** Medium. Every connection that a client closes ends with EOF instead of a CLOSE reply, so clients see an abnormal closure (1006) and lose the close code. An invalid CLOSE body is not answered with 1002. After `close()` the server still puts data frames on the wire. `close()` is documented as "Send a CLOSE frame and wait for the client's CLOSE response", but it does not wait.
- **RFC:** RFC 6455 §5.5.1: an endpoint that receives a CLOSE and has not sent one MUST send a CLOSE in response, and after sending a CLOSE it MUST NOT send more data. Per §7.4.1 and §7.1.7, a 1-byte body, an invalid code or a non-UTF-8 reason is a protocol error (1002).
- **What goes wrong:**
  - `recv` (`server.mojo:514-536`) answers PING but hands CLOSE to the caller with no reply.
  - The documented handler (`660-671`) breaks on CLOSE, and `__deinit__` closes the socket.
  - `close()` (`600-616`) keeps no state.
  - `send_text`/`send_binary`/`send_frame` (`473-512`) never check.
- **Counterexample:** `Bugs.WS_06.counterexample_no_echo` (CLOSE 1000 gets no reply), `counterexample_invalid_payload` (a 1-byte body gets no 1002) and `counterexample_data_after_close` (`close(1000)` then `send_text` writes TEXT after CLOSE). All three are `¬ CloseOK oldStep ()`.
- **Fix:** add a `close_sent` flag. On a received CLOSE, reply with the code (or an empty CLOSE, or 1002 for an invalid body) unless one was already sent; set the flag in `close()`; make `send_*` raise once it is set. `Bugs.WS_06.fixed_ok` (= `fixed_closeOK`) proves this on every trace.
- **Repro:** `formal/repro/WS-06_close_handshake_not_answered.mojo` (forks `_handle_ws_connection` with the documented handler, and with a close-then-send handler)
- **Observed (3 runs):** `client CLOSE 1000 -> server sent: (nothing)`, `client CLOSE 1-byte payload -> server sent: (nothing)`, `close() then send_text -> server sent: [op=8 code=1000][op=1]`, then `BUG REPRODUCED: closing handshake violated (echo missing: True; 1002 missing: True; data after CLOSE: True)`
- **Flip:** with the flag, the reply and the checks added to `flare/ws/server.mojo`, the repro printed `[op=8 code=1000]`, `[op=8 code=1002]` and `[op=8 code=1000]`, then `OK: CLOSE echoed, invalid payload answered with 1002, no data after CLOSE`; the file was restored.

### WS-07: the reactor upgrade tests Connection by substring and never decodes the key

- **Severity:** Low. On the shared-listener path (`serve_ws_upgrade`, `ServerConfig.ws`), `Connection: noupgrade` (or any value containing `upgrade`) and a key such as `x` get 101. The version is enforced, because the 426 check runs first (`reactor_upgrade_v13`).
- **RFC:** RFC 6455 §4.2.1 points 4-5: a `Connection` token `upgrade`, and a key that is base64 of 16 bytes.
- **What goes wrong:** `_handle_ws_upgrade` (`conn_handle.mojo:1512-1523`) uses `"upgrade" in lower(connection)` and `key.byte_length() > 0`.
- **Counterexample:** `Bugs.WS_07.counterexample`: GET, HTTP/1.1, `Upgrade: websocket`, `Connection: noupgrade`, `Sec-WebSocket-Key: x`, version 13 gives `reactor = upgrade "x"` and violates `ServerOK` (`no_conn_token`).
- **Fix:** test Connection tokens and decode the key, as in `qualFixed`. `Bugs.WS_07.fixed_ok` (= `reactorFixed_ok`).
- **Repro:** `formal/repro/WS-07_reactor_ws_key_and_connection_token.mojo` (forked `HttpServer.serve_ws_upgrade`; control: the valid handshake gets 101)
- **Observed (3 runs):** `BUG REPRODUCED: reactor upgraded a request with Connection: noupgrade and Sec-WebSocket-Key: x (HTTP/1.1 101 Switching Protocols)`
- **Flip:** with token matching and the base64 key-length check added to `flare/http/_reactor/conn_handle.mojo`: `OK: invalid handshake not upgraded (HTTP/1.1 200 OK)`; the file was restored.

After every flip, `git status --short flare/` showed none of my files. Other agents' flips can appear there briefly; one appeared once, on a file I did not touch. Every repro was run three times, with the same output each time.

## Checked, not a bug

**HTTP/1.1**
- **Strict-mode smuggling.** `no_smuggling_strict`: with the default leniency, whenever the parser accepts a request, the reactor frames it the same way (TE, CL, both, duplicates, OWS and case variations).
- **obs-fold framing.** Neither the reactor nor the parser takes TE or CL from continuation lines, so framing still agrees. The unvalidated continuation bytes are H1-10.
- **Truncated input to the full parser.** The parser accepts heads without CRLFCRLF, but the reactor only calls it after finding the terminator, so this is unreachable from the network.
- **`_parse_http_request` slicing past the end on early EOF.** This legacy path is reachable only from tests; `server.mojo` only re-exports it.
- **The minimal parser skips validation.** This is by design (it is the documented fast path) and does not affect framing.
- **The 18-digit Content-Length cap.** `parseCL_fits`: the value is < 10^18, so no Int64 overflow.
- **Chunk-size Int64 wrap.** `parseSize_fits` covers every `max_body < 2^59`. A wrap needs a configured body limit of at least 2^59 bytes, which is a misconfiguration.
- **Keep-alive.** `_wants_close` and the token-list issues are APP-02 and APP-03 in `L4_App/KeepAlive.lean`.
- **Client framing (RFC 9112 §6.3).** `respFraming` implements §6.3 exactly for the cases it accepts (`framing_*_iff`). It is stricter where §6.3 allows recovery: it refuses TE together with CL, a repeated CL, and any TE other than exactly `chunked`. HEAD, 1xx, 204 and 304 never read a body (`framing_bodyless`).
- **Response desync on a pooled keep-alive connection.** The pooled reader truncates the buffer at the scanner's end before parsing (`cDec_agree`, `framed_chunked_agrees`) and reads exactly n bytes for a length body (`framing_length_iff`), so bodies cannot spill into the next response. The remaining ways to split a response are in the head and are filed: H1-07 (bare LF) and H1-08 (status code). The pooled chunked path uses the reactor's scanner, so it inherits H1-01 and H1-02; those are not filed again.
- **A 101 on a pooled connection.** `_parse_http_response` treats 1xx other than 101 as interim. A 101 the client did not ask for would be a server MUST violation (RFC 9110 §15.2.2), so this is not a client bug.
- **A bare CR in a response field** is refused by `HeaderMap` (`headers.mojo:75-85`).
- **The 16-hex-digit chunk-size cap** in both client readers is deliberate. It is what bounds the size accumulator.
- **Encoder trailers.** The streaming serializer writes application-chosen trailers without filtering forbidden names (RFC 9110 §6.5.1). flare's own client refuses them (`ClientTrailersOK`). This is an application responsibility, listed under limitations.
- **Buffered TLS reads** refuse a close-delimited body without close_notify (`bufferedClose_safe`). The streaming download has the same guard in `_H2Transport.read` (H1-11, fixed).

**WebSocket**
- **Close-code validation on receive** was an open question in the previous round. It is now part of WS-06, whose fix answers an invalid body with 1002.
- **`WsFrame.close` does not validate the code it sends.** Codes come from the application or from `WsCloseCode` constants. The MUST NOT on sending 1005/1006 binds the application that picks them.
- **`WsClient`'s closing handshake** is not part of WS-06. `recv` hands CLOSE to the application, which is told to call `close()`. `close()` writes CLOSE and closes the transport, so a reply exists (code 1000; RFC 6455 says the code is "typically" echoed), and nothing can be sent after it.
- **RSV1 is always rejected.** permessage-deflate is never negotiated, so this is correct (RFC 6455 §5.2).
- **Non-minimal length encodings are accepted.** The RFC's MUST binds the sender, and flare's encoder is minimal (`lenCode`, `decode_encode`).
- **Key generation.** The client key is base64 of 16 CSPRNG bytes, with no fallback (`genKey_valid`).
- **Accept computation.** The client and both servers compute `base64(SHA-1(key ++ GUID))` the same way, and every fixed check accepts flare's own handshakes (`handshake_complete`).
- **Version 13 on the reactor path** is enforced: the 426 branch runs first (`reactor_upgrade_v13`). The 426 response keeps the connection open, which is APP-01 in L4 and is not repeated here.
- **The server's exact `Upgrade == "websocket"` test** is stricter than RFC 6455's token list. That is an interoperability note, not a safety issue.
- **Subprotocol selection on the server.** No server path ever sends `Sec-WebSocket-Protocol`. RFC 6455 §4.2.2 lets a server select none, so this is allowed. The client offers none and, with the WS-04 fix, refuses one in the 101.
- **A WebSocket upgrade on TLS is served in cleartext.** This is APP-48 (`conn_handle.mojo:857`, `L4_App/ConnExt.lean`) and is not repeated here.
- **UTF-8 validation of text frames** is exactly RFC 3629 (`textPayload_ok_iff`, from L1).
- **The server rejects unmasked client frames** (`server_safe`).
- **The encoder does not check opcode > 15.** Only internal constants reach it.
- **Server-side fragmentation.** `WsConnection.recv` is frame-level, and reassembly is left to the application by its API.

## Traceability

| Lean definition | Mojo file:line | Theorems | Status |
|---|---|---|---|
| `Chunked.hexVal`, `parseSize` | `http/proto/chunked.mojo:171-180`, `252-266` | `parseSize_le`, `parseSize_fits`, `parseSize_wraps_unbounded` | proved / counterexample (misconfiguration only) |
| `Chunked.findCRLF`, `CAP`, `scanL`, `scanTr` | `chunked.mojo:183`, `235-303` | `scanL_resume`, `scanL_total_le`, `scanL_done_append` | proved |
| `Chunked.scanResume`, `scanEnd` | `chunked.mojo:189-303` | `scanEnd_range`, `scanResume_resume`, `scanEnd_segmentation_independent`, `Bugs.H1_01.*`, `Bugs.H1_02.*` | proved / counterexample (H1-01, H1-02) |
| `ChunkedSpec.poll` | `http/_reactor/conn_handle.mojo:661-678` | `poll_eq_oneShot`, `fixed_poll_eq_oneShot`, `Bugs.H1_01.counterexample` | proved (fixed) / counterexample (shipped) |
| `Chunked.decL`, `decTr`, `parseHexD`, `decodeBody` | `chunked.mojo:306-360` | `decL_of_scanL`, `scanEnd_decode`, `scanEnd_lfSafe` | proved |
| `Text.isWS`, `isDigit`, `decVal`, `finCL`, `parseCL` | `http/_scan.mojo:259-294` | `parseCL_complete`, `parseCL_sound`, `parseCL_fits` | proved |
| `Text.lower`, `ieqPrefix`, `ieq` | `chunked.mojo:33-48`, `_scan.mojo:144-170`, `http/proto/ascii.mojo:85-118` | `ieqPrefix_append_left`, `ieqPrefix_take` | proved |
| `Text.splitComma`, `normTok`, `tokens`, `classifyT`, `classify` | `chunked.mojo:63-93` | `tokens_strip`, `classify_strip`, `classify_join` | proved |
| `Text.isTchar`, `isFieldVchar`, `strip`, `findB` | `http/_server/parse_util.mojo:65-162`, `parse.mojo:234-238` | `strip_decomp`, `findB_spec` | proved |
| `Framing.scanField`, `joinR`, `reactorFraming`, `linesCRLF` | `chunked.mojo:120-158`, `_scan.mojo:173-247` | `framing_agrees`, `no_smuggling_strict`, `Bugs.H1_03.*`, `Bugs.H1_04.*` | proved (strict) / counterexample (lenient) |
| `Framing.nameOf`, `wfB`, `field`, `parserField`, `joinP`, `parserFraming` | `parse.mojo:234-353` | `framing_agrees`, `shape_of_wf` | proved |
| `Framing.splitOn`, `dropCR`, `linesLF` | `parse_util.mojo:165-208` | `lf_fixed_agrees`, `Bugs.H1_04.*` | proved / counterexample |
| `FieldValue.byteOk`, `valueOk` | `parse.mojo:277-285` | `strict_value_utf8`, `fixed_value_utf8`, `Bugs.H1_05.*` | proved (strict) / counterexample (obs-text) |
| `Ws.Key.at`, `maskFrom`, `appendMasked` | `ws/frame.mojo:483-488`, `495`, `612-647` | `maskFrom_involutive`, `maskFrom_append`, `appendMasked_eq` | proved |
| `Ws.Frame`, `isControl`, `byte0`, `lenCode`, `be16`, `be64`, `extLen`, `encode`, `encodeChecked` | `ws/frame.mojo:140-170`, `234-356`, `512-520` | `decode_encode`, `lenCode_125`, `lenCode_126`, `lenCode_65535`, `lenCode_65536` | proved |
| `Ws.parseLen`, `finish`, `decode` | `ws/frame.mojo:361-508` | `decode_encode`, `decode_ok_shape`, `Bugs.WS_01.*` | proved / counterexample (WS-01) |
| `Ws.serverAccept` | `ws/server.mojo:541-575` | `server_safe` | proved |
| `Ws.clientAccept`, `recvFrame` | `ws/client.mojo:693-763` | `Bugs.WS_03.*`, `clientFixed_safe` | counterexample (WS-03) / fix proved |
| `Ws.recvMessageOld`, `Ws.nextMessage` | `ws/client.mojo:765-858` | `Bugs.WS_02.*`, `nextMessage_delivered` | counterexample (WS-02) / fix proved |
| UTF-8 check (`L1.Utf8.isValidUtf8`) | `ws/frame.mojo:553-606` | `textPayload_ok_iff` | proved (in L1) |
| `ObsFold.isSPHT`, `aStrip`, `colonAt`, `fields` | `_server/parse.mojo:203-320`, `parse_util.mojo:65-90` | `fold_unfold`, `strict_no_fold`, `fields_ok_strict`, `fieldsFixed_valid`, `Bugs.H1_10.*` | proved (strict) / counterexample (H1-10) / fix proved |
| `ClientResponse.bodyless`, `respFraming` | `_client/parse.mojo:128-170` | `framing_bodyless`, `framing_te_cl_reject`, `framing_dup_cl`, `framing_*_iff` | proved |
| `ClientChunked.isSWS`, `pyStrip`, `hexAcc`, `cHex`, `trailerOk`, `cTr`, `cDec`, `cRead` (`cReadOld` = pre-fix) | `_client/parse.mojo:497-578`, `600-630` | `cDec_agree`, `framed_chunked_agrees`, `cRead_complete`, `Bugs.H1_06.*` | proved (framed path) / counterexample (read-to-EOF path, H1-06) / fix proved |
| `ClientResponse.parseStatus` | `_client/parse.mojo:318-352` | `parseStatusFixed_delimited`, `Bugs.H1_08.*` | counterexample (H1-08) / fix proved |
| `ClientResponse.san`, `findCRLF2`, `splitGo`, `splitLines`, `headImpl` | `_client/parse.mojo:89-125`, `233-306` | `headFixed_agrees`, `Bugs.H1_07.*` | counterexample (H1-07) / fix proved |
| `ClientResponse.canReuse` | `_client/parse.mojo:836-884` | `canReuseFixed_ok`, `Bugs.H1_09.*` | counterexample (H1-09) / fix proved |
| `ClientResponse.dlCloseOld`, `dlClose`, `bufferedClose` | `_client/download.mojo:215-220`, `_client/parse.mojo:665-683` | `bufferedClose_safe`, `Bugs.H1_11.*` | counterexample (H1-11) / proved (buffered) |
| `ChunkedEncode.hexDigit`, `hexLower`, `encChunk`, `encChunks`, `trailerLine`, `encTrailers`, `encodeBody`, `encodeUpload` | `streaming_serialize.mojo:116-140`, `162-166`, `258-300`; `client.mojo:121-135`, `1420-1445`, `1470-1495` | `decL_roundtrip`, `decodeBody_roundtrip`, `scan_roundtrip`, `cDec_roundtrip`, `upload_roundtrip` | proved |
| `Handshake.acceptOf`, `genKey` | `ws/client.mojo:118-148`, `ws/server.mojo:100-111` | `genKey_valid`, `handshake_complete` | proved |
| `Handshake.clientAccepts`, `clientRequest` | `ws/client.mojo:536-550`, `562-603`, `609-646` | `clientFixed_ok`, `Bugs.WS_04.*` | counterexample (WS-04) / fix proved |
| `Handshake.srvShipped`, `srvResponse` | `ws/server.mojo:188-340` | `srvFixed_ok`, `Bugs.WS_05.*` | counterexample (WS-05) / fix proved |
| `Handshake.firstVal`, `versionMismatch`, `reactorQual`, `reactor` | `http/headers.mojo:172-184`, `_reactor/conn_handle.mojo:143-152`, `835-860`, `1512-1523` | `reactor_upgrade_v13`, `reactorFixed_ok`, `Bugs.WS_07.*` | proved (version) / counterexample (WS-07) / fix proved |
| `Close.oldStep`, `Close.fixStep` | `ws/server.mojo:473-536`, `600-616` | `fixed_closeOK`, `Bugs.WS_06.*` | counterexample (WS-06) / fix proved |
