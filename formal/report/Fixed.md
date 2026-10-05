# Fixes

One commit per finding (138 in all), as `git log` records them. Each commit changes `flare/`, adds a regression test, updates the docs, updates the Lean model and marks the repro resolved.

| ID | Severity | Commit | Subject |
|---|---|---|---|
| ENC-01 | Low | `144ed0a1` | fix(net): IpAddr.is_multicast is exactly ff00::/8 for IPv6 (ENC-01) |
| ENC-02 | Low | `5a85e66a` | fix(runtime): floor-division era in civil_to_unix_seconds/unix_seconds_to_civil (ENC-02) |
| ENC-03 | High | `ee6671c5` | fix(grpc): reject proto length-delimited fields longer than the message (ENC-03) |
| ENC-04 | Medium | `dadf0801` | fix(io): make ByteReader._need overflow-proof (ENC-04) |
| NET-01 | High | `32c48a33` | fix(udp): size the recvfrom sockaddr buffer for IPv6 senders (NET-01) |
| NET-02 | Low | `daf6b672` | fix(net): write_all raises instead of spinning when send returns 0 (NET-02) |
| NET-03 | Low | `3c870d6d` | fix(dns): saturate DnsCache expiry so a huge ttl_ms still caches (NET-03) |
| NET-04 | Medium | `10a08863` | fix(uds): drop routed frames before FrameDemux.feed raises (NET-04) |
| NET-05 | Info | `2d227425` | fix(tcp): wrap the accepted fd before decoding the peer address (NET-05) |
| NET-06 | Low | `7071fffa` | fix(uds): queried_local_path round-trips non-ASCII socket paths (NET-06) |
| NET-07 | Medium | `c279917d` | fix(uds): only a refused probe makes a socket stale in UnixListener.bind (NET-07) |
| NET-08 | Low | `ce0ac662` | fix(dns): accept absolute hostnames of 253 bytes plus the root dot (NET-08) |
| NET-09 | Low | `dd1016f6` | fix(dns): do not split a UTF-8 character in the hostname-too-long error (NET-09) |
| NET-10 | Low | `5019eb41` | fix(dns): start happy-eyeballs ordering with the first address's family (NET-10) |
| RT-01 | Low | `8fbcfc85` | fix(runtime): cap TimerWheel.next_fire_ms at the overflow promotion boundary (RT-01) |
| RT-02 | Low | `013ffcc8` | fix(runtime): raise when writev makes no progress in writev_buf_all (RT-02) |
| RT-03 | Medium | `8f1df299` | fix(runtime): re-arm the uring wakeup read after the SQ is flushed (RT-03) |
| RT-04 | Low | `811281db` | fix(runtime): peek_idle_worker no longer returns a peer with a full queue (RT-04) |
| RT-05 | Low | `8e1b2089` | fix(runtime): BufferPool.release drops handles smaller than their class (RT-05) |
| RT-06 | Medium | `966d2fbf` | fix(runtime): make the blocking-pool sem_open call ABI-correct on macOS arm64 (RT-06) |
| RT-07 | Low | `a246fb26` | fix(runtime): fail closed when the pool semaphore cannot be opened (RT-07) |
| RT-08 | Medium | `6c3e2991` | fix(runtime): treat a NULL sem_open result as failure on Linux (RT-08) |
| NET-11 | Low | `987ddc0f` | fix(udp): refuse BatchReceiver sizes whose product overflows (NET-11) |
| H1-01 | Low | `a38e326b` | fix(http): make the chunk-line cap independent of TCP segmentation (H1-01) |
| H1-02 | Medium | `a3ae72f9` | fix(http): reject a bare LF inside chunk-size and trailer lines (H1-02) |
| H1-03 | Medium | `329c5755` | fix(http): frame Name : value lines like the lenient parser does (H1-03) |
| H1-04 | Medium | `2ab99a37` | fix(http): split reactor framing lines at LF like the lenient parser (H1-04) |
| H1-05 | Low | `08829422` | fix(http): reject non-UTF-8 obs-text header values (H1-05) |
| H1-06 | Medium | `82262573` | fix(http): refuse a truncated chunked response in the client (H1-06) |
| H1-07 | Low | `bbae97f0` | fix(http): refuse a bare-LF or blank-line response head in the client (H1-07) |
| H1-08 | Low | `252c9d0e` | fix(http): refuse a status code of more than three digits in the client (H1-08) |
| H1-09 | Low | `e98fa023` | fix(http): do not pool a connection after an HTTP/1.0 response (H1-09) |
| H1-10 | Low | `1f7f7d27` | fix(http): validate obs-fold continuation lines in the server (H1-10) |
| H1-11 | Medium | `c0567415` | fix(http): raise on a TLS download that ends without close_notify (H1-11) |
| WS-01 | Low | `7aa8820c` | fix(ws): fail the connection on a reserved opcode (WS-01) |
| WS-02 | Medium | `97cfd1be` | fix(ws): reassemble fragmented messages in WsClient.recv_message (WS-02) |
| WS-03 | Low | `8b4f33ad` | fix(ws): close on a masked frame from the server in WsClient (WS-03) |
| WS-04 | Low | `0516607a` | fix(ws): check the whole 101 in WsClient.connect (WS-04) |
| WS-05 | Low | `ebd0a496` | fix(ws): check the whole opening handshake in the standalone WsServer (WS-05) |
| WS-06 | Medium | `152d8877` | fix(ws): answer CLOSE and stop sending after it in WsConnection (WS-06) |
| WS-07 | Low | `66d076ef` | fix(http): apply the full WebSocket handshake rule in the reactor upgrade (WS-07) |
| H2-01 | High | `0a8720b8` | fix(http2): enforce the connection-level receive window (H2-01) |
| H2-02 | Low | `fae1f0a1` | fix(http2): a refused stream id cannot be opened again (H2-02) |
| H2-03 | Medium | `30c98ba7` | fix(http2): client treats a late frame on a closed stream as idle (H2-03) |
| H2-04 | Low | `fc1b9ff9` | fix(http2): client rejects HEADERS on a stream it never opened (H2-04) |
| H2-05 | Medium | `6c062bde` | fix(http2): reject malformed and conflicting content-length (H2-05) |
| H2-06 | Low | `2057bb37` | fix(http2): HEADERS on stream 0 is a connection error, not an exception (H2-06) |
| H2-07 | Low | `079afaa0` | fix(http2): a GOAWAY shorter than 8 octets is a FRAME_SIZE_ERROR (H2-07) |
| H2-08 | Low | `2ab32f02` | fix(http2): the first frame after the client preface must be SETTINGS (H2-08) |
| H2-09 | Medium | `3907dc5f` | fix(http2): return connection credit for DATA discarded by a reset (H2-09) |
| H2-10 | Medium | `585cf26b` | fix(http2): reject non-ASCII and colon-bearing field names (H2-10) |
| H2-11 | Low | `16841b0d` | fix(http2): SETTINGS_MAX_CONCURRENT_STREAMS = 0 admits no stream (H2-11) |
| H2-12 | Low | `b11496a6` | fix(http2): client END_STREAM closes a half-closed (remote) stream (H2-12) |
| H2-13 | Low | `146fc000` | fix(http2): the client never sends DATA on a closed stream (H2-13) |
| H2-14 | Low | `32e349f6` | fix(http2): the client rejects HEADERS on a half-closed (remote) stream (H2-14) |
| H2-15 | Low | `51dabf3f` | fix(http2): even, never-opened stream ids are idle in server role (H2-15) |
| H2-16 | Low | `969a4758` | fix(http2): idle-stream PRIORITY/WINDOW_UPDATE errors are connection errors (H2-16) |
| H2-17 | Medium | `eaf46258` | fix(http2): PUSH_PROMISE is a connection error, not a skipped HPACK block (H2-17) |
| H2-18 | Low | `0c7cfce9` | fix(http2): the client answers an oversized frame with GOAWAY, not a raise (H2-18) |
| H2-19 | Low | `ef12277d` | fix(http2): no stream WINDOW_UPDATE for the DATA that closes a stream (H2-19) |
| H2-20 | Low | `5eefe705` | fix(http2): DATA on a server-reset stream is STREAM_CLOSED (H2-20) |
| HPACK-01 | Medium | `c165c9a1` | fix(http2): store HPACK header strings byte for byte (HPACK-01) |
| HPACK-02 | Low | `937e9462` | fix(http2): the HPACK decode budget counts the last field (HPACK-02) |
| HPACK-03 | Medium | `0394449e` | fix(http2): keep the HPACK decoder at 4096 until the peer's size update (HPACK-03) |
| QUIC-01 | Medium | `c3f84e3b` | fix(quic): reject unknown frame types instead of re-reading their body (QUIC-01) |
| QUIC-02 | Low | `d5017cad` | fix(quic): reject MAX_STREAMS / STREAMS_BLOCKED above 2^60 (QUIC-02) |
| QUIC-03 | Low | `4de23924` | fix(quic): reject ACK ranges that reach below packet number 0 (QUIC-03) |
| QUIC-04 | Medium | `bf83800b` | fix(quic): HANDSHAKE_DONE no longer reopens a closing or draining connection (QUIC-04) |
| QUIC-09 | Low | `0fc661cf` | fix(quic): the server rejects a HANDSHAKE_DONE frame from the client (QUIC-09) |
| QUIC-10 | Low | `a788265d` | fix(quic): reject initial_max_streams_* above 2^60 in transport parameters (QUIC-10) |
| QUIC-11 | Medium | `0ebc25ec` | fix(quic): validate the client's transport parameters in the server (QUIC-11) |
| QUIC-12 | Low | `dd0d4c47` | fix(quic): the client tells an absent CID parameter from a zero-length one (QUIC-12) |
| QUIC-13 | Low | `57b188d4` | fix(quic): validate the preferred_address transport parameter (QUIC-13) |
| QUIC-14 | Medium | `faa8bba1` | fix(quic): remember ACK ranges dropped at the cap as duplicates (QUIC-14) |
| QUIC-15 | Low | `45f5e21d` | fix(quic): the server checks the stream id of every stream frame (QUIC-15) |
| QUIC-16 | Low | `5e225e6c` | fix(quic): enforce the server's unidirectional stream limit (QUIC-16) |
| QUIC-17 | Low | `a357b899` | fix(quic): the client checks the stream id of every stream frame (QUIC-17) |
| QUIC-18 | Medium | `cc5a947e` | fix(quic): keep the two stream halves' resets apart (QUIC-18) |
| QUIC-19 | Low | `62c9a105` | fix(quic): answer STOP_SENDING with RESET_STREAM (QUIC-19) |
| QUIC-20 | Medium | `4b4e9f4c` | fix(quic): server idle timer follows RFC 9000 s10.1 (QUIC-20) |
| QUIC-21 | Medium | `060bca67` | fix(quic): the client applies an idle timeout (QUIC-21) |
| QUIC-22 | Medium | `a8782952` | fix(quic): the server sends CONNECTION_CLOSE and keeps a closing period (QUIC-22) |
| QUIC-23 | Low | `7c972383` | fix(quic): the server sends nothing while draining (QUIC-23) |
| QUIC-24 | Low | `a8e10fbd` | fix(quic): the client sends nothing while draining (QUIC-24) |
| QPACK-01 | High | `088dd857` | fix(qpack): reject field-section references outside the Required Insert Count (QPACK-01) |
| QPACK-02 | Medium | `39b4d5f7` | fix(qpack): bounds-check the Sign byte of the field-section prefix (QPACK-02) |
| QPACK-03 | Low | `de796c57` | fix(qpack): refuse string literals that are not valid UTF-8 (QPACK-03) |
| QPACK-04 | Low | `793ebcbb` | fix(qpack): reject encoder-stream references to missing entries (QPACK-04) |
| QPACK-05 | Medium | `c8ca7f5c` | fix(http3): undecodable field section closes the connection with QPACK_DECOMPRESSION_FAILED (QPACK-05) |
| QPACK-06 | Low | `e3e43f83` | fix(qpack): encoder references no unacknowledged entry and never evicts (QPACK-06) |
| H3-01 | Medium | `4ba5acd3` | fix(http3): refuse oversized non-HEADERS/DATA frames from their header (H3-01) |
| H3-02 | Low | `1e286111` | fix(http3): reject HTTP/2-reserved frame types on request streams (H3-02) |
| H3-03 | Low | `6254ba56` | fix(http3): refuse forbidden frame types on the control stream (H3-03) |
| H3-04 | Low | `4ec4b5c2` | fix(http3): refuse HTTP/2-reserved SETTINGS identifiers (H3-04) |
| H3-05 | Low | `4304b15a` | fix(http3): refuse client push streams and duplicate QPACK streams (H3-05) |
| H3-06 | Low | `dbaf85ab` | fix(http3): reject bytes after the GOAWAY stream id (H3-06) |
| H3-07 | Medium | `64174a8e` | fix(http3): server opens its control stream and sends SETTINGS (H3-07) |
| APP-01 | Low | `82abed98` | fix(http): close the connection after the WebSocket 426 answer (APP-01) |
| APP-02 | Low | `dc11f118` | fix(http): _wants_close matches Connection only at line start and ORs all lines (APP-02) |
| APP-03 | Low | `4178dbc5` | fix(http): read Connection as an option list in _compute_close_after / _wants_close (APP-03) |
| APP-04 | Medium | `72c46f5e` | fix(http): answer HEAD on the static fast path with the head only (APP-04) |
| APP-05 | Low | `2b8d4acb` | fix(http): error responses to HEAD carry no body (APP-05) |
| APP-06 | Low | `a6e41b3e` | fix(http): compare the read-buffer cap without summing the limits (APP-06) |
| APP-10 | Low | `a4759448` | fix(http): ComptimeRouter treats a non-final "*" as matching nothing (APP-10) |
| APP-20 | Low | `1f8487cd` | fix(http): negotiate_encoding honours the "*" wildcard weight (APP-20) |
| APP-21 | Low | `90862154` | fix(http): CORS origin allowlist no longer depends on entry order (APP-21) |
| APP-22 | Low | `a3d3d16a` | fix(http): Cors puts Vary: Origin on every response (APP-22) |
| APP-23 | Medium | `e7e6d431` | fix(http): end the URL authority at '?' and the fragment at the first '#' (APP-23) |
| APP-24 | Medium | `fe97b5fc` | fix(http): reject ill-formed UTF-8 in urldecode (APP-24) |
| APP-25 | Low | `4b1c9f56` | fix(http): Url.parse strips userinfo through the last '@' (APP-25) |
| APP-26 | Medium | `22cbd088` | fix(http): do not re-encode partial content in Compress (APP-26) |
| APP-27 | Low | `461c23ee` | fix(http): Compress sends Vary: Accept-Encoding on identity responses too (APP-27) |
| APP-40 | Medium | `571b6abf` | fix(http): RateLimit refill no longer wraps after a long idle period (APP-40) |
| APP-41 | Medium | `6bbc81a8` | fix(http): CircuitBreaker cooldown counts from the failure, not the request start (APP-41) |
| APP-42 | Low | `664a9c00` | fix(http): CircuitBreaker lets only one probe through while half-open (APP-42) |
| APP-43 | Low | `aefe2b0b` | fix(http): resolve a network-path Location (//host/path) against the base scheme only (APP-43) |
| APP-44 | Low | `02ee60d8` | fix(http): _same_origin compares hosts case-insensitively (APP-44) |
| APP-45 | Low | `fe624697` | fix(http): resolve relative Location references per RFC 3986 §5.2 (APP-45) |
| APP-46 | Medium | `2348b24b` | fix(http): single-worker drain(timeout_ms) waits out the timeout (APP-46) |
| APP-47 | Medium | `1ef3d874` | fix(http): migrate an h2c upgrade whose 101 flushes on a writable edge (APP-47) |
| APP-48 | High | `c8bce4bc` | fix(http): never upgrade a WebSocket on a TLS connection (APP-48) |
| APP-49 | Medium | `405105c0` | fix(http): complete an interim 100 Continue the socket took only in part (APP-49) |
| CONC-01 | Low | `0b291ce6` | fix(runtime): clamp the watchdog deadline into 1..Int64.MAX (CONC-01) |
| CONC-02 | Low | `acaf0eec` | fix(runtime): watchdog_arm releases a still-armed slot before it stores the new address (CONC-02) |
| CONC-03 | High | `023c77f6` | fix(runtime): drain no longer frees the stop flag under a detached worker (CONC-03) |
| CONC-04 | Medium | `bdc6e488` | fix(runtime): drain frees the joined workers' listeners when one is detached (CONC-04) |
| CONC-05 | Medium | `45813d7d` | fix(runtime): close the shared listener only after the workers joined (CONC-05) |
| CONC-06 | Medium | `3d5fa34a` | fix(runtime): Scheduler.start rollback frees the per-worker listeners (CONC-06) |
| CONC-07 | Medium | `0741fc9e` | fix(runtime): bound the idle io_uring worker's wait so it sees the stop flag (CONC-07) |
| MACH-01 | Low | `7cdf6421` | fix(http): register the listener under a token no fd can take (MACH-01) |
| DOC-01 | Medium | `dfe3f1f7` | fix(ws): fail the connection with CLOSE 1007 on a non-UTF-8 TEXT frame (DOC-01) |
| DOC-02 | Low | `ec9ec131` | fix(ws): answer an unmasked client frame with CLOSE 1002 (DOC-02) |
| DOC-03 | Medium | `9f407b38` | fix(http2): DATA before the response HEADERS is a stream error (DOC-03) |
| DOC-04 | Low | `f9ad045b` | fix(http): log sanitised error messages with the request id (DOC-04) |
| DOC-05 | Low | `a28d5eb6` | fix(http): serve_cancellable/serve_view/serve_static reject extra listeners (DOC-05) |
| DOC-06 | Medium | `89453c84` | fix(http): sessions expire server-side by default (DOC-06) |
| DOC-07 | Medium | `8a5b538c` | fix(tls): TlsAcceptor.reload() rotates the session-ticket key (DOC-07) |
| DOC-08 | Medium | `3cdc9cf6` | fix(tls): session tickets are opt-in and enable_session_tickets=False turns them off (DOC-08) |
