# L3 protocol: QUIC, QPACK and HTTP/3

This report covers the QUIC transport pieces of flare that parse peer input or keep per-connection accounting: the varint and frame parser, packet-number reconstruction, the connection state machine, ACK range expansion and the received-packet ranges behind outgoing ACKs, the per-frame stream-state rules, the `bytes_in_flight` counter, the transport-parameter decoder and encoder, what each endpoint checks in the peer's parameters, and the idle and closing/draining timers of both endpoints. It also covers QPACK (Required Insert Count, dynamic table, field-section references and string literals including the Huffman branch, encoder stream, blocked streams, and the encoder's table lookups) and the HTTP/3 server: the frame codec, the request-stream reader and its grammar, the control-stream and unidirectional-stream rules, and the server's own control stream.

Each model is a transliteration of the shipped Mojo code. Every implementation definition carries a `mirrors flare/<file>#<Symbol> sha=<hash> at=<commit>` anchor, and `formal/scripts/anchors.py` checks that the anchored symbols have not changed. Specifications are written separately, from RFC 9000, RFC 9002, RFC 9114 and RFC 9204. The aggregate module is `Flare/L3_Protocol/QuicH3.lean`, and `Flare/Audit/QuicH3.lean` prints the axioms of 91 headline theorems.

Build and audit status:
- There is no `maxHeartbeats` option anywhere.
- There are no `sorry`, `admit` or `axiom` declarations.
- Every audited theorem depends only on `propext`, `Quot.sound` and `Classical.choice`.
- `native_decide` does not appear in any QUIC, QPACK or HTTP/3 file.
- The QUIC, QPACK and HTTP/3 model files contain 312 top-level `theorem` declarations.

## Components

### QUIC wire reading and the frame parser

Files: `Quic/Wire.lean`, `Quic/Frame.lean`, `Quic/FrameProps.lean`.

**Model.**
- `Parser α := StateT Nat (Except Err) α` is a cursor over a byte list. `Err.oob` stands for an out-of-bounds read, which the Mojo code would hit as a bounds assertion; `Err.raise` stands for a raised error.
- `varint` mirrors `decode_varint` (`quic/varint.mojo`), and `bytes` and `byte` mirror `_read_varint` / `_read_bytes` (`quic/frame.mojo`).
- `kindOf` is the type-test chain of `parse_frame_into`, in source order.
- `body` dispatches on the resulting `Kind` to one small parser per frame type. Each parser mirrors its branch of `parse_frame_into`, including the three checks the audit added: an unknown frame type is a FRAME_ENCODING_ERROR (QUIC-01), MAX_STREAMS and STREAMS_BLOCKED above 2^60 are rejected (QUIC-02), and so is an ACK whose computed packet numbers go negative (`ackOk`, QUIC-03).
- `parsePayload` mirrors the `dispatch_frames` loop (`quic/state.mojo`).

Proofs are per-branch lemmas combined with `cases` on `Kind`; there is no case split over the whole parser.

| Lean name | Statement | Status |
|---|---|---|
| `Frame.parseFrame_good` | `parseFrame` never reads out of bounds, and on success the consumed length is at most the buffer length. | proved |
| `Frame.parseFrame_progress` | On success at least one byte is consumed, so the payload loop terminates. | proved |
| `Wire.varint_progress`, `Wire.good_varint`, `Wire.good_bytes`, `Wire.good_byte` | Cursor primitives stay in bounds and advance. | proved |
| `Frame.ack_range_cap` | Any ACK flare accepts has at most 0x4000 additional ranges. | proved |
| `Frame.newcid_checks` | Any NEW_CONNECTION_ID flare accepts has a CID of 1..20 bytes, a 16-byte reset token, and `retire_prior_to ≤ sequence`. | proved |
| `Frame.parseFrame_not_unknown`, `Frame.parsePayload_not_unknown` | The parser never returns an unknown frame, so an unknown frame type is a FRAME_ENCODING_ERROR and its body is never re-read as frames. | proved |
| `Frame.parseFrameFixed_ok` | Every frame `parseFrame` accepts satisfies `RfcFrameOk`: not an unknown type, MAX_STREAMS and STREAMS_BLOCKED ≤ 2^60, and ACK ranges non-negative. | proved |
| `Frame.parsePayloadFixed_ok` | Every frame in a payload `parsePayload` accepts satisfies `RfcFrameOk`. | proved |

Assumptions and limitations:
- Frame contents are kept as values here. What the handlers do with them is modelled in the later sections: connection state in `Conn`, streams in `Streams`, ACKs in `AckExpand` and `LossRecovery`, close and idle behaviour in `Timers`.
- Varint encoding correctness is owned by L1. Here only decoding bounds and progress are proved.

### Packet-number reconstruction

File: `Quic/PacketNumber.lean`.

**Model.** `decodePnImpl` transliterates `decode_packet_number` (`quic/protection.mojo`) in `UInt64`. `rfcDecode` is the RFC 9000 Appendix A.3 pseudocode over `Int`.

| Lean name | Statement | Status |
|---|---|---|
| `PacketNumber.cand_eq` | `(e & ~(w-1)) \| t = e - e % w + t` in `UInt64`, for `w = 2^k` with `k ≤ 32` and `t < w`. | proved |
| `PacketNumber.decodePnImpl_eq_rfc` | For lengths 1..4, a truncated value below `2^(8·len)` and `largest < 2^62`, flare's code equals the RFC pseudocode. | proved |
| `PacketNumber.rfcDecode_window` | If `pn < 2^62` lies in `(expected - hwin, expected + hwin]`, the RFC algorithm recovers `pn` from its low bits. | proved |
| `PacketNumber.decodePnImpl_window` | The same for flare's code. | proved |

Limitations: header protection and AEAD are out of scope.

### Connection state machine

File: `Quic/Conn.lean`.

**Model.**
- `CState` has the states handshake, established, closing, draining and closed (the `CONN_STATE_*` constants of `quic/state.mojo`).
- Events are a received frame, TLS handshake completion, and a local close.
- `implStep` mirrors four pieces of `quic/state.mojo`:
  - `handle_frame_buf`, which drops frames only once the state is CLOSED;
  - `apply_connection_close`, which moves to DRAINING;
  - `apply_handshake_done`, which moves to ESTABLISHED and acts only in HANDSHAKE (QUIC-04);
  - `on_handshake_done`, which raises PROTOCOL_VIOLATION when `Connection.is_server` is set (QUIC-09).
- `markHandshakeComplete` mirrors `mark_handshake_complete` and `localClose` mirrors `connection_close`.
- `specStep` follows RFC 9000 §10.2 and §19.20: closing and draining lead only to closed or draining, and the server rejects HANDSHAKE_DONE.

| Lean name | Statement | Status |
|---|---|---|
| `Conn.spec_closing_absorbing`, `Conn.specRun_absorbing` | Under the spec, once closing or draining, every run stays terminal. | proved |
| `Conn.implStep_eq_spec` | flare's step equals the spec on every role, state and event. | proved |
| `Conn.implStep_frame_spec`, `Conn.implStep_client_eq_spec` | The same restricted to frames, and to the client role. | proved |
| `Conn.implStep_absorbing` | In flare, once closing, draining or closed, every step stays terminal, for both roles. | proved |
| `Conn.markHandshakeComplete_spec`, `Conn.localClose_spec` | flare agrees with the spec on TLS completion and local close. | proved |
| `Conn.run_eq_spec` | Every run of flare's step equals the run of the spec. | proved |

Limitations:
- This model has no clock. The idle timeout and the closing/draining period are modelled separately, in `Quic/Timers.lean` (next section).
- `Role` is a parameter of the model. In the code it is the `Connection.is_server` flag.

### Timers: idle timeout, closing and draining

File: `Quic/Timers.lean`. Two labelled transition systems over a `Nat` clock in milliseconds, each with an RFC step function and one step function per flare endpoint.

**Idle timeout (RFC 9000 §10.1, §18.2).**
- Events: a datagram received at `t` (`auth` says whether a packet in it decrypted and was processed), an ack-eliciting send at `t`, and the timers advanced to `t`.
- `effective` is the effective timeout: the minimum of the two advertised `max_idle_timeout` values, the sole non-zero one if only one is non-zero, none if both are 0, then raised to at least 3×PTO.
- `ispecStep` restarts the period on every processed packet and on the first ack-eliciting send after one, and closes once the period exceeds the effective timeout.
- `fixedStep` is the timer both endpoints run. On the server it is `_handle_inbound` and `_process_one_packet` (only successfully processed packets re-arm it), `_build_1rtt_response` (the first ack-eliciting send), `schedule_idle_timeout` and `_client_params_ok` (the client's value); on the client it is `_dispatch_frames` (processed packets, with the monotonic clock), `_note_ack_eliciting_send`, `_apply_peer_transport_params` and `_check_idle`, called from `poll`. `R` relates it to the spec state. `effectiveMs` mirrors `_effective_idle_ms` (`quic/_server_support.mojo`), with 0 standing for no timeout.

**Closing and draining (RFC 9000 §10.2, §10.2.1, §10.2.2, §11.1).**
- Events: a local close, the peer's CONNECTION_CLOSE, any other packet for the connection, the driver having something to send, and a timer firing. The output is the list of packets sent.
- `cspecStep` is one conforming behaviour: a local close sends CONNECTION_CLOSE and enters closing until `t + 3×PTO`, answering each incoming packet with CONNECTION_CLOSE; the peer's CONNECTION_CLOSE enters draining, where nothing is sent; both states end at their deadline.
- `srvStepNow` is the server. A local close sends CONNECTION_CLOSE, clears `alive` and enters a 3×PTO closing phase in which each incoming packet is answered with CONNECTION_CLOSE and only the closing timer ends it (`_close_for`, `_enter_closing`, `_answer_closing`, `advance_timers`). Nothing is sent while draining: `_build_1rtt_response` returns no datagram and `_drain_and_send` returns at once in that state. A slot that never sent CONNECTION_CLOSE (no 1-RTT keys) is reclaimed by its next timer.
- `cliStepNow` is the client. `shutdown` sends CONNECTION_CLOSE and closes the socket; while draining, `_build_1rtt` and the Initial, Handshake and 0-RTT builders return no datagram, so `_drain_egress`, `_check_pto`, `keepalive` and `shutdown` send nothing, and `send_stream` raises.

| Lean name | Statement | Status |
|---|---|---|
| `Timers.fixed_sim`, `fixed_run`, `init_R` | flare's idle timer stays related to the spec state on every event and every run from connection start. | proved |
| `Timers.effectiveMs_spec` | `_effective_idle_ms` (0 for none) is the spec's effective timeout: the minimum of the non-zero values, at least 3×PTO, none when both are 0. | proved |
| `Timers.fixed_closed_eq_spec` | On every run flare's idle timer closes exactly when the spec does. | proved |
| `Timers.spec_none_never` | With no effective timeout (both values 0) the spec never closes on idleness. | proved |
| `Timers.spec_cc_on_close`, `spec_closing_only_cc`, `spec_draining_silent`, `spec_tick_before` | The spec sends CONNECTION_CLOSE on a local close, sends only CONNECTION_CLOSE while closing, sends nothing while draining, and keeps both states until their deadline. | proved |
| `Timers.srvFix_refines` | From an open or closing state, the server agrees with the RFC closing specification on a local close, on packets received and on timer events: it sends CONNECTION_CLOSE, answers packets in the closing period and ends it at the closing deadline. | proved |
| `Timers.srvNow_draining_silent`, `Timers.cliNow_draining_silent` | The server and the client send nothing while draining, whatever the event. | proved |
| `Timers.cli_close_ok` | The client's own close sends CONNECTION_CLOSE and ends at once, which RFC 9000 §10.2 allows an endpoint that closes its socket. | proved |

The findings in this area were the server idle timer (QUIC-20), the client's missing idle timer (QUIC-21), the server's silent close (QUIC-22), and sending while draining (QUIC-23 on the server, QUIC-24 on the client). The theorems above are about the shipped fixes.

Assumptions: the PTO is a parameter, and every theorem holds for every PTO value, so RTT estimation does not affect them. RFC 9000 §10.2.1 lets an endpoint rate-limit its closing-state replies (a MAY). The server answers the 1st, 2nd, 4th, ... packet; the model answers every packet, which is the stronger obligation.

### ACK range expansion

File: `Quic/AckExpand.lean`.

**Model.** `expand` mirrors `expand_ack_ranges` and its cap `_ACK_EXPAND_CAP` (`quic/_state_helpers.mojo`), including both inner `while` loops, the early return at the cap or at packet 0, and the `break` on a negative gap. Arithmetic is over `Nat`. That matches the Mojo code because every subtraction there is guarded, and `gap + 2` cannot wrap: `gap` is a varint, so it is below 2^62. `Claimed` is the set of integers covered by the RFC 9000 §19.3.1 intervals, computed over `Int`.

| Lean name | Statement | Status |
|---|---|---|
| `AckExpand.expand_sound` | Every packet number in the output lies in an interval the ACK claims, for any input, well-formed or not. | proved |
| `AckExpand.expand_len_le` | The output length is at most the cap (256 in flare). | proved |
| `AckExpand.expand_eq_take` | flare's output is exactly the first `cap` elements of the claimed packet numbers, newest first, cut where a range would go below 0. | proved |
| `AckExpand.expand_complete` | If every claimed interval has a non-negative low end (`WellFormed`) and the claimed numbers fit in the cap, every claimed packet number is in the output. | proved |
| `AckExpand.expand_drops_oldest`, `expand_length` | Above the cap only the oldest numbers are left out, and the output length is `min cap (number claimed)`. | proved |

### ACK generation: the received-packet ranges

File: `Quic/AckGen.lean`.

**Model.**
- `record` mirrors `_ack_record` (`quic/_server_support.mojo`): collect the pairs, add `[pn, pn]`, insertion-sort by low end (`isort`), merge overlapping or adjacent ranges (`mergeAcc`), keep the 32 highest, store descending.
- `St` adds the floor that `_ack_record` keeps in an odd trailing slot of the flat list: one above the highest range the cap has ever dropped (QUIC-14). `recordSt` and `floorAfter` mirror `_ack_record` with that slot, and `contains` mirrors `_ack_contains`: a number is seen if it lies in a stored range or below the floor. `contains` is the duplicate filter of `QuicListener._process_one_packet`. `fromRanges` mirrors `_ack_from_ranges`.
- `Rx`, `recv` and `drain` model the server's 1-RTT receive path and ACK emission (`QuicListener._process_one_packet` and `_drain_1rtt_coalesced`). The client uses the same helpers.
- Arithmetic is over `Nat`. Packet numbers are below 2^62, so `high + 1` cannot wrap, and `prev_low - high - 2` is only taken on canonical lists, where it is non-negative.

| Lean name | Statement | Status |
|---|---|---|
| `AckGen.record_canon` | The stored list is always canonical: descending, each range non-empty, neighbours separated by at least one missing number. | proved |
| `AckGen.merge_inv`, `merged_inv` | Sorting and merging keep exactly the received numbers. | proved |
| `AckGen.record_sound` | Every stored number was received. | proved |
| `AckGen.record_exact` | While the merged ranges number at most 32, the stored ranges are exactly the received set. | proved |
| `AckGen.record_drops_lowest` | Above the cap, every dropped range lies below every kept one. | proved |
| `AckGen.fromRanges_claimed`, `fromRanges_wellFormed` | The ACK frame built from canonical ranges claims exactly the stored numbers and has no negative range. | proved |
| `AckGen.ack_roundtrip` | Parsed back by flare's own `expand_ack_ranges`, that ACK retires exactly the stored numbers (when at most 256). | proved |
| `AckGen.drain_after_recv` | After a new ack-eliciting packet, the next drain emits an ACK; it claims nothing unreceived, and claims the packet whenever the merged ranges fit in the cap. | proved |
| `AckGen.never_reaccepts` | Over any packet trace, every number already received reads as seen, so no packet is processed twice. The proof carries the invariant `Inv`: the stored ranges are canonical, and every received number lies in one of them or below the floor. | proved |
| `AckGen.recordSt_flat` | The floor does not change the stored ranges, and so does not change any ACK sent. | proved |

So every received ack-eliciting packet is acknowledged in the next ACK unless more than 32 disjoint ranges are outstanding; in that case the oldest ranges are left out (see "Checked, not a bug"). What the cap did to duplicate detection was QUIC-14; `never_reaccepts` covers the floor that fixes it.

### Stream states

File: `Quic/Streams.lean`.

**Model.**
- `spec` is the per-frame acceptance rule of RFC 9000: §4.6 (stream limit), §19.4 (RESET_STREAM), §19.5 (STOP_SENDING), §19.8 (STREAM), §19.10 (MAX_STREAM_DATA) and §19.13 (STREAM_DATA_BLOCKED), over the stream id's initiator and direction bits, the locally opened streams and the advertised limits.
- `checked` is the check `check_stream_frame_id` (`quic/state.mojo`) makes on the two low bits of the stream id, the opened streams and the advertised limits.
- `server` mirrors the server: STREAM is checked in `QuicListener._route_http3_stream_chunks` (`quic/server.mojo`), including the unidirectional limit (QUIC-16); RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA and STREAM_DATA_BLOCKED go through `check_stream_frame_id` (QUIC-15).
- `client` mirrors the client: `_dispatch_frames` hands every frame to the shared state machine, whose frame handlers run `check_stream_frame_id` (QUIC-17).
- `stepHalves` mirrors `apply_reset_stream`, `apply_stop_sending` and `cancel_stream`, which set the separate `peer_reset` and `send_reset` flags of `Stream` (QUIC-18); `resetSeenH` and `sendRefusedH` mirror `stream_reset` and the check in `send_stream`. `Halves` is the RFC's split into a sending and a receiving part.

| Lean name | Statement | Status |
|---|---|---|
| `Streams.checked_eq_spec` | The bit-level check equals the RFC rule for both roles, every frame kind and every stream id. | proved |
| `Streams.serverFixed_eq_spec`, `clientFixed_eq_spec` | Each endpoint's verdict is the spec's, for every frame kind and stream id (the server's under `ServerOpened`). | proved |
| `Streams.halves_reset_iff`, `halves_stop_iff` | A received reset is seen exactly when RESET_STREAM arrived, and the send half refuses data exactly when STOP_SENDING arrived or we reset it, whatever follows. | proved |

Assumption: the server has opened no stream of its own until its first 1-RTT flight, and exactly its control stream 3 after it (`ServerOpened`, anchored to `mark_local_stream_opened` and `QuicListener._drain_1rtt_coalesced`). `check_stream_frame_id` treats a local stream as opened when it is in `conn.streams` or below `next_local_*`. The control stream (H3-07) is sent outside `conn.streams`, so `_drain_1rtt_coalesced` calls `mark_local_stream_opened`, which moves `next_local_uni` past 3. Without that call, which was missing until the H3-07 fix was re-checked for this report, a client's MAX_STREAM_DATA for stream 3 closed the connection with STREAM_STATE_ERROR, although RFC 9000 §19.10 makes that an error only for a stream that has not been created. `test_max_stream_data_for_the_control_stream_keeps_the_connection` covers it.

### Loss recovery: bytes in flight

File: `Quic/LossRecovery.lean`.

**Model.**
- The state is the `sent` list (packet number, send time, size) and the counter, both over `Nat`.
- `onSent`, `onAck`, `detectLost` and `firePto` mirror `LossRecovery.on_sent`, `on_ack`, `detect_lost` and `fire_pto` (`quic/_loss_recovery.mojo`).
- The retire predicates are abstracted: "listed in the ACK" for `on_ack`, and the packet and time thresholds for `detect_lost`. The oldest-index search of `fire_pto` is replaced by any valid index.
- Congestion control and RTT estimation are omitted; neither writes the counter.

| Lean name | Statement | Status |
|---|---|---|
| `LossRecovery.inv_onSent`, `inv_onAck`, `inv_detectLost`, `inv_firePto` | Each operation preserves `bytes_in_flight = Σ sent.size`, for every retire predicate and every index. | proved |
| `LossRecovery.inv_run` | Any sequence of operations from `init` keeps the invariant. | proved |
| `LossRecovery.retire_noUnderflow`, `firePto_noUnderflow` | Under the invariant, no `-=` in these loops underflows `UInt64`. | proved |

Assumption: the sum of in-flight sizes stays below 2^64, so `on_sent`'s `+=` does not wrap.

### QPACK (RFC 9204)

Files: `Qpack/Ric.lean`, `Qpack/Table.lean`, `Qpack/FieldSection.lean`, `Qpack/Encoder.lean`. The first three were written by the QPACK agent. In the second pass I rebuilt them and checked their axioms in the audit. In the final pass I added the Huffman literal branch, the encoder's lookups (`Qpack/Encoder.lean`) and the blocked-stream behaviour.

**Required Insert Count.** `implEncode` and `implDecode` transliterate `encode_required_insert_count` and `decode_required_insert_count` (`qpack/dynamic.mojo`) in `UInt64`; `none` means the code raised. `specEncode` and `specDecode` are the RFC 9204 §4.5.1.1 pseudocode over `Nat`.

| Lean name | Statement | Status |
|---|---|---|
| `Ric.implDecode_eq_spec` | For `me < 2^61` and `total < 2^62`, flare's decode equals the RFC decode, including its error cases. | proved |
| `Ric.specDecode_encode` | Window theorem: decode inverts encode when `0 < ric ≤ T + ME` and `T < ric + ME`. | proved |
| `Ric.implEncode_toNat`, `Ric.implDecode_encode` | The window theorem also holds for flare's `UInt64` encoder and decoder. | proved |

**Dynamic table.** Entries are generic, with a size function. `evictTo`, `setCapacity`, `insert`, `getAbs` and `insertCount` mirror `QpackDynamicTable._evict_to`, `set_capacity`, `insert`, `get_abs` and `insert_count` (`qpack/dynamic.mojo`).

| Lean name | Statement | Status |
|---|---|---|
| `Table.inv_init`, `inv_setCapacity`, `inv_insert` | `size = Σ esz ∧ size ≤ capacity ≤ maxCapacity` holds initially and after every operation. | proved |
| `Table.evictTo_spec` | Eviction keeps the sum, reaches the target or empties the table, and leaves a suffix of the entries. | proved |
| `Table.evict_noUnderflow`, `insert_noUnderflow` | No `UInt64` subtraction in these operations underflows. | proved |
| `Table.insertCount_insert`, `getAbs_insert_new`, `getAbs_insert` | An insert adds exactly one entry at the old insert count; absolute indices are stable. | proved |

**Field sections and the encoder stream.**
- `decodeInt` is a local model of `decode_integer` (`http2/hpack.mojo`).
- `implResolve` models the Base and pre-base and post-base index arithmetic of `decode_field_section_dynamic`, with the range checks of `_pre_base_abs` and `_post_base_abs` (QPACK-01).
- `implSignReadIndex` models the Sign-byte read of `decode_field_section_dynamic` with its bounds check (QPACK-02).
- `implLiteralRaw` is the byte stage of `_decode_string_literal` (`qpack/codec.mojo`), both branches, and `implLiteral` adds the UTF-8 check of `_literal_to_string` (QPACK-03). The Huffman branch calls `Flare.L1.Huffman.okOnly (decodeSimdImpl payload)`, the L1 model of `huffman_decode_simd`; `specLiteral` uses the proved L1 decoder `Flare.L1.Huffman.decode`.
- `implDynRef` models the encoder-stream reference check of `_relative_to_abs` (QPACK-04).

| Lean name | Statement | Status |
|---|---|---|
| `FieldSection.decodeInt_offset_le` | On success the end offset `o` satisfies `off < o ≤ len`. | proved |
| `FieldSection.implResolve_eq_spec` | The resolver equals RFC §4.5.1.2 and §4.5.2-4.5.5 for values below 2^62. | proved |
| `FieldSection.implResolve_safe` | Every index the resolver returns is below RIC. | proved |
| `FieldSection.rel_roundtrip` | The decoder inverts the encoder's relative index. | proved |
| `FieldSection.implSignOffset_le` | After a successful Required Insert Count decode the Sign-byte offset is at most `len`, so only the Sign read itself could go out of bounds. | proved |
| `FieldSection.implSignReadIndex_inBounds` | The Sign byte is read only below `len`. | proved |
| `FieldSection.implLiteral_ok` | Every literal `implLiteral` returns is valid UTF-8. | proved |
| `FieldSection.implDynRef_eq_spec` | An encoder-stream reference resolves to the entry RFC 9204 §4.3.2 and §4.3.4 name, and is a QPACK_ENCODER_STREAM_ERROR when it names no live entry. | proved |
| `FieldSection.implLiteralRaw_eq_spec` | The literal decoder's byte stage, Huffman branch included, equals `specLiteral` on every input (via L1's `okOnly_decodeSimdImpl`). | proved |
| `FieldSection.implLiteral_eq_spec_of_ok` | `implLiteral` equals `specLiteral` whenever the decoded bytes are valid UTF-8. | proved |
| `FieldSection.implLiteralRaw_huffman` | A Huffman literal whose length prefix fits decodes to exactly the original bytes (via L1's `decode_encode`). | proved |

So the Huffman branch decodes correctly, and its output goes through the same UTF-8 check as the plain branch. Before the QPACK-03 fix both branches went to the unchecked `String` constructor.

**Encoder lookups.** `findBy` mirrors `QpackDynamicTable.find` and `find_name`: the first matching entry, as an absolute index. `ric` mirrors the Required Insert Count computation of `encode_field_section_dynamic`. `implRic` and `implInsert` mirror `QpackEncoder.encode`, which encodes against an empty table, and `QpackEncoder.insert`, which refuses an entry that would evict (QPACK-06).

| Lean name | Statement | Status |
|---|---|---|
| `Encoder.findBy_some` | A returned index is the absolute index of an entry still in the table that satisfies the predicate, and no earlier live entry does. | proved |
| `Encoder.findBy_none` | `none` means no live entry satisfies the predicate. | proved |
| `Encoder.ric_bound` | The section's RIC is at least one more than every absolute index the encoder references. | proved |
| `Encoder.implRic_zero` | Every section `QpackEncoder.encode` produces has RIC 0. | proved |
| `Encoder.implInsert_noEvict` | An insert `QpackEncoder.insert` accepts keeps every earlier entry and appends the new one. | proved |
| `Encoder.encoder_spec` | RFC 9204 §2.1.1 and §2.1.2 with Known Received Count 0: no section can block a decoder, and no insert evicts an entry. | proved |

So the lookups are correct. Since the encoder tracks no acknowledgments, `QpackEncoder` does not use them: it references no dynamic entry and never evicts (QPACK-06).

**Blocked streams.** RFC 9204 §2.1.2: a decoder that meets more blocked streams than its SETTINGS_QPACK_BLOCKED_STREAMS MUST fail the connection with QPACK_DECOMPRESSION_FAILED. The QUIC server always builds `Http3Connection()` with the default configuration: table capacity 0 and 0 blocked streams. A section with a non-zero encoded Required Insert Count therefore fails to decode, and a section whose RIC exceeds the insert count raises "blocked on missing inserts". `sectionImpl` mirrors what the server does with either failure (`feed_into`, `Http3Connection.feed_stream_chunk`, `QuicListener._route_http3_stream_chunks`): it records QPACK_DECOMPRESSION_FAILED as a connection error and closes the connection with it (QPACK-05). `sectionSpec` is RFC 9204 §2.1.2, §2.2.1, §2.2.3 and §4.5.1.1 for a blocked-stream budget `B`.

| Lean name | Statement | Status |
|---|---|---|
| `Ric.implDecode_cap0` | With table capacity 0, every non-zero encoded Required Insert Count fails to decode. | proved |
| `Ric.sectionImpl_spec` | For the advertised budget of 0 blocked streams, flare's verdict on a field section (headers or connection error) is the spec's. | proved |

### HTTP/3 frames, request reader and grammar

Files: `H3/Frame.lean`, `H3/RequestReader.lean`, `H3/Grammar.lean`.

**Model.**
- `decodeFrame`, `encodeFrame`, `decodeSettings` and `encodeSettings` mirror `decode_http3_frame`, `encode_http3_frame`, `decode_http3_settings` and `encode_http3_settings` (`http3/frame.mojo`).
- `feed` and `stepFrame` mirror `feed_into` (`http3/request_reader.mojo`). A frame of any type other than HEADERS and DATA that declares more than `max_field_section_bytes` is refused from its header (H3-01), and the HTTP/2-reserved types are rejected next to the control types (H3-02).
- `drain` and `feedChunks` mirror the inbox loop of `Http3Connection.feed_stream_chunk` (`http3/server.mojo`).
- `Grammar.specStep` is the RFC 9114 §4.1 request-stream automaton `HEADERS DATA* [HEADERS]`. Unknown types are ignored. Control types and the HTTP/2-reserved types are rejections.
- `BoundedNeed step bound` says that `bound r` buffered bytes are always enough for the reader to act.

| Lean name | Statement | Status |
|---|---|---|
| `H3.decodeFrame_bounds` | A decoded payload is a slice of the buffer after a header of at least 2 bytes. | proved |
| `H3.decodeFrame_encode`, `H3.decodeSettings_encode` | Decoding inverts encoding, for any correct varint codec. | proved |
| `H3.feed_le` | `feed` consumes at most the buffer. | proved |
| `H3.feed_bounded` | `feed` satisfies `BoundedNeed` with bound `16 + max_field_section_bytes + max_body_bytes`: that many buffered bytes always make the reader act. | proved |
| `H3.feedChunks_chunking_independent` | The events do not depend on how the stream bytes are split into chunks. | proved |
| `H3.run_accept_impl`, `H3.run_reject_impl` | For every frame sequence (HTTP/2-reserved types included), flare reports no error and tracks the spec state on accepted sequences, and reports an error on rejected ones. | proved |
| `H3.spec_rejects`, `H3.implRejects_reserved` | The grammar and the reader reject types 0x02, 0x06, 0x08 and 0x09 in every state. | proved |

Assumption: the QPACK field-section decoder is a parameter `qd`.

### HTTP/3 control stream and unidirectional streams

Files: `H3/Control.lean`, `H3/ControlStart.lean`.

**Model.**
- `applySettings` mirrors `_apply_peer_settings` (`http3/server.mojo`), which rejects the HTTP/2-reserved identifiers 0x02..0x05 (H3-04).
- `dispatchControl` mirrors `_dispatch_control_frame`, which rejects the frame types forbidden on the control stream (H3-03). `goaway` is its GOAWAY branch, which requires the payload to be exactly one varint (H3-06).
- `feedControlLoop` mirrors the frame loop of `_feed_peer_control_stream`, including the 16384-byte carry cap.
- `classify` mirrors `_classify_uni_kind`, which rejects a client push stream and a second control, QPACK encoder or QPACK decoder stream (H3-05), and `route` / `feedUni` mirror `feed_uni_stream_chunk`.

| Lean name | Statement | Status |
|---|---|---|
| `Control.applySettingsFixed_eq_spec` | SETTINGS application equals RFC 9114 §7.2.4.1. | proved |
| `Control.dispatchControlFixed_eq_spec` | Control-frame dispatch equals RFC 9114 §6.2.1, §7.2.1-7.2.8 and §5.2. | proved |
| `Control.goawayFixed_eq_spec` | The GOAWAY branch equals RFC 9114 §7.2.6 and §7.1: the payload is exactly one varint, and the id does not increase (§5.2). | proved |
| `Control.feedControlLoop_suffix`, `Control.feedControl_le` | The carry left after a control-stream feed is a suffix of the input. | proved |
| `Control.classifyFixed_eq_spec` | Uni-stream classification equals RFC 9114 §6.2 and RFC 9204 §4.2. | proved |
| `Control.runClassifyFixed_unique` | At most one control, encoder and decoder stream is accepted, and no push stream. | proved |

The rules above cover what the server accepts from the client. In the other direction, `H3/ControlStart.lean` models the server's own control stream (H3-07):
- `Config` holds the `Http3Config` fields that `emit_initial_settings` reads, and `Config.Valid` says each fits in a varint. `settingsList` and `emitInitialSettings` mirror `Http3Connection.emit_initial_settings`.
- `implOut` is the server's outbound stream set after the handshake and the first requests, as `(stream id, bytes from offset 0)` pairs: stream 3 carrying the bytes of `take_control_stream_start()`, which `QuicListener._drain_1rtt_coalesced` sends with the first 1-RTT flight, then one response stream per request.
- `ClientBidi` says the request streams are client-initiated bidirectional. `ControlStart` says a byte string opens with stream type 0x00 and a SETTINGS frame whose payload decodes. `Spec` is RFC 9114 §6.2.1 on the outbound set: some server-initiated unidirectional stream opens that way, and only one does.

| Lean name | Statement | Status |
|---|---|---|
| `ControlStart.emit_control_start` | The control stream opens with type 0x00 and a SETTINGS frame that decodes back to exactly the configured settings, for any correct varint encoder and any `Config.Valid` configuration. | proved |
| `ControlStart.implOut_spec` | For every `ClientBidi` set of request streams, the outbound set satisfies `Spec`. | proved |
| `ControlStart.control_stream_sendable` | Stream 3 is a server-initiated unidirectional stream with a send part and no receive part at the server. | proved |
| `ControlStart.control_classified` | The receiver's uni-stream classifier (`Control.classify`) takes type 0x00 on stream 3 as the control stream. | proved |

### QUIC transport parameters and peer-parameter checks

Files: `Quic/TransportParams.lean`, `Quic/PeerParams.lean`.

**Model.**
- `decode` / `decodeLoop` mirror `decode_transport_parameters` (`quic/transport_params.mojo`): the `varint(id) varint(len) value` loop, its truncation checks, the duplicate list and the per-id branches, including the initial_max_streams_* ≤ 2^60 bound (QUIC-10) and the preferred_address layout check `paValid` (QUIC-13). `readVar` mirrors `_read_param_varint`.
- The spec `specDecode` is RFC 9000 §7.4 and §18: a TLV sequence with pairwise distinct ids, each value valid by §18.2, folded into the record. `specFrom` is the same spec processed one parameter at a time.
- `clientCheck` mirrors `check_server_transport_params` (QUIC-12): presence scans of 0x00, 0x0f, 0x10 and 0x0d on the raw blob, next to the comparisons on the decoded record. `serverCheck` mirrors `transport_parameter_present` and `check_client_transport_params`, which the server runs on the client's blob once the 1-RTT keys are installed (`QuicListener._dispatch_crypto_frames`, `_client_params_ok`; QUIC-11). `clientSpec` and `serverSpec` are RFC 9000 §7.3 and §18.2, stated over the raw TLV list (`present`) so that an absent parameter differs from a zero-length one.
- `encode`, `params` and `wire` mirror `encode_transport_parameters` and its three emitters `_emit_varint_param`, `_emit_bytes_param` and `_emit_flag_param`, for any varint encoder `enc` with `VarintCodec enc` (the same hypothesis as the H3 frame round trips; L1 discharges it for flare's `encode_varint`).

| Lean name | Statement | Status |
|---|---|---|
| `TransportParams.decodeFixed_eq_spec` | The decoder succeeds exactly when the spec does, with the same record, on every input. So flare's duplicate, truncation, trailing-byte and value checks are right. | proved |
| `TransportParams.specFrom_eq` | The one-parameter-at-a-time spec accepts exactly the lists whose ids are fresh and pairwise distinct and whose values are all valid, and returns their fold. | proved |
| `TransportParams.tlvs_wire` | The wire form of any parameter list (ids and lengths below 2^62) parses back into that list. | proved |
| `TransportParams.encode_roundtrip` | For every `Sendable` parameter set the encoder does not raise, and `specDecode` (hence the decoder) accepts the blob and returns the same parameters. | proved |
| `PeerParams.clientCheckFixed_spec` | The client's check is exactly the client-side spec on every input. | proved |
| `PeerParams.serverCheck_spec` | The server's check is exactly the server-side spec on every input. | proved |
| `PeerParams.serverCheck_sound` | Any blob the server's check accepts decodes, has no server-only parameter, and has the client's Source CID as initial_source_connection_id. | proved |

## Findings

There are 33 repros. The first 25 were re-run from the repository root at the end of the second follow-up pass, with no flare file of mine modified; each printed the `BUG REPRODUCED:` line quoted below and exited 1. The six added in that pass (QUIC-14..19) and H3-07, added in the third pass, were each also run three times when written, with the same line each time. The seven added in the final pass (QUIC-20..24, QPACK-05, QPACK-06) were each run three times; every run printed the quoted line and exited 1.

The flip checks for QUIC-01..24, QPACK-05, QPACK-06 and H3-01..07 were run (QUIC-10..13 and H3-06 in the first follow-up pass, QUIC-14..19 in the second, H3-07 in the third, QUIC-20..24, QPACK-05 and QPACK-06 in the final pass). Each applied the stated minimal fix to the single flare/ file and re-ran the repro, which printed `OK:` and exited 0; the file was then restored with `git checkout --` and showed a clean `git status`. The QPACK-01..04 flips were run by the QPACK agent and were not repeated here.

### QUIC-01: an unknown frame's body is parsed as further frames

Status: resolved. Fixed: `parse_frame_into` raises `FRAME_ENCODING_ERROR` for a frame type outside the v1 table instead of calling `on_unknown` (the `FrameHandler.on_unknown` callback is removed). Tests: `tests/quic/test_state.mojo::test_unknown_frame_body_is_not_reparsed`, `tests/quic/test_frame.mojo::test_unknown_frame_type_rejected_for_every_codepoint`. Lean: `Frame.parseFrame_not_unknown`, `Frame.parsePayload_not_unknown`.

- **Severity:** Medium. A peer can make flare act on frames hidden inside a frame type it does not know. The peer could also send those frames directly, so no extra authority is gained. The problem is that frame boundaries are lost: any extension frame flare does not implement is executed as a sequence of unrelated frames.
- **RFC:** RFC 9000 §12.4: "An endpoint MUST treat the receipt of a frame of unknown type as a connection error of type FRAME_ENCODING_ERROR."
- **What goes wrong:**
  - For an unknown type, `parse_frame_into` (`quic/frame.mojo:957-958`) calls `on_unknown` and returns the length of the type varint only.
  - The connection handler ignores the frame (`state.mojo:756-760`).
  - `dispatch_frames` resumes parsing right after the type byte.
- **Counterexample:** `Flare.Bugs.QUIC_01.smuggled_close` (at tag `formal-audit-0.12`): the payload `21 1c 00 00 00` parses as `[unknown 0x21, CONNECTION_CLOSE(0,0,"")]`. `violates_spec` shows this breaks `PayloadOk`.
- **Fix:** raise `FRAME_ENCODING_ERROR` instead of calling `on_unknown`. `Frame.parsePayloadFixed_ok` shows every frame of a payload the shipped parser accepts meets `RfcFrameOk`, so no unknown frame's body is run as frames.
- **Repro:** `formal/repro/QUIC-01_unknown_frame_body_reparsed.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: unknown frame type 0x21 accepted; its body ran as CONNECTION_CLOSE (connection_closed = True , draining = True )`
- **Flip:** `OK: unknown frame type rejected`, exit 0.

### QUIC-02: MAX_STREAMS and STREAMS_BLOCKED above 2^60 are accepted

Status: resolved. MAX_STREAMS / STREAMS_BLOCKED values above 2^60 are now a FRAME_ENCODING_ERROR (frame.mojo).

- **Severity:** Low. The value reaches the stream-limit bookkeeping unchecked; no memory-safety effect was found.
- **RFC:** RFC 9000 §4.6 and §19.11 (MAX_STREAMS) and §19.14 (STREAMS_BLOCKED): a value greater than 2^60 MUST cause a FRAME_ENCODING_ERROR.
- **What goes wrong:** `frame.mojo:853-861` and `873-884` pass the decoded varint to the handler without a bound check.
- **Counterexample:** `Flare.Bugs.QUIC_02.max_streams_accepted` and `streams_blocked_accepted` (at tag `formal-audit-0.12`): `12 d0 00 00 00 00 00 00 01` and the same wire with type `16` parse with value 2^60 + 1. `violates_spec` shows the result breaks `RfcFrameOk`.
- **Fix:** raise when `v > 1 << 60` in both branches. `Frame.parseFrameFixed_ok` shows this suffices.
- **Repro:** `formal/repro/QUIC-02_max_streams_over_2p60_accepted.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: frame types 0x12 0x16 with value 2^60+1 accepted (FRAME_ENCODING_ERROR expected)`
- **Flip:** `OK: MAX_STREAMS / STREAMS_BLOCKED above 2^60 rejected`, exit 0.

### QUIC-03: an ACK reaching below packet number 0 is clamped, not rejected

Status: resolved. An ACK whose first or later range computes a negative packet number is now a FRAME_ENCODING_ERROR (frame.mojo).

- **Severity:** Low. `AckExpand.expand_sound` shows the clamped expansion only retires packets the ACK claims, so flare never retires a packet the peer did not claim. The defect is a missing connection error.
- **RFC:** RFC 9000 §19.3.1: "If any computed packet number is negative, an endpoint MUST generate a connection error of type FRAME_ENCODING_ERROR."
- **What goes wrong:** `frame.mojo:765-792` builds the AckFrame without checking the ranges. `expand_ack_ranges` (`state.mojo:400-427`) then clamps the lowest packet number to 0, and stops early when a gap would go negative.
- **Counterexample:** `Flare.Bugs.QUIC_03.accepted` (at tag `formal-audit-0.12`): `02 00 00 00 05` (largest 0, first range 5) parses. `violates_spec` shows it breaks `RfcFrameOk`.
- **Fix:** in the parser, raise if `first > largest`, and for each range raise if `gap + 2 > smallest` or `length > next_largest`. In Lean this is `ackOk` in `ackFinish`. `Frame.parseFrameFixed_ok` shows it suffices.
- **Repro:** `formal/repro/QUIC-03_ack_negative_range_clamped.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: ACK with largest=0, first_ack_range=5 accepted (packets reported acked: 1 )`
- **Flip:** `OK: ACK with a negative computed packet number rejected`, exit 0.

### QUIC-04: HANDSHAKE_DONE moves a closing or draining connection back to ESTABLISHED

Status: resolved. Fixed: `apply_handshake_done` (`flare/quic/state.mojo`) acts only in HANDSHAKE, as `mark_handshake_complete` does. Test: `tests/quic/test_state.mojo::test_handshake_done_does_not_reopen_closed_connection`. Lean: `Conn.implStep_client_eq_spec`, `Conn.implStep_absorbing`.

- **Severity:** Medium. After CONNECTION_CLOSE, a peer can put the connection back in ESTABLISHED. The `connection_closed` event has already fired at that point, so the application and the transport disagree about whether the connection is alive.
- **RFC:** RFC 9000 §10.2: the closing and draining states lead only to closed. An endpoint in the draining state MUST NOT send packets.
- **What goes wrong:** `apply_handshake_done` (`state.mojo:489-494`) sets ESTABLISHED without checking the current state, and `handle_frame_buf` (782) drops frames only in CLOSED.
- **Counterexample:** `Flare.Bugs.QUIC_04.reopens`, `reopens_closing` and `trace` (at tag `formal-audit-0.12`): `1c 00 00 00 1e` takes HANDSHAKE → DRAINING → ESTABLISHED. `violates_spec` contrasts this with the spec trace.
- **Fix:** apply HANDSHAKE_DONE only when the state is HANDSHAKE. `Conn.implStep_absorbing` and `Conn.run_eq_spec` show it suffices.
- **Repro:** `formal/repro/QUIC-04_handshake_done_reopens_closed_connection.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: CONNECTION_CLOSE then HANDSHAKE_DONE leaves the connection ESTABLISHED (connection_closed event = True )`
- **Flip:** `OK: connection stays draining, state = 3`, exit 0.

### QUIC-09: the server accepts HANDSHAKE_DONE from the client

Status: resolved. A server now closes with PROTOCOL_VIOLATION on a received HANDSHAKE_DONE (state.mojo: Connection.is_server).

- **Severity:** Low on its own. Combined with QUIC-04, a client can use it to reopen a closing or draining server connection.
- **RFC:** RFC 9000 §19.20: "A server MUST treat receipt of a HANDSHAKE_DONE frame as a connection error of type PROTOCOL_VIOLATION."
- **What goes wrong:**
  - `on_handshake_done` (`state.mojo:744-746`) has no role check, and the sans-I/O `Connection` has no role.
  - `QuicConnection.dispatch_plaintext` (`_server_types.mojo:559-578`) runs 1-RTT payloads with `before_1rtt = False`, so the frame is applied.
- **Counterexample:** `Flare.Bugs.QUIC_09.server_accepts`, with `spec_rejects` and `violates_spec` (at tag `formal-audit-0.12`).
- **Fix:** give `Connection` an `is_server` flag and raise PROTOCOL_VIOLATION in `on_handshake_done` when it is set. `Conn.implStep_eq_spec` (the shipped step equals the spec, for the server role too) shows it suffices.
- **Repro:** `formal/repro/QUIC-09_server_accepts_handshake_done.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: server accepted HANDSHAKE_DONE from the client (handshake_done event = True , conn.state = 1 )`
- **Flip:** `OK: server rejected HANDSHAKE_DONE with PROTOCOL_VIOLATION`, exit 0.

### QUIC-10: initial_max_streams_* above 2^60 accepted in transport parameters

Status: resolved. decode_transport_parameters now rejects initial_max_streams_bidi / _uni above 2^60 (transport_params.mojo).

- **Severity:** Low. Same bound as QUIC-02, on the transport-parameter path; the value reaches the stream-limit bookkeeping unchecked.
- **RFC:** RFC 9000 §18.2 (initial_max_streams_bidi / _uni): a value greater than 2^60 MUST be treated as TRANSPORT_PARAMETER_ERROR.
- **What goes wrong:** the 0x08 and 0x09 branches (`transport_params.mojo:482-489`) store the varint with no bound.
- **Counterexample:** `Flare.Bugs.QUIC_10.impl_accepts` (at tag `formal-audit-0.12`): `08 08 d0 00 00 00 00 00 00 01` decodes to initial_max_streams_bidi = 2^60 + 1, and `specDecode` rejects it.
- **Fix:** raise when the value exceeds `1 << 60` in both branches. `TransportParams.decodeFixed_eq_spec` shows the shipped decoder (with the QUIC-13 check too) equals the spec.
- **Repro:** `formal/repro/QUIC-10_tp_max_streams_over_2p60_accepted.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: transport parameter max_streams > 2^60 accepted: 0x8=1152921504606846977 0x9=1152921504606846977`
- **Flip:** `OK: max_streams > 2^60 rejected`, exit 0.

### QUIC-11: the server never validates the client's transport parameters

Status: resolved. Fixed: once the 1-RTT keys are installed the server decodes the client parameters and closes with TRANSPORT_PARAMETER_ERROR (0x08) for a blob that does not decode, a server-only parameter (0x00, 0x02, 0x0d, 0x10), or an absent or wrong `initial_source_connection_id` (`check_client_transport_params` in `quic/transport_params.mojo`, called from `QuicListener._client_params_ok`). Tests: `tests/quic/test_quic_server_peer_params.mojo` (unit and loopback). Lean: `PeerParams.serverCheck_spec`, `PeerParams.serverCheck_sound`.

- **Severity:** Medium. A client can send server-only parameters, duplicates, invalid values, or no or a wrong initial_source_connection_id, and the server keeps the connection. The ISCID check is the one RFC 9000 relies on to detect a middlebox that rewrote the client's Source CID.
- **RFC:** RFC 9000 §18.2 (a server MUST treat receipt of original_destination_connection_id, stateless_reset_token, preferred_address or retry_source_connection_id as TRANSPORT_PARAMETER_ERROR); §7.3 (an absent or mismatched initial_source_connection_id is a connection error); §7.4 and §18 (duplicates and invalid values).
- **What goes wrong:** `_dispatch_crypto_frames` (`quic/server.mojo:1199-1368`) drives the handshake to 1-RTT keys and the connection becomes usable. No server path reads the client's `quic_transport_parameters`; `_do_peer_transport_params` is not imported by the server.
- **Counterexample:** `Flare.Bugs.QUIC_11.impl_accepts` (at tag `formal-audit-0.12`): an empty blob (no ISCID) and a blob carrying original_destination_connection_id are accepted, and `serverSpec` rejects both.
- **Fix:** once the 1-RTT keys are installed, read and decode the client's blob, reject server-only ids, and require the ISCID to be present and equal to the client's Initial Source CID; close with TRANSPORT_PARAMETER_ERROR otherwise. `serverCheck_spec` shows this equals the spec.
- **Repro:** `formal/repro/QUIC-11_server_ignores_client_transport_params.mojo` (at tag `formal-audit-0.12`; in-memory rustls handshake over loopback UDP; a seventh, valid blob is the control).
- **Observed:** `BUG REPRODUCED: server completed the handshake and kept the connection for 6 of 6 invalid client transport-parameter blobs`
- **Flip** (the fix above in the 1-RTT install branch of `_dispatch_crypto_frames`): all six blobs rejected, the control still established, `OK: every invalid client transport-parameter blob rejected`, exit 0.

### QUIC-12: the client's CID authentication confuses absent with empty

Status: resolved. The client now checks the presence of initial_source_connection_id, retry_source_connection_id and preferred_address on the raw blob (check_server_transport_params).

- **Severity:** Low. The checks that remain catch a rewritten non-empty CID; what is missed is the zero-length cases and a Retry CID sent without a Retry.
- **RFC:** RFC 9000 §7.3 (absence of initial_source_connection_id, and presence of retry_source_connection_id without a Retry, are connection errors); §18.2 (a server with a zero-length CID MUST NOT send preferred_address, and a client MUST treat a violation as TRANSPORT_PARAMETER_ERROR).
- **What goes wrong:** `_check_peer_cids` (`quic/client.mojo:641-669`) compares the CIDs of the decoded record, where an absent parameter and a zero-length one are both the empty list. The ISCID comparison is skipped while the server's CID is empty, and the decoder skips 0x0d.
- **Counterexample:** `Flare.Bugs.QUIC_12.impl_accepts_absent_iscid` (zero-length server CID, no ISCID), `impl_accepts_empty_rscid` (no Retry, zero-length retry_source_connection_id), `impl_accepts_pa_with_empty_cid` (zero-length server CID with a preferred_address), all at tag `formal-audit-0.12`. `control_ok` shows a correct blob passes both.
- **Fix:** scan the raw blob for 0x0f, 0x10 and 0x0d next to the existing comparisons (`check_server_transport_params`). `PeerParams.clientCheckFixed_spec` shows this equals the spec.
- **Repro:** `formal/repro/QUIC-12_client_cid_auth_absent_vs_empty.mojo` (at tag `formal-audit-0.12`; in-memory rustls handshake with a crafted server blob).
- **Observed:** `BUG REPRODUCED: _check_peer_cids accepted 3 of 3 server parameter blobs RFC 9000 §7.3/§18.2 require it to reject`
- **Flip:** `OK: absent / zero-length CID parameters handled per RFC 9000 §7.3`, exit 0, with both controls unchanged.

### QUIC-13: preferred_address is not validated

Status: resolved. decode_transport_parameters now validates the preferred_address layout (transport_params.mojo, 0x0d branch).

- **Severity:** Low. flare does not use preferred_address, so a malformed one has no effect beyond the missing connection error.
- **RFC:** RFC 9000 §18.2 gives preferred_address a fixed layout with a 1..20-byte CID; §7.4 makes an invalid value a TRANSPORT_PARAMETER_ERROR.
- **What goes wrong:** `decode_transport_parameters` has no 0x0d branch. The module docstring (`transport_params.mojo:42-45`) documents this: "not currently handled and is skipped on decode like any other unknown id".
- **Counterexample:** `Flare.Bugs.QUIC_13.impl_accepts` (at tag `formal-audit-0.12`): a zero-length preferred_address and a 41-byte one with CID length 0 both decode; the spec rejects both.
- **Fix:** a 0x0d branch requiring at least 25 bytes, a CID length in 1..20 and a total of 41 + CID length (the value is checked, not stored). In Lean this is `paValid`, and `TransportParams.decodeFixed_eq_spec` shows the shipped decoder equals the spec.
- **Repro:** `formal/repro/QUIC-13_preferred_address_not_validated.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: invalid preferred_address accepted in 3 of 3 cases`
- **Flip:** `OK: invalid preferred_address rejected`, exit 0.

### QUIC-14: ACK ranges forget dropped packets, which are then processed again

Status: resolved. Fixed: `_ack_record` keeps a floor (one above the highest range dropped at the 32-range cap) in an odd trailing slot of the flat list and `_ack_contains` treats every number below it as seen (`quic/_server_support.mojo`: `_ack_floor`, `_ack_record`, `_ack_contains`). Tests: `tests/quic/test_quic_post_initial_decrypt.mojo` (`test_dropped_ack_ranges_are_not_forgotten`, `test_ack_floor_only_moves_up`). Lean: `AckGen.contains` / `recordSt` mirror the shipped code; `AckGen.never_reaccepts`.

- **Severity:** Medium. A packet processed once (a request, a CONNECTION_CLOSE) can be processed a second time. An on-path attacker can replay a captured 1-RTT packet (it still decrypts, since the packet number is unchanged) once the receiver has had more than 32 gaps and a later packet has merged two ranges.
- **RFC:** RFC 9000 §13.2.3: "A receiver MUST retain an ACK Range unless it can ensure that it will not subsequently accept packets with numbers in that range"; §12.3: packet numbers are not reused, so a duplicate must not be processed again.
- **What goes wrong:** `_ack_record` (`quic/_server_support.mojo:76-124`) keeps the 32 highest ranges and drops the rest. `_ack_contains` (60-73) counts a number below every stored range as seen only while the list is full (`len(flat) >= 64`). When a later packet fills a gap and two ranges merge, 31 remain, the guard turns off, and a number from a dropped range reads as unseen; `server.mojo:844` then dispatches it.
- **Counterexample:** `Flare.Bugs.QUIC_14.impl_reaccepts` (at tag `formal-audit-0.12`): receive 0, 2, 4, ..., 64 (33 ranges, so [0,0] is dropped), then 3, which merges [2,2], [3,3] and [4,4]; `contains 0 = false`.
- **Fix:** keep a floor, one above the highest number ever dropped, and count anything below it as seen. `AckGen.never_reaccepts` shows that for every packet trace every received number reads as seen; `recordSt_flat` shows the stored ranges, and so the ACKs sent, are unchanged.
- **Repro:** `formal/repro/QUIC-14_ack_ranges_forget_dropped_packets.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: packet 0 was received, its range was dropped at the 32-range cap, and after packet 3 merged two ranges ( 31 ranges left) _ack_contains(0) = False, so it would be dispatched again`
- **Flip** (`quic/_server_support.mojo`: the floor stored in an odd trailing slot, set from the highest dropped range in `_ack_record` and read in `_ack_contains`): `OK: packet 0 still reads as received after the merge ( 31 ranges )`, exit 0.

### QUIC-15: the server accepts stream frames that name the wrong direction

Status: resolved. The server checks the stream id of RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA and STREAM_DATA_BLOCKED (state.mojo: check_stream_frame_id).

- **Severity:** Low. The frames are applied to a stream the server does not have, or ignored; the missing connection error is the defect.
- **RFC:** RFC 9000 §19.4 (RESET_STREAM on a send-only stream), §19.5 (STOP_SENDING on a receive-only stream or a locally initiated stream not yet created), §19.10 (MAX_STREAM_DATA, the same two cases) and §19.13 (STREAM_DATA_BLOCKED on a send-only stream) each require STREAM_STATE_ERROR; §4.6 requires STREAM_LIMIT_ERROR above the advertised stream count.
- **What goes wrong:** only STREAM is checked, in `_route_http3_stream_chunks` (`quic/server.mojo:1407-1430`). RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA and STREAM_DATA_BLOCKED reach `state.mojo:454-486, 712-722` from `QuicConnection.dispatch_plaintext` (`_server_types.mojo:559-579`) and nothing checks their stream id.
- **Counterexample:** `Flare.Bugs.QUIC_15.impl_accepts` (at tag `formal-audit-0.12`): RESET_STREAM and STREAM_DATA_BLOCKED on stream 3, STOP_SENDING and MAX_STREAM_DATA on stream 2, STOP_SENDING on stream 1 and on client stream 400 (100 allowed); the spec rejects each.
- **Fix:** check those four frames' stream ids by direction, the server's set of opened streams and the advertised limit (`check_stream_frame_id`, called from the four handlers when `Connection.is_server`; the server also turns a state-machine error into a CONNECTION_CLOSE). `Streams.serverFixed_eq_spec` shows the shipped verdict is the spec's for every frame and id.
- **Repro:** `formal/repro/QUIC-15_server_stream_frames_wrong_direction.mojo` (at tag `formal-audit-0.12`; controls: STOP_SENDING and MAX_STREAM_DATA on client stream 0 are accepted).
- **Observed:** `BUG REPRODUCED: server accepted stream frames RFC 9000 requires it to reject: [RESET_STREAM sid 3] [STREAM_DATA_BLOCKED sid 3] [STOP_SENDING sid 2] [MAX_STREAM_DATA sid 2] [STOP_SENDING sid 1] [STOP_SENDING sid 400]`
- **Flip** (`quic/_server_types.mojo`: `dispatch_plaintext` walks the 1-RTT frames itself and checks the four frame types before `handle_frame_buf`): `OK: all six wrong-direction / unopened / over-limit stream frames rejected`, exit 0.

### QUIC-16: the server does not enforce its unidirectional stream limit

Status: resolved. The server closes with STREAM_LIMIT_ERROR for a client unidirectional stream above the advertised limit (server.mojo).

- **Severity:** Low to Medium. A client can open any number of unidirectional streams; each gets an `fc_stream_end` entry and H3 per-stream state, bounded only by connection-level flow control.
- **RFC:** RFC 9000 §4.6: "An endpoint that receives a frame with a stream ID exceeding the limit it has sent MUST treat this as a connection error of type STREAM_LIMIT_ERROR."
- **What goes wrong:** `_route_http3_stream_chunks` (`quic/server.mojo:1419-1430`) compares the stream count with `fc_adv_max_bidi` for bidirectional streams only. The server advertises `initial_max_streams_uni` (3 by default, `_server_types.mojo:162`, sent at 701) and never raises it.
- **Counterexample:** `Flare.Bugs.QUIC_16.impl_accepts` (at tag `formal-audit-0.12`): STREAM on stream 14, the fourth client unidirectional stream, with a limit of 3.
- **Fix:** close with STREAM_LIMIT_ERROR when `(sid >> 2) + 1 > config.initial_max_streams_uni` for a unidirectional stream. `Streams.serverFixed_eq_spec` shows the shipped STREAM check equals the spec for every stream id.
- **Repro:** `formal/repro/QUIC-16_server_uni_stream_limit_not_enforced.mojo` (at tag `formal-audit-0.12`; controls: stream 10 accepted, bidirectional stream 400 rejected).
- **Observed:** `BUG REPRODUCED: STREAM on client uni stream 14 (4th, limit 3) accepted; connection still alive`
- **Flip** (`quic/server.mojo`, the fix above): `OK: client uni stream 14 (4th, limit 3) closed the connection`, exit 0.

### QUIC-17: the client checks no stream id on any stream frame

Status: resolved. The client checks the stream id of every stream frame (state.mojo: check_stream_frame_id, enabled by Connection.check_stream_ids) and closes on a violation.

- **Severity:** Low. A server can write into the client's own control stream's receive state, pre-load data on a request stream the client has not opened yet (it is delivered as `stream_chunks` and the stream is created), and open server streams above the client's advertised 16.
- **RFC:** RFC 9000 §19.8, §19.4, §19.5, §19.10, §19.13 (STREAM_STATE_ERROR) and §4.6 (STREAM_LIMIT_ERROR), as for QUIC-15 with the roles swapped.
- **What goes wrong:** `_dispatch_frames` (`quic/client.mojo:902-912`) hands every frame to the shared state machine; `apply_stream` (`state.mojo:325-365`) creates a stream for any id.
- **Counterexample:** `Flare.Bugs.QUIC_17.impl_accepts` (at tag `formal-audit-0.12`): STREAM on stream 2 (the client's own control stream) and on stream 4 (not opened), RESET_STREAM on stream 2, STOP_SENDING on stream 3, STREAM on server stream 65 (the seventeenth). `spec_accepts` checks the legitimate cases stay accepted.
- **Fix:** check each stream frame's id by direction, `next_bidi_stream` / `next_uni_stream` (mirrored in `Connection.next_local_*`) and the advertised limits (`check_stream_frame_id`, run for STREAM and the four other frames; the client ends the connection with a CONNECTION_CLOSE on a rejected frame). `Streams.clientFixed_eq_spec` shows it equals the spec.
- **Repro:** `formal/repro/QUIC-17_client_stream_frames_wrong_direction.mojo` (at tag `formal-audit-0.12`; NULL rustls session; controls: STREAM on 0 and on 3 accepted).
- **Observed:** `BUG REPRODUCED: client accepted stream frames RFC 9000 requires it to reject: [STREAM 2] [STREAM 4] [RESET_STREAM 2] [STOP_SENDING 3] [STREAM 65]`
- **Flip** (`quic/client.mojo`, the fix above): `OK: all five wrong-direction / unopened / over-limit stream frames rejected`, exit 0.

### QUIC-18: one state for both stream halves loses a reset

Status: resolved. Fixed: `Stream` records `peer_reset` (RESET_STREAM received) and `send_reset` (STOP_SENDING received or `cancel_stream`) separately; `stream_reset` and `send_stream` read those (`quic/state.mojo`, `quic/client.mojo`). Tests: `tests/quic/test_state.mojo` (`test_reset_and_stop_sending_are_recorded_independently`), `tests/quic/test_quic_client.mojo` (`test_stream_reset_survives_a_following_stop_sending`, `test_send_stays_refused_after_cancel_then_peer_reset`). Lean: `Streams.halves_reset_iff`, `Streams.halves_stop_iff`.

- **Severity:** Medium. In case A an HTTP/3 request whose stream the server reset is never failed; the client waits for a response that will not come. In case B the client sends data on a stream it already reset, the situation the comment in `cancel_stream` says was fixed.
- **RFC:** RFC 9000 §3: a bidirectional stream has a sending part (§3.1) and a receiving part (§3.2) with independent states. RESET_STREAM moves the receiving part to Reset Recvd; STOP_SENDING, or our own RESET_STREAM, moves the sending part to Reset Sent. §3.1: no STREAM frames once in Reset Sent.
- **What goes wrong:** `apply_reset_stream` and `apply_stop_sending` (`state.mojo:467-486`) both overwrite the stream's single `state`, as does `cancel_stream` (`client.mojo:1406-1428`). `stream_reset` (1455-1460) reads RESET_RECVD and `send_stream` (1357-1362) refuses only in RESET_SENT, so the later event hides the earlier one.
  - A: RESET_STREAM then STOP_SENDING (how a server abandoning a request typically answers) leaves RESET_SENT, so `stream_reset` is false and `http3/client.mojo:465` does not fail the response.
  - B: `cancel_stream` then the peer's RESET_STREAM leaves RESET_RECVD, so `send_stream` accepts more data.
- **Counterexample:** `Flare.Bugs.QUIC_18.impl_loses` (at tag `formal-audit-0.12`), both orders, against the two-halves model.
- **Fix:** keep the halves apart (a per-stream "peer reset" and "send reset" flag), set them from the frames and from `cancel_stream`, and read them in `stream_reset` and `send_stream`. `Streams.halves_reset_iff` and `halves_stop_iff` show the reset is seen exactly when RESET_STREAM arrived, and the send half refuses exactly when STOP_SENDING arrived or we reset it, for every event sequence.
- **Repro:** `formal/repro/QUIC-18_stream_reset_state_overwritten.mojo` (at tag `formal-audit-0.12`; NULL rustls session; controls: a lone RESET_STREAM is seen, a lone `cancel_stream` refuses sends).
- **Observed:** `BUG REPRODUCED: the single stream state lost a reset (A stream_reset = False , B send refused = False )`
- **Flip** (`quic/client.mojo`, the fix above): `OK: both halves' resets survive the other half's event`, exit 0.

### QUIC-19: STOP_SENDING is never answered with RESET_STREAM

Status: resolved. The client answers STOP_SENDING with RESET_STREAM (state.mojo: on_stop_sending -> ConnectionEvents.stop_sending_resets; client.mojo: _answer_stop_sending).

- **Severity:** Low to Medium. A client mid-upload that receives STOP_SENDING stops sending but never tells the peer the final size, so the peer's receiving part never reaches a terminal state and its connection-level accounting for the stream is never settled (§4.5).
- **RFC:** RFC 9000 §3.5: "An endpoint that receives a STOP_SENDING frame MUST send a RESET_STREAM frame if the stream is in the "Ready" or "Send" state."
- **What goes wrong:** `apply_stop_sending` (`state.mojo:478-486`) only set RESET_SENT, and `_dispatch_frames` (`client.mojo:902-912`) sent nothing. The only RESET_STREAM flare encodes is in `cancel_stream`. The server has no RESET_STREAM path either; the repro and flip cover the client.
- **Counterexample:** `Flare.Bugs.QUIC_19.impl_silent` (at tag `formal-audit-0.12`): in the Send state the reply is empty; the spec requires RESET_STREAM.
- **Fix:** `on_stop_sending` records each STOP_SENDING on a stream not already reset in `ConnectionEvents.stop_sending_resets`; `_dispatch_frames` then calls `_answer_stop_sending`, which sends one RESET_STREAM per entry with the frame's error code and the final size `send_offsets[stream]` (a stream not yet seen counts as Ready). `Flare.Bugs.QUIC_19.shipped_replies` and `fixed_spec` (at tag `formal-audit-0.12`) show the reply then matches the spec for every event history, given the QUIC-18 split; no current model covers the reply.
- **Repro:** `formal/repro/QUIC-19_stop_sending_not_answered.mojo` (at tag `formal-audit-0.12`; in-memory rustls handshake for real 1-RTT keys; the client's peer is a UDP socket the repro owns; control: the 100-byte body chunk sent before STOP_SENDING arrives).
- **Observed:** `BUG REPRODUCED: STOP_SENDING on stream 0 (in Send state, 100 bytes sent) was not answered: no datagram within 500 ms`
- **Flip** (`quic/client.mojo`, the fix above): `OK: the client answered STOP_SENDING with a packet (RESET_STREAM)`, exit 0.

### QUIC-20: the server's idle timer does not follow RFC 9000 §10.1

Status: resolved. Fixed: the server restarts the idle timer only for packets that were processed successfully and for the first ack-eliciting packet sent after one; `schedule_idle_timeout` arms `_effective_idle_ms` (minimum of the two non-zero values, at least 3×PTO, nothing when both are 0), with the client value read in `_client_params_ok` (`quic/server.mojo`, `quic/_server_support.mojo`, `LossRecovery.pto_interval_ms`). Tests: `tests/quic/test_quic_idle_timeout.mojo`. Lean: `Timers.fixedStep` / `effectiveMs` mirror the shipped timer; `Timers.fixed_closed_eq_spec`, `Timers.effectiveMs_spec`.

- **Severity:** Medium. An off-path attacker who knows a connection ID can keep a dead connection's slot alive indefinitely with garbage datagrams. A client's shorter idle timeout is ignored, so the server holds state up to its own 30 s after the client has discarded the connection. With `max_idle_timeout_ms = 0`, which RFC 9000 defines as "no timeout", every connection dies within a millisecond of silence.
- **RFC:** RFC 9000 §10.1: the effective timeout is "the minimum of the two advertised values (or the sole advertised value, if only one endpoint advertises a non-zero value)"; the timer restarts "when a packet from its peer is received and processed successfully" and on the first ack-eliciting send after that; the timeout is at least three times the current PTO. §18.2: "Idle timeout is disabled when both endpoints omit this transport parameter or specify a value of 0."
- **What goes wrong:**
  - `_handle_inbound` (`quic/server.mojo:724-782`) sets `processed_any = True` for every packet, whether `_process_one_packet` succeeded or not, and then re-arms the timer.
  - `schedule_idle_timeout` (2874-2898) uses `config.max_idle_timeout_ms` only. The client's transport parameters are never read (QUIC-11), and 0 is clamped to 1 ms by the timer wheel (`runtime/timer_wheel.mojo:119-144`).
  - Sends never re-arm the timer, and there is no 3×PTO floor.
- **Counterexample:** `Flare.Bugs.QUIC_20.impl_unauth_restarts` (an undecryptable datagram at 900 ms keeps the slot open at 1500 ms with a 1000 ms timeout), `impl_ignores_peer` (client 1000 ms, server 30000 ms: open at 2000 ms), `impl_zero_closes` (both 0: closed at 1 ms, while `Timers.spec_none_never` shows the spec never closes), `impl_no_send_restart` and `impl_no_pto_floor`, all at tag `formal-audit-0.12`.
- **Fix:** re-arm only when a packet was processed successfully and on the first ack-eliciting send after a receipt; arm at `max(min of the non-zero local and peer values, 3×PTO)`; arm nothing when both are 0. `Timers.fixed_closed_eq_spec` shows the shipped timer closes exactly when the spec does, on every run.
- **Repro:** `formal/repro/QUIC-20_server_idle_timer.mojo` (at tag `formal-audit-0.12`) runs three loopback connections (real `QuicListener` and `QuicClientConnection`), each silent after the handshake while the server runs `tick` and `advance_timers`: A, client 1000 ms and server 30000 ms; B, server 1000 ms while the client socket sends an undecryptable short-header datagram with the server's CID every 300 ms; C, both 0. It is inconclusive if a handshake stalls without the server closing the slot.
- **Observed:** `BUG REPRODUCED: A: peer's 1000 ms ignored, open after 5 s; B: undecryptable packets kept it open past 5 s; C: idle timeout 0 on both sides, server closed the connection anyway` (three runs, same line each time, exit 1). In C the slot dies before the handshake completes.
- **Flip** (`quic/server.mojo`: `if ok:` before `processed_any = True`; in `schedule_idle_timeout`, take the minimum with the client's non-zero `max_idle_timeout` decoded from `_do_peer_transport_params`, and arm nothing when the result is 0): A and B close after about 900 ms, C stays open, `OK: A closed, B closed, C open (RFC 9000 sec 10.1 idle timeout)`, exit 0. The flip does not add the send restart or the PTO floor, which the repro does not exercise.

### QUIC-21: the client never applies an idle timeout

Status: resolved. Fixed: the client runs the same idle timer as the server (QUIC-20): `_dispatch_frames` hands the monotonic clock to the state machine, `_note_ack_eliciting_send` restarts the period on the first ack-eliciting send after a processed packet, `_apply_peer_transport_params` reads the server value, and `poll` calls `_check_idle`, which closes the connection (CLOSED, not established, `connection_closed`) once the effective timeout has elapsed (`quic/client.mojo`). Tests: `tests/quic/test_quic_client.mojo` (`test_client_closes_after_its_idle_timeout`, `test_client_uses_the_servers_shorter_idle_timeout`, `test_client_idle_timer_restarts_on_processed_packets`). Lean: `Timers.fixedStep` mirrors the shipped timer; `Timers.fixed_closed_eq_spec`.

- **Severity:** Medium. A client whose server has gone away (or whose path is dead) keeps the connection, and a pool keeps handing it out. Requests then wait on PTOs instead of failing at the idle deadline.
- **RFC:** RFC 9000 §10.1: "If a max_idle_timeout is specified by either endpoint in its transport parameters (Section 18.2), the connection is silently closed and its state is discarded when it remains idle for longer than the minimum of the max_idle_timeout value advertised by both endpoints."
- **What goes wrong:** `poll` (`quic/client.mojo:557-608`) never checks a timer. `_dispatch_frames` (902-912) passes `now_us = 0` to `handle_frame_buf`, so `last_activity_us` never moves, and `is_idle_timeout_expired` (`state.mojo:876-887`) has no caller anywhere in `flare/`.
- **Counterexample:** `Flare.Bugs.QUIC_21.impl_never_closes` (at tag `formal-audit-0.12`): on every run the client's idle state is unchanged. `impl_counterexample`: with both values 1000 ms, the client is open at 5000 ms and the spec has closed.
- **Fix:** pass the monotonic clock to `handle_frame_buf`, and in `poll` close the connection once the effective timeout has elapsed. `Timers.fixed_closed_eq_spec` is the same refinement theorem as for QUIC-20.
- **Repro:** `formal/repro/QUIC-21_client_has_no_idle_timeout.mojo` (at tag `formal-audit-0.12`): a loopback `QuicListener` (30000 ms) and a client started with `max_idle_timeout_ms = 1000`. After the handshake the server stops running and the client polls for 5 s. Inconclusive if the handshake does not complete.
- **Observed:** `BUG REPRODUCED: client advertised max_idle_timeout 1000 ms, peer silent for 5 s, connection still established (not closed)` (three runs, exit 1).
- **Flip** (`quic/client.mojo`: `_monotonic_ms() * 1000` in `_dispatch_frames`; at the top of `poll`, if `is_idle_timeout_expired`, set CLOSED, `established = False` and `connection_closed`): `OK: client closed the idle connection after 918 ms (max_idle_timeout 1000 ms)`, exit 0.
- **Note:** the client's `conn.state` is never set to ESTABLISHED; it stays HANDSHAKE (0) for the life of the connection. The RFC does not prescribe internal state names, so this is not filed. It matters only to code that reads `conn.state` instead of `is_established()`.

### QUIC-22: the server closes connections without sending CONNECTION_CLOSE

Status: resolved. Fixed: `_close_for` sends a 1-RTT CONNECTION_CLOSE with the error code and enters the closing state for 3×PTO (at most 10 s): incoming packets are answered with CONNECTION_CLOSE (1st, 2nd, 4th, ... packet) and only the closing timer ends the state; the CRYPTO-overflow and ACK-of-an-unsent-packet sites go through it (`quic/server.mojo`: `_close_for`, `_enter_closing`, `_answer_closing`, `advance_timers`). Closes without a frame remain for a slot with no 1-RTT keys and for PTO exhaustion. Tests: `tests/quic/test_quic_server_close.mojo`. Lean: `Timers.srvStepNow`, `Timers.srvFix_refines`.

- **Severity:** Medium. Every connection error the server detects (stream-state, stream-limit and flow-control errors, PTO exhaustion) ends with silence. The client learns of it only through its own idle timeout, which flare's client does not have (QUIC-21), and gets no error code. Packets that arrive after the close are not answered, and the slot is reclaimed at the next timer event rather than after 3×PTO.
- **RFC:** RFC 9000 §10.2: an endpoint enters the closing state "after initiating an immediate close", which "causes the connection to be immediately closed" by sending CONNECTION_CLOSE; §10.2.1: in the closing state an endpoint "sends a packet containing a CONNECTION_CLOSE frame in response to any incoming packet"; §11.1: errors that make the connection unusable are signalled with CONNECTION_CLOSE; §10.2: the states "SHOULD persist for at least three times the current PTO interval", and "Servers that retain an open socket ... SHOULD NOT end the closing or draining states early".
- **What goes wrong:** `_close_for` (`quic/server.mojo:2177-2180`) and the other close sites (1255-1262, 2965-2971, 3006-3012) call `connection_close` (`state.mojo:890-911`, sets CLOSING) and set `alive = False`. `_drain_and_send` returns at once for a non-alive slot (2033-2038). The server never calls `encode_connection_close`. `advance_timers` reclaims the slot when its next timer fires.
- **Counterexample:** `Flare.Bugs.QUIC_22.impl_no_cc` (at tag `formal-audit-0.12`): a local close sends nothing, and a packet received while closing is not answered. `spec_answers`: the spec sends CONNECTION_CLOSE on the close and again for the packet. `impl_short_period`: one tick after the close flare's slot is gone, while the spec is closing until 300 ms (PTO 100).
- **Fix:** on a local close, send a 1-RTT CONNECTION_CLOSE with the error code, keep the slot in the closing state for 3×PTO answering incoming packets with CONNECTION_CLOSE, and then reclaim it. `Timers.spec_cc_on_close` and `spec_closing_only_cc` show that behaviour sends CONNECTION_CLOSE on close and only CONNECTION_CLOSE while closing, and `Timers.srvFix_refines` shows the shipped server follows it.
- **Repro:** `formal/repro/QUIC-22_server_close_never_sends_connection_close.mojo` (at tag `formal-audit-0.12`): after a loopback handshake the client sends STREAM data on stream 1, a server-initiated id the server never opened, and the server closes with STREAM_STATE_ERROR (0x05; the control is `alive` false and `close_error_code` 5). The client polls for 2 s. Inconclusive if the handshake does not complete or the server does not close.
- **Observed:** `BUG REPRODUCED: server closed the connection (error 5 ) but sent no CONNECTION_CLOSE; client still not draining after 2 s` (three runs, exit 1).
- **Flip** (`quic/server.mojo`: `_close_for` encodes `ConnectionCloseFrame(False, code, 0, [])`, pads to 16 bytes, builds it with `_build_1rtt_response` and sends it to `peer_addrs[slot]` before clearing `alive`): `OK: the server's close reached the client as CONNECTION_CLOSE`, exit 0; the client was then DRAINING. The flip covers the missing frame, not the closing-period length.

### QUIC-23: the server keeps sending after the peer's CONNECTION_CLOSE

Status: resolved. A draining server builds no packet (server.mojo: _build_1rtt_response, _drain_and_send).

- **Severity:** Low to Medium. After a client closes, the server goes on acknowledging and answering requests on the closed connection. The client, which has discarded its state, may answer with stateless resets, and the server spends bandwidth until the idle timer fires.
- **RFC:** RFC 9000 §10.2.2: "An endpoint that has received a CONNECTION_CLOSE frame ... An endpoint in the draining state MUST NOT send any packets."
- **What goes wrong:** `apply_connection_close` (`state.mojo:430-445`) sets DRAINING, but `alive` stays true, and no egress path checks the state: `_drain_and_send` (gate at `quic/server.mojo:2033-2038` tests `alive` only), `_drain_1rtt_coalesced` (2210-2433), and the PTO and ACK-delay timer paths (2925-2980) all build packets through `_build_1rtt_response` (2673).
- **Counterexample:** `Flare.Bugs.QUIC_23.impl_sends_draining` (at tag `formal-audit-0.12`): in draining, with something to send, the server sends. `impl_trace`: the peer closes at 0 and the server sends at 1.
- **Fix:** send nothing while DRAINING: `_build_1rtt_response` returns an empty datagram in that state (every 1-RTT egress path goes through it) and `_drain_and_send` returns at once (the Initial and Handshake flights). `Timers.srvNow_draining_silent` proves the shipped server sends nothing in draining on any event; `Timers.spec_draining_silent` does the same for the spec.
- **Repro:** `formal/repro/QUIC-23_server_sends_while_draining.mojo` (at tag `formal-audit-0.12`): after a loopback handshake the client sends a 1-RTT CONNECTION_CLOSE (NO_ERROR). The control is that the server's state is then DRAINING. The client's socket is flushed, a GET arrives on stream 0, and the server runs a handler between ticks for about 2 s while every datagram reaching the client is counted.
- **Observed:** `BUG REPRODUCED: server in DRAINING sent 2 datagram(s) after the peer's CONNECTION_CLOSE` (three runs, exit 1).
- **Flip** (`quic/server.mojo`: `_build_1rtt_response` returns an empty datagram when the slot's state is DRAINING): `OK: no datagram from the server while draining`, exit 0.

### QUIC-24: the client keeps sending after the peer's CONNECTION_CLOSE

Status: resolved. A draining client builds no packet and send_stream raises (client.mojo: _build_1rtt, _build_initial, _build_handshake, _build_0rtt, send_stream).

- **Severity:** Low to Medium. After the server closes, the client goes on retransmitting unacknowledged data on PTO and sends keep-alive PINGs and new stream data on the dead connection.
- **RFC:** RFC 9000 §10.2.2: "An endpoint in the draining state MUST NOT send any packets."
- **What goes wrong:** the peer's CONNECTION_CLOSE sets DRAINING (`state.mojo:430-445`), but `poll`'s `_drain_egress` (`quic/client.mojo:1035-1085`) and `_check_pto` (688-706), `keepalive` (1619-1634) and `send_stream` (1347-1400) never check the state; all of them build packets through `_build_1rtt` (1231). The client's own close (`shutdown`, 1758-1778) is conforming (`Timers.cli_close_ok`).
- **Counterexample:** `Flare.Bugs.QUIC_24.impl_sends_draining` and `impl_trace` (at tag `formal-audit-0.12`): after the peer's close at 0 the client sends at 1 and 2.
- **Fix:** send nothing while DRAINING: `_build_1rtt`, `_build_initial`, `_build_handshake` and `_build_0rtt` return an empty datagram in that state (so `_drain_egress`, `_check_pto`, `keepalive` and `shutdown` send nothing), and `send_stream` raises. `Timers.cliNow_draining_silent` proves it; the spec's counterpart is `Timers.spec_draining_silent`.
- **Repro:** `formal/repro/QUIC-24_client_sends_while_draining.mojo` (at tag `formal-audit-0.12`): an in-memory rustls handshake gives the client real 1-RTT keys, and its peer is a UDP socket the repro owns. The client sends 100 bytes on stream 0, then a CONNECTION_CLOSE is dispatched. The controls are that the body reaches the peer and that the state is then DRAINING. The client is polled for 3 s, and then `keepalive()` is called.
- **Observed:** `BUG REPRODUCED: client in DRAINING sent 4 datagram(s) (poll: 3 , keepalive: 1 )` (three runs, exit 1).
- **Flip** (`quic/client.mojo`: `_build_1rtt` returns an empty datagram when `conn.state` is DRAINING): `OK: no datagram sent while draining`, exit 0.

### QPACK-01: a field section with Required Insert Count 0 can read the dynamic table

- **Severity:** High when `qpack_max_table_capacity > 0`, because a peer reads dynamic-table entries the section did not declare. It cannot be reached with the default capacity of 0.
- **RFC:** RFC 9204 §4.5.1.2 (Sign = 1 with RIC ≤ DeltaBase is invalid) and §4.5.1 (an absolute index ≥ RIC is QPACK_DECOMPRESSION_FAILED).
- **What goes wrong:**
  - `ric - delta - 1` wraps at `dynamic.mojo:493`, and `base + ip` wraps at 544 and 550.
  - There is no `abs < ric` check and no pre-base `ip < base` check.
- **Counterexample:** `Flare.Bugs.QPACK_01.counterexample` and `violates_safety` (at tag `formal-audit-0.12`): RIC = 0, Sign = 1, Delta = 0 and post-base index 1 give Base = 2^64 - 1 and absolute index 0. `counterexample_noWrap` gives a variant without a wrap.
- **Fix:** raise if `sign_set and delta >= ric`, if a pre-base `ip >= base`, or if `abs_idx >= ric`. `FieldSection.implResolve_eq_spec` and `implResolve_safe` show it suffices.
- **Repro:** `formal/repro/QPACK-01_ric_zero_reads_dynamic_table.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: field section with Required Insert Count 0 decoded dynamic entry abs 0 -> x-secret: dynamic-entry-0`
- **Flip (QPACK agent):** `OK`, exit 0.
Status: resolved. `decode_field_section_dynamic` now raises QPACK_DECOMPRESSION_FAILED when Sign is set with Delta Base >= RIC, when a pre-base relative index is >= Base, and when a resolved absolute index is >= RIC (`_pre_base_abs`, `_post_base_abs`). Tests: `tests/qpack/test_qpack_dynamic.mojo::test_ric_zero_section_cannot_read_the_dynamic_table` and three siblings. The repro prints `OK`.

### QPACK-02: reading the Sign byte goes one past the end and aborts the process

- **Severity:** Medium. A peer can crash the process when the table capacity is at least 4096. It cannot be reached with the default capacity.
- **RFC:** RFC 9204 §4.5.1 (the prefix contains both fields, so a truncated prefix is a decompression failure).
- **What goes wrong:** `dynamic.mojo:482-489` checks only `len(buf) >= 2`, then reads `buf[ric_enc.offset]`.
- **Counterexample:** `Flare.Bugs.QPACK_02.counterexample` and `out_of_bounds` (at tag `formal-audit-0.12`): the section `[0xFF, 0x01]` with MaxEntries = 256 reads index 2 = len.
- **Fix:** raise if `ric_enc.offset >= len(buf)`. `FieldSection.implSignReadIndex_inBounds` shows it suffices.
- **Repro:** `formal/repro/QPACK-02_sign_byte_oob_read.mojo` (at tag `formal-audit-0.12`; the decode runs in a forked child).
- **Observed:** `BUG REPRODUCED: decoding the 2-byte field section [0xFF, 0x01] killed the process with signal 6 (out-of-bounds read of buf[2] at dynamic.mojo:489)`
- **Flip (QPACK agent):** `OK`, exit 0.
Status: resolved. `decode_field_section_dynamic` raises QPACK_DECOMPRESSION_FAILED when the Required Insert Count ends the section (`ric_enc.offset >= len(buf)`) before reading the Sign byte. Test: `tests/qpack/test_qpack_dynamic.mojo::test_truncated_prefix_without_sign_byte_is_refused`. The repro prints `OK`.

### QPACK-03: string literals become Strings without UTF-8 validation

- **Severity:** Low. It breaks the `String` invariant that the contents are valid UTF-8.
- **Contract:** `ascii_unchecked_string` (`http/proto/ascii.mojo:63-70`) requires every byte to be below 0x80.
- **What goes wrong:** `qpack/codec.mojo:231` and `233` pass arbitrary peer bytes to that constructor.
- **Counterexample:** `Flare.Bugs.QPACK_03.counterexample` and `not_string_ok` (at tag `formal-audit-0.12`): the literal `[0x01, 0xFF]` is accepted. `huffman_counterexample` shows the Huffman encoding of 0xFF decoding to `[0xFF]`, so the defect covered both branches.
- **Fix:** `_literal_to_string` builds the value: pure ASCII keeps the `ascii_unchecked_string` fast path, anything else goes through `String(from_utf8=...)` and raises when it is not valid UTF-8. `FieldSection.implLiteral_ok` shows `implLiteral` only returns valid strings, and `implLiteral_eq_spec_of_ok` that valid-UTF-8 payloads decode as before.
- **Repro:** `formal/repro/QPACK-03_literal_not_utf8_validated.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: decoded header value is a String holding byte 0xFF (validating String constructor accepts it: False )`
- **Flip (QPACK agent):** `OK`, exit 0.
Status: resolved. `_decode_string_literal` validates the decoded bytes (`_literal_to_string`) and raises on invalid UTF-8; on the encoder stream that is a QPACK_ENCODER_STREAM_ERROR instead of a stall. Tests: `tests/qpack/test_qpack.mojo::test_raw_literal_value_that_is_not_utf8_is_refused` (and three siblings), `tests/qpack/test_qpack_dynamic.mojo::test_non_utf8_literal_on_the_encoder_stream_is_an_error`. The repro prints `OK` (three runs).

### QPACK-04: a bad encoder-stream reference stalls instead of raising an error

- **Severity:** Low to Medium. The encoder stream stops making progress. `http3/server.mojo:1139` eventually raises, but only once the carry buffer exceeds the capacity plus 64 bytes.
- **RFC:** RFC 9204 §4.3.2 and §4.3.4 require QPACK_ENCODER_STREAM_ERROR.
- **What goes wrong:**
  - `insert_count() - 1 - ip` wraps at `dynamic.mojo:319` and `337`.
  - `get_abs` raises an untagged error.
  - `apply_encoder_instructions_partial` (281-297) treats the untagged error as a truncated instruction and returns `(0, 0)`.
- **Counterexample:** `Flare.Bugs.QPACK_04.counterexample` and `counterexample_evicted`, with `spec_errors` (at tag `formal-audit-0.12`).
- **Fix:** check `ip < len(entries)` and raise an error tagged QPACK_ENCODER_STREAM_ERROR (`_relative_to_abs`, used by Insert With Name Reference and Duplicate). `FieldSection.implDynRef_eq_spec` shows `implDynRef` equals the spec.
- **Repro:** `formal/repro/QPACK-04_bad_encoder_ref_stalls.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: dynamic name ref into an empty table returned (inserts, consumed) = ( 0 , 0 ) -- treated as truncation, no QPACK_ENCODER_STREAM_ERROR`
- **Flip (QPACK agent):** `OK: ... QPACK_ENCODER_STREAM_ERROR: bad dynamic name ref`, exit 0.
Status: resolved. `_relative_to_abs` rejects a relative index that names no live entry with a tagged QPACK_ENCODER_STREAM_ERROR, and `apply_encoder_instructions_partial` re-raises it, so `Http3Connection` raises it and the QUIC layer closes with 0x201; a truncated valid instruction still waits for more bytes. Tests: `tests/qpack/test_qpack_dynamic.mojo::test_name_ref_into_an_empty_table_is_an_encoder_stream_error` (and three siblings), `tests/h3/test_h3_qpack_dynamic.mojo::test_bad_name_reference_on_the_encoder_stream_is_a_stream_error`. The repro prints `OK` (three runs).

### QPACK-05: an undecodable or blocked field section is not a connection error

- **Severity:** Medium. A request whose field section cannot be decoded is dropped silently: the stream is never answered, reset or refused, and the connection stays up. The peer gets no error, and the stream's state stays in the per-connection table until the connection ends.
- **RFC:** RFC 9204 §2.1.2: "If a decoder encounters more blocked streams than it promised to support, it MUST treat this as a connection error of type QPACK_DECOMPRESSION_FAILED"; §4.5.1.1: a Required Insert Count the encoder could not have produced is QPACK_DECOMPRESSION_FAILED; §2.2.3: an invalid dynamic reference is QPACK_DECOMPRESSION_FAILED. Within the advertised budget, §2.2.1: the stream "becomes blocked" and resumes when the inserts arrive.
- **What goes wrong:** `decode_field_section_dynamic` (`qpack/dynamic.mojo:473-498`) raises when the Required Insert Count cannot be decoded (with the server's capacity 0, any non-zero encoded value: `decode_required_insert_count`, 188-209) and when it exceeds the insert count (498). `request_reader.mojo:276-284` turns the raise into `on_protocol_error`, a flag on that stream. `take_completed_streams` (`http3/server.mojo:820-850`) skips the stream, and nothing reads `stream_protocol_error` (725); `quic/server.mojo` never calls it. The server advertises the defaults (capacity 0, 0 blocked streams), since it always builds `Http3Connection()` (`quic/server.mojo:1819, 1836`).
- **Counterexample:** `Flare.Bugs.QPACK_05.implOld_counterexample` (at tag `formal-audit-0.12`): the section `01 00 80` (encoded RIC 1, one indexed dynamic line) on the shipped configuration was a stream error in flare and is a connection error in the spec. `implOld_never_connErr`: flare never raised a connection error for a field section. `implOld_drops_blockable`: with a blocked-stream budget of 1, which is reachable only through `Http3Connection.with_config`, a section that should wait for an insert fails for good. `Ric.implDecode_cap0` shows that with MaxEntries 0 every non-zero encoded RIC fails to decode.
- **Fix:** for the shipped configuration (0 blocked streams), turn every QPACK decode failure on a request stream into a connection error QPACK_DECOMPRESSION_FAILED (0x200). `Ric.sectionImpl_spec` shows this equals the spec for every input when the budget is 0. A configuration with a non-zero budget would also need a blocked-stream queue.
- **Repro:** `formal/repro/QPACK-05_undecodable_field_section_not_connection_error.mojo` (at tag `formal-audit-0.12`): after a loopback handshake the client sends a HEADERS frame with the section `01 00 80` and FIN on stream 0, then a valid GET on stream 4, while the server runs a handler between ticks. Inconclusive if the handshake does not complete, or if the connection is neither closed with 0x200 nor still serving stream 4.
- **Observed:** `BUG REPRODUCED: field section 01 00 80 (RIC 1, table capacity 0, 0 blocked streams) left the connection open (stream 4 answered); stream 0 was never answered or reset` (three runs, exit 1).
- **Flip** (`quic/server.mojo`: at the end of `_route_http3_stream_chunks`, if any fed stream's `stream_protocol_error` starts with `h3 reader: QPACK`, `_close_for(slot, 0x200, ...)`): the connection closed with code 512 (0x200), `OK: undecodable field section closed the connection with QPACK_DECOMPRESSION_FAILED (0x200)`, exit 0.
Status: resolved. `Http3Connection.feed_stream_chunk` records `connection_error_code = QPACK_DECOMPRESSION_FAILED` when the request reader reports a QPACK decode failure, and `QuicListener._route_http3_stream_chunks` closes the slot with it (a minimal call-site change in `quic/server.mojo`, which also turns any H3 error the driver raises into a connection close with its H3 code via `h3_error_code`, instead of letting it escape `tick`). Tests: `tests/h3/test_h3_dispatch.mojo::test_undecodable_field_section_is_a_connection_error` (and `test_blocked_field_section_without_a_budget_is_a_connection_error`), `tests/h3/test_h3_end_to_end.mojo::test_undecodable_field_section_closes_the_connection`. The repro prints `OK` (three runs).

### QPACK-06: the dynamic-table encoder tracks no acknowledgments

- **Severity:** Low. `QpackEncoder` is exported library API (`flare/qpack/__init__.mojo`); neither flare endpoint uses it, because both encode with the static-only `encode_field_section`. An application that uses it against a conforming peer produces streams that can block a decoder that allows none, and sections the decoder cannot decode once a referenced entry is evicted.
- **RFC:** RFC 9204 §2.1.2: "An encoder MUST limit the number of streams that could become blocked to the value of SETTINGS_QPACK_BLOCKED_STREAMS at all times" (default 0). §2.1.1: "A dynamic table entry cannot be evicted immediately after insertion, even if it has never been referenced", and "the encoder MUST NOT insert that entry" if it would have to evict entries that are not evictable.
- **What goes wrong:** `encode_field_section_dynamic` (`qpack/dynamic.mojo:405-470`, called by `QpackEncoder.encode`, 617-619) references every entry `find` / `find_name` return, whether or not the decoder has acknowledged it. `QpackEncoder.insert` (606-615) inserts through `QpackDynamicTable.insert` (138-148), which evicts the oldest entries. The encoder has no Known Received Count, no reference tracking, and no way to consume Section Acknowledgment or Insert Count Increment, and it is never told the peer's blocked-stream limit.
- **Counterexample:** with entries of size 34 and capacity 40, `Flare.Bugs.QPACK_06.implOld_references_unacked` (at tag `formal-audit-0.12`): right after inserting `(1, 2)` a section for it has RIC 1 although nothing is acknowledged. `implOld_evicts_unacked`: the next insert evicts that entry (`dropped = 1`, `getAbs 0 = none`).
- **Fix:** until acknowledgments are tracked, encode against no dynamic entries and refuse an insert that would evict. `Encoder.implRic_zero` shows that every section then has RIC 0, `Encoder.implInsert_noEvict` shows an accepted insert keeps every earlier entry, and `Encoder.encoder_spec` combines them: no stream can block, and nothing unacknowledged is evicted.
- **Repro:** `formal/repro/QPACK-06_encoder_ignores_acknowledgments.mojo` (at tag `formal-audit-0.12`): a `QpackEncoder` with capacity 40 inserts `("a", "b")`, encodes `a: b`, then inserts `("c", "d")`. A `QpackDecoder` with the same capacity applies the encoder stream and decodes the section. Inconclusive if the first insert is refused.
- **Observed:** `BUG REPRODUCED: encoder referenced an unacknowledged entry (encoded Required Insert Count field 2 , non-zero) and then evicted it; the decoder cannot decode the section: qpack: field section blocked on missing inserts` (three runs, exit 1). The encoded value 2 means RIC 1 with MaxEntries 1. After the eviction the RFC decoding of that value against the decoder's insert count of 2 gives RIC 3, so the decoder reports the section as blocked.
- **Flip** (`qpack/dynamic.mojo`: `QpackEncoder.encode` passes an empty `QpackDynamicTable(0)`, and `insert` refuses when `size + entry_size > capacity`): the RIC field is 0, the second insert is refused, and the section decodes: `OK: nothing unacknowledged referenced or evicted; section decodes`, exit 0.
Status: resolved. That flip is the shipped fix: `QpackEncoder.encode` references no dynamic entry and `QpackEncoder.insert` refuses an entry that would evict, until acknowledgments are tracked. Tests: `tests/qpack/test_qpack_dynamic.mojo::test_encoder_references_no_unacknowledged_entry`, `tests/qpack/test_qpack_dynamic.mojo::test_encoder_refuses_an_insert_that_would_evict`; `test_blocked_section_raises` now builds its blocked section with `encode_field_section_dynamic` because `QpackEncoder.encode` can no longer produce one. The repro prints `OK` (three runs).

### H3-01: the request reader buffers non-HEADERS/DATA frames without bound

- **Severity:** Medium. A peer can make the server hold up to the QUIC flow-control window per request stream for one frame it would otherwise ignore.
- **RFC:** RFC 9114 §7.2.8 (unknown types are ignored, so their payload can be discarded as it arrives) and §10.5 (an endpoint can limit what a peer commits it to, using H3_EXCESSIVE_LOAD).
- **What goes wrong:**
  - `request_reader.mojo:240-259` checks HEADERS and DATA against their limits using the frame header alone.
  - Every other type returns NEEDS_MORE until the whole declared payload, up to 2^62 - 1 bytes, is buffered.
  - `feed_stream_chunk` (`server.mojo:732-807`) keeps appending to the per-stream inbox while this happens.
- **Counterexample:** `Flare.Bugs.H3_01.unknown_needs_unbounded_buffer` (at tag `formal-audit-0.12`): type 0x21 with declared length 2^62 - 1, followed by any `n < 2^62 - 1` bytes, returns `(0, r, none)`. `violates_spec` shows that no bound below 2^62 - 1 satisfies `BoundedNeed` for the pre-fix reader.
- **Fix:** reject a frame of any other type whose declared length exceeds `max_field_section_bytes`, using H3_EXCESSIVE_LOAD. `H3.feed_bounded` shows the reader `feed` then acts once `16 + max_field_section_bytes + max_body_bytes` bytes are buffered.
- **Repro:** `formal/repro/H3-01_unknown_frame_unbounded_buffering.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: feed_into returned NEEDS_MORE with 1048585 bytes buffered for an unknown frame declaring 2^62-1 bytes; the caller must keep buffering`
- **Flip:** `OK: reader acted on the oversized unknown frame from its header`, exit 0.
Status: resolved. `feed_into` now refuses a frame of any type other than HEADERS and DATA that declares more than `max_field_section_bytes` from its header (`H3_EXCESSIVE_LOAD`, stream-level protocol error). Test: `tests/h3/test_request_reader.mojo::test_oversized_unknown_frame_is_refused_from_its_header`. The repro prints `OK`.

### H3-02: HTTP/2-reserved frame types are ignored on request streams

- **Severity:** Low (a conformance gap).
- **RFC:** RFC 9114 §7.2.8 and §11.2.1: receipt of types 0x02, 0x06, 0x08 or 0x09 MUST be treated as H3_FRAME_UNEXPECTED.
- **What goes wrong:** `request_reader.mojo:308-327` rejects only the control-stream types. The reserved types go to `on_unknown_frame`.
- **Counterexample:** `Flare.Bugs.H3_02.implOld_ignores_reserved` and `violates_spec` (at tag `formal-audit-0.12`): HEADERS followed by PING was accepted.
- **Fix:** add the four types to the rejected set (`feed_into` now rejects `isControlType t || isH2Reserved t`). `H3.implRejects_reserved`, `run_accept_impl` and `run_reject_impl` show the reader matches the grammar on every sequence, with no side condition on frame types.
- **Repro:** `formal/repro/H3-02_h2_reserved_frame_types_ignored.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: HTTP/2-reserved frame types accepted as unknown (no H3_FRAME_UNEXPECTED): 0x2 0x6 0x8 0x9`
- **Flip:** `OK: all HTTP/2-reserved frame types rejected`, exit 0.
Status: resolved. `feed_into` rejects 0x02, 0x06, 0x08 and 0x09 with an `H3_FRAME_UNEXPECTED` protocol error, and `Http3Connection.feed_stream_chunk` records it as a connection error (`connection_error_code = H3_FRAME_UNEXPECTED`) that the listener closes with. Tests: `tests/h3/test_request_reader.mojo::test_h2_reserved_frame_types_are_refused`, `tests/h3/test_h3_dispatch.mojo::test_h2_reserved_request_frame_is_a_connection_error`. The repro prints `OK` (three runs).

### H3-03: frames forbidden on the control stream are silently ignored

- **Severity:** Low (a conformance gap; the frames are dropped).
- **RFC:** RFC 9114 §7.2.1 (DATA), §7.2.2 (HEADERS), §7.2.5 (PUSH_PROMISE), and §7.2.8 / §11.2.1 (the HTTP/2-reserved types): each MUST be H3_FRAME_UNEXPECTED on the control stream.
- **What goes wrong:** after the SETTINGS-first check, `_dispatch_control_frame` (`server.mojo:1170-1211`) acts only on SETTINGS and GOAWAY and returns without error for every other type.
- **Counterexample:** `Flare.Bugs.H3_03.implOld_accepts_data_on_control` and `trace_implOld` (at tag `formal-audit-0.12`): SETTINGS followed by an empty frame of each type in {0, 1, 5, 2, 6, 8, 9} was accepted. `spec_rejects` shows the spec rejects these.
- **Fix:** raise for those types. `Control.dispatchControlFixed_eq_spec` shows it suffices.
- **Repro:** `formal/repro/H3-03_control_stream_forbidden_frames_ignored.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: control stream accepted forbidden frame types (no H3_FRAME_UNEXPECTED): 0x0 0x1 0x5 0x2 0x6 0x8 0x9`
- **Flip:** `OK: forbidden control-stream frame types rejected`, exit 0.
Status: resolved. `_dispatch_control_frame` raises H3_FRAME_UNEXPECTED for DATA, HEADERS, PUSH_PROMISE and the HTTP/2-reserved types after the SETTINGS-first check; CANCEL_PUSH, MAX_PUSH_ID and unknown types are still accepted. Tests: `tests/h3/test_h3_uni_streams.mojo::test_forbidden_frame_types_on_the_control_stream_are_refused`, `tests/h3/test_h3_uni_streams.mojo::test_allowed_control_frames_are_still_accepted`. The repro prints `OK` (three runs).

### H3-04: HTTP/2-reserved SETTINGS identifiers are accepted

- **Severity:** Low (a conformance gap).
- **RFC:** RFC 9114 §7.2.4.1 and §11.2.2: receipt of identifiers 0x02..0x05 MUST be treated as H3_SETTINGS_ERROR.
- **What goes wrong:** `_apply_peer_settings` (`server.mojo:1213-1228` at 59bda50) ignored unknown identifiers and never raised.
- **Counterexample:** `Flare.Bugs.H3_04.implOld_accepts_reserved_setting` and `trace_implOld` (at tag `formal-audit-0.12`). `spec_rejects` shows the spec rejects these identifiers.
- **Fix:** raise if `2 <= id <= 5`. `Control.applySettingsFixed_eq_spec` and `Control.dispatchControlFixed_eq_spec` show it suffices.
- **Repro:** `formal/repro/H3-04_reserved_settings_accepted.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: SETTINGS with HTTP/2-reserved identifiers accepted (no H3_SETTINGS_ERROR): 0x2 0x3 0x4 0x5`
- **Flip:** `OK: reserved SETTINGS identifiers rejected`, exit 0.
Status: resolved. `_apply_peer_settings` raises H3_SETTINGS_ERROR for identifiers 0x02 to 0x05 before applying any value; the neighbours 0x01 and 0x06 and unknown or grease identifiers are unchanged. Tests: `tests/h3/test_h3_uni_streams.mojo::test_http2_reserved_setting_identifiers_are_refused`, `tests/h3/test_h3_uni_streams.mojo::test_unknown_and_known_setting_identifiers_are_still_accepted`. The repro prints `OK` (three runs).

### H3-05: a second QPACK encoder or decoder stream, and a client push stream, are accepted

- **Severity:** Low. A second encoder or decoder stream overwrites the recorded stream id, and a client push stream is recorded while its bytes are dropped.
- **RFC:**
  - RFC 9204 §4.2: a second instance of either stream type MUST be H3_STREAM_CREATION_ERROR.
  - RFC 9114 §6.2.2: a client-initiated push stream MUST be H3_STREAM_CREATION_ERROR.
- **What goes wrong:** `_classify_uni_kind` (`server.mojo:1045-1068`) rejects only a second control stream.
- **Counterexample:** `Flare.Bugs.H3_05.implOld_accepts_second_encoder`, `implOld_accepts_second_decoder`, `implOld_accepts_push` and `trace_implOld` (at tag `formal-audit-0.12`). `spec_rejects` and `implOld_violates_spec` show the spec rejects these streams.
- **Fix:** raise on a push stream and on a second encoder or decoder stream. `Control.classifyFixed_eq_spec` and `Control.runClassifyFixed_unique` show it suffices.
- **Repro:** `formal/repro/H3-05_duplicate_qpack_and_client_push_streams.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: uni streams accepted without H3_STREAM_CREATION_ERROR: second-encoder-stream second-decoder-stream client-push-stream`
- **Flip:** `OK: duplicate QPACK streams and client push streams rejected`, exit 0.
Status: resolved. `_classify_uni_kind` raises H3_STREAM_CREATION_ERROR for a client push stream and for a second QPACK encoder or decoder stream; the error reaches the connection close through `h3_error_code`. Tests: `tests/h3/test_h3_uni_streams.mojo::test_second_qpack_stream_of_either_type_is_refused`, `tests/h3/test_h3_uni_streams.mojo::test_client_push_stream_is_refused` (replaces `test_push_uni_stream_tolerated`, which encoded the bug). The repro prints `OK` (three runs).

### H3-06: bytes after the GOAWAY stream id are accepted

- **Severity:** Low. The extra bytes are ignored; the recorded id is the first varint.
- **RFC:** RFC 9114 §7.2.6 defines the GOAWAY payload as one varint, and §7.1 requires H3_FRAME_ERROR for bytes after the identified fields.
- **What goes wrong:** the GOAWAY branch of `_dispatch_control_frame` (`http3/server.mojo:1198-1211`) decodes one varint and never compares `goaway_id.consumed` with `len(payload)`.
- **Counterexample:** `Flare.Bugs.H3_06.implOld_accepts_trailing` (after SETTINGS, any one-byte id followed by a non-empty tail is accepted), `spec_rejects_trailing`, and `trace_implOld` for the control stream `00 | 04 03 06 60 00 | 07 02 00 ff`, all at tag `formal-audit-0.12`.
- **Fix:** raise when `goaway_id.consumed != len(payload)`. `Control.goawayFixed_eq_spec` and `Control.dispatchControlFixed_eq_spec` show the shipped dispatch equals the spec.
- **Repro:** `formal/repro/H3-06_goaway_trailing_bytes_accepted.mojo` (at tag `formal-audit-0.12`)
- **Observed:** `BUG REPRODUCED: GOAWAY payload 00 ff accepted (no H3_FRAME_ERROR); peer_goaway_max_stream_id = 0`
- **Flip:** `OK: GOAWAY with trailing bytes rejected`, exit 0.
Status: resolved. The GOAWAY branch raises H3_FRAME_ERROR when `goaway_id.consumed != len(payload)`; the empty-payload and truncated-varint errors now carry the same tag (before, they mapped to H3_GENERAL_PROTOCOL_ERROR). Tests: `tests/h3/test_h3_uni_streams.mojo::test_goaway_with_bytes_after_the_id_is_a_frame_error`, `tests/h3/test_h3_uni_streams.mojo::test_goaway_exactly_one_varint_is_still_accepted`. The repro prints `OK` (three runs).

### H3-07: the server never opens its control stream or sends SETTINGS

- **Severity:** Medium. Requests are still answered, but the client never receives the server's SETTINGS: it does not learn SETTINGS_MAX_FIELD_SECTION_SIZE, the QPACK table capacity and blocked-streams limits, or SETTINGS_ENABLE_CONNECT_PROTOCOL. A client that waits for the peer's SETTINGS before using extended CONNECT or the QPACK dynamic table never gets them, and a strict client may close the connection with H3_MISSING_SETTINGS.
- **RFC:** RFC 9114 §6.2.1: "Each side MUST initiate a single control stream at the beginning of the connection and send its SETTINGS frame as the first frame on this stream."
- **What goes wrong:** the QUIC server never sends on a server-initiated unidirectional stream. The 1-RTT egress `_drain_1rtt_coalesced` (`quic/server.mojo:2210-2433`) writes ACK, HANDSHAKE_DONE, MAX_DATA, MAX_STREAMS, NEW_CONNECTION_ID and the response streams from `http3_response_egress`, which are keyed by the client's request stream. The comment at `quic/server.mojo:1411-1414` calls the server's uni streams send-only, but none is ever opened. `Http3Connection.emit_initial_settings` (`http3/server.mojo:1230-1275`) builds the right bytes (stream type 0x00, then SETTINGS) but is not called anywhere under `flare/`; its only callers are `tests/h3/test_h3_uni_streams.mojo` and `examples/advanced/http3_server.mojo:167`. `control_stream_id` (`http3/server.mojo:588`) is set to -1 and never assigned.
- **Documentation gap:** the docstring of `emit_initial_settings` says "The reactor opens a local control uni-stream via QUIC and emits these bytes as the very first payload"; no such code exists. The example at `examples/advanced/http3_server.mojo:163-169` says the listener "will write" the bytes "on the new control stream", but it only prints their length (`[h3] initial server SETTINGS emit length = ...`) and sends nothing.
Status: resolved. `Http3Connection.take_control_stream_start()` hands over type 0x00 plus the SETTINGS frame once (and records `control_stream_id = 3`), and `QuicListener._drain_1rtt_coalesced` (a minimal call-site change in `quic/server.mojo`) sends it as a STREAM frame on stream 3 at offset 0 with the first 1-RTT flight, next to HANDSHAKE_DONE; the existing loss recovery retransmits it. Tests: `tests/h3/test_h3_uni_streams.mojo::test_take_control_stream_start_is_once_and_decodes_at_the_peer`, `tests/h3/test_h3_client_e2e.mojo::test_server_opens_its_control_stream_with_settings`. The repro prints `OK` (three runs).

- **Counterexample:** `Flare.Bugs.H3_07.implOld_no_control` (at tag `formal-audit-0.12`) shows that for any set of client bidirectional request streams, the pre-fix server's outbound stream set contains no server-initiated unidirectional stream, so RFC 9114 §6.2.1 fails. `implOld_observed` is the repro's run: one GET on stream 0, and the server sends only on stream 0.
- **Fix:** with the first 1-RTT flight (the drain that sends the first HANDSHAKE_DONE), append a STREAM frame on stream 3 at offset 0 carrying `self.http3_connections[slot].emit_initial_settings()`. `ControlStart.implOut_spec` proves the shipped set (`implOut`) has exactly one server-initiated unidirectional stream that starts with type 0x00 and a SETTINGS frame. `ControlStart.emit_control_start` shows the SETTINGS payload decodes back to exactly the configured settings, for any correct varint encoder and configuration values below 2^62. `ControlStart.control_stream_sendable` shows stream 3 is a server-initiated unidirectional stream with a send part and no receive part at the server, and `ControlStart.control_classified` shows the receiver's uni-stream classifier types it as the control stream.
- **Repro:** `formal/repro/H3-07_server_never_opens_control_stream.mojo` (at tag `formal-audit-0.12`) runs a real `QuicListener` and a `QuicClientConnection` over loopback UDP with the rustls fixtures. After the handshake the client sends GET / on stream 0, the server runs a handler and answers, and every STREAM chunk the client decrypts is recorded. It prints `inconclusive:` and raises if the handshake or the response FIN never arrives.
- **Observed:** `BUG REPRODUCED: request answered, but no server-initiated uni stream carried 00 + SETTINGS; streams the server sent on: 0` (three runs, same line each time, exit 1).
- **Flip:** the fix above, applied in `quic/server.mojo` inside the `if not self.handshake_done_sent[slot]:` block after `_issue_new_connection_id`, gives `OK: server control stream (type 0x00 + SETTINGS) received; streams: 3 0`, exit 0. The file was restored with `git checkout --` and `git status --short flare/` was clean.

## Checked, not a bug

- **Packet-number decode.** flare's underflow-free `decode_packet_number` equals the RFC 9000 A.3 pseudocode on all valid inputs (`decodePnImpl_eq_rfc`).
- **Frame parser bounds.** The parser never reads out of bounds and always makes progress (`parseFrame_good`, `parseFrame_progress`).
- **ACK range count.** It is capped at 0x4000 (`ack_range_cap`).
- **NEW_CONNECTION_ID field checks.** These follow RFC 9000 §19.15 (`newcid_checks`).
- **ACK expansion.** The clamping in `expand_ack_ranges` never retires a packet the ACK does not claim, and the output never exceeds 256 entries (`expand_sound`, `expand_len_le`). For a well-formed ACK of at most 256 numbers it retires every claimed packet (`expand_complete`); above 256 it retires the newest 256 (`expand_drops_oldest`), as its docstring says. The only defect was the missing error, QUIC-03.
- **ACK generation.** The stored ranges are canonical, never claim an unreceived packet, and are exactly the received set while at most 32 ranges are needed; the ACK built from them claims exactly that set (`record_canon`, `record_sound`, `record_exact`, `fromRanges_claimed`, `ack_roundtrip`). After an ack-eliciting packet the next drain sends an ACK (`drain_after_recv`).
- **ACK range cap.** Above 32 ranges the oldest are left out of every later ACK (`record_drops_lowest`). RFC 9000 §13.2.3 allows a receiver to stop acknowledging old ranges, and the peer then declares those packets lost and retransmits their frames, so not acknowledging them is allowed. What the cap must not do is let those numbers be accepted again; that was QUIC-14 (`never_reaccepts` covers the fix).
- **Server STREAM checks.** The server's STREAM check in `_route_http3_stream_chunks` (server-initiated ids rejected, both stream limits) equals the spec (`serverFixed_eq_spec`). Of these, only the unidirectional limit was missing (QUIC-16).
- **Transport-parameter encoder.** For every parameter set RFC 9000 lets an endpoint send, `encode_transport_parameters` does not raise and its output decodes, under the spec, to the same parameters (`tlvs_wire`, `encode_roundtrip`). The encoder does not itself check max_udp_payload_size ≥ 1200 or initial_max_streams_* ≤ 2^60. Neither flare endpoint sends max_udp_payload_size; the stream limits come from `QuicServerConfig` (defaults 100 and 3) and are 16 on the client. A configured stream limit above 2^60 would be sent and rejected by the peer; that is a configuration-validation gap, not reachable with flare's defaults.
- **`bytes_in_flight`.** It always equals the sum of the in-flight packet sizes and never underflows (`inv_run`, `retire_noUnderflow`, `firePto_noUnderflow`).
- **Connection state on other events.** CONNECTION_CLOSE, local close and TLS completion are handled as the spec requires (`implStep_frame_spec`, `localClose_spec`, `markHandshakeComplete_spec`).
- **Duplicate SETTINGS identifiers** are accepted. RFC 9114 §7.2.4 says a receiver MAY treat this as an error, so accepting them is allowed.
- **Request-stream grammar.** The request-stream reader follows RFC 9114 §4.1 exactly (`run_accept_impl`, `run_reject_impl`), and its events do not depend on how the input is split into chunks (`feedChunks_chunking_independent`).
- **QPACK Required Insert Count.** `decode_required_insert_count` is exactly the RFC algorithm and inverts the encoder within the window (`implDecode_eq_spec`, `implDecode_encode`).
- **QPACK table.** The size and capacity counters cannot wrap, and eviction does not move absolute indices. `get_abs` stays in bounds whenever it does not raise.
- **Transport-parameter decoding** apart from QUIC-10 and QUIC-13: duplicates, truncation, trailing bytes and the other §18.2 value rules are right (`decodeFixed_eq_spec`).
- **QPACK default configuration.** The static-only `decode_field_section` does not have the QPACK-02 problem. With the default capacity of 0, QPACK-01 and QPACK-02 cannot be reached.
- **QPACK Huffman literals.** The Huffman branch of `_decode_string_literal` decodes exactly what L1's proved decoder does (`implLiteralRaw_eq_spec`) and inverts the Huffman encoder (`implLiteralRaw_huffman`). Its only defect was the shared unchecked `String` constructor, QPACK-03.
- **QPACK `find` / `find_name`.** They return the first live matching entry as an absolute index, or none when there is none (`findBy_some`, `findBy_none`), and the encoder's RIC covers every index it references (`ric_bound`).
- **QPACK Section Acknowledgment and the decoder stream.** RFC 9204 §2.2.2.1 requires a decoder to acknowledge sections with a non-zero RIC. The server never sends a decoder stream: `take_qpack_decoder_frames` (`http3/server.mojo`) has no caller, and its docstring records the acknowledgment as deferred. With the shipped capacity of 0, no section with a non-zero RIC is ever decoded (`Ric.implDecode_cap0`), so there is nothing to acknowledge, and §4.2 lets an endpoint omit the decoder stream in that case. This becomes a gap only if a server is configured with a non-zero capacity through `with_config`.
- **The client's own close.** `shutdown` sends CONNECTION_CLOSE and closes the socket, which RFC 9000 §10.2 allows instead of a closing period (`Timers.cli_close_ok`).

## Traceability

| Lean definition | Mojo symbol | Theorems | Status |
|---|---|---|---|
| `Quic.Wire.varint`, `bytes`, `byte` | quic/varint.mojo `decode_varint`, quic/frame.mojo `_read_varint`, `_read_bytes` | `good_varint`, `good_bytes`, `good_byte`, `varint_progress` | proved |
| `Quic.Frame.kindOf`, `body`, `parseFrame` | quic/frame.mojo `parse_frame_into` (QUIC-01, QUIC-02, QUIC-03 fixed) | `parseFrame_good`, `parseFrame_progress`, `ack_range_cap`, `newcid_checks`, `parseFrame_not_unknown`, `parseFrameFixed_ok` | proved |
| `Quic.Frame.parsePayload` | quic/state.mojo `dispatch_frames` | `parsePayload_not_unknown`, `parsePayloadFixed_ok` | proved |
| `Quic.PacketNumber.decodePnImpl` | quic/protection.mojo `decode_packet_number` | `decodePnImpl_eq_rfc`, `decodePnImpl_window` | proved |
| `Quic.Conn.implStep`, `frameEffect` | quic/state.mojo `handle_frame_buf`, `apply_connection_close`, `apply_handshake_done`, `_ConnFrameHandler.on_handshake_done` (QUIC-04, QUIC-09 fixed) | `implStep_eq_spec`, `run_eq_spec`, `implStep_frame_spec`, `implStep_client_eq_spec`, `implStep_absorbing` | proved |
| `Quic.Conn.markHandshakeComplete`, `localClose` | quic/state.mojo `mark_handshake_complete`, `connection_close` | `markHandshakeComplete_spec`, `localClose_spec` | proved |
| `Quic.AckExpand.expand` | quic/_state_helpers.mojo `expand_ack_ranges`, `_ACK_EXPAND_CAP` | `expand_sound`, `expand_len_le`, `expand_eq_take`, `expand_complete`, `expand_drops_oldest`, `expand_length` | proved |
| `Quic.AckGen.record`, `isort`, `mergeAcc` | quic/_server_support.mojo `_ack_record` | `record_canon`, `merge_inv`, `merged_inv`, `record_sound`, `record_exact`, `record_drops_lowest` | proved |
| `Quic.AckGen.contains`, `recordSt`, `floorAfter` | quic/_server_support.mojo `_ack_record`, `_ack_contains` (QUIC-14 fixed) | `never_reaccepts`, `recordSt_flat` | proved |
| `Quic.AckGen.fromRanges`, `gaps` | quic/_server_support.mojo `_ack_from_ranges` | `fromRanges_claimed`, `fromRanges_wellFormed`, `ack_roundtrip` | proved |
| `Quic.AckGen.recv`, `drain` | quic/server.mojo `QuicListener._process_one_packet`, `QuicListener._drain_1rtt_coalesced` | `drain_after_recv` | proved |
| `Quic.Streams.checked` | quic/state.mojo `check_stream_frame_id` | `checked_eq_spec` | proved |
| `Quic.Streams.server` | quic/server.mojo `QuicListener._route_http3_stream_chunks`, quic/state.mojo `check_stream_frame_id` (QUIC-15, QUIC-16 fixed) | `serverFixed_eq_spec` | proved |
| `Quic.Streams.client` | quic/client.mojo `QuicClientConnection._dispatch_frames`, quic/state.mojo `check_stream_frame_id` (QUIC-17 fixed) | `clientFixed_eq_spec` | proved |
| `Quic.Streams.stepHalves`, `resetSeenH`, `sendRefusedH` | quic/state.mojo `apply_reset_stream`, `apply_stop_sending`, quic/client.mojo `cancel_stream`, `stream_reset`, `send_stream` (QUIC-18 fixed) | `halves_reset_iff`, `halves_stop_iff` | proved |
| `Quic.Timers.fixedStep`, `effectiveMs` | quic/server.mojo `_handle_inbound`, `_process_one_packet`, `_build_1rtt_response`, `schedule_idle_timeout`, `_client_params_ok`, quic/_server_support.mojo `_effective_idle_ms`, quic/client.mojo `_dispatch_frames`, `_note_ack_eliciting_send`, `_apply_peer_transport_params`, `_check_idle` (QUIC-20, QUIC-21 fixed) | `fixed_sim`, `fixed_run`, `init_R`, `fixed_closed_eq_spec`, `effectiveMs_spec` | proved |
| `Quic.Timers.ispecStep` | RFC 9000 §10.1 (spec) | `spec_none_never` | proved |
| `Quic.Timers.srvStepNow` | quic/server.mojo `_close_for`, `_enter_closing`, `_answer_closing`, `_handle_inbound`, `advance_timers`, `_build_1rtt_response`, `_drain_and_send`, quic/state.mojo `apply_connection_close` (QUIC-22, QUIC-23 fixed) | `srvFix_refines`, `srvNow_draining_silent` | proved |
| `Quic.Timers.cliStepNow` | quic/client.mojo `_build_1rtt`, `_build_initial`, `_build_handshake`, `_build_0rtt`, `send_stream`, `shutdown` (QUIC-24 fixed) | `cliNow_draining_silent`, `cli_close_ok` | proved |
| `Quic.Timers.cspecStep` | RFC 9000 §10.2 (spec) | `spec_cc_on_close`, `spec_closing_only_cc`, `spec_draining_silent`, `spec_tick_before` | proved |
| `Quic.LossRecovery.onSent`, `onAck`, `detectLost`, `firePto` | quic/_loss_recovery.mojo `LossRecovery.on_sent`, `on_ack`, `detect_lost`, `fire_pto` | `inv_run`, `retire_noUnderflow`, `firePto_noUnderflow` | proved |
| `Qpack.Ric.implEncode`, `implDecode` | qpack/dynamic.mojo `encode_required_insert_count`, `decode_required_insert_count` | `implDecode_eq_spec`, `implDecode_encode`, `implDecode_cap0` | proved |
| `Qpack.Ric.sectionImpl` | http3/request_reader.mojo `feed_into`, http3/server.mojo `Http3Connection.feed_stream_chunk`, quic/server.mojo `QuicListener._route_http3_stream_chunks` (QPACK-05 fixed) | `sectionImpl_spec` | proved |
| `Qpack.Table.*` | qpack/dynamic.mojo `QpackDynamicTable.__init__`, `insert_count`, `_evict_to`, `set_capacity`, `insert`, `get_abs` | `inv_insert`, `inv_setCapacity`, `getAbs_insert` | proved |
| `Qpack.FieldSection.implResolve` | qpack/dynamic.mojo `decode_field_section_dynamic`, `_pre_base_abs`, `_post_base_abs` (QPACK-01 fixed) | `implResolve_eq_spec`, `implResolve_safe` | proved |
| `Qpack.FieldSection.implSignReadIndex`, `implSignOffset` | qpack/dynamic.mojo `decode_field_section_dynamic` (QPACK-02 fixed) | `implSignReadIndex_inBounds`, `implSignOffset_le` | proved |
| `Qpack.FieldSection.implLiteralRaw`, `implLiteral` | qpack/codec.mojo `_decode_string_literal`, `_literal_to_string` (QPACK-03 fixed) | `implLiteralRaw_eq_spec`, `implLiteralRaw_huffman`, `implLiteral_ok`, `implLiteral_eq_spec_of_ok` | proved |
| `Qpack.FieldSection.implDynRef` | qpack/dynamic.mojo `_relative_to_abs`, `_apply_one_encoder_instruction` (QPACK-04 fixed) | `implDynRef_eq_spec` | proved |
| `Qpack.FieldSection.decodeInt` | http2/hpack.mojo `decode_integer` | `decodeInt_offset_le` | proved |
| `Qpack.Encoder.findBy` | qpack/dynamic.mojo `QpackDynamicTable.find`, `find_name` | `findBy_some`, `findBy_none` | proved |
| `Qpack.Encoder.ric` | qpack/dynamic.mojo `encode_field_section_dynamic` | `ric_bound` | proved |
| `Qpack.Encoder.implRic`, `implInsert` | qpack/dynamic.mojo `QpackEncoder.encode`, `QpackEncoder.insert` (QPACK-06 fixed) | `implRic_zero`, `implInsert_noEvict`, `encoder_spec` | proved |
| `H3.decodeFrame`, `encodeFrame`, `decodeSettings`, `encodeSettings` | http3/frame.mojo `decode_http3_frame`, `encode_http3_frame`, `decode_http3_settings`, `encode_http3_settings` | `decodeFrame_encode`, `decodeSettings_encode`, `decodeFrame_bounds` | proved |
| `H3.feed`, `stepFrame` | http3/request_reader.mojo `feed_into`, `_parse_frame_header` (H3-01, H3-02 fixed) | `feed_le`, `feed_bounded`, `run_accept_impl`, `run_reject_impl`, `implRejects_reserved` | proved |
| `H3.drain`, `feedChunks` | http3/server.mojo `Http3Connection.feed_stream_chunk` | `feedChunks_chunking_independent` | proved |
| `H3.Control.applySettings` | http3/server.mojo `Http3Connection._apply_peer_settings` (H3-04 fixed) | `applySettingsFixed_eq_spec` | proved |
| `H3.Control.dispatchControl`, `goaway` | http3/server.mojo `Http3Connection._dispatch_control_frame` (H3-03, H3-06 fixed) | `dispatchControlFixed_eq_spec`, `goawayFixed_eq_spec` | proved |
| `H3.Control.feedControlLoop` | http3/server.mojo `Http3Connection._feed_peer_control_stream` | `feedControlLoop_suffix`, `feedControl_le` | proved |
| `H3.Control.classify`, `route`, `feedUni` | http3/server.mojo `Http3Connection._classify_uni_kind`, `feed_uni_stream_chunk` (H3-05 fixed) | `classifyFixed_eq_spec`, `runClassifyFixed_unique` | proved |
| `H3.ControlStart.Config`, `settingsList`, `emitInitialSettings` | http3/server.mojo `Http3Config`, `Http3Connection.emit_initial_settings` | `emit_control_start` | proved |
| `H3.ControlStart.implOut` | quic/server.mojo `QuicListener._drain_1rtt_coalesced`, http3/server.mojo `Http3Connection.take_control_stream_start` (H3-07 fixed) | `implOut_spec`, `control_stream_sendable`, `control_classified` | proved |
| `Quic.TransportParams.decode`, `apply`, `readVar` | quic/transport_params.mojo `decode_transport_parameters`, `_read_param_varint` (QUIC-10, QUIC-13 fixed) | `decodeFixed_eq_spec`, `specFrom_eq` | proved |
| `Quic.TransportParams.encode`, `params`, `wire` | quic/transport_params.mojo `encode_transport_parameters`, `_emit_varint_param`, `_emit_bytes_param`, `_emit_flag_param` | `tlvs_wire`, `encode_roundtrip` | proved |
| `Quic.PeerParams.clientCheck` | quic/transport_params.mojo `check_server_transport_params` (QUIC-12 fixed) | `clientCheckFixed_spec` | proved |
| `Quic.PeerParams.serverCheck` | quic/transport_params.mojo `transport_parameter_present`, `check_client_transport_params`, quic/server.mojo `QuicListener._dispatch_crypto_frames`, `QuicListener._client_params_ok` (QUIC-11 fixed) | `serverCheck_spec`, `serverCheck_sound` | proved |
