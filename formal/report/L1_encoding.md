# L1: Pure encodings (ENC)

Scope: the byte- and text-level codecs in flare that sit underneath every
protocol. That means:

- raw struct buffers and little-endian word codecs for the io_uring ABI;
- network byte order;
- the `SocketAddr` text codec and the IPv4/IPv6 string predicates;
- `sockaddr_in`/`sockaddr_in6` filling;
- the UTF-8 validators and the lossy decoder (including its Unicode §3.9
  maximal-subpart replacement policy);
- `ByteReader`/`ByteWriter`, the gRPC `ProtoReader` and the protobuf varint
  writer;
- the civil-time conversions in `runtime/date_cache.mojo`;
- the QUIC variable-length integer and the HPACK prefix integer;
- io_uring `user_data` tags and CQE field decoding;
- the `HttpStatusError` message codec;
- Base64 (standard and URL-safe);
- the HPACK Huffman code: the table, the encoder, the scalar decoder and the
  SIMD fast-path decoder;
- Mojo's `Int(String)` (the stdlib `atol`), which `HttpStatusError.parse`
  relies on.

All flare references are to commit 59bda50. Mojo stdlib references are to
the Mojo 1.1.0 compiler source at commit 8189361e (the version pinned by the
pixi environment).

Each model lives in `Flare/L1_Encoding/<Component>.lean`, in namespace
`Flare.L1.<Component>`. The aggregate is `Flare/L1_Encoding.lean` and the axiom
audit is `Flare/Audit/L1.lean`. Mojo `Int` is modelled as `Int64` (wrapping)
wherever overflow matters: `ByteCursor`, `ProtoVarint`, `Address`,
`CivilTime64`, `MojoAtol` and the Bugs files. Elsewhere it is unbounded
`Int`/`Nat`; where that could hide an overflow, a 64-bit companion model
proves it does not (or says exactly when it does). libc's
`inet_pton`/`inet_ntop` is an environment input, stated as the explicit Prop
hypothesis `InetEnv.Valid`. Mojo's `Int(String)` is modelled from its source
(`MojoAtol.lean`). Nothing is an `axiom`.

Totals:

- Model files: 21, with 440 `theorem` declarations.
- Bugs files: 4 (`ENC_01`..`ENC_04`), with 31 theorems.
- No `sorry`, `admit` or `axiom`.
- The audit prints 111 headline theorems. Outside `Flare.Bugs` the footprint is
  at most `propext`, `Quot.sound` and `Classical.choice`.
- No model file uses `native_decide` or `bv_decide`. Bit-level goals use the
  kernel-checked `bit_blast` macro in `Bits.lean`, which does a per-bit
  extensionality followed by `decide`.
- `ENC_01`, `ENC_03` and `ENC_04` use `native_decide` for concrete traces, and
  the audited ones show the auxiliary axiom.

Every module elaborates in under 40 s. The slowest are `Huffman` (about
35 s, the codec loops) and `HuffmanTable` (about 27 s, the 257-entry pairwise
prefix check by `decide`); `Utf8` takes about 10 s, `CivilTime64` about 8 s,
and the rest a few seconds each.

## Components

### Raw buffers and little-endian words (`Buf.lean`)

Model: `writeBytes` and `readBytes` are the per-byte `unsafe_write` and load
loops. `le16/32/64` and `fromLE16/32/64` are the io_uring ABI store and load
helpers.
Mojo: flare/runtime/io_uring_abi.mojo:394-496.

| Lean name | Statement | Status |
|---|---|---|
| `readBytes_writeBytes` | reading the field just written returns it (in bounds) | proved |
| `readBytes_writeBytes_disjoint` | a write does not disturb a disjoint field | proved |
| `fromLE16_le16`, `fromLE32_le32`, `fromLE64_le64` | load ∘ store = id | proved |
| `le32_fromLE32` | store ∘ load = id on 4-byte buffers | proved |

Assumptions: none. Limitations: the `debug_assert` offset checks are not
modelled. Callers are assumed to stay inside the 64-byte SQE.

### Network byte order (`ByteOrder.lean`)

Model: `htons`, `ntohs`, `htonl` as byte swaps.
Mojo: flare/net/_libc.mojo:176-200.

| Lean name | Statement | Status |
|---|---|---|
| `ntohs_htons`, `htons_ntohs` | mutually inverse | proved |
| `htons_involutive`, `htonl_involutive` | involutions | proved |
| `htons_bytes`, `htonl_bytes` | the swapped value's bytes are the big-endian bytes | proved |
| `htons_injective`, `htonl_injective` | injective | proved |

### `SocketAddr` text codec and port parser (`Address.lean`, `Decimal.lean`)

Model:

- `parsePortStrict` uses Int64 arithmetic.
- `parseIp` and `parseSock` are the `IpAddr.parse` and `SocketAddr.parse`
  paths.
- `render` is `SocketAddr.write_to`.
- `dec` and `decVal` are the shortest decimal rendering and its value.

Mojo: flare/net/address.mojo:54-150, 384-433, 454-464, 468-486.

| Lean name | Statement | Status |
|---|---|---|
| `parsePortStrict_eq_spec` | the strict port parser equals the spec: 1-5 ASCII digits with value ≤ 65535 | proved |
| `parsePortStrict_dec` | parses every port's decimal rendering back to the port | proved |
| `parseIp_canonical` | `IpAddr.parse` returns the address for canonical `inet_ntop` text | proved |
| `parseSock_render` | `SocketAddr.parse ∘ write_to = id` for canonical addresses | proved |
| `decVal_dec`, `dec_all_digit` | `dec` is a digit string whose value is `n` | proved |

Assumption: `InetEnv.Valid`, which says `inet_pton` accepts what `inet_ntop`
prints and returns the same address, plus the character classes of the
canonical text (POSIX, RFC 5952).

### IP predicates (`IpPredicates.lean`)

Model: `isLoopback`, `isUnspecified`, `isPrivate`, `is172Private` and
`isMulticast` operate on the stored text.
Mojo: flare/net/address.mojo:198-293.

| Lean name | Statement | Status |
|---|---|---|
| `isLoopback_dotted`, `isPrivate_dotted`, `isMulticast_dotted`, `is172_dotted`, `isUnspecified_dotted` | on a canonical dotted quad, each string predicate equals the numeric RFC 1122 / 1918 / 5771 predicate | proved |
| `dotted_inj` | the dotted-quad rendering is injective | proved |
| `Bugs.ENC_01.counterexample` | the IPv6 `is_multicast` is true for `00ff::1` | counterexample (ENC-01) |

Limitation: the IPv4 results cover canonical text only. See "Checked, not a
bug".

### `sockaddr_in` / `sockaddr_in6` (`Sockaddr.lean`)

Model: `fillIn` and `fillIn6` write into an arbitrary initial buffer.
`readPort` and `getFamily` are the decoders. The spec side (`kFamily`,
`kPort`, `kLen`, `kByte`) is the kernel's view of the struct on macOS and
Linux.
Mojo: flare/net/_libc.mojo:209-321, 395-411.

| Lean name | Statement | Status |
|---|---|---|
| `fillIn_kFamily`, `kPort_fillIn`, `addr_fillIn`, `zero_fillIn`, `fillIn_len_macos` | the struct flare writes is what the kernel reads, per platform | proved |
| `fillIn6_*`, `kPort_fillIn6`, `flow_scope_fillIn6`, `addr_fillIn6`, `tail_fillIn6` | the same for `sockaddr_in6` | proved |
| `readPort_fillIn`, `readPort_fillIn6` | read_port ∘ fill = id | proved |
| `getFamily_eq_kFamily` | the family decoder agrees with the ABI on both platforms | proved |

Assumption: the platform layouts are transcribed from `<netinet/in.h>`.

### UTF-8 (`Utf8.lean`)

Model:

- Spec: `seqOK` is the RFC 3629 §4 byte table. `WF` is `*UTF8-char`.
  `encode`/`decode` are the §3 bit-pattern encoding over Unicode scalar values.
- `validFrom`/`isValidUtf8` model `_is_valid_utf8`, which has two identical
  copies.
- `step`, `scan`, `fix` and `lossy` model `utf8_lossy_string`: the classifier,
  the fast-path scan, and the U+FFFD replacement loop.

Mojo:

- flare/io/byte_cursor.mojo:52-107
- flare/ws/frame.mojo:553-606
- flare/http/proto/utf8.mojo:24-139

| Lean name | Statement | Status |
|---|---|---|
| `seqOK_iff_encode` | the RFC 3629 §4 table is exactly the image of the §3 encoding on scalar values | proved |
| `decode_encode`, `encode_decode` | the §3 encoding is a bijection between scalars and `seqOK` sequences | proved |
| `isValidUtf8_iff` | both `_is_valid_utf8` copies accept exactly the well-formed strings | proved |
| `scan_none_iff_valid` | the lossy decoder's fast path agrees with the validators | proved |
| `lossy_wf` | `utf8_lossy_string` always returns well-formed UTF-8 | proved |
| `lossy_of_wf`, `lossy_eq_self_iff` | it is the identity exactly on well-formed input | proved |
| `pfx_iff` | a byte string extends to a well-formed sequence iff it is a prefix of a §4 row (`PfxP`) | proved |
| `step_maxSub` | when the classifier rejects position `i`, the length it skips is exactly the maximal subpart of the ill-formed sequence at `i` (`MaxSub`, Unicode 15 §3.9 D93b) | proved |
| `Subst`, `Subst.unique` | the §3.9 "U+FFFD substitution of maximal subparts" relation (well-formed sequences copied, each maximal subpart replaced by one U+FFFD); it is a function | proved |
| `lossy_subst`, `lossy_eq_iff_subst` | `utf8_lossy_string data` is the maximal-subpart substitution of `data`, and the only one | proved |

The replacement policy matches the W3C/WHATWG and Unicode-recommended
practice exactly, for every byte string.

### `ByteReader` / `ByteWriter` / `ProtoReader` (`ByteCursor.lean`)

Model: `Reader` holds `buf` plus an Int64 `pos`.

- `Reader.need` is the shipped `_need` (`guardFixed`: `n > len - pos`, fixed,
  ENC-04). `guard`, `needOld` and `skipOld` are the pre-fix `_need` with
  wrapping `pos + n`.
- The model covers the readers and writers for u8/u16/u32/u64 in both
  endiannesses, plus `read_bytes`, `read_utf8` and `skip`.
- `PReader` is the gRPC `ProtoReader`: `_raw_varint`, `read_tag`, and the
  length-delimited `read_bytes`/`skip`.
- `guardFixed` is the shipped check in both readers. `PReader.skipLen` and
  `PReader.readBytes` use it (fixed, ENC-03); `skipLenOld` and
  `readBytesOld` keep the pre-fix wrapping check for the counterexample.

Mojo:

- flare/io/byte_cursor.mojo:143-346
- flare/grpc/proto.mojo:212-303

| Lean name | Statement | Status |
|---|---|---|
| `guard_iff` | the pre-fix `_need` accepts in-bounds requests and every request whose `pos + n` overflows | proved (characterises ENC-04) |
| `guard_iff_of_small` | for `n < 2^63 - len` (all in-tree callers) the pre-fix `_need` was exact | proved |
| `guardFixed_iff` | the shipped check is exact for every `n` | proved |
| `readU16be_write` … `readU64le_write` | every `read_uN` returns the value `write_uN` wrote, advancing by N/8 | proved |
| `skipOld_inv_of_small`, `skip_inv` | `0 ≤ pos ≤ len` is preserved (pre-fix, small `n`; shipped, any `n`) | proved |
| `readBytes_spec` | shipped `read_bytes(n)` returns exactly `buf[pos:pos+n]` | proved |
| `readUtf8_wf` | `read_utf8` only returns well-formed UTF-8 | proved |
| `rawVarint_inv`, `skipLen_inv`, `readBytes_inv` | the varint reader and the shipped (fixed) length skip and `read_bytes` preserve the invariant | proved |
| `Bugs.ENC_03.counterexample`, `Bugs.ENC_04.counterexample` | the pre-fix checks (`skipLenOld`; `skipOld`) accept a length that moves `pos` negative | counterexample |

The varint round trip is in `ProtoVarint.lean`, below.

### Protobuf varint (`ProtoVarint.lean`)

Model: `writeVarint` is `ProtoWriter._raw_varint` on `UInt64`. The reader is
`PReader.rawVarint` from `ByteCursor.lean` (Int64 position, `UInt64`
accumulator, shift checked against 64 before each byte).
Mojo: flare/grpc/proto.mojo:108-117 (writer), 212-226 (reader).

| Lean name | Statement | Status |
|---|---|---|
| `writeVarint_eq` | the writer, unfolded to `Nat` arithmetic: one byte `v % 128` if `v < 128`, else `v % 128 + 128` followed by the encoding of `v / 128` | proved |
| `writeVarint_length` | the writer emits 1..10 bytes | proved |
| `writeVarint_canonical` | every byte but the last has the continuation bit, the last does not, and the last is non-zero unless it is the only byte: the shortest encoding | proved |
| `rawVarint_writeVarint` | for every `UInt64` `v`, any prefix and any trailing bytes (buffer shorter than 2^63), the reader at the writer's offset returns `v` and advances `pos` by exactly the encoded length | proved |
| `rawVarint_eleven` | a run of 10 continuation bytes, or a run of continuation bytes cut off by the end of the buffer, is rejected | proved |
| `tenth_byte_truncates` | `80 80 80 80 80 80 80 80 80 02` decodes to 0 (bits above 2^63 in the tenth byte are dropped) | proved (see "Checked, not a bug") |

### Civil time (`CivilTime.lean`)

Model: the spec is the proleptic Gregorian calendar:

- `IsLeap`, `monthLen` and `Valid`;
- `next`, the following day;
- `DayNumbering f`, which holds iff `f(1970-01-01) = 0` and `f` increases by
  exactly one per calendar day.

The impl defines `daysFromCivil`, `civilToUnix`, `civilFromDays` and
`unixToCivil`, with Hinnant's era formulas evaluated with floor division (Mojo
`//`). `daysFromCivilFloor` and `civilFromDaysFloor` are the fixed forms.
Mojo: flare/runtime/date_cache.mojo:71-174.

| Lean name | Statement | Status |
|---|---|---|
| `daysFloor_spec` | the fixed forward function is the Gregorian day numbering | proved |
| `civilFloor_daysFloor`, `daysFloor_civilFloor`, `civilFloor_valid` | the fixed pair is a bijection between valid dates and all of `Int` | proved |
| `daysFromCivil_eq_floor`, `civilFromDays_eq_floor` | flare equals the fixed form for March-based year ≥ 0 and day ≥ -719468 (0000-03-01) | proved |
| `daysFromCivil_next` | flare's forward function steps by one per day for March-based year ≥ 0 | proved |
| `civilFromDays_daysFromCivil`, `daysFromCivil_civilFromDays` | flare's pair is mutually inverse from 0000-03-01 on | proved |
| `civilToUnix_unixToCivil`, `unixToCivil_civilToUnix`, `unixToCivil_fields` | the same at second resolution; h/m/s are in range | proved |
| `Bugs.ENC_02.counterexample` | flare's forward function is not a day numbering | counterexample (ENC-02) |

### Civil time on 64-bit `Int` (`CivilTime64.lean`)

Model: `W x` is two's-complement wrapping to 64 bits. `civilToUnix64`,
`civilFromDays64` and `unixToCivil64` wrap every `+`, `-` and `*` of the Mojo
code. `//` and `%` by positive constants cannot overflow and are floor
division and modulus. `parseDigits` is the HTTP-date digit reader.
Mojo: flare/runtime/date_cache.mojo:71-98, 130-174;
flare/http/conditional.mojo:207-216.

| Lean name | Statement | Status |
|---|---|---|
| `civilToUnix64_eq` | for every year in `[-2^63 + 400, 2^63)` and month within `±2^55`, the 64-bit forward function is the exact result wrapped to 64 bits | proved |
| `civilToUnix64_eq_iff` | it is exact iff the exact result is representable | proved |
| `civilToUnix64_exact` | exact for `|year| ≤ 2^38` and the other fields within `±2^30` | proved |
| `jan1_inRange_iff` | 1 January of year `y` is representable exactly for `-292277022656 ≤ y ≤ 292277026596` | proved |
| `civilToUnix64_wraps` | year `2^39` wraps | proved |
| `httpdate_exact` | year 0..9999, month index 0..11 and two-digit day/hour/minute/second (what `_httpdate_to_unix` can pass) never overflow | proved |
| `parseDigits_range`, `parseDigits_two`, `parseDigits_four` | the digit reader returns -1 or a value below 10^n | proved |
| `unixToCivil64_eq` | the 64-bit inverse equals the unbounded model for every 64-bit input | proved |
| `inverse_intermediate_wraps` | `days * 86400` does wrap near `-2^63`; the final result is still exact | proved |
| `daysFromCivil_eq_floor_of_year_nonneg` | every non-negative civil year, including 0000-01 and 0000-02 (March-based year -1), is on the exact side of ENC-02 | proved |

### QUIC variable-length integer (`QuicVarint.lean`)

Model: `encodedLength`, `encode` (None above 2^62 - 1), `tagLength` and
`decode`.
Mojo: flare/quic/varint.mojo:33-138.

| Lean name | Statement | Status |
|---|---|---|
| `decode_encode` | for v ≤ 2^62 - 1, encode succeeds and decode returns (v, length) with any trailing bytes | proved |
| `encode_none_iff` | encode fails exactly above 2^62 - 1 | proved |
| `encode_minimal` | the encoder always picks the shortest form (RFC 9000 §16) | proved |
| `decode_bound`, `decode_le_max` | a k-byte form decodes to < 2^(8k-2) ≤ 2^62 | proved |
| `decode_nonminimal` | non-minimal forms are accepted | proved (by design) |

### HPACK prefix integer (`HpackInt.lean`)

Model: `decode` and its continuation loop `go`, and `encode` with `encRest`.
`Nat` is used because values are capped at 2^31.
Mojo: flare/http2/hpack.mojo:101-153.

| Lean name | Statement | Status |
|---|---|---|
| `decode_encode` | for prefix N in 1..8 and value ≤ 2^31, decode(encode) returns the value and the encoded length, for any surrounding bytes | proved |
| `encode_flags` | the flag bits above the prefix are preserved in the first byte | proved |
| `decode_bounds` | decoded value ≤ 2^31; consumes 1..6 bytes inside the buffer | proved |

### io_uring tags and CQE fields (`UringTag.lean`)

Model: `pack`, `unpackOp`, `unpackConn` (8-bit op, 56-bit connection id),
`connAssert`, `cqeRes` (sign extension of the raw u32), `errno`, `bufferId`.

Mojo:

- flare/runtime/_uring_optag.mojo:57-90
- flare/runtime/io_uring_sqe.mojo:932-982

| Lean name | Statement | Status |
|---|---|---|
| `unpack_pack`, `pack_inj` | unpack ∘ pack = id within the field widths; pack is injective | proved |
| `pack_unpack` | pack ∘ unpack = id on every u64 | proved |
| `cqeRes_eq_toInt32` | the manual sign extension equals the two's-complement reinterpretation | proved |
| `errno_range` | a negative result yields errno in 1..2^31 | proved |
| `bufferId_range` | the buffer id is -1 without `IORING_CQE_F_BUFFER`, else the upper 16 bits | proved |
| `connAssert_fails_open` | the range assert accepts conn_id = 2^63, which unpacks to 0 | proved (see "Checked, not a bug") |

### `HttpStatusError` message codec (`StatusError.lean`)

Model: `render` and `parse`. `parse` locates the `")` marker and converts the
status with an `atol` parameter. `MojoAtol.atol10` is Mojo's
`Int(String)`: `Int.__init__(String)` (simd.mojo:701-714) calls
`String.__int__` (string.mojo:2025-2035), which is `atol(self, base=10)`
(string.mojo:2480-2634). The model covers the POSIX whitespace trim
(codepoint.mojo:491-535), the sign (2637-2662), the digit loop with `_`
separators (2574-2621) and the Int64 overflow check.
Mojo: flare/errors.mojo:87, 217-273.

| Lean name | Statement | Status |
|---|---|---|
| `atol10_dec` | Mojo `atol` maps the decimal rendering of every `n < 2^63` to `n` | proved |
| `atol10_plus`, `atol10_spaces`, `atol10_underscore`, `atol10_leading_zero`, `atol10_rejects`, `atol10_min` | `+404`, ` 404 `, `4_04`, `0404` give 404; `_404`, `404_`, `4__04`, `4 04`, empty, `-` and 2^63 raise; `-2^63` is accepted | proved |
| `parse_render_mojo` | with Mojo's real `atol`, for 100 ≤ status ≤ 599 and any message, parse(render) = (status, message) | proved |
| `parse_render`, `parse_render_of` | the same for any `atol` satisfying `AtolDec` (kept for callers) | proved |
| `parse_status_range` | anything parse accepts has the prefix and a status in 100..599 | proved |

Every row of `atol10_*` was checked against the Mojo runtime in this session
(including `"\t404\x1c"` giving 404); all agreed.

### Base64 (`Base64.lean`)

Model: `encodeStd` (standard alphabet, padded) and `encodeUrl` (URL-safe
alphabet, unpadded). The two decoders accept both alphabets and optional
padding; they are identical and modelled as one `decode`.

Mojo:

- flare/crypto/base64.mojo:35-163
- flare/crypto/hmac.mojo:146-205

| Lean name | Statement | Status |
|---|---|---|
| `decode_encodeStd`, `decode_encodeUrl` | decode ∘ encode = id for both encoders | proved |
| `decodeByte_inv` | the per-character decoder inverts the table up to `-`/`+` and `_`/`/` | proved |
| `decode_canonical` | every accepted input is the standard encoding of its output, up to the alphabet swap and padding | proved |
| `decode_padding` | accepted padding is none, or one or two `=` completing a multiple of 4 | proved |

### HPACK Huffman codec (`HuffmanTable.lean`, `HuffmanRfc.lean`, `Huffman.lean`)

Model:

- `TBL` holds the 257 (code, length) pairs, transcribed mechanically from the
  code switch and the `_LEN_TABLE` string. `RFC_B` is RFC 7541 Appendix B,
  transcribed from the RFC text (symbol, code, length).
- Spec on bit strings (MSB first): `encode` concatenates the codes, pads with
  1-bits and packs; `decodeBits` strips the unique matching code until none
  matches, then requires at most 7 one-bits; EOS is an error. `decode` keeps
  only successful results.
- Impl: `encodeImpl` and `encodedLengthImpl` (64-bit accumulator encoder),
  `lookupImpl` and `decodeImpl` (the canonical-code scalar decoder),
  `decodeSimdImpl` (256-entry root table, long-code walker and tail walker),
  and `decodeDispatch` (SIMD path from 32 bytes).

Mojo: flare/http/hpack_huffman.mojo:119-880; flare/http/hpack_huffman_simd.mojo:110-276.

| Lean name | Statement | Status |
|---|---|---|
| `TBL_eq_rfc` | flare's table equals RFC 7541 Appendix B, entry by entry | proved |
| `table_size`, `fits` | 257 entries; lengths 5..30; each code fits its length | proved |
| `kraft`, `prefix_free` | complete prefix code | proved |
| `eos_all_ones`, `padding_not_code` | EOS is 30 one-bits; no code is a run of 1-7 one-bits | proved |
| `canon_covers`, `tableLengthImpl_eq`, `canonSyms_eq`, `lookupImpl_spec` | the canonical decode tables built at compile time look up exactly the Appendix B code for every bit window | proved |
| `encodeImpl_eq`, `encodedLengthImpl_eq` | the encoder loop computes the spec `encode` and its length | proved |
| `decodeImpl_eq`, `decodeSimdImpl_eq` | the scalar and SIMD decoders compute `decodeFull`, including the partial output and error kind on failure | proved |
| `decodeSimdImpl_eq_decodeImpl`, `decodeDispatch_eq` | the SIMD fast path and the dispatcher agree with the scalar decoder on every input | proved |
| `okOnly_decodeImpl`, `okOnly_decodeSimdImpl`, `okOnly_decodeDispatch` | keeping only successful results, each decoder is `decode` | proved |
| `decode_eq_some_iff` | `decode x = some out` iff the bits of `x` are the codes of `out` followed by at most 7 one-bits | proved |
| `decode_encode`, `decodeImpl_encodeImpl` | decode ∘ encode = id, for the spec and for the Mojo loops | proved |
| `decodeBits_eos`, `decodeBits_padding_too_long`, `decodeBits_padding_eos`, `decodeBits_invalid_padding` | each RFC 7541 §5.2 violation (EOS in the string, padding over 7 bits, padding that is not an EOS prefix) yields its error | proved |

The API for other layers is described in `formal/.lake/notes/huffman_api.md`.

## Findings

Repro status below is from runs on macOS arm64 in this session. "Flip" means
the minimal fix was applied to the single flare file and the repro rerun.
The file was then restored with `git checkout`, and `git status --short flare/`
was empty after each flip.

### ENC-01: `IpAddr.is_multicast` misclassifies IPv6 addresses with a short first group

Severity: low. The predicate is public API with no in-tree caller. A caller
using it for a policy decision (for example, refusing to connect to multicast)
gets wrong answers for `0x00ff`, `0x0ff0`..`0x0fff` first groups.
Spec: RFC 4291 §2.7 says IPv6 multicast is `ff00::/8`, i.e. the first byte is
`0xff`.
What goes wrong: flare/net/address.mojo:232-240 tests
`self._addr.startswith("ff")` on the `inet_ntop` text. RFC 5952 §4.1 drops
leading zeros, so `00ff::1` is stored as `ff::1` and reported as multicast.
Lean: `Flare.Bugs.ENC_01.counterexample`.
Fix: also require that the first `:` is at index 4. `isMulticast6Fixed_correct`
proves the fix equals the RFC predicate for every first group.
Repro: `formal/repro/ENC-01_ipv6_multicast_short_group.mojo`, observed
`BUG REPRODUCED: is_multicast() is True for non-ff00::/8 addresses: 00ff::1 (stored as ff::1); fff:: (stored as fff::); ff0:1:: (stored as ff0:1::); `.
Flip: `OK: is_multicast() is False for 00ff::1, fff::, ff0:1:: and True for ff02::1`, exit 0.

### ENC-02: civil-time conversion is one day off before 0000-03-01

Severity: low. In-tree inputs are HTTP-dates with a 4-digit year, which are
exact (`daysFromCivil_eq_floor`), and clock seconds after 1970. The defect is
inside the public helpers' documented domain: the comments say "exact across
the proleptic Gregorian calendar" (date_cache.mojo:69-70) and "negative is
fine" (:138).
Spec: `DayNumbering`, the Gregorian day count anchored at 1970-01-01.
What goes wrong: date_cache.mojo:92 and :153 compute the era with Hinnant's
formula `(year if year >= 0 else year - 399) // 400`. That formula was written
for truncating division; Mojo `//` floors. The consequences:

- Every date whose March-based year is negative and not ≡ 399 (mod 400) comes
  out one day early.
- The inverse is wrong for every day before 0000-03-01 except 29 February of
  years divisible by 400.

Lean:

- `Flare.Bugs.ENC_02.counterexample`: -1-02-28 and -1-03-01 map to -719836 and
  -719834.
- `inverse_counterexample`: the true day number of -1-03-01 decodes as
  -1-03-02.

Fix: `era = year // 400` and `era = days // 146097`. `fixed_spec`,
`fixed_left_inverse` and `fixed_right_inverse` prove the fixed pair is the
Gregorian numbering and a bijection on all of `Int`.
Repro: `formal/repro/ENC-02_civil_time_negative_years.mojo`, observed
`BUG REPRODUCED: civil_to_unix_seconds(-1-02-28 -> -1-03-01) gap = 172800 s (want 86400); unix_seconds_to_civil(-719834 days) = -1 3 2 (want -1 3 1)`.
Flip (both lines): `OK: consecutive days before year 0 differ by 86400 s and round-trip`, exit 0.

### ENC-03: `ProtoReader` length check overflows; one gRPC health request crashes the server

Severity: high. The trigger is an 11-byte unauthenticated request body to
`grpc.health.v1.Health/Check` or `/Watch`. In a checked build this is a remote
abort (bounds assertion); in an unchecked build it is an out-of-bounds read at
a wild offset. `read_bytes` on the same path also requests
`List(capacity≈2^63)`.
Spec: protobuf length-delimited records must fit in the message. The reader's
contract is that a truncated field raises and `0 ≤ pos ≤ len(data)`.
What goes wrong: flare/grpc/proto.mojo:282-283 and :299-300 check
`self.pos + n > len(self.data)` with wrapping `Int`. For the length
`n = 2^63 - 1` the sum is negative, so the check passes and `pos` becomes
`-9223372036854775799` while `has_more()` stays true.
`decode_health_request` (grpc/health.mojo:44-55, called at :110 and :150) runs
this loop on the request body. Earlier in this session the decoder itself
aborted with `Assert Error: index -9223372036854775799 is out of bounds, valid range is 0 to 10`
(proto.mojo:223).
Lean: `Flare.Bugs.ENC_03.counterexample`. From a reader satisfying the
invariant, `skipLen` succeeds, breaks the invariant, and leaves `hasMore`
true.
Fix: `if n < 0 or n > len(self.data) - self.pos` at both sites.
`fixed_preserves_inv` proves the fixed check keeps the invariant for every
input, and `fixed_rejects` proves it rejects the trace.
Repro: `formal/repro/ENC-03_proto_length_overflow.mojo`, observed
`BUG REPRODUCED: skip() accepted a length of 2^63-1 in an 11-byte message; pos = -9223372036854775799 has_more() = True`.
Flip (both sites): `OK: skip() rejects a length-delimited field longer than the message`, exit 0.
Status: resolved. Both sites in `flare/grpc/proto.mojo` now test `n > len(self.data) - self.pos`; the model's `PReader.skipLen` / `readBytes` mirror the fixed code (the old ones are `skipLenOld` / `readBytesOld`, used by `Bugs.ENC_03.counterexample`). Tests: `tests/grpc/test_grpc_proto.mojo::test_skip_rejects_length_beyond_message`, `::test_read_bytes_rejects_length_beyond_message`, `::test_skip_len_exact_remaining_ok` and `tests/grpc/test_grpc_interceptor_health.mojo::test_health_request_huge_length_raises`.

### ENC-04: `ByteReader._need` overflows; `skip`/`read_bytes` accept a huge length

Severity: medium for the public API, not reachable in-tree. The module promises
"every read is bounds-checked". In-tree callers pass `Int(u32)` lengths, for
which `guard_iff_of_small` proves the check exact. A caller that forwards a
64-bit length from the wire gets the same failure as ENC-03.
Spec: byte_cursor.mojo:1-8 and 114-119 say a short buffer raises and
`0 ≤ pos ≤ len(buf)`.
What goes wrong: byte_cursor.mojo:144-155 checks `self.pos + n > len(self.buf)`
with wrapping `Int`. After one `read_u8()` on a 4-byte buffer,
`skip(Int.MAX)` succeeds and sets `pos = -2^63`. `guard_iff` characterises
exactly which requests are wrongly accepted.
Lean: `Flare.Bugs.ENC_04.counterexample`.
Fix: `if n < 0 or n > len(self.buf) - self.pos`. `fixed_preserves_inv` and
`fixed_rejects` cover it, and `guardFixed_iff` shows the fixed check is exact
for every `n`.
Repro: `formal/repro/ENC-04_byte_reader_need_overflow.mojo`, observed
`BUG REPRODUCED: skip(Int.MAX) on a 4-byte buffer succeeded; pos = -9223372036854775808 remaining() = -9223372036854775804`.
Flip: `OK: skip(Int.MAX) raises; pos stays 1`, exit 0.
Status: resolved. `ByteReader._need` now tests `n > len(self.buf) - self.pos`; the model's `Reader.need`/`skip`/`readBytes` mirror it (old: `needOld`, `skipOld`; shipped: `skip_inv`, `readBytes_spec`). Tests: `tests/io/test_byte_cursor.mojo::test_huge_length_rejected_without_moving_cursor`, `::test_exact_remaining_length_accepted`.

## Checked, not a bug

- QUIC varint: non-minimal encodings are accepted (`decode_nonminimal`). RFC
  9000 §16 permits them, and the encoder is always minimal
  (`encode_minimal`).
- HPACK integer: overlong continuation forms are accepted; RFC 7541 §5.1 does
  not forbid them. Values are capped at 2^31 and at most 6 bytes are consumed
  (`decode_bounds`), so there is no overflow.
- Base64:
  - Both decoders accept both alphabets and optional padding. This is
    deliberate, documented leniency; RFC 4648 §3.3 allows it when the
    referencing spec says so.
  - `decode_canonical` bounds the leniency: accepted inputs differ from the
    canonical encoding only by the `-`/`+` and `_`/`/` swap and the padding.
  - For signed cookies this means a MAC has several accepted spellings. The
    MAC still covers the exact payload string, so this is malleability of the
    token text, not a forgery.
- `HttpStatusError.parse`:
  - Mojo `Int(String)` also accepts `+404`, ` 404 `, `4_04` and `0404`
    (`atol10_plus` .. `atol10_leading_zero`, matching the runtime).
  - The result is still range-checked (`parse_status_range`), and the message
    is produced by `render` in-tree, so this leniency cannot make a rendered
    message parse differently (`parse_render_mojo`).
- Protobuf varint, tenth byte: `_raw_varint` uses only bit 0 of a tenth byte,
  so a non-canonical 10-byte varint such as `80 80 80 80 80 80 80 80 80 02`
  decodes to 0 instead of raising (`tenth_byte_truncates`). Go's `protowire`
  rejects such input. It is not a bug here: every `UInt64` already has a
  canonical encoding that the reader accepts (`rawVarint_writeVarint`), so
  the extra spellings add no reachable value and no new length-check bypass
  (ENC-03 is triggered by the canonical encoding of 2^63 - 1). Varints longer
  than 10 bytes are rejected (`rawVarint_eleven`).
- Civil time overflow: `civil_to_unix_seconds` wraps for years beyond about
  ±2.9·10^11 (`jan1_inRange_iff`, `civilToUnix64_wraps`), but its only
  in-tree caller passes a 4-digit year and 2-digit fields
  (`parseDigits_four`, `httpdate_exact`), and `unix_seconds_to_civil` is
  exact for every 64-bit input (`unixToCivil64_eq`). No overflow is
  reachable.
- io_uring `connAssert`: the debug assert accepts conn_id ≥ 2^63
  (`connAssert_fails_open`). It is debug-only, and conn ids are slot indices
  far below 2^56. Within that range pack/unpack is exact (`unpack_pack`).
- IPv4 string predicates on non-canonical text: `IpAddr(addr, is_v6)` accepts
  any string, and the predicates do not re-validate it. That is a documented,
  unenforced precondition. On canonical text they are exact.
- CQE result, errno and buffer-id decoding are correct for every raw value
  (`cqeRes_eq_toInt32`, `errno_range`, `bufferId_range`).
- `utf8_lossy_string`, `_is_valid_utf8` (both copies) and `read_utf8` agree
  with RFC 3629, and their outputs are always well-formed.
  `utf8_lossy_string` also replaces exactly one U+FFFD per maximal ill-formed
  subpart (`lossy_eq_iff_subst`), so it conforms to Unicode §3.9 and there is
  no deviation. HPACK-01 (L3 report) is not caused by the replacement
  policy. It follows from applying any lossy conversion to header bytes,
  which changes exactly the non-UTF-8 inputs (`lossy_eq_self_iff`).
- HPACK Huffman: the table is RFC 7541 Appendix B (`TBL_eq_rfc`), and the
  encoder, scalar decoder and SIMD decoder implement §5.2 exactly, including
  all three padding/EOS error rules. The SIMD path agrees with the scalar
  path on every input, so it cannot be used to smuggle a value past the
  scalar decoder.

## Traceability

| Lean definition | Mojo file:line @59bda50 | Theorems | Status |
|---|---|---|---|
| `Flare.L1.Buf.writeBytes`, `readBytes` | flare/runtime/io_uring_abi.mojo:407-408, 425-428, 445-446, 462-463, 477-479, 495-496 | `readBytes_writeBytes`, `readBytes_writeBytes_disjoint` | proved |
| `Flare.L1.Buf.le16/32/64`, `fromLE16/32/64` | flare/runtime/io_uring_abi.mojo:394-496 | `fromLE64_le64`, `le32_fromLE32` | proved |
| `Flare.L1.ByteOrder.htons`, `ntohs`, `htonl` | flare/net/_libc.mojo:176-200 | `htons_involutive`, `htonl_involutive`, `htonl_bytes` | proved |
| `Flare.L1.Address.parsePortStrict` | flare/net/address.mojo:468-486 | `parsePortStrict_eq_spec`, `parsePortStrict_dec` | proved |
| `Flare.L1.Address.parseIp`, `parseSock`, `render` | flare/net/address.mojo:54-150, 384-433, 454-464 | `parseIp_canonical`, `parseSock_render` | proved |
| `Flare.L1.IpPredicates.isLoopback`, `isUnspecified`, `isPrivate`, `is172Private`, `isMulticast` | flare/net/address.mojo:198-293 | `*_dotted`, `Bugs.ENC_01.counterexample` | proved; counterexample (ENC-01) |
| `Flare.L1.Sockaddr.fillIn`, `fillIn6`, `readPort`, `getFamily` | flare/net/_libc.mojo:209-321, 395-411 | `readPort_fillIn`, `addr_fillIn6`, `getFamily_eq_kFamily` | proved |
| `Flare.L1.Utf8.validFrom`, `isValidUtf8` | flare/io/byte_cursor.mojo:52-107; flare/ws/frame.mojo:553-606 | `isValidUtf8_iff` | proved |
| `Flare.L1.Utf8.step`, `scan`, `fix`, `lossy` | flare/http/proto/utf8.mojo:24-139 | `scan_none_iff_valid`, `lossy_wf`, `lossy_eq_self_iff` | proved |
| `Flare.L1.ByteCursor.guard`, `Reader.*` | flare/io/byte_cursor.mojo:143-268 | `guard_iff`, `guard_iff_of_small`, `guardFixed_iff`, `readU64le_write`, `readUtf8_wf`, `skip_inv`, `Bugs.ENC_04.counterexample` | proved; counterexample (ENC-04) |
| `Flare.L1.ByteCursor.writeU16be` … `writeU64le` | flare/io/byte_cursor.mojo:307-340 | `readU16be_write` … `readU64le_write` | proved |
| `Flare.L1.ByteCursor.PReader.*` | flare/grpc/proto.mojo:212-303 | `rawVarint_inv`, `skipLen_inv`, `readBytes_inv`, `Bugs.ENC_03.counterexample` | proved; counterexample (ENC-03) |
| `Flare.L1.ProtoVarint.writeVarint` | flare/grpc/proto.mojo:108-117 | `writeVarint_length`, `writeVarint_canonical`, `rawVarint_writeVarint` | proved |
| `Flare.L1.ByteCursor.PReader.rawVarint` | flare/grpc/proto.mojo:212-226 | `rawVarint_writeVarint`, `rawVarint_eleven`, `tenth_byte_truncates` | proved |
| `Flare.L1.CivilTime.daysFromCivil`, `civilToUnix` | flare/runtime/date_cache.mojo:71-98 | `daysFromCivil_eq_floor`, `daysFromCivil_next`, `Bugs.ENC_02.counterexample` | proved (year ≥ 0); counterexample (ENC-02) |
| `Flare.L1.CivilTime.civilFromDays`, `unixToCivil` | flare/runtime/date_cache.mojo:130-174 | `civilFromDays_daysFromCivil`, `civilToUnix_unixToCivil`, `Bugs.ENC_02.inverse_counterexample` | proved (from 0000-03-01); counterexample (ENC-02) |
| `Flare.L1.CivilTime.civilToUnix64` | flare/runtime/date_cache.mojo:71-98 | `civilToUnix64_eq`, `civilToUnix64_exact`, `jan1_inRange_iff`, `httpdate_exact` | proved |
| `Flare.L1.CivilTime.civilFromDays64`, `unixToCivil64` | flare/runtime/date_cache.mojo:130-174 | `civilFromDays64_eq`, `unixToCivil64_eq` | proved |
| `Flare.L1.CivilTime.parseDigits` | flare/http/conditional.mojo:207-216 | `parseDigits_range`, `parseDigits_four` | proved |
| `Flare.L1.QuicVarint.encode`, `decode`, `tagLength` | flare/quic/varint.mojo:33-138 | `decode_encode`, `encode_minimal`, `decode_le_max` | proved |
| `Flare.L1.HpackInt.encode`, `decode`, `go` | flare/http2/hpack.mojo:101-153 | `decode_encode`, `decode_bounds` | proved |
| `Flare.L1.UringTag.pack`, `unpackOp`, `unpackConn`, `connAssert` | flare/runtime/_uring_optag.mojo:57-90 | `unpack_pack`, `pack_unpack`, `connAssert_fails_open` | proved |
| `Flare.L1.UringTag.cqeRes`, `errno`, `bufferId` | flare/runtime/io_uring_sqe.mojo:932-982 | `cqeRes_eq_toInt32`, `errno_range`, `bufferId_range` | proved |
| `Flare.L1.StatusError.render`, `parse` | flare/errors.mojo:87, 217-273 | `parse_render_mojo`, `parse_render`, `parse_status_range` | proved |
| `Flare.L1.MojoAtol.isPosixSpace`, `trimSign`, `digits`, `atol10` | Mojo std/collections/string/codepoint.mojo:491-535, string.mojo:2480-2662 @8189361e | `atol10_dec`, `atol10_rejects`, `atol10_min` | proved |
| `Flare.L1.Base64.encodeStd`, `decode` | flare/crypto/base64.mojo:35-163 | `decode_encodeStd`, `decode_canonical`, `decode_padding` | proved |
| `Flare.L1.Base64.encodeUrl`, `decode` | flare/crypto/hmac.mojo:146-205 | `decode_encodeUrl` | proved |
| `Flare.L1.Huffman.TBL` | flare/http/hpack_huffman.mojo:119-641, 643-667 | `TBL_eq_rfc`, `kraft`, `prefix_free`, `padding_not_code` | proved |
| `Flare.L1.Huffman.canonTableImpl`, `canonSymsImpl`, `lookupImpl` | flare/http/hpack_huffman.mojo:744-807 | `canonSyms_eq`, `canon_covers`, `lookupImpl_spec` | proved |
| `Flare.L1.Huffman.encodeImpl`, `encodedLengthImpl` | flare/http/hpack_huffman.mojo:684-737 | `encodeImpl_eq`, `encodedLengthImpl_eq` | proved |
| `Flare.L1.Huffman.decodeImpl` | flare/http/hpack_huffman.mojo:820-880 | `decodeImpl_eq`, `decodeImpl_encodeImpl`, `okOnly_decodeImpl` | proved |
| `Flare.L1.Huffman.decodeSimdImpl`, `decodeDispatch` | flare/http/hpack_huffman_simd.mojo:110-276 | `decodeSimdImpl_eq`, `decodeSimdImpl_eq_decodeImpl`, `decodeDispatch_eq`, `okOnly_decodeDispatch` | proved |
