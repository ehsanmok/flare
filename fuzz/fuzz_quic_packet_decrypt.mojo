"""Fuzz harness: ``OpenSslQuicCrypto.decrypt`` over random
ciphertext + AAD + packet-number inputs, plus the
``unprotect_handshake_packet`` and ``unprotect_1rtt_packet``
entry points over random datagrams.

This is the safety harness for the QUIC AEAD-open path.  The
prod hot path will feed the carrier arbitrary bytes from the
network, so the AEAD open primitive MUST:

1. Never panic / leak / read past the buffer on arbitrary input.
2. Either return a plaintext (impossible on random bytes -- the
   AEAD tag failure rate against a fixed key is ~ 1 / 2^128) or
   raise a regular ``Error``.
3. Specifically *raise* (not crash) when ciphertext is shorter
   than the 16-byte AEAD tag.
4. Reject malformed long-header / short-header bytes cleanly
   (header-parse + HP-mask paths in protection.mojo).

The harness builds inputs by partitioning the fuzz bytes into
``(aead_choice, packet_number, aad, ct)`` and runs decrypt under
all three AEADs (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305).
After the AEAD round it feeds the same bytes through
``unprotect_handshake_packet`` and ``unprotect_1rtt_packet`` so
the new Q10-W header-parse + HP-mask paths see the same fuzz
breadth (200K runs total). The carrier's keys are fixed across
runs so the AEAD failure path is the dominant code path the
fuzzer explores; the round-trip property (encrypt -> decrypt
yields the plaintext) is covered by the unit tests against RFC
9001 Appendix A vectors.

Run:
    pixi run --environment fuzz fuzz-quic-packet-decrypt
"""

from mozz import fuzz, FuzzConfig
from std.memory import Span

from flare.quic.crypto import (
    OpenSslQuicCrypto,
    PacketKeys,
    QuicAead,
)
from flare.quic.protection import (
    unprotect_1rtt_packet,
    unprotect_handshake_packet,
)

# The egress builders that route Handshake + 1-RTT through
# rustls AEAD share their inbound level-derivation helper with
# the dispatch pump; the helper
# must never panic on arbitrary first bytes, since it's the
# very first thing the reactor calls per datagram.
from flare.quic.server import _inbound_level_for_datagram
from flare.tls import QuicEncryptionLevel


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


def _make_keys(aead: Int, key_len: Int) -> PacketKeys:
    var key = List[UInt8]()
    for i in range(key_len):
        key.append(UInt8(0x10 + (i % 16)))
    var iv = List[UInt8]()
    for i in range(12):
        iv.append(UInt8(0x40 + i))
    var hp = List[UInt8]()
    for i in range(key_len):
        hp.append(UInt8(0x60 + (i % 16)))
    return PacketKeys(aead=aead, key=key^, iv=iv^, hp=hp^)


def _carrier_for(choice: Int) raises -> OpenSslQuicCrypto:
    if choice == 0:
        return OpenSslQuicCrypto(keys=_make_keys(QuicAead.AES_128_GCM, 16))
    if choice == 1:
        return OpenSslQuicCrypto(keys=_make_keys(QuicAead.AES_256_GCM, 32))
    return OpenSslQuicCrypto(keys=_make_keys(QuicAead.CHACHA20_POLY1305, 32))


def target(data: List[UInt8]) raises:
    if len(data) < 1:
        return
    # First byte selects the AEAD; mod 3.
    var aead_choice = Int(data[0]) % 3
    var crypto = _carrier_for(aead_choice)

    # Bytes 1..9 (8 bytes) form the packet number BE.
    var pn = UInt64(0)
    var n_pn_bytes = 8 if len(data) >= 9 else (len(data) - 1)
    for i in range(n_pn_bytes):
        pn = (pn << 8) | UInt64(data[1 + i])

    # Bytes 9..(9+aad_len) form the AAD; the rest is ciphertext.
    # Cap aad_len to 32 to keep the input space split useful.
    var rest_start = 1 + n_pn_bytes
    var rest_len = len(data) - rest_start
    if rest_len <= 0:
        return
    var aad_len = (Int(data[0]) >> 2) % 33  # 0..32
    if aad_len > rest_len:
        aad_len = 0
    var aad = List[UInt8]()
    for i in range(aad_len):
        aad.append(data[rest_start + i])
    var ct = List[UInt8]()
    for i in range(rest_start + aad_len, len(data)):
        ct.append(data[i])

    # Property: decrypt either returns (impossibly, for random
    # bytes against a fixed key) or raises.  It must never crash.
    try:
        _ = crypto.decrypt(Span[UInt8, _](ct), Span[UInt8, _](aad), pn)
    except _:
        # Tag-failure / short-ct / misconfig all surface as Error
        # at the Mojo boundary; that's the expected path.
        pass

    # Also exercise header_protection_mask on the first 16 bytes
    # of the ciphertext if available -- the HP mask path is a
    # different FFI thunk and has its own buffer-bounds discipline.
    if len(ct) >= 16:
        var sample = List[UInt8]()
        for i in range(16):
            sample.append(ct[i])
        try:
            _ = crypto.header_protection_mask(Span[UInt8, _](sample))
        except _:
            pass

    # Drive the Handshake + 1-RTT unprotect entry points with
    # the same fuzz datagram. The carriers use
    # the same fixed PacketKeys schedule so the AEAD-tag-failure
    # path dominates; the prior interesting bug class
    # (out-of-bounds in the HP-sample window or in the truncated-
    # pn pointer) is exactly what these two extra calls
    # rediscover on every run with random first bytes.
    var fuzz_secret = List[UInt8]()
    for i in range(32):
        fuzz_secret.append(UInt8(0x80 + (i % 16)))
    var aead = QuicAead.AES_128_GCM
    if aead_choice == 1:
        aead = QuicAead.AES_256_GCM
    elif aead_choice == 2:
        aead = QuicAead.CHACHA20_POLY1305
    # Try Handshake (long header) unprotect.
    try:
        _ = unprotect_handshake_packet(
            Span[UInt8, _](data),
            Span[UInt8, _](fuzz_secret),
            UInt64(0),
            aead,
        )
    except _:
        pass
    # Try 1-RTT (short header) unprotect for two pinned DCID
    # lengths the reactor cares about: 0 (the RFC A.5 shape) and
    # 8 (the default flare server local-CID length).
    try:
        _ = unprotect_1rtt_packet(
            Span[UInt8, _](data),
            Span[UInt8, _](fuzz_secret),
            UInt64(0),
            0,
            aead,
        )
    except _:
        pass
    try:
        _ = unprotect_1rtt_packet(
            Span[UInt8, _](data),
            Span[UInt8, _](fuzz_secret),
            UInt64(0),
            8,
            aead,
        )
    except _:
        pass

    # Exercise the inbound level classifier over the same fuzz
    # datagram.  Property: the
    # classifier MUST return one of the four valid QUIC
    # encryption-level codepoints, and MUST NOT panic on any
    # first-byte combination (including the long-header bit
    # flipped with otherwise garbage type bits).
    var lvl = _inbound_level_for_datagram(Span[UInt8, _](data))
    if (
        lvl != QuicEncryptionLevel.INITIAL
        and lvl != QuicEncryptionLevel.EARLY_DATA
        and lvl != QuicEncryptionLevel.HANDSHAKE
        and lvl != QuicEncryptionLevel.APPLICATION
    ):
        raise Error(
            "fuzz: _inbound_level_for_datagram returned out-of-range level "
            + String(lvl)
        )


def main() raises:
    print("=" * 60)
    print("fuzz_quic_packet_decrypt.mojo -- QUIC AEAD open safety")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    # Tiny input -- just the AEAD selector byte.
    seeds.append(_bytes("\x00"))
    # AEAD selector + zero packet number + short ct.
    seeds.append(_bytes("\x01\x00\x00\x00\x00\x00\x00\x00\x00"))
    # Long input -- a 100-byte buffer the carrier can chew on.
    var big = List[UInt8]()
    big.append(UInt8(0x02))  # ChaCha20-Poly1305
    for i in range(100):
        big.append(UInt8(i))
    seeds.append(big^)
    # Exactly the 17-byte minimum (1-byte AEAD + 16-byte tag).
    var minimal = List[UInt8]()
    minimal.append(UInt8(0))
    for i in range(16):
        minimal.append(UInt8(0))
    seeds.append(minimal^)

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_packet_decrypt",
            corpus_dir="fuzz/corpus/quic_packet_decrypt",
            max_input_len=256,
        ),
        seeds,
    )
