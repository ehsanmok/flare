"""QUIC v1 crypto primitives (RFC 9001).

Sans-I/O. Every entry point is a pure function over byte spans;
no socket, no fd, no TLS context, no allocator that survives the
call. The QUIC server reactor plumbs the AEAD output
into the packet codec; this module owns the math.

## Layering

The full QUIC crypto story has three slabs that compose:

1. **HKDF** (RFC 5869) -- key derivation. Implemented here over the
   ``hmac_sha256`` primitive that ``flare.crypto`` already exports
   from the OpenSSL FFI. Pure math; no AEAD dependency.

2. **HKDF-Expand-Label** (RFC 8446 §7.1) -- the TLS 1.3 label
   wrapper around HKDF-Expand. RFC 9001 §5.1 reuses TLS 1.3's
   schedule with QUIC-specific labels (``quic key``, ``quic iv``,
   ``quic hp``, ``quic ku``). Implemented here.

3. **AEAD packet protection** (RFC 9001 §5.3-5.4) -- AES-128-GCM /
   AES-256-GCM / ChaCha20-Poly1305 encrypt-with-AD over each
   packet's frame contents, plus the AES-128-CTR-based header
   protection mask (§5.4) that hides the packet number and the
   four header low bits. The trait :trait:`QuicCrypto` names the
   surface a backend must implement; :class:`OpenSslQuicCrypto`
   wires that surface to the OpenSSL FFI for h3 server
   connections (the OpenSSL-backed packet protection path), and
   the rustls binding under :mod:`flare.tls.rustls_quic` drives
   the TLS exchange itself.

## Backends

- :class:`StubQuicCrypto` -- typed sentinel for tests that
  want to assert the trait boundary without driving a real
  AEAD. Encrypt / decrypt / mask raise ``NotImplemented``.
- :class:`OpenSslQuicCrypto` -- production AEAD + header-
  protection backend. Binds the ``flare_quic_aead_*`` /
  ``flare_quic_hp_mask`` FFI thunks from ``libflare_tls.so``
  to the trait surface. Constructs from a 32-byte direction
  secret via :py:meth:`OpenSslQuicCrypto.from_secret`, which
  runs the RFC 9001 paragraph 5.1 schedule.

References:
- RFC 5869 "HMAC-based Extract-and-Expand Key Derivation Function".
- RFC 8446 "The Transport Layer Security (TLS) Protocol Version 1.3".
- RFC 9000 "QUIC: A UDP-Based Multiplexed and Secure Transport".
- RFC 9001 "Using TLS to Secure QUIC".
"""

from std.collections import List, Optional
from std.ffi import OwnedDLHandle, c_int
from std.memory import Span

from flare.crypto.hmac import hmac_sha256
from flare.net.socket import _find_flare_lib


# ── RFC 9001 §5.2 initial salt (QUIC v1) ────────────────────────────────


comptime QUIC_V1_INITIAL_SALT: List[UInt8] = [
    UInt8(0x38),
    UInt8(0x76),
    UInt8(0x2C),
    UInt8(0xF7),
    UInt8(0xF5),
    UInt8(0x59),
    UInt8(0x34),
    UInt8(0xB3),
    UInt8(0x4D),
    UInt8(0x17),
    UInt8(0x9A),
    UInt8(0xE6),
    UInt8(0xA4),
    UInt8(0xC8),
    UInt8(0x0C),
    UInt8(0xAD),
    UInt8(0xCC),
    UInt8(0xBB),
    UInt8(0x7F),
    UInt8(0x0A),
]
"""RFC 9001 §5.2 QUIC v1 initial salt -- ``0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a``.

Used as the HKDF-Extract salt when deriving the initial-secret
from the client's Destination Connection ID. RFC 9001 §5.2 names
this as the only valid salt for the v1 wire format."""


comptime SHA256_OUTPUT_BYTES: Int = 32
"""SHA-256 hash output size in bytes. Used as the HKDF-Extract
output length and the default HKDF-Expand-Label output length
for the QUIC initial-secret derivations."""


# ── RFC 5869 HKDF ──────────────────────────────────────────────────────


def hkdf_extract(
    salt: Span[UInt8, _], ikm: Span[UInt8, _]
) raises -> List[UInt8]:
    """RFC 5869 §2.2 -- ``PRK = HMAC-Hash(salt, IKM)``.

    Returns the 32-byte pseudorandom key (PRK). The hash is fixed
    at SHA-256; QUIC v1 mandates SHA-256 for the initial keys
    schedule (RFC 9001 §5.2).
    """
    var salt_bytes = List[UInt8]()
    for i in range(len(salt)):
        salt_bytes.append(salt[i])
    var ikm_bytes = List[UInt8]()
    for i in range(len(ikm)):
        ikm_bytes.append(ikm[i])
    return hmac_sha256(salt_bytes, ikm_bytes)


def hkdf_expand(
    prk: Span[UInt8, _], info: Span[UInt8, _], length: Int
) raises -> List[UInt8]:
    """RFC 5869 §2.3 -- ``OKM = HKDF-Expand(PRK, info, L)``.

    Iteratively computes ``T(i) = HMAC-Hash(PRK, T(i-1) || info || i)``
    where ``T(0)`` is empty and ``i`` is a single byte counter
    starting at 1. The output is the first ``length`` bytes of
    ``T(1) || T(2) || ... || T(N)``. ``length`` must be at most
    ``255 * 32`` (the SHA-256 hash output size).
    """
    if length < 0:
        raise Error("hkdf_expand: negative length")
    if length > 255 * SHA256_OUTPUT_BYTES:
        raise Error("hkdf_expand: length exceeds 255*HashLen")
    var prk_bytes = List[UInt8]()
    for i in range(len(prk)):
        prk_bytes.append(prk[i])
    var out = List[UInt8]()
    var t_prev = List[UInt8]()  # empty for the first iteration
    var counter: UInt8 = UInt8(1)
    while len(out) < length:
        var msg = List[UInt8]()
        for b in t_prev:
            msg.append(b)
        for i in range(len(info)):
            msg.append(info[i])
        msg.append(counter)
        var t_cur = hmac_sha256(prk_bytes, msg)
        var remaining = length - len(out)
        var take = remaining if remaining < len(t_cur) else len(t_cur)
        for i in range(take):
            out.append(t_cur[i])
        t_prev = t_cur^
        counter = counter + UInt8(1)
    return out^


# ── RFC 8446 §7.1 HKDF-Expand-Label (TLS 1.3 schedule) ──────────────────


def hkdf_expand_label(
    secret: Span[UInt8, _],
    label: String,
    context: Span[UInt8, _],
    length: Int,
) raises -> List[UInt8]:
    """RFC 8446 §7.1 -- ``HKDF-Expand-Label(Secret, Label, Context, Length)``.

    Wraps HKDF-Expand with the canonical TLS 1.3 HkdfLabel struct
    serialization:

    ```
    struct {
        uint16 length = Length;
        opaque label<7..255> = "tls13 " + Label;
        opaque context<0..255> = Context;
    } HkdfLabel;
    ```

    QUIC v1 (RFC 9001 §5.1) replaces ``"tls13 "`` with ``"tls13 "``
    -- same prefix -- and uses labels ``"client in"`` /
    ``"server in"`` for initial-secret derivation, then ``"quic key"``
    / ``"quic iv"`` / ``"quic hp"`` for the AEAD packet-protection
    keys.
    """
    var prefix = String("tls13 ")
    var full_label = prefix + label
    if full_label.byte_length() > 255:
        raise Error("hkdf_expand_label: full label too long")
    if len(context) > 255:
        raise Error("hkdf_expand_label: context too long")
    if length > 0xFFFF:
        raise Error("hkdf_expand_label: length exceeds 0xFFFF")
    var info = List[UInt8]()
    info.append(UInt8((length >> 8) & 0xFF))
    info.append(UInt8(length & 0xFF))
    info.append(UInt8(full_label.byte_length()))
    for b in full_label.as_bytes():
        info.append(b)
    info.append(UInt8(len(context)))
    for i in range(len(context)):
        info.append(context[i])
    return hkdf_expand(secret, Span[UInt8, _](info), length)


# Convenience wrapper: most QUIC callers pass an empty context.
def hkdf_expand_label_empty_context(
    secret: Span[UInt8, _], label: String, length: Int
) raises -> List[UInt8]:
    """``hkdf_expand_label`` with an empty Context value."""
    var info = List[UInt8]()
    info.append(UInt8((length >> 8) & 0xFF))
    info.append(UInt8(length & 0xFF))
    var prefix = String("tls13 ")
    var full_label = prefix + label
    info.append(UInt8(full_label.byte_length()))
    for b in full_label.as_bytes():
        info.append(b)
    info.append(UInt8(0))  # empty context length
    var secret_bytes = List[UInt8]()
    for i in range(len(secret)):
        secret_bytes.append(secret[i])
    return hkdf_expand(
        Span[UInt8, _](secret_bytes), Span[UInt8, _](info), length
    )


# ── RFC 9001 §5.2 initial-secret derivation ─────────────────────────────


@fieldwise_init
struct InitialSecrets(Copyable, Movable):
    """Per-direction initial-secret pair derived from the client's
    Destination Connection ID per RFC 9001 §5.2.

    Each secret is 32 bytes (SHA-256 hash output). The packet-
    protection keys (``quic key`` / ``quic iv`` / ``quic hp``) are
    derived from each secret independently via HKDF-Expand-Label.
    """

    var initial_secret: List[UInt8]
    """``HKDF-Extract(QUIC_V1_INITIAL_SALT, dst_cid)`` -- 32 bytes."""

    var client_initial_secret: List[UInt8]
    """``HKDF-Expand-Label(initial_secret, "client in", "", 32)``."""

    var server_initial_secret: List[UInt8]
    """``HKDF-Expand-Label(initial_secret, "server in", "", 32)``."""


def derive_initial_secrets(dst_cid: Span[UInt8, _]) raises -> InitialSecrets:
    """RFC 9001 §5.2 -- derive the initial-direction secrets from
    the client's Destination Connection ID.

    The DCID is the client's first-flight ``Initial`` packet's
    Destination Connection ID (RFC 9000 §17.2.2). Bookkeeping
    notes:

    - Both endpoints derive the same secrets from this DCID.
    - Once the handshake produces 1-RTT keys, the initial-secret
      branch is discarded (RFC 9001 §4.9.1).
    - DCID length must be between 8 and 20 bytes per RFC 9000
      §7.2; this function doesn't enforce the length so callers
      can pass any byte span (fuzz harnesses include zero-length
      DCIDs to probe the trait surface).
    """
    var salt = materialize[QUIC_V1_INITIAL_SALT]()
    var initial_secret = hkdf_extract(Span[UInt8, _](salt), dst_cid)
    var client_secret = hkdf_expand_label_empty_context(
        Span[UInt8, _](initial_secret), "client in", SHA256_OUTPUT_BYTES
    )
    var server_secret = hkdf_expand_label_empty_context(
        Span[UInt8, _](initial_secret), "server in", SHA256_OUTPUT_BYTES
    )
    return InitialSecrets(
        initial_secret=initial_secret^,
        client_initial_secret=client_secret^,
        server_initial_secret=server_secret^,
    )


# ── AEAD enum + trait surface ──────────────────────────────────────────


struct QuicAead:
    """RFC 9001 §5.3 AEAD selector codepoint.

    The TLS 1.3 cipher suite negotiated during the handshake
    selects one of three AEAD algorithms; the AEAD enum carries
    the choice forward into the per-direction packet-protection
    keying schedule.

    All three are mandatory-to-implement for a TLS 1.3 endpoint
    per RFC 8446 §9.1, but RFC 9001 §5.1 mandates that *at least*
    AES-128-GCM be supported by every QUIC v1 endpoint.
    """

    comptime AES_128_GCM: Int = 0
    """RFC 5288 AES-128 in GCM mode (the QUIC v1 mandatory-to-implement)."""

    comptime AES_256_GCM: Int = 1
    """RFC 5288 AES-256 in GCM mode."""

    comptime CHACHA20_POLY1305: Int = 2
    """RFC 8439 ChaCha20-Poly1305 AEAD construction."""


trait QuicCrypto(Copyable, Movable):
    """Pluggable QUIC v1 AEAD + header-protection backend.

    The QUIC server reactor drives one carrier per
    connection. The carrier owns the per-direction packet-
    protection keys derived from the initial-secret pair (and
    later the 1-RTT secrets) and exposes the encrypt-with-AD /
    decrypt-with-AD operations plus the header-protection mask
    used to hide the packet number.

    Backends:

    * ``OpensslQuicCrypto`` (OpenSSL FFI backend)
      -- production default. Routes through the OpenSSL EVP_AEAD
      surface plus EVP_aes_*_ecb for the AES-128-CTR header-
      protection mask.
    * ``RustlsQuicCrypto`` -- alternative backend used
      when ``rustls`` is selected as the QUIC TLS provider.

    The :class:`StubQuicCrypto` is a typed sentinel: it raises a
    clear ``NotImplemented`` ``Error`` on encrypt / decrypt /
    header_protection so test harnesses can confirm the trait
    boundary is wired up correctly before the real backend lands.
    """

    def aead(self) -> Int:
        """Return the negotiated :data:`QuicAead` value."""
        ...

    def encrypt(
        self,
        plaintext: Span[UInt8, _],
        associated_data: Span[UInt8, _],
        packet_number: UInt64,
    ) raises -> List[UInt8]:
        """Encrypt ``plaintext`` against ``associated_data`` with
        the current packet-protection key, returning ciphertext
        plus the 16-byte authentication tag appended.

        ``packet_number`` is XOR'd into the per-key static IV per
        RFC 9001 §5.3 to form the AEAD nonce.
        """
        ...

    def decrypt(
        self,
        ciphertext: Span[UInt8, _],
        associated_data: Span[UInt8, _],
        packet_number: UInt64,
    ) raises -> List[UInt8]:
        """Decrypt ``ciphertext`` (which must include the 16-byte
        AEAD tag appended) against ``associated_data``, returning
        the plaintext. Raises on tag mismatch.
        """
        ...

    def header_protection_mask(
        self, sample: Span[UInt8, _]
    ) raises -> List[UInt8]:
        """RFC 9001 §5.4 -- compute the 5-byte header-protection
        mask from a 16-byte ``sample`` of the packet's encrypted
        payload (starting at offset 4 into the payload, per
        §5.4.2). For AES-based AEADs the mask is the first 5 bytes
        of ``AES-128-ECB(hp_key, sample)``; for ChaCha20-Poly1305
        it is the first 5 bytes of ``ChaCha20(hp_key, counter ||
        nonce)`` where the sample's first 4 bytes are the counter
        and the remaining 12 are the nonce.
        """
        ...


# Stub backend used by the trait-conformance tests. Encrypt /
# decrypt / header_protection_mask all raise; the OpenSSL backend
# replaces it once the AEAD FFI wiring lands.


struct StubQuicCrypto(Copyable, Movable, QuicCrypto):
    """Typed sentinel that raises ``NotImplemented`` on every
    AEAD operation.

    Exists so unit tests can exercise the :trait:`QuicCrypto`
    trait boundary without driving a real AEAD; production code
    constructs :class:`OpenSslQuicCrypto` instead.
    """

    var aead_choice: Int

    def __init__(out self, aead_choice: Int = QuicAead.AES_128_GCM):
        self.aead_choice = aead_choice

    def aead(self) -> Int:
        return self.aead_choice

    def encrypt(
        self,
        plaintext: Span[UInt8, _],
        associated_data: Span[UInt8, _],
        packet_number: UInt64,
    ) raises -> List[UInt8]:
        raise Error(
            "StubQuicCrypto.encrypt: OpenSSL AEAD backend not wired"
            " yet. The trait boundary is in place; tests that need"
            " a real handshake should switch to OpensslQuicCrypto."
        )

    def decrypt(
        self,
        ciphertext: Span[UInt8, _],
        associated_data: Span[UInt8, _],
        packet_number: UInt64,
    ) raises -> List[UInt8]:
        raise Error(
            "StubQuicCrypto.decrypt: OpenSSL AEAD backend not wired yet."
        )

    def header_protection_mask(
        self, sample: Span[UInt8, _]
    ) raises -> List[UInt8]:
        raise Error(
            "StubQuicCrypto.header_protection_mask: OpenSSL backend"
            " not wired yet."
        )


# ── RFC 9001 §5.1 packet-protection key schedule ───────────────────────


def aead_key_length(aead: Int) raises -> Int:
    """Per-AEAD key length in bytes (RFC 9001 §5.1 + RFC 8439)."""
    if aead == QuicAead.AES_128_GCM:
        return 16
    if aead == QuicAead.AES_256_GCM:
        return 32
    if aead == QuicAead.CHACHA20_POLY1305:
        return 32
    raise Error("aead_key_length: unknown AEAD codepoint")


@fieldwise_init
struct PacketKeys(Copyable, Movable):
    """Per-direction packet-protection keys derived from a 32-byte
    secret per RFC 9001 §5.1.

    The handshake produces two secrets per encryption level (one
    per direction); each becomes a ``PacketKeys`` via
    :func:`derive_packet_keys`.
    """

    var aead: Int
    """``QuicAead`` codepoint these keys are scheduled for."""

    var key: List[UInt8]
    """AEAD key -- 16 bytes (AES-128) or 32 bytes (AES-256, ChaCha20)."""

    var iv: List[UInt8]
    """AEAD IV -- 12 bytes (RFC 9001 §5.3 nonce-construction base)."""

    var hp: List[UInt8]
    """Header-protection key -- same length as ``key`` for AES;
    32 bytes for ChaCha20-Poly1305 (RFC 9001 §5.4)."""


def derive_packet_keys(secret: Span[UInt8, _], aead: Int) raises -> PacketKeys:
    """RFC 9001 §5.1 -- derive ``(key, iv, hp)`` from a 32-byte
    per-direction secret.

    Labels are the canonical RFC 9001 §5.1 set:

    - ``"quic key"`` -- AEAD key (key length per AEAD).
    - ``"quic iv"``  -- AEAD IV (always 12 bytes).
    - ``"quic hp"``  -- header-protection key (same length as
      AEAD key for AES; 32 bytes for ChaCha20).

    The same schedule applies to initial, handshake, and 1-RTT
    secrets; only the source secret changes. The handshake +
    1-RTT secrets come from the TLS 1.3 exporter (RFC 9001 §7
    handshake state machine, wired once rustls is integrated).
    """
    var key_len = aead_key_length(aead)
    var key = hkdf_expand_label_empty_context(secret, "quic key", key_len)
    var iv = hkdf_expand_label_empty_context(secret, "quic iv", 12)
    var hp = hkdf_expand_label_empty_context(secret, "quic hp", key_len)
    return PacketKeys(aead=aead, key=key^, iv=iv^, hp=hp^)


# ── OpenSslQuicCrypto -- production AEAD + HP backend ──────────────────


# Header-protection cipher IDs the FFI accepts; distinct from the
# AEAD IDs because the mask path is its own primitive.
comptime _HP_AES_128: Int = 1
comptime _HP_AES_256: Int = 2
comptime _HP_CHACHA20: Int = 3


# AEAD cipher IDs the FFI accepts (must match
# FLARE_QUIC_AEAD_* in flare/tls/ffi/openssl_wrapper.h).
comptime _AEAD_AES_128_GCM_C: Int = 1
comptime _AEAD_AES_256_GCM_C: Int = 2
comptime _AEAD_CHACHA20_POLY1305_C: Int = 3


comptime _AEAD_TAG_LEN: Int = 16
comptime _AEAD_NONCE_LEN: Int = 12
comptime _HP_SAMPLE_LEN: Int = 16
comptime _HP_MASK_LEN: Int = 5


def _aead_to_ffi(aead: Int) raises -> Int:
    """Map the ``QuicAead`` Mojo enum to the FFI cipher_id constant."""
    if aead == QuicAead.AES_128_GCM:
        return _AEAD_AES_128_GCM_C
    if aead == QuicAead.AES_256_GCM:
        return _AEAD_AES_256_GCM_C
    if aead == QuicAead.CHACHA20_POLY1305:
        return _AEAD_CHACHA20_POLY1305_C
    raise Error("OpenSslQuicCrypto: unknown AEAD codepoint")


def _aead_to_hp_ffi(aead: Int) raises -> Int:
    """Map ``QuicAead`` to the *header-protection* FFI cipher_id."""
    if aead == QuicAead.AES_128_GCM:
        return _HP_AES_128
    if aead == QuicAead.AES_256_GCM:
        return _HP_AES_256
    if aead == QuicAead.CHACHA20_POLY1305:
        return _HP_CHACHA20
    raise Error("OpenSslQuicCrypto: unknown AEAD codepoint")


def _do_aead_seal(
    read lib: OwnedDLHandle,
    cipher_id: Int,
    key: List[UInt8],
    iv: List[UInt8],
    pn: UInt64,
    aad: List[UInt8],
    plaintext: List[UInt8],
    mut out: List[UInt8],
) raises -> Int:
    var seal_fn = lib.get_function[
        def(
            c_int,
            Int,
            Int,
            Int,
            UInt64,
            Int,
            Int,
            Int,
            Int,
            Int,
            Int,
            Int,
        ) thin abi("C") -> c_int
    ]("flare_quic_aead_seal")
    var written = List[Int](length=1, fill=0)
    var rc = seal_fn(
        c_int(cipher_id),
        Int(key.unsafe_ptr()),
        len(key),
        Int(iv.unsafe_ptr()),
        pn,
        Int(aad.unsafe_ptr()),
        len(aad),
        Int(plaintext.unsafe_ptr()),
        len(plaintext),
        Int(out.unsafe_ptr()),
        len(out),
        Int(written.unsafe_ptr()),
    )
    if Int(rc) != 0:
        raise Error("OpenSslQuicCrypto.encrypt: FFI rc=" + String(Int(rc)))
    return written[0]


def _do_aead_open(
    read lib: OwnedDLHandle,
    cipher_id: Int,
    key: List[UInt8],
    iv: List[UInt8],
    pn: UInt64,
    aad: List[UInt8],
    ct: List[UInt8],
    mut out: List[UInt8],
) raises -> Int:
    var open_fn = lib.get_function[
        def(
            c_int,
            Int,
            Int,
            Int,
            UInt64,
            Int,
            Int,
            Int,
            Int,
            Int,
            Int,
            Int,
        ) thin abi("C") -> c_int
    ]("flare_quic_aead_open")
    var written = List[Int](length=1, fill=0)
    var rc = open_fn(
        c_int(cipher_id),
        Int(key.unsafe_ptr()),
        len(key),
        Int(iv.unsafe_ptr()),
        pn,
        Int(aad.unsafe_ptr()),
        len(aad),
        Int(ct.unsafe_ptr()),
        len(ct),
        Int(out.unsafe_ptr()),
        len(out),
        Int(written.unsafe_ptr()),
    )
    var rc_i = Int(rc)
    if rc_i == -2:
        raise Error(
            "OpenSslQuicCrypto.decrypt: AEAD tag verification failed"
            " (RFC 9001 paragraph 5.3 invalid packet)"
        )
    if rc_i != 0:
        raise Error("OpenSslQuicCrypto.decrypt: FFI rc=" + String(rc_i))
    return written[0]


def _do_hp_mask(
    read lib: OwnedDLHandle,
    cipher_id: Int,
    hp_key: List[UInt8],
    sample: List[UInt8],
    mut out: List[UInt8],
) raises:
    var mask_fn = lib.get_function[
        def(c_int, Int, Int, Int, Int) thin abi("C") -> c_int
    ]("flare_quic_hp_mask")
    var rc = mask_fn(
        c_int(cipher_id),
        Int(hp_key.unsafe_ptr()),
        len(hp_key),
        Int(sample.unsafe_ptr()),
        Int(out.unsafe_ptr()),
    )
    if Int(rc) != 0:
        raise Error(
            "OpenSslQuicCrypto.header_protection_mask: FFI rc="
            + String(Int(rc))
        )


struct OpenSslQuicCrypto(Copyable, Movable, QuicCrypto):
    """Production QUIC v1 AEAD + header-protection backend backed
    by OpenSSL via the ``flare_quic_aead_*`` / ``flare_quic_hp_mask``
    FFI thunks.

    The carrier holds the per-direction ``PacketKeys`` (AEAD key,
    AEAD IV, header-protection key) for a single encryption level
    in a single direction. The QUIC server reactor maintains four
    carriers per connection: client/server initial, handshake, and
    1-RTT (the initial-secret pair gets dropped after the handshake
    completes per RFC 9001 paragraph 4.9.1).

    Construction:

    - :py:meth:`from_secret` -- derive ``PacketKeys`` from a 32-byte
      direction secret + AEAD codepoint, then wrap into the carrier.
    - :py:meth:`__init__` -- bring-your-own ``PacketKeys`` for the
      test path or when the keys come from an outboard schedule
      (e.g. the rustls QUIC binding).
    """

    var keys: PacketKeys

    def __init__(out self, var keys: PacketKeys):
        self.keys = keys^

    @staticmethod
    def from_secret(secret: Span[UInt8, _], aead_choice: Int) raises -> Self:
        """Derive ``PacketKeys`` from ``secret`` per RFC 9001 §5.1
        and wrap into a carrier ready to encrypt / decrypt against
        the schedule's keys."""
        var keys = derive_packet_keys(secret, aead_choice)
        return Self(keys=keys^)

    def aead(self) -> Int:
        return self.keys.aead

    def encrypt(
        self,
        plaintext: Span[UInt8, _],
        associated_data: Span[UInt8, _],
        packet_number: UInt64,
    ) raises -> List[UInt8]:
        var cipher_id = _aead_to_ffi(self.keys.aead)
        var pt = List[UInt8]()
        for i in range(len(plaintext)):
            pt.append(plaintext[i])
        var aad = List[UInt8]()
        for i in range(len(associated_data)):
            aad.append(associated_data[i])
        # Output buffer = plaintext_len + 16-byte tag per RFC 9001
        # paragraph 5.3 (RFC 5116 paragraph 3.1 default tag length).
        var out = List[UInt8](
            length=len(plaintext) + _AEAD_TAG_LEN, fill=UInt8(0)
        )
        var lib = OwnedDLHandle(_find_flare_lib())
        var written = _do_aead_seal(
            lib,
            cipher_id,
            self.keys.key,
            self.keys.iv,
            packet_number,
            aad,
            pt,
            out,
        )
        # Trim in case the buffer was over-allocated (it shouldn't
        # be -- the FFI writes exactly plaintext_len + tag_len).
        while len(out) > written:
            _ = out.pop()
        return out^

    def decrypt(
        self,
        ciphertext: Span[UInt8, _],
        associated_data: Span[UInt8, _],
        packet_number: UInt64,
    ) raises -> List[UInt8]:
        if len(ciphertext) < _AEAD_TAG_LEN:
            raise Error(
                "OpenSslQuicCrypto.decrypt: ciphertext shorter than"
                " 16-byte AEAD tag"
            )
        var cipher_id = _aead_to_ffi(self.keys.aead)
        var ct = List[UInt8]()
        for i in range(len(ciphertext)):
            ct.append(ciphertext[i])
        var aad = List[UInt8]()
        for i in range(len(associated_data)):
            aad.append(associated_data[i])
        var pt_len = len(ciphertext) - _AEAD_TAG_LEN
        var out = List[UInt8](length=pt_len, fill=UInt8(0))
        var lib = OwnedDLHandle(_find_flare_lib())
        var written = _do_aead_open(
            lib,
            cipher_id,
            self.keys.key,
            self.keys.iv,
            packet_number,
            aad,
            ct,
            out,
        )
        while len(out) > written:
            _ = out.pop()
        return out^

    def header_protection_mask(
        self, sample: Span[UInt8, _]
    ) raises -> List[UInt8]:
        if len(sample) != _HP_SAMPLE_LEN:
            raise Error(
                "OpenSslQuicCrypto.header_protection_mask: sample"
                " must be exactly 16 bytes (RFC 9001 paragraph 5.4.2)"
            )
        var cipher_id = _aead_to_hp_ffi(self.keys.aead)
        var sample_bytes = List[UInt8]()
        for i in range(len(sample)):
            sample_bytes.append(sample[i])
        var out = List[UInt8](length=_HP_MASK_LEN, fill=UInt8(0))
        var lib = OwnedDLHandle(_find_flare_lib())
        _do_hp_mask(lib, cipher_id, self.keys.hp, sample_bytes, out)
        return out^
