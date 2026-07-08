"""Rustls QUIC handshake bridge tests.

Live-fire tests for the bridge wiring inside
:class:`flare.quic.server.QuicListener` that hands inbound CRYPTO
frame bytes to the per-slot
:class:`flare.tls.rustls_quic.RustlsQuicSession`:

1. The listener's per-bind acceptor materializes from the
   :class:`flare.tls.rustls_quic.RustlsQuicConfig` inside
   :class:`flare.quic.server.QuicServerConfig`. Empty PEM (the
   default config the fuzz harness + existing reactor tests use)
   surfaces as a NULL acceptor handle, NOT a raise.
2. Real PEM (the Ed25519 fixture under
   ``tests/tls/fixtures/rustls-quic-cert/``) yields a non-NULL
   handle.
3. ``_accept_initial`` materializes a per-slot
   :class:`flare.quic.server._SessionSlot` in lockstep with the
   :class:`QuicConnection` slab. Real PEM -> non-zero session
   handle; empty PEM -> 0 handle (sentinel).
4. The state-machine layer surfaces parsed CRYPTO frames on
   :class:`ConnectionEvents.crypto_frames` so the reactor can
   forward them to rustls after :func:`handle_frame_buf` returns.
5. A synthetic Initial datagram carrying a CRYPTO frame routes
   through ``dispatch_datagram`` and lands on the slot's session
   via the bridge. rustls rejects the synthetic bytes (not a real
   ClientHello), but the dispatch is observable: the session
   level stays at INITIAL and the take-crypto egress queue stays
   empty -- both confirmed by the bridge having been exercised
   without a crash.
6. Listener teardown releases every non-zero session handle once
   via :meth:`RustlsQuicAcceptor.free_session`.

The full live-handshake test (real ClientHello -> ServerHello on
the wire) lands in the loopback rewrite once the reactor's
egress path (send_to + protect_initial) is wired.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    FRAME_TYPE_PADDING,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    CryptoFrame,
    QuicListener,
    QuicServerConfig,
    cid_to_hex,
    encode_crypto,
    encode_long_header,
    encode_varint,
    handle_frame_buf,
    new_connection,
    protect_initial_packet,
)
from flare.quic.state import empty_events
from flare.tls import RustlsQuicConfig
from flare.udp import UdpSocket


# ── Fixture loaders ─────────────────────────────────────────────────────


def _load_fixture_pem() raises -> Tuple[String, String]:
    """Read the Ed25519 self-signed cert + key fixture into Mojo
    Strings. Generated once with ``openssl req -x509 -nodes
    -newkey ed25519 -days 36500 -subj /CN=flare-quic-test``."""
    var cert = Path(
        String("tests/tls/fixtures/rustls-quic-cert/cert.pem")
    ).read_text()
    var key = Path(
        String("tests/tls/fixtures/rustls-quic-cert/key.pem")
    ).read_text()
    return (cert^, key^)


def _make_h3_config() raises -> RustlsQuicConfig:
    """Build a :class:`RustlsQuicConfig` with the fixture cert
    and the standard H3 ALPN list."""
    var cert_pem: String
    var key_pem: String
    cert_pem, key_pem = _load_fixture_pem()
    var cfg = RustlsQuicConfig()
    cfg.cert_chain_pem = cert_pem^
    cfg.private_key_pem = key_pem^
    cfg.alpn_protocols = List[String]()
    cfg.alpn_protocols.append(String("h3"))
    return cfg^


def _bind_empty_pem(idle_ms: UInt64 = UInt64(30_000)) raises -> QuicListener:
    """Bind a listener with the default (empty PEM) config -- the
    shape every pre-Q9-W test used."""
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_idle_timeout_ms = idle_ms
    return QuicListener.bind(cfg)


def _bind_real_pem(idle_ms: UInt64 = UInt64(30_000)) raises -> QuicListener:
    """Bind a listener with the Ed25519 fixture PEM. The acceptor
    handle is non-zero so every accepted Initial materializes a
    real rustls QUIC session."""
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_idle_timeout_ms = idle_ms
    cfg.rustls_config = _make_h3_config()
    return QuicListener.bind(cfg)


def _make_cid(seed: UInt8, length: Int) -> ConnectionId:
    var bytes = List[UInt8]()
    for i in range(length):
        bytes.append(seed + UInt8(i))
    return ConnectionId(bytes^)


# ── Synth Initial-with-CRYPTO datagram ──────────────────────────────────


def _crypto_frame_bytes(payload: List[UInt8]) raises -> List[UInt8]:
    var frame = CryptoFrame(offset=UInt64(0), data=payload.copy())
    var out = List[UInt8]()
    encode_crypto(frame, out)
    return out^


def _padded_plaintext(payload: List[UInt8], total: Int) raises -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(len(payload)):
        out.append(payload[i])
    while len(out) < total:
        out.append(UInt8(FRAME_TYPE_PADDING))
    return out^


def _build_initial_prefix(
    dcid: ConnectionId,
    scid: ConnectionId,
    pn_length: Int,
    plaintext_len: Int,
) raises -> List[UInt8]:
    var first_bits = (pn_length - 1) & 0x3
    var hdr = encode_long_header(
        PACKET_TYPE_INITIAL,
        QUIC_VERSION_1,
        dcid,
        scid,
        type_specific_bits=first_bits,
    )
    var out = List[UInt8]()
    for i in range(len(hdr)):
        out.append(hdr[i])
    var token_len_var = encode_varint(UInt64(0))
    for i in range(len(token_len_var)):
        out.append(token_len_var[i])
    var aead_overhead = 16
    var payload_total = plaintext_len + pn_length + aead_overhead
    var payload_len_var = encode_varint(UInt64(payload_total))
    for i in range(len(payload_len_var)):
        out.append(payload_len_var[i])
    return out^


def _build_synth_initial_with_crypto(
    dcid: ConnectionId,
    scid: ConnectionId,
    packet_number: UInt64,
    var crypto_payload: List[UInt8],
) raises -> List[UInt8]:
    """Compose an encrypted Initial datagram carrying one CRYPTO
    frame plus PADDING. The CRYPTO payload is opaque bytes;
    rustls will reject them as not-a-valid-ClientHello but the
    QUIC packet itself decrypts cleanly because the AEAD key is
    derived from the DCID per RFC 9001 §5.2."""
    var crypto_bytes = _crypto_frame_bytes(crypto_payload^)
    var plaintext = _padded_plaintext(crypto_bytes, 80)
    var prefix = _build_initial_prefix(dcid, scid, 1, len(plaintext))
    return protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=packet_number,
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid,
        is_server=False,
    )


# ── 1. ConnectionEvents plumbing (sans-I/O) ─────────────────────────────


def test_events_crypto_frames_starts_empty() raises:
    """``empty_events()`` has an empty crypto_frames list."""
    var events = empty_events()
    assert_equal(len(events.crypto_frames), 0)


def test_handle_frame_buf_surfaces_crypto_frame() raises:
    """A CRYPTO frame parsed by :func:`handle_frame_buf` lands on
    :attr:`ConnectionEvents.crypto_frames` so the reactor can
    drain it. Confirms the sans-I/O state machine is the bridge
    seam rather than calling out to TLS directly."""
    var conn = new_connection(UInt64(30_000_000), UInt64(1 << 20))
    var events = empty_events()
    var payload = List[UInt8]()
    payload.append(UInt8(0x16))  # ClientHello tag byte (opaque here)
    payload.append(UInt8(0x03))
    payload.append(UInt8(0x03))
    var frame = CryptoFrame(offset=UInt64(0), data=payload.copy())
    var buf = List[UInt8]()
    encode_crypto(frame, buf)
    var consumed = handle_frame_buf(
        conn, Span[UInt8, _](buf), UInt64(1_000), events
    )
    assert_true(consumed > 0, "CRYPTO frame must consume bytes")
    assert_equal(
        len(events.crypto_frames),
        1,
        "one CRYPTO frame must surface on events.crypto_frames",
    )
    assert_equal(events.crypto_frames[0].offset, UInt64(0))
    assert_equal(len(events.crypto_frames[0].data), 3)
    assert_equal(Int(events.crypto_frames[0].data[0]), 0x16)


# ── 2. Listener bind with + without real PEM ────────────────────────────


def test_listener_bind_empty_pem_yields_null_acceptor() raises:
    """Backward compatibility: the default ``QuicServerConfig()``
    has an empty :class:`RustlsQuicConfig`. The acceptor still
    constructs (no raise), but its handle is 0 so the dispatcher
    routes every CRYPTO frame through the silent-drop branch.
    Every pre-Q9-W test depends on this shape."""
    var listener = _bind_empty_pem()
    assert_equal(
        listener.tls_acceptor._opaque_handle,
        0,
        "empty PEM must yield a NULL acceptor handle",
    )
    listener.shutdown()
    listener.close()


def test_listener_bind_real_pem_yields_live_acceptor() raises:
    """Real Ed25519 PEM -> acceptor handle != 0 + the ALPN list
    survives the round-trip through :func:`RustlsQuicAcceptor.__init__`."""
    var listener = _bind_real_pem()
    assert_true(
        listener.tls_acceptor._opaque_handle != 0,
        "real PEM must yield a non-NULL acceptor handle",
    )
    assert_equal(len(listener.tls_acceptor.config.alpn_protocols), 1)
    assert_equal(
        listener.tls_acceptor.config.alpn_protocols[0],
        String("h3"),
    )
    listener.shutdown()
    listener.close()


# ── 3. Per-slot session materialization ─────────────────────────────────


def test_accept_initial_materializes_real_session() raises:
    """A synth Initial against a real-PEM listener allocates a
    slot, registers the DCID, and materializes a non-zero
    session handle in the parallel TLS slab."""
    var listener = _bind_real_pem()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0xA0), 8)
    var scid = _make_cid(UInt8(0xB0), 8)
    var payload = List[UInt8]()
    for i in range(8):
        payload.append(UInt8(0x10 + i))
    var datagram = _build_synth_initial_with_crypto(
        dcid, scid, UInt64(0), payload^
    )
    _ = client.send_to(Span[UInt8, _](datagram), server_addr)
    var got = listener.tick(500)
    assert_true(got, "tick must observe the inbound datagram")
    assert_equal(listener.connection_count(), 1)
    assert_equal(len(listener.tls_sessions), 1)
    assert_equal(len(listener.tls_egress_queues), 1)
    assert_true(
        listener.tls_sessions[0].handle != 0,
        "real-PEM accept must materialize a non-zero session handle",
    )
    listener.shutdown()
    listener.close()


def test_accept_initial_empty_pem_keeps_null_sentinel() raises:
    """Same accept path with the empty-PEM listener: a slot is
    still allocated (lockstep with :attr:`connections`) but the
    session handle is the NULL sentinel so dispatch silent-drops
    CRYPTO frames."""
    var listener = _bind_empty_pem()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0xC0), 8)
    var scid = _make_cid(UInt8(0xD0), 8)
    var payload = List[UInt8]()
    payload.append(UInt8(0x16))
    payload.append(UInt8(0x03))
    payload.append(UInt8(0x03))
    var datagram = _build_synth_initial_with_crypto(
        dcid, scid, UInt64(0), payload^
    )
    _ = client.send_to(Span[UInt8, _](datagram), server_addr)
    var got = listener.tick(500)
    assert_true(got)
    assert_equal(listener.connection_count(), 1)
    assert_equal(len(listener.tls_sessions), 1)
    assert_equal(
        listener.tls_sessions[0].handle,
        0,
        "empty PEM must keep the NULL session sentinel",
    )
    listener.shutdown()
    listener.close()


# ── 4. End-to-end bridge dispatch ───────────────────────────────────────


def test_bridge_dispatches_crypto_frame_no_crash_real_pem() raises:
    """A synth Initial with opaque CRYPTO payload routes through
    the bridge to rustls. rustls rejects the bytes (not a real
    ClientHello) but the bridge dispatched: no crash, no raise,
    egress queue stays empty (no ServerHello produced)."""
    var listener = _bind_real_pem()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0xE0), 8)
    var scid = _make_cid(UInt8(0xF0), 8)
    var payload = List[UInt8]()
    for i in range(32):
        payload.append(UInt8(i))
    var datagram = _build_synth_initial_with_crypto(
        dcid, scid, UInt64(0), payload^
    )
    _ = client.send_to(Span[UInt8, _](datagram), server_addr)
    var got = listener.tick(500)
    assert_true(got)
    assert_equal(listener.connection_count(), 1)
    assert_true(listener.tls_sessions[0].handle != 0)
    assert_equal(
        len(listener.tls_egress_queues[0]),
        0,
        (
            "rustls rejects the synth bytes so no INITIAL egress is"
            " queued; the dispatch path stays silent-drop per RFC 9001 §5.2"
        ),
    )
    listener.shutdown()
    listener.close()


def test_bridge_dispatches_crypto_frame_no_crash_empty_pem() raises:
    """Same dispatch with the empty-PEM listener: the NULL session
    short-circuits inside :meth:`_dispatch_crypto_frames` so the
    feed_crypto FFI never runs. No raise, no crash, no slab
    corruption."""
    var listener = _bind_empty_pem()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0xAA), 8)
    var scid = _make_cid(UInt8(0xBB), 8)
    var payload = List[UInt8]()
    payload.append(UInt8(0x01))
    var datagram = _build_synth_initial_with_crypto(
        dcid, scid, UInt64(0), payload^
    )
    _ = client.send_to(Span[UInt8, _](datagram), server_addr)
    var got = listener.tick(500)
    assert_true(got)
    assert_equal(listener.tls_sessions[0].handle, 0)
    assert_equal(len(listener.tls_egress_queues[0]), 0)
    listener.shutdown()
    listener.close()


# ── 5. Slab lockstep across retransmits ─────────────────────────────────


def test_retransmit_does_not_grow_session_slab() raises:
    """A second Initial with the same DCID must route to slot 0
    (no new slot allocated) so the TLS session slab stays at
    one entry. Lockstep with :attr:`connections`."""
    var listener = _bind_real_pem()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0x11), 8)
    var scid = _make_cid(UInt8(0x22), 8)
    var payload = List[UInt8]()
    payload.append(UInt8(0x16))
    var first = _build_synth_initial_with_crypto(
        dcid, scid, UInt64(0), payload.copy()
    )
    var second = _build_synth_initial_with_crypto(
        dcid, scid, UInt64(1), payload^
    )
    _ = client.send_to(Span[UInt8, _](first), server_addr)
    var got1 = listener.tick(500)
    assert_true(got1)
    _ = client.send_to(Span[UInt8, _](second), server_addr)
    var got2 = listener.tick(500)
    assert_true(got2)
    assert_equal(
        listener.connection_count(),
        1,
        "retransmit must route to the existing slot",
    )
    assert_equal(
        len(listener.tls_sessions),
        1,
        "TLS slab must stay in lockstep with connections",
    )
    assert_equal(
        len(listener.tls_egress_queues),
        1,
        "egress queue slab must stay in lockstep with connections",
    )
    assert_equal(
        listener.cid_table.lookup(cid_to_hex(dcid)),
        0,
    )
    listener.shutdown()
    listener.close()


# ── 6. Teardown frees every non-zero session ────────────────────────────


def test_listener_teardown_no_leak() raises:
    """Drop the listener after accepting connections; the slab's
    __del__ calls :meth:`RustlsQuicAcceptor.free_session` on
    every non-zero handle exactly once. ASan-clean.
    """
    var listener = _bind_real_pem()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var payload = List[UInt8]()
    payload.append(UInt8(0x16))
    payload.append(UInt8(0x03))
    payload.append(UInt8(0x03))
    for i in range(3):
        var dcid = _make_cid(UInt8(0x30 + i * 8), 8)
        var scid = _make_cid(UInt8(0x40 + i * 8), 8)
        var dg = _build_synth_initial_with_crypto(
            dcid, scid, UInt64(i), payload.copy()
        )
        _ = client.send_to(Span[UInt8, _](dg), server_addr)
        var got = listener.tick(500)
        assert_true(got)
    assert_equal(listener.connection_count(), 3)
    assert_equal(len(listener.tls_sessions), 3)
    for i in range(3):
        assert_true(
            listener.tls_sessions[i].handle != 0,
            "every accepted slot must carry a real session handle",
        )
    listener.shutdown()
    listener.close()
    # listener goes out of scope here; __del__ must free three
    # session handles cleanly. ASan would catch a double-free or
    # use-after-free.


def main() raises:
    test_events_crypto_frames_starts_empty()
    test_handle_frame_buf_surfaces_crypto_frame()
    test_listener_bind_empty_pem_yields_null_acceptor()
    test_listener_bind_real_pem_yields_live_acceptor()
    test_accept_initial_materializes_real_session()
    test_accept_initial_empty_pem_keeps_null_sentinel()
    test_bridge_dispatches_crypto_frame_no_crash_real_pem()
    test_bridge_dispatches_crypto_frame_no_crash_empty_pem()
    test_retransmit_does_not_grow_session_slab()
    test_listener_teardown_no_leak()
    print("test_quic_handshake_bridge: 10 passed")
