# PLATFORM: any (needs the rustls QUIC shim and the fixtures in
# tests/tls/fixtures/rustls-quic-client/; no network I/O)
"""QUIC-12: the client's connection-ID authentication cannot tell an absent
transport parameter from a zero-length one.

Lean: Flare.Bugs.QUIC_12.impl_accepts_absent_iscid,
      Flare.Bugs.QUIC_12.impl_accepts_empty_rscid,
      Flare.Bugs.QUIC_12.impl_accepts_pa_with_empty_cid (impl),
      Flare.Bugs.QUIC_12.checkFixed_spec (fix).
flare/quic/client.mojo:641-669 @59bda50 (`_check_peer_cids`) over
flare/quic/transport_params.mojo:410-525 (`decode_transport_parameters`,
which stores CIDs as `List[UInt8]`, empty meaning absent, and skips 0x0d).

RFC 9000 §7.3: absence of initial_source_connection_id from either endpoint
MUST be treated as TRANSPORT_PARAMETER_ERROR; presence of
retry_source_connection_id when no Retry packet was received MUST be
treated as TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION. §18.2: a server
that chooses a zero-length connection ID MUST NOT provide a
preferred_address; a client MUST treat a violation as
TRANSPORT_PARAMETER_ERROR.

The rustls handshake runs in memory (client session from
`RustlsQuicConnector.connect`, server session from `_do_accept` with a
crafted server parameter blob), then `_check_peer_cids` runs on a
`QuicClientConnection` holding the client session. Cases:

  A  server used a zero-length SCID and omits initial_source_connection_id
  B  no Retry, server sends retry_source_connection_id with length 0
  C  server used a zero-length SCID (sent as a zero-length
     initial_source_connection_id) and sends a preferred_address

Expected: `_check_peer_cids` raises in A, B, C. Actual: it returns. Controls:
a correct blob passes, an initial_source_connection_id mismatch raises.

Minimal fix: scan the raw blob for the presence of ids 0x0f / 0x10 / 0x0d
and require 0x0f present (once a server CID is known), 0x10 present iff a
Retry was followed, and no 0x0d when the server CID is empty.
"""

from std.collections import List, Optional
from std.collections.span import Span
from std.ffi import OwnedDLHandle
from std.pathlib import Path

from flare.net.address import IpAddr, SocketAddr
from flare.udp import UdpSocket
from flare.quic.client import QuicClientConnection
from flare.quic.crypto import QuicAead
from flare.quic.packet import ConnectionId
from flare.quic.state import new_connection
from flare.quic.transport_params import (
    empty_transport_parameters,
    encode_transport_parameters,
)
from flare.tls import RustlsQuicConnector
from flare.tls.rustls_quic import (
    QuicEncryptionLevel,
    RustlsQuicAcceptor,
    RustlsQuicConfig,
    RustlsQuicSession,
)
from flare.tls._rustls_quic_ffi import _do_accept, _find_rustls_quic_lib


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _cid(b: UInt8) -> List[UInt8]:
    var v = List[UInt8]()
    for _ in range(8):
        v.append(b)
    return v^


def _tlv(mut out: List[UInt8], id: UInt8, value: List[UInt8]):
    out.append(id)
    out.append(UInt8(len(value)))
    for i in range(len(value)):
        out.append(value[i])


def _server_blob(kase: Int) raises -> List[UInt8]:
    var tp = empty_transport_parameters()
    tp.original_destination_connection_id = _cid(0xAA)
    tp.initial_max_data = Optional(UInt64(1 << 20))
    tp.initial_max_stream_data_bidi_remote = Optional(UInt64(1 << 20))
    tp.initial_max_streams_bidi = Optional(UInt64(16))
    if kase == 3:  # control: correct
        tp.initial_source_connection_id = _cid(0xBB)
    elif kase == 4:  # control: mismatch
        tp.initial_source_connection_id = _cid(0xCC)
    elif kase == 1:
        tp.initial_source_connection_id = _cid(0xBB)
    var out = encode_transport_parameters(tp)
    if kase == 1:
        _tlv(out, 0x10, List[UInt8]())  # retry_source_connection_id, len 0
    elif kase == 2:
        _tlv(out, 0x0F, List[UInt8]())  # initial_source_connection_id, len 0
        var pa = List[UInt8]()
        for _ in range(4 + 2 + 16 + 2):
            pa.append(0)
        pa.append(8)  # CID length
        for _ in range(8):
            pa.append(0x44)
        for _ in range(16):
            pa.append(0x55)  # stateless reset token
        _tlv(out, 0x0D, pa)
    return out^


def _handshake(kase: Int) raises -> RustlsQuicSession:
    var cfg = RustlsQuicConfig()
    cfg.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.alpn_protocols = _alpn()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var h = _do_accept(acceptor._lib, acceptor._opaque_handle, _server_blob(kase))
    if h == 0:
        raise Error("harness: _do_accept failed")
    var srv = RustlsQuicSession._wrap(
        OwnedDLHandle(_find_rustls_quic_lib()), h, _cid(0xAA)
    )
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var ctp = empty_transport_parameters()
    ctp.initial_source_connection_id = _cid(0xDD)
    var cli = connector.connect(String("localhost"), encode_transport_parameters(ctp))
    var levels = List[Int]()
    levels.append(QuicEncryptionLevel.INITIAL)
    levels.append(QuicEncryptionLevel.HANDSHAKE)
    levels.append(QuicEncryptionLevel.APPLICATION)
    for _ in range(10):
        for i in range(len(levels)):
            var d = cli.take_crypto(levels[i])
            if len(d) > 0:
                srv.feed_crypto(levels[i], d)
            var e = srv.take_crypto(levels[i])
            if len(e) > 0:
                cli.feed_crypto(levels[i], e)
        if cli.is_handshake_complete() and srv.is_handshake_complete():
            break
    if not cli.is_handshake_complete():
        raise Error("harness: in-memory handshake did not complete")
    return cli^


def _rejected(kase: Int) raises -> Bool:
    var session = _handshake(kase)
    var sock = UdpSocket.bind(SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)))
    var client = QuicClientConnection(
        new_connection(UInt64(30_000_000), UInt64(1 << 20)),
        session^,
        sock^,
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(9)),
        ConnectionId(bytes=_cid(0xAA)),
        ConnectionId(bytes=_cid(0xDD)),
        QuicAead.AES_128_GCM,
        1452,
    )
    client.got_server_cid = True
    if kase == 0 or kase == 2:
        client.server_scid = List[UInt8]()  # zero-length server SCID
    else:
        client.server_scid = _cid(0xBB)
    try:
        client._check_peer_cids()
    except e:
        print("   raised:", e)
        return True
    return False


def main() raises:
    if _rejected(3):
        raise Error("harness: correct server parameters rejected")
    if not _rejected(4):
        raise Error("harness: initial_source_connection_id mismatch accepted")
    print("controls: correct blob accepted, mismatch rejected")
    var names = List[String]()
    names.append("A zero-length server SCID, initial_source_connection_id absent")
    names.append("B no Retry, zero-length retry_source_connection_id present")
    names.append("C zero-length server SCID with preferred_address")
    var bad = 0
    for c in range(3):
        var r = _rejected(c)
        print(names[c], "->", "rejected" if r else "accepted")
        if not r:
            bad += 1
    if bad > 0:
        print(
            "BUG REPRODUCED: _check_peer_cids accepted",
            bad,
            "of 3 server parameter blobs RFC 9000 §7.3/§18.2 require it to"
            " reject",
        )
        raise Error("QUIC-12")
    print("OK: absent / zero-length CID parameters handled per RFC 9000 §7.3")
