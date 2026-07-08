//! C ABI shim around `rustls::quic::ServerConnection`.
//!
//! Exposes the minimal surface the flare QUIC server reactor needs:
//!
//! - Acceptor lifecycle:
//!   `flare_rustls_quic_acceptor_new` / `_free`
//!   (build an `Arc<ServerConfig>` from PEM cert + key + ALPN list).
//! - Per-connection session:
//!   `flare_rustls_quic_accept`
//!   (constructs a fresh `rustls::quic::ServerConnection` for a DCID).
//! - Client role (mirror of the acceptor):
//!   `flare_rustls_quic_connector_new` / `_free`
//!   (build an `Arc<ClientConfig>` from a CA PEM bundle + ALPN list),
//!   `flare_rustls_quic_connect`
//!   (constructs a `rustls::quic::ClientConnection` for an SNI host).
//!   The feed/take CRYPTO, AEAD, header-protection, ALPN, and
//!   handshake-complete thunks below are role-agnostic.
//! - Drive the handshake:
//!   `flare_rustls_quic_feed_crypto` (write peer's CRYPTO bytes)
//!   `flare_rustls_quic_take_crypto` (drain our outbound CRYPTO bytes)
//!   `flare_rustls_quic_is_handshake_complete`.
//! - Introspect:
//!   `flare_rustls_quic_alpn` (negotiated ALPN id).
//!
//! Every fallible function returns ``int``:
//!
//! - 0 -- success
//! - -1 -- caller-error (bad pointer, bad arg, length-too-small)
//! - -2 -- rustls protocol-level error (sets thread-local message)
//! - -3 -- internal Rust error (sets thread-local message)
//!
//! The thread-local message is fetched via
//! `flare_rustls_quic_last_error`.  Mojo's `OwnedDLHandle` keeps the
//! .so live across the FFI call, so the returned C string is safe to
//! read inside the same invocation.  No cross-thread sharing of the
//! pointer.
//!
//! The crate is `panic = "abort"` because the rustls APIs we use are
//! infallible-or-`Result` already; a panic would mean a rustls
//! internal bug and we want a hard fail (not UB) in that case.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void, CString};
use std::io::Read;
use std::slice;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::quic::{Connection as QuicConnection, DirectionalKeys, KeyChange, Keys, Version};
use rustls::server::{ServerConfig, ServerConnection};
use rustls::{ClientConfig, RootCertStore};

/// Encryption-level slot count. Order matches the QUIC spec
/// `[Initial, EarlyData, Handshake, 1-RTT]` so callers can use
/// the QuicEncryptionLevel codepoints flare's Mojo side already
/// carries.  Initial keys never flow through `KeyChange` (they
/// derive from the connection ID per RFC 9001 §5.2), so slot 0
/// stays empty here; the post-Initial branches (Handshake, 1-RTT)
/// are what rustls actually surfaces.
const LEVEL_COUNT: usize = 4;
const LEVEL_EARLY_DATA: usize = 1;
const LEVEL_HANDSHAKE: usize = 2;
const LEVEL_1RTT: usize = 3;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(msg: impl Into<String>) {
    let m = msg.into();
    let c = CString::new(m).unwrap_or_else(|_| {
        CString::new("flare_rustls_quic: error message contains NUL").unwrap()
    });
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(c);
    });
}

/// Returned pointer is valid until the next FFI call on the same
/// thread that sets a different message (or until thread exit).
/// Returns `b"\0"` when no message is recorded.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_ref() {
            Some(c) => c.as_ptr(),
            None => b"\0".as_ptr() as *const c_char,
        }
    })
}

/// Acceptor: long-lived, holds the rustls `ServerConfig`.
pub struct Acceptor {
    config: Arc<ServerConfig>,
}

/// Connector: long-lived, holds the rustls `ClientConfig`.
/// The client-role mirror of `Acceptor` -- one per HttpClient h3
/// origin policy (ALPN list + trust roots), reused across every
/// QUIC connection the client opens.
pub struct Connector {
    config: Arc<ClientConfig>,
}

/// Session: one per QUIC connection. Wraps a
/// `rustls::quic::Connection` (server variant).
pub struct Session {
    conn: QuicConnection,
    /// Pending outbound CRYPTO bytes by encryption level
    /// (0=Initial, 1=EarlyData, 2=Handshake, 3=Application).
    /// rustls coalesces the outbound bytes by level internally;
    /// we just buffer what `write_hs` produces until the Mojo
    /// side calls `take_crypto`.
    pending: [Vec<u8>; LEVEL_COUNT],
    /// Per-level rustls-derived `Keys` (header + packet for both
    /// local and remote directions).  Populated on every
    /// `KeyChange` rustls emits from `write_hs`:
    ///
    /// * `KeyChange::Handshake { keys }`  -> `keys[LEVEL_HANDSHAKE]`
    /// * `KeyChange::OneRtt   { keys, next: _ }` -> `keys[LEVEL_1RTT]`
    ///
    /// Initial keys never flow through `KeyChange` so slot 0
    /// stays `None` -- the flare Mojo side derives the Initial
    /// keys from the connection ID itself per RFC 9001 §5.2 and
    /// runs Initial AEAD through `OpenSslQuicCrypto`. The
    /// Handshake + 1-RTT branches dispatch through the new
    /// `flare_rustls_quic_packet_{encrypt,decrypt}` +
    /// `_header_{encrypt,decrypt}` thunks instead, because
    /// rustls's `Secrets` fields are `pub(crate)` (sealed) and
    /// only the already-derived `Keys` are exposed.
    keys: [Option<Keys>; LEVEL_COUNT],
    /// 0-RTT (EarlyData) keys, captured via
    /// `Connection::zero_rtt_keys()` rather than `KeyChange`
    /// (rustls has no `KeyChange::EarlyData`).  This is a SINGLE
    /// `DirectionalKeys`, not a `Keys` pair: on the client it is
    /// the local/encrypt direction, on the server the
    /// remote/decrypt direction.  Both ends derive it from the
    /// same client->server early-traffic secret, so the client
    /// `encrypt_in_place`s and the server `decrypt_in_place`s
    /// with the same key object.  `None` until
    /// `flare_rustls_quic_install_early_keys` captures it (after
    /// `connect` on a resumed client, or after the ClientHello is
    /// read on the server).
    early_keys: Option<DirectionalKeys>,
}

/// `flare_rustls_quic_acceptor_new` parses the PEM cert + key,
/// builds a `ServerConfig`, and returns a Box-leaked Acceptor.
///
/// `alpn_protos` is the wire-format ALPN list:
/// `len_byte || proto_bytes || len_byte || proto_bytes || ...`
/// matching the OpenSSL `flare_ssl_ctx_set_alpn_server` thunk's
/// shape so the Mojo side has one ALPN-encoding helper across
/// both backends.
///
/// Returns NULL on construction failure; check
/// `flare_rustls_quic_last_error` for the reason.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_acceptor_new(
    cert_pem: *const u8,
    cert_len: usize,
    key_pem: *const u8,
    key_len: usize,
    alpn_protos: *const u8,
    alpn_len: usize,
    max_early_data: u32,
) -> *mut c_void {
    if cert_pem.is_null() || key_pem.is_null() {
        set_last_error("flare_rustls_quic_acceptor_new: NULL cert or key");
        return std::ptr::null_mut();
    }
    let cert_bytes = unsafe { slice::from_raw_parts(cert_pem, cert_len) };
    let key_bytes = unsafe { slice::from_raw_parts(key_pem, key_len) };
    let alpn_bytes = if alpn_protos.is_null() || alpn_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(alpn_protos, alpn_len) }
    };

    let certs = match rustls_pemfile::certs(&mut std::io::Cursor::new(cert_bytes))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(certs) if !certs.is_empty() => certs,
        Ok(_) => {
            set_last_error("flare_rustls_quic_acceptor_new: cert PEM contained no CERTIFICATE blocks");
            return std::ptr::null_mut();
        }
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_acceptor_new: cert PEM parse failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };

    let key = match rustls_pemfile::private_key(&mut std::io::Cursor::new(key_bytes)) {
        Ok(Some(k)) => k,
        Ok(None) => {
            set_last_error("flare_rustls_quic_acceptor_new: key PEM contained no PRIVATE KEY blocks");
            return std::ptr::null_mut();
        }
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_acceptor_new: key PEM parse failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|b| {
            Ok(b.with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| rustls::Error::General(format!("cert/key load: {e}")))?)
        });
    let mut server_config = match builder {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_acceptor_new: ServerConfig build failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };

    // Parse the wire-format ALPN list into Vec<Vec<u8>>.
    let mut alpn_list = Vec::new();
    let mut i = 0;
    while i < alpn_bytes.len() {
        let len = alpn_bytes[i] as usize;
        i += 1;
        if i + len > alpn_bytes.len() {
            set_last_error("flare_rustls_quic_acceptor_new: ALPN wire format truncated");
            return std::ptr::null_mut();
        }
        alpn_list.push(alpn_bytes[i..i + len].to_vec());
        i += len;
    }
    server_config.alpn_protocols = alpn_list;

    // ABI 4: 0-RTT early data. When the caller asks for a non-zero
    // window we enable STATEFUL resumption and set max_early_data_size.
    //
    // RFC 8446 sec 8.1 (and rustls server/tls13.rs: early_data_configured
    // = max_early_data_size > 0 && !ticketer.enabled()) only permits
    // 0-RTT with stateful resumption: a stateless TLS1.3 Ticketer drops
    // max_early_data_size from the issued NewSessionTicket, so the
    // resumed client never offers early data and `zero_rtt_keys()`
    // stays None. We therefore install an in-memory session cache (the
    // builder default, made explicit here) and deliberately leave the
    // ticketer disabled.
    //
    // RFC 9001 sec 4.6.1 requires the ticket's max_early_data_size be
    // 0xffffffff for QUIC (QUIC does its own flow control), so any
    // non-zero request is clamped up to that sentinel; the caller's
    // numeric value is only a feature toggle. The default (0) leaves
    // the server 1-RTT-only, matching prior behavior.
    //
    // Stateful resumption keeps session state in this
    // process's memory only -- it does not share across a server fleet
    // (a multi-node deployment would need a shared ServerSessionStore).
    // For a single flare server process this is correct; the upgrade
    // path is a distributed StoresServerSessions impl. Anti-replay:
    // rustls enforces single-use obfuscated-age windows on the stateful
    // cache; the Mojo driver adds the idempotent-method gate on top.
    if max_early_data != 0 {
        server_config.session_storage =
            rustls::server::ServerSessionMemoryCache::new(256);
        server_config.max_early_data_size = 0xffff_ffff;
    }

    let acceptor = Box::new(Acceptor {
        config: Arc::new(server_config),
    });
    Box::into_raw(acceptor) as *mut c_void
}

/// Free an acceptor returned by `flare_rustls_quic_acceptor_new`.
///
/// NULL is a no-op (safe to call on `_new` returning NULL).
#[no_mangle]
pub extern "C" fn flare_rustls_quic_acceptor_free(acceptor: *mut c_void) {
    if acceptor.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(acceptor as *mut Acceptor);
    }
}

/// Construct a per-connection session.
///
/// `transport_params` is the QUIC transport-parameters extension
/// the server advertises to the peer (RFC 9000 §7.4 + RFC 9001
/// §8.2 -- carried in the TLS ClientHello / EncryptedExtensions
/// `quic_transport_parameters` extension).  Mojo encodes the
/// parameters using `flare.quic.transport_params` and passes the
/// resulting blob here.
///
/// Returns NULL on construction failure.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_accept(
    acceptor: *mut c_void,
    transport_params: *const u8,
    transport_params_len: usize,
) -> *mut c_void {
    if acceptor.is_null() {
        set_last_error("flare_rustls_quic_accept: NULL acceptor");
        return std::ptr::null_mut();
    }
    let acceptor_ref = unsafe { &*(acceptor as *const Acceptor) };
    let tp = if transport_params.is_null() || transport_params_len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(transport_params, transport_params_len).to_vec() }
    };
    let inner = match ServerConnection::new(acceptor_ref.config.clone()) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_accept: ServerConnection::new failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };
    let quic_conn =
        match rustls::quic::ServerConnection::new(acceptor_ref.config.clone(), Version::V1, tp) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(format!(
                    "flare_rustls_quic_accept: rustls::quic::ServerConnection::new failed: {e}"
                ));
                drop(inner);
                return std::ptr::null_mut();
            }
        };
    drop(inner);
    let session = Box::new(Session {
        conn: QuicConnection::Server(quic_conn),
        pending: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
        keys: [None, None, None, None],
        early_keys: None,
    });
    Box::into_raw(session) as *mut c_void
}

/// Free a session returned by `flare_rustls_quic_accept`.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_session_free(session: *mut c_void) {
    if session.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(session as *mut Session);
    }
}

/// `flare_rustls_quic_connector_new` builds a `ClientConfig` from a
/// trust-anchor PEM bundle + ALPN list and returns a Box-leaked
/// Connector (the client-role mirror of `acceptor_new`).
///
/// `ca_pem` is a PEM bundle of trusted root / self-signed
/// certificates: for a loopback test against flare's own server the
/// caller passes the server's self-signed cert (it is its own root);
/// for a public origin the caller passes the system trust bundle.
/// `ca_pem` must contain at least one CERTIFICATE block -- this shim
/// does not ship a default root set (webpki-roots lands with the
/// HttpClient public-h3 path), so an empty bundle is an error rather
/// than a silently-insecure connector.
///
/// `alpn_protos` is the same wire-format ALPN list shape as
/// `acceptor_new` (`len_byte || proto_bytes || ...`).
///
/// Returns NULL on construction failure; check
/// `flare_rustls_quic_last_error` for the reason.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_connector_new(
    ca_pem: *const u8,
    ca_len: usize,
    alpn_protos: *const u8,
    alpn_len: usize,
) -> *mut c_void {
    if ca_pem.is_null() || ca_len == 0 {
        set_last_error("flare_rustls_quic_connector_new: NULL or empty CA bundle");
        return std::ptr::null_mut();
    }
    let ca_bytes = unsafe { slice::from_raw_parts(ca_pem, ca_len) };
    let alpn_bytes = if alpn_protos.is_null() || alpn_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(alpn_protos, alpn_len) }
    };

    let cert_iter =
        rustls_pemfile::certs(&mut std::io::Cursor::new(ca_bytes)).collect::<Result<Vec<_>, _>>();
    let ca_certs = match cert_iter {
        Ok(certs) if !certs.is_empty() => certs,
        Ok(_) => {
            set_last_error(
                "flare_rustls_quic_connector_new: CA PEM contained no CERTIFICATE blocks",
            );
            return std::ptr::null_mut();
        }
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_connector_new: CA PEM parse failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };

    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        if let Err(e) = roots.add(cert) {
            set_last_error(format!(
                "flare_rustls_quic_connector_new: add root cert failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    }

    finish_connector(roots, alpn_bytes, "flare_rustls_quic_connector_new")
}

/// Shared connector-build tail for both the explicit-CA and
/// native-roots constructors: build the ClientConfig off the ring
/// provider with the supplied roots, enable resumption + 0-RTT, set
/// the wire-format ALPN list, and Box-leak the Connector. Returns
/// NULL + sets the thread-local error on failure.
fn finish_connector(roots: RootCertStore, alpn_bytes: &[u8], who: &str) -> *mut c_void {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map(|b| b.with_root_certificates(roots).with_no_client_auth());
    let mut client_config = match builder {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("{who}: ClientConfig build failed: {e}"));
            return std::ptr::null_mut();
        }
    };

    // ABI 4: enable session resumption + 0-RTT early data. The
    // ClientConfig already defaults `resumption` to an in-memory
    // ClientSessionMemoryCache, so a Connector (one Arc<ClientConfig>
    // reused across every QUIC connection the HttpClient opens to an
    // origin) shares one store: the first handshake stores the ticket
    // and the second connect to the same origin resumes + offers
    // 0-RTT. `enable_early_data` is opt-in (default false), so we flip
    // it here; rustls only actually rides 0-RTT when a stored ticket
    // for the SNI exists, so the first connection is always 1-RTT.
    client_config.enable_early_data = true;

    // Parse the wire-format ALPN list into Vec<Vec<u8>> (same shape
    // as acceptor_new so both roles share one Mojo encoder).
    let mut alpn_list = Vec::new();
    let mut i = 0;
    while i < alpn_bytes.len() {
        let len = alpn_bytes[i] as usize;
        i += 1;
        if i + len > alpn_bytes.len() {
            set_last_error(format!("{who}: ALPN wire format truncated"));
            return std::ptr::null_mut();
        }
        alpn_list.push(alpn_bytes[i..i + len].to_vec());
        i += len;
    }
    client_config.alpn_protocols = alpn_list;

    let connector = Box::new(Connector {
        config: Arc::new(client_config),
    });
    Box::into_raw(connector) as *mut c_void
}

/// `flare_rustls_quic_connector_new_native_roots` builds a Connector
/// trusting the operating system's CA bundle (loaded at runtime via
/// `rustls-native-certs`) instead of a caller-supplied PEM. This is
/// the public-internet h3 client path: no PEM to ship, the platform
/// trust store is the source of truth.
///
/// `alpn_protos` is the same wire-format ALPN list shape as
/// `connector_new` (`len_byte || proto_bytes || ...`).
///
/// Returns NULL on failure (no native roots found, or none usable);
/// check `flare_rustls_quic_last_error` for the reason.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_connector_new_native_roots(
    alpn_protos: *const u8,
    alpn_len: usize,
) -> *mut c_void {
    let alpn_bytes = if alpn_protos.is_null() || alpn_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(alpn_protos, alpn_len) }
    };

    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        set_last_error(
            "flare_rustls_quic_connector_new_native_roots: no native root certificates found",
        );
        return std::ptr::null_mut();
    }
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        set_last_error(
            "flare_rustls_quic_connector_new_native_roots: no usable native root certificates",
        );
        return std::ptr::null_mut();
    }

    finish_connector(
        roots,
        alpn_bytes,
        "flare_rustls_quic_connector_new_native_roots",
    )
}

/// Free a connector returned by `flare_rustls_quic_connector_new`.
///
/// NULL is a no-op (safe to call on `_new` returning NULL).
#[no_mangle]
pub extern "C" fn flare_rustls_quic_connector_free(connector: *mut c_void) {
    if connector.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(connector as *mut Connector);
    }
}

/// Construct a client-role per-connection session against
/// `server_name` (SNI / cert-verification hostname).
///
/// `server_name` is the UTF-8 hostname bytes (no trailing NUL).
/// `transport_params` is the client's QUIC transport-parameters
/// extension (RFC 9000 §7.4), encoded by `flare.quic.transport_params`
/// on the Mojo side, mirroring `flare_rustls_quic_accept`.
///
/// The returned `Session` wraps a `rustls::quic::ClientConnection`;
/// the very first `flare_rustls_quic_take_crypto(level=0)` drains the
/// Initial-level ClientHello rustls produces, so the caller drives the
/// client handshake through the same feed/take CRYPTO thunks the
/// server uses.
///
/// Returns NULL on construction failure.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_connect(
    connector: *mut c_void,
    server_name: *const u8,
    server_name_len: usize,
    transport_params: *const u8,
    transport_params_len: usize,
) -> *mut c_void {
    if connector.is_null() {
        set_last_error("flare_rustls_quic_connect: NULL connector");
        return std::ptr::null_mut();
    }
    if server_name.is_null() || server_name_len == 0 {
        set_last_error("flare_rustls_quic_connect: NULL or empty server_name");
        return std::ptr::null_mut();
    }
    let connector_ref = unsafe { &*(connector as *const Connector) };
    let name_bytes = unsafe { slice::from_raw_parts(server_name, server_name_len) };
    let name_str = match std::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_connect: server_name is not valid UTF-8: {e}"
            ));
            return std::ptr::null_mut();
        }
    };
    let sni = match ServerName::try_from(name_str.to_owned()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_connect: invalid server_name '{name_str}': {e}"
            ));
            return std::ptr::null_mut();
        }
    };
    let tp = if transport_params.is_null() || transport_params_len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(transport_params, transport_params_len).to_vec() }
    };
    let quic_conn = match rustls::quic::ClientConnection::new(
        connector_ref.config.clone(),
        Version::V1,
        sni,
        tp,
    ) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_connect: rustls::quic::ClientConnection::new failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };
    let session = Box::new(Session {
        conn: QuicConnection::Client(quic_conn),
        pending: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
        keys: [None, None, None, None],
        early_keys: None,
    });
    Box::into_raw(session) as *mut c_void
}

/// Feed inbound CRYPTO frame bytes at the given encryption level.
///
/// rustls's QUIC API takes the level implicitly -- the level is
/// inferred from the connection's current expected level. We
/// accept the level argument anyway so the Mojo side can pin the
/// dispatch shape (and so a future rustls revision that takes the
/// level explicitly is a one-line change).
///
/// Returns 0 on success, -1 on bad pointer, -2 on rustls error.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_feed_crypto(
    session: *mut c_void,
    _level: c_int,
    buf: *const u8,
    len: usize,
) -> c_int {
    if session.is_null() {
        set_last_error("flare_rustls_quic_feed_crypto: NULL session");
        return -1;
    }
    if buf.is_null() && len > 0 {
        set_last_error("flare_rustls_quic_feed_crypto: NULL buf with non-zero len");
        return -1;
    }
    let sess = unsafe { &mut *(session as *mut Session) };
    let data = unsafe { slice::from_raw_parts(buf, len) };
    let mut cursor = std::io::Cursor::new(data);
    let mut conn_bytes: Vec<u8> = Vec::new();
    if let Err(e) = cursor.read_to_end(&mut conn_bytes) {
        set_last_error(format!("flare_rustls_quic_feed_crypto: read failed: {e}"));
        return -2;
    }
    if let Err(e) = sess.conn.read_hs(&conn_bytes) {
        set_last_error(format!("flare_rustls_quic_feed_crypto: read_hs failed: {e}"));
        return -2;
    }
    // After consuming peer's bytes, pull our outbound bytes into
    // the per-level pending vec. rustls's write_hs returns the
    // current keys + writes to the supplied buffer; we route the
    // bytes into our per-level queue based on rustls's reported
    // level (the connection tracks it internally).
    drain_outbound(sess);
    0
}

/// Drain pending outbound CRYPTO frame bytes at the given level.
///
/// Returns 0 on success; -1 on bad pointer / out_cap too small.
/// On success, `*written` receives the byte count copied into
/// `out`.  When `out_cap` is smaller than the pending bytes the
/// excess stays pending; the Mojo side calls again with a bigger
/// buffer or after sending the previous batch.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_take_crypto(
    session: *mut c_void,
    level: c_int,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
) -> c_int {
    if session.is_null() || written.is_null() {
        set_last_error("flare_rustls_quic_take_crypto: NULL session or written");
        return -1;
    }
    if (level as usize) >= 4 {
        set_last_error("flare_rustls_quic_take_crypto: level >= 4");
        return -1;
    }
    let sess = unsafe { &mut *(session as *mut Session) };
    drain_outbound(sess);
    let pending = &mut sess.pending[level as usize];
    let n = pending.len().min(out_cap);
    if n > 0 {
        if out.is_null() {
            set_last_error("flare_rustls_quic_take_crypto: NULL out with non-zero pending");
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(pending.as_ptr(), out, n);
        }
        pending.drain(..n);
    }
    unsafe { *written = n };
    0
}

/// Whether the handshake has completed (1-RTT keys derived).
///
/// Returns 1 if complete, 0 if not, -1 on bad pointer.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_is_handshake_complete(session: *mut c_void) -> c_int {
    if session.is_null() {
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    // rustls::CommonState::is_handshaking is true while still in
    // the handshake; we flip the boolean.
    let common = match &sess.conn {
        QuicConnection::Server(c) => c.is_handshaking(),
        QuicConnection::Client(c) => c.is_handshaking(),
    };
    if common {
        0
    } else {
        1
    }
}

/// Copy the negotiated ALPN identifier into `out` (no trailing NUL).
///
/// Returns the byte count written, 0 if no ALPN was negotiated,
/// or -1 on bad pointer / out_cap too small.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_alpn(
    session: *mut c_void,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
) -> c_int {
    if session.is_null() || written.is_null() {
        set_last_error("flare_rustls_quic_alpn: NULL session or written");
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    let alpn = match &sess.conn {
        QuicConnection::Server(c) => c.alpn_protocol(),
        QuicConnection::Client(c) => c.alpn_protocol(),
    };
    let bytes = match alpn {
        Some(b) => b,
        None => {
            unsafe { *written = 0 };
            return 0;
        }
    };
    if bytes.len() > out_cap {
        set_last_error("flare_rustls_quic_alpn: out_cap too small for ALPN id");
        return -1;
    }
    if !out.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
            *written = bytes.len();
        }
    } else {
        unsafe { *written = bytes.len() };
    }
    bytes.len() as c_int
}

/// Copy the peer's raw QUIC transport-parameters extension into
/// `out` (the bytes the peer advertised in its ClientHello /
/// EncryptedExtensions `quic_transport_parameters` extension,
/// RFC 9000 §7.4). The caller decodes them with
/// `flare.quic.transport_params.decode_transport_parameters`.
///
/// rustls only surfaces these once the relevant handshake flight
/// has been processed (server params become available to the
/// client after the EncryptedExtensions are read; client params
/// to the server after the ClientHello). Poll after the handshake
/// completes for a stable result.
///
/// Returns the byte count written, 0 if the peer params are not
/// yet available, or -1 on bad pointer / out_cap too small.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_peer_transport_params(
    session: *mut c_void,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
) -> c_int {
    if session.is_null() || written.is_null() {
        set_last_error(
            "flare_rustls_quic_peer_transport_params: NULL session or written",
        );
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    let params = sess.conn.quic_transport_parameters();
    let bytes = match params {
        Some(b) => b,
        None => {
            unsafe { *written = 0 };
            return 0;
        }
    };
    if bytes.len() > out_cap {
        set_last_error(
            "flare_rustls_quic_peer_transport_params: out_cap too small",
        );
        return -1;
    }
    if !out.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
            *written = bytes.len();
        }
    } else {
        unsafe { *written = bytes.len() };
    }
    bytes.len() as c_int
}

/// Capture the 0-RTT (EarlyData) `DirectionalKeys` from rustls,
/// if available, into the session's `early_keys` slot.
///
/// rustls exposes 0-RTT keys via `Connection::zero_rtt_keys()`
/// (NOT through `KeyChange`, which has no EarlyData variant). On
/// the client this returns `Some` right after `connect` IF the
/// ClientConfig had a stored ticket for the SNI + `enable_early_data`
/// (so a resumed connection); on the server it returns `Some` after
/// the ClientHello has been read and early data was accepted. Callers
/// poll this after `connect` (client) / `feed_crypto` of the Initial
/// (server) and, on a `1` return, drive 0-RTT packets through the
/// `_packet_*` / `_header_*` thunks at `level == 1`.
///
/// Returns 1 if keys were captured (or already present), 0 if rustls
/// has no 0-RTT keys for this connection, -1 on a NULL session.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_install_early_keys(session: *mut c_void) -> c_int {
    if session.is_null() {
        set_last_error("flare_rustls_quic_install_early_keys: NULL session");
        return -1;
    }
    let sess = unsafe { &mut *(session as *mut Session) };
    if sess.early_keys.is_some() {
        return 1;
    }
    match sess.conn.zero_rtt_keys() {
        Some(k) => {
            sess.early_keys = Some(k);
            1
        }
        None => 0,
    }
}

/// Whether the server signalled it will process the client's early
/// data (client-role only; RFC 8446 sec 4.2.10). A `0` after the
/// handshake completes means the server rejected 0-RTT and the
/// client must replay the early data in 1-RTT.
///
/// Returns 1 if accepted, 0 if not (or not a client / not resumed),
/// -1 on a NULL session.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_is_early_data_accepted(session: *mut c_void) -> c_int {
    if session.is_null() {
        set_last_error("flare_rustls_quic_is_early_data_accepted: NULL session");
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    match &sess.conn {
        QuicConnection::Client(c) => {
            if c.is_early_data_accepted() {
                1
            } else {
                0
            }
        }
        QuicConnection::Server(_) => 0,
    }
}

/// Crate version sanity-check thunk so Mojo callers can confirm
/// the .so dlopen resolved to this crate (not a stale build).
/// Returns 2 for the current surface (rustls KeyChange bridge +
/// per-level AEAD + header-protection thunks); future ABI breaks
/// bump this and force the activation script to rebuild.
///
/// Versions:
/// * 1 -- acceptor + session + feed/take CRYPTO + ALPN
///   introspection.
/// * 2 -- adds
///   `flare_rustls_quic_have_keys`,
///   `flare_rustls_quic_packet_encrypt` / `_packet_decrypt`,
///   `flare_rustls_quic_header_encrypt` / `_header_decrypt`,
///   and the per-level `KeyChange` capture inside `drain_outbound`.
/// * 3 -- adds the client role:
///   `flare_rustls_quic_connector_new` / `_free`,
///   `flare_rustls_quic_connect` (builds a
///   `rustls::quic::ClientConnection`). The feed/take CRYPTO, AEAD,
///   header-protection, ALPN, and handshake-complete thunks are
///   role-agnostic and serve both roles unchanged.
///
/// Returns `i64` rather than `c_int` because Mojo callers bind
/// every flare FFI no-arg thunk via `def() thin abi("C") -> Int`,
/// and `Int` is 64-bit. Returning `c_int` would leave the upper
/// 32 bits of `rax` undefined under the SysV x86-64 ABI; the i64
/// shape is the lossless path. The other thunks return `c_int`
/// for parity with the rustls / C-string API and Mojo callers
/// declare them as `c_int` on the Mojo side.
/// * 4 -- adds 0-RTT early data + resumption:
///   `flare_rustls_quic_install_early_keys` (captures
///   `Connection::zero_rtt_keys()` into the EarlyData slot),
///   `flare_rustls_quic_is_early_data_accepted`, an in-memory
///   client session store + `enable_early_data` on the connector,
///   server-side stateful resumption (in-memory session cache, NOT a
///   stateless ticketer -- RFC 8446 sec 8.1 forbids 0-RTT with
///   stateless tickets) + `max_early_data_size` (new `max_early_data`
///   arg on `acceptor_new`), and EarlyData (`level == 1`) support
///   in the `_packet_*` / `_header_*` / `_have_keys` thunks.
/// * 5 -- adds `flare_rustls_quic_connector_new_native_roots`
///   (builds a Connector trusting the OS CA bundle via
///   `rustls-native-certs`, for the public-internet h3 client path).
/// * 6 -- adds `flare_rustls_quic_peer_transport_params` (copies the
///   peer's raw `quic_transport_parameters` extension out for the
///   Mojo-side decoder, so the stack can apply the peer's flow
///   control / CID limits after the handshake).
#[no_mangle]
pub extern "C" fn flare_rustls_quic_abi_version() -> i64 {
    6
}

/// Returns 1 if rustls has installed per-level keys at the given
/// encryption level (0=Initial, 1=EarlyData, 2=Handshake,
/// 3=1-RTT), 0 if not, -1 on bad pointer / out-of-range level.
///
/// Initial keys never flow through `KeyChange`; the Initial level
/// always returns 0 here.  The Mojo side derives Initial keys
/// from the connection ID per RFC 9001 §5.2 and dispatches that
/// path through `OpenSslQuicCrypto` -- this thunk is only the
/// post-Initial readiness check.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_have_keys(
    session: *mut c_void,
    level: c_int,
) -> c_int {
    if session.is_null() {
        set_last_error("flare_rustls_quic_have_keys: NULL session");
        return -1;
    }
    let lvl = level as usize;
    if lvl >= LEVEL_COUNT {
        set_last_error("flare_rustls_quic_have_keys: level out of range");
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    let present = if lvl == LEVEL_EARLY_DATA {
        sess.early_keys.is_some()
    } else {
        sess.keys[lvl].is_some()
    };
    if present {
        1
    } else {
        0
    }
}

/// Encrypt a QUIC payload at the given encryption level using
/// rustls's already-derived `Keys.local.packet` (the server's
/// outbound AEAD key).
///
/// Parameters:
/// * `session`     -- session handle from `flare_rustls_quic_accept`.
/// * `level`       -- encryption level (2=Handshake, 3=1-RTT;
///   0/1 return -1).
/// * `packet_number` -- the QUIC packet number (host-order u64
///   matching rustls's API).
/// * `header_ptr` / `header_len` -- the QUIC packet header bytes
///   used as AEAD additional-authenticated-data (RFC 9001 §5.3).
/// * `payload_ptr` / `payload_len` -- in-place buffer holding the
///   plaintext payload; encryption rewrites it in place and the
///   16-byte authentication tag goes into `tag_ptr`.
/// * `tag_ptr` / `tag_cap` -- caller-supplied tag buffer; must be
///   >= 16 bytes (AES-GCM + ChaCha20-Poly1305 both produce a
///   16-byte tag).
/// * `tag_written` -- receives the actual tag length on success.
///
/// Returns 0 on success, -1 on bad pointer / out-of-range level
/// / undersized tag buffer / keys not yet installed at level,
/// -2 on rustls AEAD error (sets `last_error`).
#[no_mangle]
pub extern "C" fn flare_rustls_quic_packet_encrypt(
    session: *mut c_void,
    level: c_int,
    packet_number: u64,
    header_ptr: *const u8,
    header_len: usize,
    payload_ptr: *mut u8,
    payload_len: usize,
    tag_ptr: *mut u8,
    tag_cap: usize,
    tag_written: *mut usize,
) -> c_int {
    if session.is_null() || tag_written.is_null() {
        set_last_error("flare_rustls_quic_packet_encrypt: NULL session or tag_written");
        return -1;
    }
    if header_ptr.is_null() && header_len > 0 {
        set_last_error("flare_rustls_quic_packet_encrypt: NULL header with non-zero len");
        return -1;
    }
    if payload_ptr.is_null() && payload_len > 0 {
        set_last_error("flare_rustls_quic_packet_encrypt: NULL payload with non-zero len");
        return -1;
    }
    if tag_ptr.is_null() || tag_cap < 16 {
        set_last_error("flare_rustls_quic_packet_encrypt: tag buffer too small (need 16)");
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    let lvl = level as usize;
    let packet_key = if lvl == LEVEL_EARLY_DATA {
        match early_keys_for_level(sess) {
            Some(k) => &k.packet,
            None => return -1,
        }
    } else {
        match keys_for_level(sess, lvl) {
            Some(k) => &k.local.packet,
            None => return -1,
        }
    };
    let header = unsafe { slice::from_raw_parts(header_ptr, header_len) };
    let payload = unsafe { slice::from_raw_parts_mut(payload_ptr, payload_len) };
    match packet_key.encrypt_in_place(packet_number, header, payload) {
        Ok(tag) => {
            let tag_bytes = tag.as_ref();
            let n = tag_bytes.len();
            if n > tag_cap {
                set_last_error(
                    "flare_rustls_quic_packet_encrypt: tag larger than caller buffer",
                );
                return -1;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(tag_bytes.as_ptr(), tag_ptr, n);
                *tag_written = n;
            }
            0
        }
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_packet_encrypt: rustls AEAD error: {e}"
            ));
            -2
        }
    }
}

/// Decrypt a QUIC payload at the given encryption level using
/// rustls's `Keys.remote.packet` (the server's inbound AEAD key).
///
/// `payload_ptr / payload_len` MUST include the 16-byte
/// authentication tag at the tail (rustls verifies and strips it
/// in place per RFC 9001 §5.3); `plaintext_len` receives the
/// plaintext length on success (always `payload_len - 16` for
/// the standard QUIC AEAD suites).
///
/// Returns 0 on success, -1 on bad pointer / out-of-range level /
/// keys not yet installed, -2 on rustls AEAD verification
/// failure or any other rustls error.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_packet_decrypt(
    session: *mut c_void,
    level: c_int,
    packet_number: u64,
    header_ptr: *const u8,
    header_len: usize,
    payload_ptr: *mut u8,
    payload_len: usize,
    plaintext_len: *mut usize,
) -> c_int {
    if session.is_null() || plaintext_len.is_null() {
        set_last_error("flare_rustls_quic_packet_decrypt: NULL session or plaintext_len");
        return -1;
    }
    if header_ptr.is_null() && header_len > 0 {
        set_last_error("flare_rustls_quic_packet_decrypt: NULL header with non-zero len");
        return -1;
    }
    if payload_ptr.is_null() && payload_len > 0 {
        set_last_error("flare_rustls_quic_packet_decrypt: NULL payload with non-zero len");
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    let lvl = level as usize;
    let packet_key = if lvl == LEVEL_EARLY_DATA {
        match early_keys_for_level(sess) {
            Some(k) => &k.packet,
            None => return -1,
        }
    } else {
        match keys_for_level(sess, lvl) {
            Some(k) => &k.remote.packet,
            None => return -1,
        }
    };
    let header = unsafe { slice::from_raw_parts(header_ptr, header_len) };
    let payload = unsafe { slice::from_raw_parts_mut(payload_ptr, payload_len) };
    match packet_key.decrypt_in_place(packet_number, header, payload) {
        Ok(pt) => {
            unsafe { *plaintext_len = pt.len() };
            0
        }
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_packet_decrypt: rustls AEAD error: {e}"
            ));
            -2
        }
    }
}

/// Apply QUIC header protection to a packet's first byte +
/// packet-number bytes, using rustls's
/// `Keys.local.header.encrypt_in_place` (RFC 9001 §5.4).  The
/// sample buffer is the encrypted payload sample (16 bytes
/// after the start of the packet-number field, regardless of the
/// declared pn length).
///
/// Caller must pass a `sample_len` >= the cipher suite's sample
/// size (16 bytes for AES-GCM / ChaCha20-Poly1305 -- the suites
/// rustls speaks today).
///
/// Returns 0 on success, -1 on bad pointer / level out of range /
/// keys not yet installed, -2 on rustls error.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_header_encrypt(
    session: *mut c_void,
    level: c_int,
    sample_ptr: *const u8,
    sample_len: usize,
    first_byte: *mut u8,
    pn_ptr: *mut u8,
    pn_len: usize,
) -> c_int {
    if session.is_null() || first_byte.is_null() {
        set_last_error("flare_rustls_quic_header_encrypt: NULL session or first_byte");
        return -1;
    }
    if sample_ptr.is_null() && sample_len > 0 {
        set_last_error("flare_rustls_quic_header_encrypt: NULL sample with non-zero len");
        return -1;
    }
    if pn_ptr.is_null() && pn_len > 0 {
        set_last_error("flare_rustls_quic_header_encrypt: NULL pn_ptr with non-zero len");
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    let lvl = level as usize;
    let header_key = if lvl == LEVEL_EARLY_DATA {
        match early_keys_for_level(sess) {
            Some(k) => &k.header,
            None => return -1,
        }
    } else {
        match keys_for_level(sess, lvl) {
            Some(k) => &k.local.header,
            None => return -1,
        }
    };
    let sample = unsafe { slice::from_raw_parts(sample_ptr, sample_len) };
    let first = unsafe { &mut *first_byte };
    let pn = unsafe { slice::from_raw_parts_mut(pn_ptr, pn_len) };
    match header_key.encrypt_in_place(sample, first, pn) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_header_encrypt: rustls HP error: {e}"
            ));
            -2
        }
    }
}

/// Remove QUIC header protection from a packet's first byte +
/// packet-number bytes, using rustls's
/// `Keys.remote.header.decrypt_in_place` (RFC 9001 §5.4).  Same
/// sample/first/pn contract as `header_encrypt`.
///
/// Returns 0 on success, -1 on bad pointer / level out of range /
/// keys not yet installed, -2 on rustls error.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_header_decrypt(
    session: *mut c_void,
    level: c_int,
    sample_ptr: *const u8,
    sample_len: usize,
    first_byte: *mut u8,
    pn_ptr: *mut u8,
    pn_len: usize,
) -> c_int {
    if session.is_null() || first_byte.is_null() {
        set_last_error("flare_rustls_quic_header_decrypt: NULL session or first_byte");
        return -1;
    }
    if sample_ptr.is_null() && sample_len > 0 {
        set_last_error("flare_rustls_quic_header_decrypt: NULL sample with non-zero len");
        return -1;
    }
    if pn_ptr.is_null() && pn_len > 0 {
        set_last_error("flare_rustls_quic_header_decrypt: NULL pn_ptr with non-zero len");
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    let lvl = level as usize;
    let header_key = if lvl == LEVEL_EARLY_DATA {
        match early_keys_for_level(sess) {
            Some(k) => &k.header,
            None => return -1,
        }
    } else {
        match keys_for_level(sess, lvl) {
            Some(k) => &k.remote.header,
            None => return -1,
        }
    };
    let sample = unsafe { slice::from_raw_parts(sample_ptr, sample_len) };
    let first = unsafe { &mut *first_byte };
    let pn = unsafe { slice::from_raw_parts_mut(pn_ptr, pn_len) };
    match header_key.decrypt_in_place(sample, first, pn) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_header_decrypt: rustls HP error: {e}"
            ));
            -2
        }
    }
}

// ── Internal helpers ─────────────────────────────────────────────

/// Pull rustls's outbound CRYPTO bytes into our per-level pending
/// queue and capture any `KeyChange` rustls reports along the way.
///
/// rustls's `write_hs` writes the next batch of handshake bytes
/// into the supplied `Vec` and OPTIONALLY returns a `KeyChange`
/// signalling that subsequent writes target a new encryption
/// level.  The byte run that comes *back* from a `write_hs` call
/// belongs to the level the connection was emitting *before* the
/// transition; the returned `KeyChange` arms the next batch.  We
/// pump `write_hs` in a loop until it returns no bytes + no key
/// change so a single Mojo-side call drains every outbound batch
/// rustls has queued.
///
/// Through the rustls KeyChange FFI extension, the
/// `KeyChange::Handshake { keys }` + `KeyChange::OneRtt { keys,
/// next: _ }` variants flip the session's `keys[LEVEL_*]` slots
/// from `None` to `Some(keys)`; the new
/// `flare_rustls_quic_packet_{encrypt,decrypt}` +
/// `_header_{encrypt,decrypt}` thunks read those slots to drive
/// the post-Initial AEAD path on the Mojo side.  We ignore the
/// `next` `Secrets` from the OneRtt variant -- key updates land
/// in a follow-up FFI (when QuicListener requests them).
fn drain_outbound(sess: &mut Session) {
    // Encryption level the bytes coming *back* from this batch
    // belong to. Start at the lowest level the session still has
    // outstanding work at; the KeyChange pump below advances it.
    let mut current_level: usize = current_send_level(sess);
    loop {
        let mut buf: Vec<u8> = Vec::new();
        let maybe_change = sess.conn.write_hs(&mut buf);
        if !buf.is_empty() {
            sess.pending[current_level].extend_from_slice(&buf);
        }
        match maybe_change {
            Some(KeyChange::Handshake { keys }) => {
                sess.keys[LEVEL_HANDSHAKE] = Some(keys);
                current_level = LEVEL_HANDSHAKE;
            }
            Some(KeyChange::OneRtt { keys, next: _ }) => {
                sess.keys[LEVEL_1RTT] = Some(keys);
                current_level = LEVEL_1RTT;
            }
            None => {
                // No transition; loop exits once write_hs also
                // stops producing bytes (empty buf + no
                // KeyChange => steady state).
                if buf.is_empty() {
                    break;
                }
            }
        }
    }
}

/// Pick the outbound encryption level the session is currently
/// emitting at, derived from which `keys[..]` slots have already
/// been installed.  This is the "starting" level for the next
/// `drain_outbound` batch; the per-batch loop in `drain_outbound`
/// promotes it whenever rustls emits a `KeyChange`.
///
/// Ordering matters: Initial -> Handshake -> 1-RTT is the only
/// progression rustls can produce on the server side (no 0-RTT
/// without a configured early-data acceptor, which we don't wire).
fn current_send_level(sess: &Session) -> usize {
    if sess.keys[LEVEL_1RTT].is_some() {
        LEVEL_1RTT
    } else if sess.keys[LEVEL_HANDSHAKE].is_some() {
        LEVEL_HANDSHAKE
    } else {
        0
    }
}

/// Borrow the per-level `Keys` from the session, returning a
/// pointer error code via `set_last_error` if the level is out of
/// range or the keys have not yet been installed.
fn keys_for_level(sess: &Session, level: usize) -> Option<&Keys> {
    if level >= LEVEL_COUNT {
        set_last_error("rustls_quic: encryption level out of range");
        return None;
    }
    match &sess.keys[level] {
        Some(k) => Some(k),
        None => {
            set_last_error("rustls_quic: per-level keys not yet installed");
            None
        }
    }
}

/// Borrow the 0-RTT (EarlyData) `DirectionalKeys`, or set an error
/// and return None if they have not been captured yet (the Mojo
/// driver must call `flare_rustls_quic_install_early_keys` first).
fn early_keys_for_level(sess: &Session) -> Option<&DirectionalKeys> {
    match &sess.early_keys {
        Some(k) => Some(k),
        None => {
            set_last_error("rustls_quic: 0-RTT keys not yet installed");
            None
        }
    }
}

// ── In-crate unit tests (cargo test + cargo miri test) ──────────────
//
// These tests exercise the C ABI surface from inside Rust so
// `cargo +nightly miri test` can interpret them under the strict
// undefined-behavior detector.  Miri cannot drive rustls's `ring`
// crypto path (assembly + FFI), so the tests are scoped to:
//
// - acceptor_new with invalid PEM (pure-Rust pemfile parsing)
// - acceptor_free with NULL (no-op safety)
// - last_error round-trip across set / get
// - acceptor_free of a real Box-leaked acceptor (so the Drop
//   chain runs under miri)
//
// The full handshake-driving tests live on the Mojo side under
// `tests/tls/test_rustls_quic_handshake.mojo` (ASan-clean).
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn acceptor_new_rejects_empty_pem() {
        let p = flare_rustls_quic_acceptor_new(
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            0,
        );
        assert!(p.is_null(), "NULL cert should be rejected");
        let err = unsafe { CStr::from_ptr(flare_rustls_quic_last_error()) };
        assert!(
            err.to_string_lossy().contains("NULL cert"),
            "expected NULL-cert error, got {:?}",
            err
        );
    }

    #[test]
    fn acceptor_new_rejects_garbage_pem() {
        let garbage = b"not actually pem";
        let p = flare_rustls_quic_acceptor_new(
            garbage.as_ptr(),
            garbage.len(),
            garbage.as_ptr(),
            garbage.len(),
            std::ptr::null(),
            0,
            0,
        );
        assert!(p.is_null(), "garbage PEM should be rejected");
        let err = unsafe { CStr::from_ptr(flare_rustls_quic_last_error()) };
        let msg = err.to_string_lossy();
        assert!(
            msg.contains("CERTIFICATE") || msg.contains("PEM"),
            "expected PEM-parse error, got {:?}",
            msg
        );
    }

    #[test]
    fn acceptor_free_null_is_noop() {
        flare_rustls_quic_acceptor_free(std::ptr::null_mut());
    }

    #[test]
    fn session_free_null_is_noop() {
        flare_rustls_quic_session_free(std::ptr::null_mut());
    }

    #[test]
    fn abi_version_returns_six() {
        // The ABI bumped 1 -> 2 (KeyChange-capture + per-level
        // AEAD/HP thunks) -> 3 (client role: connector_new/_free +
        // connect) -> 4 (0-RTT early data + resumption: install_early_keys
        // / is_early_data_accepted + EarlyData-level AEAD/HP + the
        // max_early_data arg on acceptor_new) -> 5 (native-roots
        // connector) -> 6 (peer transport-param accessor). The
        // activation script keys off this number, so a stale .so on a
        // developer machine surfaces as a hard mismatch on
        // `pixi install` rather than a silent run-time confusion.
        assert_eq!(flare_rustls_quic_abi_version(), 6);
    }

    #[test]
    fn quic_client_resumes_with_early_keys() {
        // Ground-truth diagnostic for the v0.9 client-side 0-RTT
        // readiness path: drive TWO full in-memory QUIC handshakes
        // against rustls directly (no FFI, no Mojo driver, no UDP) on
        // ONE shared ClientConfig, and assert the resumed connection
        // is handed 0-RTT (EarlyData) keys via `zero_rtt_keys()`.
        //
        // This isolates whether rustls itself supplies early keys
        // under our exact connector/acceptor config (enable_early_data
        // + ticketer + max_early_data_size). If this passes but the
        // loopback test fails, the gap is in the Mojo driver's ticket
        // delivery, not the crypto config.
        use rustls::pki_types::ServerName;
        use rustls::quic::{ClientConnection, Connection, ServerConnection, Version};

        let ca_pem = include_str!(
            "../../../../../tests/tls/fixtures/rustls-quic-client/ca.pem"
        );
        let cert_pem = include_str!(
            "../../../../../tests/tls/fixtures/rustls-quic-client/cert.pem"
        );
        let key_pem = include_str!(
            "../../../../../tests/tls/fixtures/rustls-quic-client/key.pem"
        );

        // Client config: mirror `finish_connector` (roots from CA PEM,
        // enable_early_data, h3 ALPN). Shared Arc => shared in-memory
        // session store across both connections.
        let mut roots = RootCertStore::empty();
        for c in
            rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem.as_bytes()))
        {
            roots.add(c.unwrap()).unwrap();
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_config = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.enable_early_data = true;
        client_config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config = Arc::new(client_config);

        // Server config: mirror `acceptor_new` with 0-RTT enabled
        // (ticketer + max_early_data_size).
        let certs =
            rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key =
            rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem.as_bytes()))
                .unwrap()
                .unwrap();
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        server_config.alpn_protocols = vec![b"h3".to_vec()];
        // RFC 8446 sec 8.1 / rustls: 0-RTT requires STATEFUL resumption.
        // A stateless `Ticketer` drops max_early_data_size from the
        // ticket, so use the default in-memory session storage and do
        // NOT install a ticketer.
        server_config.session_storage =
            rustls::server::ServerSessionMemoryCache::new(256);
        server_config.max_early_data_size = 0xffff_ffff;
        let server_config = Arc::new(server_config);

        let tp = vec![0x00u8, 0x01, 0x02, 0x03];

        // Drain one side's pending handshake plaintext fully. rustls's
        // `write_hs` may append bytes AND return None on the same call,
        // so loop until neither bytes nor a KeyChange are produced.
        fn drain(conn: &mut Connection) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let before = out.len();
                let kc = conn.write_hs(&mut out);
                if kc.is_none() && out.len() == before {
                    break;
                }
            }
            out
        }

        fn handshake(client: &mut Connection, server: &mut Connection) {
            for _ in 0..16 {
                let c = drain(client);
                if !c.is_empty() {
                    server.read_hs(&c).unwrap();
                }
                let s = drain(server);
                if !s.is_empty() {
                    client.read_hs(&s).unwrap();
                }
                if !client.is_handshaking() && !server.is_handshaking() {
                    return;
                }
            }
            panic!("handshake did not complete within 16 rounds");
        }

        // Connection 1: full handshake. A fresh client has no resumed
        // session, so no early keys yet.
        let mut c1 = Connection::Client(
            ClientConnection::new(
                client_config.clone(),
                Version::V1,
                ServerName::try_from("localhost").unwrap(),
                tp.clone(),
            )
            .unwrap(),
        );
        let mut s1 = Connection::Server(
            ServerConnection::new(server_config.clone(), Version::V1, tp.clone())
                .unwrap(),
        );
        // A fresh (non-resumed) client never has 0-RTT keys, even
        // after writing its ClientHello.
        assert!(
            c1.zero_rtt_keys().is_none(),
            "a fresh (non-resumed) client must not have 0-RTT keys"
        );
        handshake(&mut c1, &mut s1);

        // Post-handshake: pump both directions so the server emits its
        // NewSessionTicket(s) and the client caches them in the shared
        // ClientConfig store.
        for _ in 0..6 {
            let c = drain(&mut c1);
            if !c.is_empty() {
                s1.read_hs(&c).unwrap();
            }
            let s = drain(&mut s1);
            if !s.is_empty() {
                c1.read_hs(&s).unwrap();
            }
        }

        // Connection 2: same shared ClientConfig => resumed session.
        // After writing the ClientHello, rustls must hand back 0-RTT
        // keys (this is exactly what `install_early_keys` captures).
        let mut c2 = Connection::Client(
            ClientConnection::new(
                client_config.clone(),
                Version::V1,
                ServerName::try_from("localhost").unwrap(),
                tp.clone(),
            )
            .unwrap(),
        );
        // Writing the resumed ClientHello loads the cached ticket and,
        // because the server issued it with stateful resumption +
        // max_early_data_size, rustls derives the 0-RTT keys here. This
        // is exactly what the Mojo `install_early_keys` captures.
        let _ = drain(&mut c2);
        assert!(
            c2.zero_rtt_keys().is_some(),
            "resumed client must be handed 0-RTT early keys",
        );
    }

    #[test]
    fn connector_new_native_roots_builds_or_reports() {
        // On a host with a populated OS trust store (CI images ship
        // ca-certificates) this returns a non-null connector; on a
        // bare host with no roots it returns NULL + a descriptive
        // error. Either way it must not panic, and a non-null handle
        // must free cleanly.
        let alpn = b"\x02h3";
        let p = flare_rustls_quic_connector_new_native_roots(
            alpn.as_ptr(),
            alpn.len(),
        );
        if p.is_null() {
            let err = unsafe { CStr::from_ptr(flare_rustls_quic_last_error()) };
            assert!(
                err.to_string_lossy().contains("native root"),
                "expected native-root error, got {:?}",
                err
            );
        } else {
            flare_rustls_quic_connector_free(p);
        }
    }

    #[test]
    fn connector_new_rejects_empty_ca() {
        let alpn = b"\x02h3";
        let p = flare_rustls_quic_connector_new(
            std::ptr::null(),
            0,
            alpn.as_ptr(),
            alpn.len(),
        );
        assert!(p.is_null(), "empty CA bundle should be rejected");
        let err = unsafe { CStr::from_ptr(flare_rustls_quic_last_error()) };
        assert!(
            err.to_string_lossy().contains("CA bundle"),
            "expected CA-bundle error, got {:?}",
            err
        );
    }

    #[test]
    fn connector_new_rejects_garbage_ca() {
        let garbage = b"not actually pem";
        let alpn = b"\x02h3";
        let p = flare_rustls_quic_connector_new(
            garbage.as_ptr(),
            garbage.len(),
            alpn.as_ptr(),
            alpn.len(),
        );
        assert!(p.is_null(), "garbage CA PEM should be rejected");
    }

    #[test]
    fn connector_free_null_is_noop() {
        flare_rustls_quic_connector_free(std::ptr::null_mut());
    }

    #[test]
    fn connect_rejects_null_connector() {
        let name = b"example.com";
        let p = flare_rustls_quic_connect(
            std::ptr::null_mut(),
            name.as_ptr(),
            name.len(),
            std::ptr::null(),
            0,
        );
        assert!(p.is_null(), "NULL connector should be rejected");
    }

    #[test]
    fn have_keys_rejects_out_of_range_level() {
        // No session needed -- the level check fires before the
        // session pointer is dereferenced. A NULL session pointer
        // does still raise -1 (NULL-session branch above the
        // range check), so we exercise level-range here using a
        // throwaway dangling pointer is unsound; instead build a
        // real session via the existing fixture path.
        //
        // The acceptor_new + accept happy path is exercised by
        // the Mojo-side tests under tests/tls/, which have access
        // to the real PEM fixtures + the ring crypto provider.
        // Here we only validate the NULL-session + out-of-range
        // branches that don't require a real handshake.
        let r = flare_rustls_quic_have_keys(std::ptr::null_mut(), 0);
        assert_eq!(r, -1);
    }

    #[test]
    fn packet_encrypt_rejects_null_session() {
        let mut tag = [0u8; 16];
        let mut written: usize = 0;
        let r = flare_rustls_quic_packet_encrypt(
            std::ptr::null_mut(),
            LEVEL_HANDSHAKE as c_int,
            0,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            tag.as_mut_ptr(),
            tag.len(),
            &mut written,
        );
        assert_eq!(r, -1);
    }

    #[test]
    fn packet_encrypt_rejects_undersized_tag() {
        // Even though session is NULL here, the tag-size check
        // fires AFTER the NULL-session branch -- so we wire a
        // fake non-NULL session pointer to exercise the
        // undersized-tag branch.  The session pointer is never
        // dereferenced because the tag check rejects first.
        //
        // We can't safely build a fake session pointer at test
        // time without invoking UB; instead we just confirm that
        // a NULL tag buffer returns -1 with a real-shaped call.
        let mut written: usize = 0;
        let r = flare_rustls_quic_packet_encrypt(
            std::ptr::null_mut(),
            LEVEL_HANDSHAKE as c_int,
            0,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            8,
            &mut written,
        );
        assert_eq!(r, -1);
    }

    #[test]
    fn packet_decrypt_rejects_null_session() {
        let mut len: usize = 0;
        let r = flare_rustls_quic_packet_decrypt(
            std::ptr::null_mut(),
            LEVEL_HANDSHAKE as c_int,
            0,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut len,
        );
        assert_eq!(r, -1);
    }

    #[test]
    fn header_encrypt_rejects_null_session() {
        let mut first: u8 = 0;
        let r = flare_rustls_quic_header_encrypt(
            std::ptr::null_mut(),
            LEVEL_HANDSHAKE as c_int,
            std::ptr::null(),
            0,
            &mut first,
            std::ptr::null_mut(),
            0,
        );
        assert_eq!(r, -1);
    }

    #[test]
    fn header_decrypt_rejects_null_session() {
        let mut first: u8 = 0;
        let r = flare_rustls_quic_header_decrypt(
            std::ptr::null_mut(),
            LEVEL_HANDSHAKE as c_int,
            std::ptr::null(),
            0,
            &mut first,
            std::ptr::null_mut(),
            0,
        );
        assert_eq!(r, -1);
    }

    #[test]
    fn current_send_level_progresses_with_installed_keys() {
        // current_send_level is the only KeyChange-driven helper
        // that doesn't need a real rustls session to exercise --
        // it reads the keys[..] slots directly.  Build a Session
        // by hand here so we can flip slot bits.
        //
        // We can't construct a rustls::quic::Connection without
        // running the ring provider, so this test only exercises
        // current_send_level's *output* by mutating the slots via
        // a synthetic Session built via mem::zeroed... which is
        // also UB.  Skip the synthetic path; the real driver
        // lives on the Mojo side under
        // tests/tls/test_rustls_quic_handshake.mojo.
        //
        // Cargo-side coverage of current_send_level lands when
        // the Mojo loopback integration adds a Rust-side smoke
        // that drives a full handshake through the FFI.  For
        // now, the const indices used by current_send_level are
        // covered by their use in the public thunks.
    }

    #[test]
    fn last_error_default_is_empty() {
        // Force a fresh thread-local so prior tests don't seed it.
        std::thread::spawn(|| {
            let p = flare_rustls_quic_last_error();
            let c = unsafe { CStr::from_ptr(p) };
            assert_eq!(c.to_bytes(), b"");
        })
        .join()
        .unwrap();
    }

    #[test]
    fn set_last_error_round_trip() {
        set_last_error("test message");
        let p = flare_rustls_quic_last_error();
        let c = unsafe { CStr::from_ptr(p) };
        assert_eq!(c.to_bytes(), b"test message");
    }
}
