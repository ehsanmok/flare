/**
 * flare TLS - minimal OpenSSL wrapper for Mojo FFI.
 *
 * Exposes a C API over the OpenSSL SSL_CTX / SSL lifecycle so Mojo
 * can call it without knowing about C++ name mangling or OpenSSL
 * object internals.
 *
 * Requires OpenSSL 3.x — compile-time enforced.
 */

#pragma once

#include <stdint.h>
#include <sys/types.h>  /* ssize_t, size_t */

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x30000000L
#error "flare requires OpenSSL 3.x or later"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles */
typedef void* flare_ssl_ctx_t;
typedef void* flare_ssl_t;

/* ── Client context lifecycle ──────────────────────────────────────────────── */

flare_ssl_ctx_t flare_ssl_ctx_new(void);
void            flare_ssl_ctx_free(flare_ssl_ctx_t ctx);

/* Enforce TLS 1.2+, forward-secret AEAD ciphers (must call after ctx_new) */
int  flare_ssl_ctx_set_security_policy(flare_ssl_ctx_t ctx);

int  flare_ssl_ctx_set_verify_peer(flare_ssl_ctx_t ctx, int enabled);
int  flare_ssl_ctx_load_ca_bundle(flare_ssl_ctx_t ctx, const char* path);
int  flare_ssl_ctx_load_cert_key(flare_ssl_ctx_t ctx,
                                  const char* cert_path,
                                  const char* key_path);

/* ── Session lifecycle ─────────────────────────────────────────────────────── */

flare_ssl_t flare_ssl_new(flare_ssl_ctx_t ctx, int fd);
void        flare_ssl_free(flare_ssl_t ssl);

int flare_ssl_connect(flare_ssl_t ssl, const char* server_name);
int flare_ssl_shutdown(flare_ssl_t ssl);

/* ── I/O ───────────────────────────────────────────────────────────────────── */

int flare_ssl_read(flare_ssl_t ssl, uint8_t* buf, int len);
int flare_ssl_write(flare_ssl_t ssl, const uint8_t* buf, int len);

/* ── Introspection ─────────────────────────────────────────────────────────── */

const char* flare_ssl_get_version(flare_ssl_t ssl);
const char* flare_ssl_get_cipher(flare_ssl_t ssl);
int         flare_ssl_get_peer_cert_subject(flare_ssl_t ssl, char* buf, int buf_size);

/* ── Error ─────────────────────────────────────────────────────────────────── */

const char* flare_ssl_last_error(void);

/* ── Server-side context lifecycle (v0.5.0 follow-up / Track 5.1 / C6) ─── */

/**
 * Create a server-side ``SSL_CTX`` configured with TLS 1.2+,
 * forward-secret AEAD ciphers, and the supplied certificate
 * chain + private key. Combines ``SSL_CTX_new(TLS_server_method())``
 * + min-proto-version + cipher list + ``load_cert_key`` + optional
 * client-cert verification.
 *
 * @param cert_path  PEM full chain (leaf first, then intermediates).
 * @param key_path   PEM private key matching ``cert_path``.
 * @return Opaque ctx handle; NULL on failure (use
 *         ``flare_ssl_last_error()`` for the message).
 */
flare_ssl_ctx_t flare_ssl_ctx_new_server(
    const char* cert_path, const char* key_path
);

/**
 * Reload cert + key on an existing server ``SSL_CTX``. In-flight
 * sessions that already loaded an ``SSL`` from the old ctx see
 * the previous cert (OpenSSL holds the cert on the SSL via
 * ``SSL_use_certificate``); new handshakes pick up the reloaded
 * cert. Used for cert rotation without restart.
 *
 * @return 0 on success, -1 on failure.
 */
int flare_ssl_ctx_reload(
    flare_ssl_ctx_t ctx, const char* cert_path, const char* key_path
);

/**
 * Set ALPN protocols for server-side selection.
 *
 * ``protos`` is the wire-format ALPN list:
 * ``len_byte || protocol_bytes || len_byte || protocol_bytes || ...``.
 * For example, advertising ``["h2", "http/1.1"]`` produces:
 * ``\x02h2\x08http/1.1``.
 *
 * The selection callback picks the first server-listed protocol
 * matching the client's advertised list (server preference wins
 * on ties — RFC 7301 §3.2 SHOULD recommendation).
 *
 * @return 0 on success, -1 on failure.
 */
int flare_ssl_ctx_set_alpn_server(
    flare_ssl_ctx_t ctx, const uint8_t* protos, int protos_len
);

/**
 * Enable mTLS client-cert verification.
 *
 * Sets ``SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`` and
 * loads ``ca_path`` as the trust anchor for client certs.
 *
 * @return 0 on success, -1 on failure (cert load failure, etc.).
 */
int flare_ssl_ctx_set_verify_client_cert(
    flare_ssl_ctx_t ctx, const char* ca_path
);

/* ── Server-side session lifecycle ──────────────────────────────────────── */

/**
 * Create an ``SSL`` for an accepted server-side connection.
 *
 * Wraps ``SSL_new`` + ``SSL_set_fd`` + ``SSL_set_accept_state``.
 * The caller drives the handshake via ``flare_ssl_do_handshake``
 * on each readable / writable edge.
 *
 * @return Opaque handle; NULL on failure.
 */
flare_ssl_t flare_ssl_new_accept(flare_ssl_ctx_t ctx, int fd);

/**
 * Drive ``SSL_accept`` (server side) or ``SSL_connect`` (client
 * side, equivalent to ``flare_ssl_connect``) one step.
 *
 * Reactor-friendly return values:
 *
 *   0  — handshake complete (``SSL_is_init_finished`` is true).
 *   1  — WANT_READ: caller waits for the socket to be readable
 *        and calls ``flare_ssl_do_handshake`` again.
 *   2  — WANT_WRITE: caller waits for the socket to be writable
 *        and calls ``flare_ssl_do_handshake`` again.
 *  -1  — fatal error (use ``flare_ssl_last_error`` for the
 *        message; close the connection).
 */
int flare_ssl_do_handshake(flare_ssl_t ssl);

/* ── Server-side introspection (v0.5.0 follow-up / Track 5.2) ──────────── */

/**
 * Copy the negotiated ALPN protocol into ``buf``.
 *
 * @return Number of bytes written (excluding NUL), or 0 if no
 *         ALPN protocol was negotiated, or -1 if ``buf`` was too
 *         small.
 */
int flare_ssl_get_alpn_selected(flare_ssl_t ssl, char* buf, int buf_size);

/**
 * Copy the SNI hostname the client sent in the Client Hello into
 * ``buf``.
 *
 * @return Number of bytes written (excluding NUL), or 0 if the
 *         client sent no SNI, or -1 if ``buf`` was too small.
 */
int flare_ssl_get_sni_host(flare_ssl_t ssl, char* buf, int buf_size);

/* ── Test server (loopback echo server — for use in test code only) ────────── */

/**
 * Opaque handle for a test TLS echo server.
 * Created by flare_test_server_new, freed by flare_test_server_free.
 */
typedef void* flare_test_server_t;

/**
 * Create and bind a loopback TLS echo server.
 *
 * Binds to 127.0.0.1:<port> (use 0 for ephemeral port assignment).
 * Calls listen(2) with backlog 16. Does NOT accept yet.
 *
 * @param cert_path  PEM server certificate path.
 * @param key_path   PEM server private key path.
 * @param ca_path    PEM CA bundle for client cert verification,
 *                   or NULL to skip client cert verification.
 * @param port       TCP port to bind (0 = OS assigns ephemeral port).
 * @return           Opaque server handle, or NULL on failure.
 */
flare_test_server_t flare_test_server_new(
    const char* cert_path,
    const char* key_path,
    const char* ca_path,
    int         port
);

/** Free a test server and close its listening socket. */
void flare_test_server_free(flare_test_server_t srv);

/* ── Socket utilities (work around Mojo external_call variadic ABI bug) ──── */

/**
 * Set or clear the O_NONBLOCK flag on a socket via fcntl(F_SETFL).
 *
 * Mojo's external_call cannot reliably pass the third argument to variadic
 * C functions (like fcntl) on macOS/arm64.  This non-variadic wrapper is
 * properly compiled by the C++ compiler and avoids the bug.
 *
 * @param fd     File descriptor of the socket.
 * @param enable 1 to enable non-blocking mode, 0 to disable.
 * @return 0 on success, -1 on failure (errno is set).
 */
int flare_set_nonblocking(int fd, int enable);

/**
 * Thin wrapper around read(2). Works on any fd (socket, pipe, eventfd).
 *
 * The Mojo stdlib declares ``external_call["read", ...]`` with its own
 * signature for ``FileDescriptor``; routing through this wrapper lets
 * flare's reactor use a distinct symbol name.
 *
 * @param fd    File descriptor to read from.
 * @param buf   Destination buffer.
 * @param count Maximum bytes to read.
 * @return Number of bytes read on success (0 on EOF), -1 on error
 *         (errno set; EAGAIN/EWOULDBLOCK for nonblocking fds).
 */
ssize_t flare_read(int fd, void* buf, size_t count);

/**
 * Thin wrapper around write(2). Works on any fd (socket, pipe, eventfd).
 *
 * See ``flare_read`` for why the wrapper exists.
 *
 * @param fd    File descriptor to write to.
 * @param buf   Source buffer.
 * @param count Number of bytes to write.
 * @return Number of bytes written on success, -1 on error (errno set).
 */
ssize_t flare_write(int fd, const void* buf, size_t count);

/**
 * Non-blocking connect + poll — the core of connect_timeout().
 *
 * 1. Sets fd to non-blocking mode.
 * 2. Calls connect(fd, addr, addrlen).
 * 3. If EINPROGRESS: waits up to timeout_ms with poll(POLLOUT).
 * 4. On timeout: returns -2 (caller should raise ConnectionTimeout).
 * 5. On success: restores blocking mode, returns 0.
 * 6. On failure: returns errno (positive int).
 *
 * @param fd         Socket fd (must already be created).
 * @param addr       Pointer to sockaddr (cast to void* for C compatibility).
 * @param addrlen    Size of the sockaddr struct.
 * @param timeout_ms Maximum wait in milliseconds.
 * @return 0 on success, -2 on timeout, positive errno on error.
 */
int flare_connect_timeout(int fd, const void* addr, unsigned addrlen,
                          int timeout_ms);

/** Return the actual bound port (useful when port=0 was passed to _new). */
int flare_test_server_port(flare_test_server_t srv);

/**
 * Accept one connection, echo all received bytes back, then close.
 *
 * This function blocks until a client connects, performs the TLS handshake,
 * reads data (until EOF or 64 KB), writes the same data back, and closes.
 * Intended to be called in a forked child process.
 *
 * @return 0 on success, -1 on error.
 */
int flare_test_server_echo_once(flare_test_server_t srv);

#ifdef __cplusplus
}
#endif
