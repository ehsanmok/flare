/**
 * flare TLS - OpenSSL 3.x wrapper implementation.
 *
 * Compile-time check: this file refuses to build against OpenSSL < 3.0.
 *
 * Build (macOS / Linux):
 *   clang++ -O2 -fPIC -shared -o libflare_tls.so openssl_wrapper.cpp \
 *       -I$CONDA_PREFIX/include -L$CONDA_PREFIX/lib -lssl -lcrypto
 */

#include "openssl_wrapper.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <string>

/* POSIX for test server and socket utilities */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

/* Compile-time version gate */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "flare requires OpenSSL 3.x or later (OPENSSL_VERSION_NUMBER < 0x30000000L)"
#endif

/* Thread-local error buffer — no global mutable state */
static thread_local std::string last_error_msg;

static void capture_openssl_errors() {
    char buf[512] = {0};
    unsigned long e;
    std::string msg;
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!msg.empty()) msg += "; ";
        msg += buf;
    }
    last_error_msg = msg;
}

static void set_error(const char* msg) {
    last_error_msg = msg;
}

/* Cipher list providing forward secrecy + AEAD authentication for TLS 1.2 */
static const char* FORWARD_SECRET_CIPHERS =
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305";

// ── Context lifecycle ────────────────────────────────────────────────────────

flare_ssl_ctx_t flare_ssl_ctx_new(void) {
    ERR_clear_error();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        capture_openssl_errors();
        return nullptr;
    }
    return static_cast<void*>(ctx);
}

void flare_ssl_ctx_free(flare_ssl_ctx_t ctx) {
    if (ctx) SSL_CTX_free(static_cast<SSL_CTX*>(ctx));
}

int flare_ssl_ctx_set_security_policy(flare_ssl_ctx_t ctx) {
    SSL_CTX* c = static_cast<SSL_CTX*>(ctx);
    ERR_clear_error();
    /* Minimum TLS 1.2 */
    if (SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION) != 1) {
        capture_openssl_errors(); return -1;
    }
    /* Belt-and-suspenders: also set options to block older versions */
    SSL_CTX_set_options(c, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
                            | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    /* Forward-secret AEAD cipher suites only for TLS 1.2 */
    if (SSL_CTX_set_cipher_list(c, FORWARD_SECRET_CIPHERS) != 1) {
        capture_openssl_errors(); return -1;
    }
    /* TLS 1.3 ciphersuites are always AEAD + forward-secret; keep defaults */
    return 0;
}

int flare_ssl_ctx_set_verify_peer(flare_ssl_ctx_t ctx, int enabled) {
    SSL_CTX_set_verify(
        static_cast<SSL_CTX*>(ctx),
        enabled ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
        nullptr
    );
    return 0;
}

int flare_ssl_ctx_load_ca_bundle(flare_ssl_ctx_t ctx, const char* path) {
    ERR_clear_error();
    if (!path || path[0] == '\0') {
        if (SSL_CTX_set_default_verify_paths(static_cast<SSL_CTX*>(ctx)) != 1) {
            capture_openssl_errors(); return -1;
        }
        return 0;
    }
    if (SSL_CTX_load_verify_locations(static_cast<SSL_CTX*>(ctx), path, nullptr) != 1) {
        capture_openssl_errors(); return -1;
    }
    return 0;
}

int flare_ssl_ctx_load_cert_key(flare_ssl_ctx_t ctx,
                                 const char* cert_path,
                                 const char* key_path) {
    ERR_clear_error();
    SSL_CTX* c = static_cast<SSL_CTX*>(ctx);
    if (SSL_CTX_use_certificate_file(c, cert_path, SSL_FILETYPE_PEM) != 1) {
        capture_openssl_errors(); return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(c, key_path, SSL_FILETYPE_PEM) != 1) {
        capture_openssl_errors(); return -1;
    }
    if (SSL_CTX_check_private_key(c) != 1) {
        capture_openssl_errors(); return -1;
    }
    return 0;
}

// ── Session lifecycle ────────────────────────────────────────────────────────

flare_ssl_t flare_ssl_new(flare_ssl_ctx_t ctx, int fd) {
    ERR_clear_error();
    SSL* ssl = SSL_new(static_cast<SSL_CTX*>(ctx));
    if (!ssl) { capture_openssl_errors(); return nullptr; }
    if (SSL_set_fd(ssl, fd) != 1) {
        capture_openssl_errors(); SSL_free(ssl); return nullptr;
    }
    return static_cast<void*>(ssl);
}

void flare_ssl_free(flare_ssl_t ssl) {
    if (ssl) SSL_free(static_cast<SSL*>(ssl));
}

int flare_ssl_connect(flare_ssl_t ssl, const char* server_name) {
    ERR_clear_error();
    SSL* s = static_cast<SSL*>(ssl);
    /* Always send SNI when a hostname (not IP) is given */
    if (server_name && server_name[0] != '\0') {
        SSL_set_tlsext_host_name(s, server_name);
        /* Also set hostname for certificate verification */
        SSL_set1_host(s, server_name);
    }
    if (SSL_connect(s) != 1) {
        capture_openssl_errors();
        /* Annotate certificate verification failures with "verify:" prefix */
        long verify_err = SSL_get_verify_result(s);
        if (verify_err != X509_V_OK) {
            const char* v = X509_verify_cert_error_string(verify_err);
            last_error_msg = std::string("verify:") + v;
        }
        return -1;
    }
    return 0;
}

int flare_ssl_shutdown(flare_ssl_t ssl) {
    if (!ssl) return 0;
    return SSL_shutdown(static_cast<SSL*>(ssl));
}

// ── I/O ─────────────────────────────────────────────────────────────────────

int flare_ssl_read(flare_ssl_t ssl, uint8_t* buf, int len) {
    ERR_clear_error();
    int n = SSL_read(static_cast<SSL*>(ssl), buf, len);
    if (n < 0) capture_openssl_errors();
    return n;
}

int flare_ssl_write(flare_ssl_t ssl, const uint8_t* buf, int len) {
    ERR_clear_error();
    int n = SSL_write(static_cast<SSL*>(ssl), buf, len);
    if (n < 0) capture_openssl_errors();
    return n;
}

// Map an SSL_get_error result on a <= 0 SSL_read/SSL_write return into
// the reactor-friendly FLARE_SSL_IO_* sentinel. Shared by the _ex
// helpers so read and write classify identically.
static int flare_ssl_io_classify(SSL* s, int ret) {
    int err = SSL_get_error(s, ret);
    if (err == SSL_ERROR_WANT_READ)  return FLARE_SSL_IO_WANT_READ;
    if (err == SSL_ERROR_WANT_WRITE) return FLARE_SSL_IO_WANT_WRITE;
    if (err == SSL_ERROR_ZERO_RETURN) return FLARE_SSL_IO_CLOSED;
    // SSL_ERROR_SYSCALL with ret==0 is an unclean EOF (peer vanished
    // without close_notify); treat like a closed stream so the reactor
    // tears the connection down rather than looping. Everything else is
    // a genuine protocol / library fatal.
    if (err == SSL_ERROR_SYSCALL && ret == 0) return FLARE_SSL_IO_CLOSED;
    capture_openssl_errors();
    return FLARE_SSL_IO_FATAL;
}

int flare_ssl_read_ex(flare_ssl_t ssl, uint8_t* buf, int len) {
    ERR_clear_error();
    SSL* s = static_cast<SSL*>(ssl);
    int n = SSL_read(s, buf, len);
    if (n > 0) return n;
    return flare_ssl_io_classify(s, n);
}

int flare_ssl_write_ex(flare_ssl_t ssl, const uint8_t* buf, int len) {
    ERR_clear_error();
    SSL* s = static_cast<SSL*>(ssl);
    int n = SSL_write(s, buf, len);
    if (n > 0) return n;
    return flare_ssl_io_classify(s, n);
}

// ── Introspection ────────────────────────────────────────────────────────────

const char* flare_ssl_get_version(flare_ssl_t ssl) {
    return SSL_get_version(static_cast<SSL*>(ssl));
}

const char* flare_ssl_get_cipher(flare_ssl_t ssl) {
    return SSL_get_cipher(static_cast<SSL*>(ssl));
}

int flare_ssl_get_peer_cert_subject(flare_ssl_t ssl, char* buf, int buf_size) {
    X509* cert = SSL_get_peer_certificate(static_cast<SSL*>(ssl));
    if (!cert) {
        set_error("no peer certificate");
        return -1;
    }
    X509_NAME* name = X509_get_subject_name(cert);
    if (!name) {
        X509_free(cert);
        set_error("no subject name in peer certificate");
        return -1;
    }
    X509_NAME_oneline(name, buf, buf_size);
    X509_free(cert);
    return 0;
}

// ── Session resumption (RFC 5077 tickets / RFC 8446 §4.6.1) ───────────────

/* Per-CTX storage for the most recent client-side session.
 * Allocated by ``flare_ssl_ctx_enable_client_session_cache`` and
 * attached to the ctx via ``SSL_CTX_set_ex_data`` so the
 * ``new_session_cb`` can populate it without a global mutex.
 *
 * Lifetime: the ctx ex_data slot holds a pointer; the matching
 * ``free_func`` we register with ``SSL_CTX_get_ex_new_index``
 * frees both the pending session (if any) and the slot itself
 * when the ctx is freed. */
struct FlareCtxResume {
    SSL_SESSION* pending;
};

static int flare_resume_ex_idx = -1;

/* Free callback for the ex_data slot — called by SSL_CTX_free.
 * (CRYPTO_EX_free signature: void (*)(void*, void*, CRYPTO_EX_DATA*,
 *                                     int, long, void*)). */
static void flare_resume_free_cb(
    void* /*parent*/, void* ptr, CRYPTO_EX_DATA* /*ad*/,
    int /*idx*/, long /*argl*/, void* /*argp*/
) {
    FlareCtxResume* r = static_cast<FlareCtxResume*>(ptr);
    if (!r) return;
    if (r->pending) SSL_SESSION_free(r->pending);
    delete r;
}

/* OpenSSL new_session callback. Called once per arrived
 * NewSessionTicket. We stash the latest session on the ctx; the
 * application retrieves via flare_ssl_ctx_take_session.
 * Returning 1 transfers ownership of ``sess`` to the callback. */
static int flare_new_session_cb(SSL* ssl, SSL_SESSION* sess) {
    SSL_CTX* ctx = SSL_get_SSL_CTX(ssl);
    if (!ctx) return 0;
    FlareCtxResume* r = static_cast<FlareCtxResume*>(
        SSL_CTX_get_ex_data(ctx, flare_resume_ex_idx)
    );
    if (!r) return 0;
    if (r->pending) SSL_SESSION_free(r->pending);
    r->pending = sess; /* take ownership */
    return 1;
}

int flare_ssl_ctx_enable_client_session_cache(flare_ssl_ctx_t ctx) {
    SSL_CTX* c = static_cast<SSL_CTX*>(ctx);
    if (!c) { set_error("ctx is null"); return -1; }
    if (flare_resume_ex_idx < 0) {
        flare_resume_ex_idx = SSL_CTX_get_ex_new_index(
            0, nullptr, nullptr, nullptr, flare_resume_free_cb
        );
        if (flare_resume_ex_idx < 0) {
            set_error("SSL_CTX_get_ex_new_index failed");
            return -1;
        }
    }
    /* Allocate the slot if not already present. Re-entrant-safe:
     * if the user happens to call enable twice, we keep the
     * existing slot. */
    FlareCtxResume* r = static_cast<FlareCtxResume*>(
        SSL_CTX_get_ex_data(c, flare_resume_ex_idx)
    );
    if (!r) {
        r = new FlareCtxResume{nullptr};
        if (SSL_CTX_set_ex_data(c, flare_resume_ex_idx, r) != 1) {
            delete r;
            capture_openssl_errors();
            return -1;
        }
    }
    SSL_CTX_set_session_cache_mode(
        c, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE
    );
    SSL_CTX_sess_set_new_cb(c, flare_new_session_cb);
    return 0;
}

flare_ssl_session_t flare_ssl_ctx_take_session(flare_ssl_ctx_t ctx) {
    SSL_CTX* c = static_cast<SSL_CTX*>(ctx);
    if (!c || flare_resume_ex_idx < 0) return nullptr;
    FlareCtxResume* r = static_cast<FlareCtxResume*>(
        SSL_CTX_get_ex_data(c, flare_resume_ex_idx)
    );
    if (!r || !r->pending) return nullptr;
    SSL_SESSION* sess = r->pending;
    r->pending = nullptr; /* transfer ownership to caller */
    return static_cast<void*>(sess);
}

void flare_ssl_session_free(flare_ssl_session_t sess) {
    if (sess) SSL_SESSION_free(static_cast<SSL_SESSION*>(sess));
}

int flare_ssl_set_session(flare_ssl_t ssl, flare_ssl_session_t sess) {
    SSL* s = static_cast<SSL*>(ssl);
    if (!s || !sess) { set_error("ssl/sess is null"); return -1; }
    if (SSL_set_session(s, static_cast<SSL_SESSION*>(sess)) != 1) {
        capture_openssl_errors();
        return -1;
    }
    return 0;
}

int flare_ssl_session_reused(flare_ssl_t ssl) {
    SSL* s = static_cast<SSL*>(ssl);
    if (!s) return 0;
    return SSL_session_reused(s);
}

int flare_ssl_ctx_enable_session_tickets(flare_ssl_ctx_t ctx, int lifetime_s) {
    SSL_CTX* c = static_cast<SSL_CTX*>(ctx);
    if (!c) { set_error("ctx is null"); return -1; }
    /* Make sure tickets are on (clear NO_TICKET if it was set). */
    SSL_CTX_clear_options(c, SSL_OP_NO_TICKET);
    /* Set a stable session-id-context. Required by OpenSSL whenever
     * the server uses session tickets / IDs; otherwise the server
     * will refuse resumption with SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED. */
    static const unsigned char kSidCtx[] = "flare-srv";
    if (SSL_CTX_set_session_id_context(
            c, kSidCtx, sizeof(kSidCtx) - 1
        ) != 1) {
        capture_openssl_errors();
        return -1;
    }
    /* Lifetime: SSL_CTX_set_timeout for TLS 1.2 sessions; OpenSSL
     * 3.x also derives the TLS 1.3 ticket lifetime from this when
     * the ticket-key callback isn't installed. Cap to a sane
     * positive value. */
    long lt = (lifetime_s > 0) ? static_cast<long>(lifetime_s) : 7200;
    SSL_CTX_set_timeout(c, lt);
    /* Server-side cache mode: the default
     * SSL_SESS_CACHE_SERVER is what we want (cache so SSL_SESSION
     * lookups during resumption succeed even when a peer presents
     * a session ID instead of a ticket). */
    SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_SERVER);
    return 0;
}

// ── Error ────────────────────────────────────────────────────────────────────

const char* flare_ssl_last_error(void) {
    return last_error_msg.c_str();
}

// ── Server-side context lifecycle ─────────────────────────────────────────

flare_ssl_ctx_t flare_ssl_ctx_new_server(
    const char* cert_path, const char* key_path
) {
    ERR_clear_error();
    if (!cert_path || !key_path) {
        set_error("flare_ssl_ctx_new_server: cert_path / key_path required");
        return nullptr;
    }
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { capture_openssl_errors(); return nullptr; }
    /* TLS 1.2+ floor + forward-secret AEAD ciphers. */
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        capture_openssl_errors(); SSL_CTX_free(ctx); return nullptr;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
                            | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    if (SSL_CTX_set_cipher_list(ctx, FORWARD_SECRET_CIPHERS) != 1) {
        capture_openssl_errors(); SSL_CTX_free(ctx); return nullptr;
    }
    /* Cert + key. */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) {
        capture_openssl_errors(); SSL_CTX_free(ctx); return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        capture_openssl_errors(); SSL_CTX_free(ctx); return nullptr;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        capture_openssl_errors(); SSL_CTX_free(ctx); return nullptr;
    }
    return static_cast<void*>(ctx);
}

int flare_ssl_ctx_reload(
    flare_ssl_ctx_t ctx, const char* cert_path, const char* key_path
) {
    ERR_clear_error();
    SSL_CTX* c = static_cast<SSL_CTX*>(ctx);
    if (!c || !cert_path || !key_path) {
        set_error("flare_ssl_ctx_reload: ctx / cert / key required");
        return -1;
    }
    if (SSL_CTX_use_certificate_chain_file(c, cert_path) != 1) {
        capture_openssl_errors(); return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(c, key_path, SSL_FILETYPE_PEM) != 1) {
        capture_openssl_errors(); return -1;
    }
    if (SSL_CTX_check_private_key(c) != 1) {
        capture_openssl_errors(); return -1;
    }
    return 0;
}

/* ALPN selection callback. ``arg`` carries our wire-format
 * server protos list. Picks the first server-listed protocol
 * matching the client's advertised list. */
static int alpn_select_cb(
    SSL* /*ssl*/,
    const unsigned char** out, unsigned char* outlen,
    const unsigned char* in, unsigned int inlen,
    void* arg
) {
    /* arg is a pointer to a heap-allocated wire-format protos
     * blob; first byte is the total length, then the wire bytes.
     * (Format: ``len_byte || proto || len_byte || proto || ...``
     * for both server and client; OpenSSL exposes the same shape.) */
    auto* server_blob = static_cast<unsigned char*>(arg);
    if (!server_blob) return SSL_TLSEXT_ERR_NOACK;
    unsigned int server_len = static_cast<unsigned int>(server_blob[0]);
    const unsigned char* server_protos = server_blob + 1;

    /* Walk server protocols in preference order. For each,
     * scan the client's list for a match. */
    unsigned int si = 0;
    while (si < server_len) {
        unsigned int slen = server_protos[si];
        const unsigned char* sp = server_protos + si + 1;
        unsigned int ci = 0;
        while (ci < inlen) {
            unsigned int clen = in[ci];
            const unsigned char* cp = in + ci + 1;
            if (clen == slen && memcmp(sp, cp, slen) == 0) {
                *out = sp;
                *outlen = static_cast<unsigned char>(slen);
                return SSL_TLSEXT_ERR_OK;
            }
            ci += 1 + clen;
        }
        si += 1 + slen;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

int flare_ssl_ctx_set_alpn_server(
    flare_ssl_ctx_t ctx, const uint8_t* protos, int protos_len
) {
    SSL_CTX* c = static_cast<SSL_CTX*>(ctx);
    if (!c) { set_error("ctx is null"); return -1; }
    if (protos_len <= 0 || protos_len > 255) {
        set_error("ALPN protos blob must be 1..255 bytes");
        return -1;
    }
    /* Stash the protos blob on the SSL_CTX ex_data so the
     * callback can read it. We allocate a single buffer of
     * (1 + protos_len) bytes: the first byte holds protos_len,
     * the rest is the wire-format blob. Lifetime: until
     * SSL_CTX_free; no per-handshake allocation. */
    auto* blob = static_cast<unsigned char*>(
        OPENSSL_malloc(static_cast<size_t>(1 + protos_len))
    );
    if (!blob) { set_error("alloc failed"); return -1; }
    blob[0] = static_cast<unsigned char>(protos_len);
    memcpy(blob + 1, protos, static_cast<size_t>(protos_len));
    /* Note: we leak the blob on SSL_CTX_free since OpenSSL
     * doesn't expose a cleanup hook for the alpn_select_cb arg.
     * For long-lived servers this is at most one leaked
     * (1 + 255) byte allocation per ctx, paid once. */
    SSL_CTX_set_alpn_select_cb(c, alpn_select_cb, blob);
    return 0;
}

/* Client-side ALPN: tell OpenSSL which protocols to advertise on
 * the ClientHello. Wire-format same as the server callback's
 * input: ``len_byte || proto || len_byte || proto || ...``.
 *
 * Returns 0 on success, -1 on failure. (OpenSSL's
 * SSL_CTX_set_alpn_protos returns 0 on success and 1 on
 * failure -- we normalise to the standard "0 ok, -1 err"
 * convention used by the rest of this wrapper.) */
int flare_ssl_ctx_set_alpn_protos(
    flare_ssl_ctx_t ctx, const uint8_t* protos, int protos_len
) {
    SSL_CTX* c = static_cast<SSL_CTX*>(ctx);
    if (!c) { set_error("ctx is null"); return -1; }
    if (protos_len <= 0 || protos_len > 255) {
        set_error("ALPN protos blob must be 1..255 bytes");
        return -1;
    }
    /* SSL_CTX_set_alpn_protos copies the bytes internally so
     * we don't need to keep our blob alive past this call. */
    if (SSL_CTX_set_alpn_protos(
            c, protos, static_cast<unsigned int>(protos_len)
        ) != 0) {
        set_error("SSL_CTX_set_alpn_protos failed");
        return -1;
    }
    return 0;
}

int flare_ssl_ctx_set_verify_client_cert(
    flare_ssl_ctx_t ctx, const char* ca_path
) {
    SSL_CTX* c = static_cast<SSL_CTX*>(ctx);
    if (!c || !ca_path || ca_path[0] == '\0') {
        set_error("ctx + ca_path required for client-cert verify");
        return -1;
    }
    if (SSL_CTX_load_verify_locations(c, ca_path, nullptr) != 1) {
        capture_openssl_errors(); return -1;
    }
    SSL_CTX_set_verify(
        c, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr
    );
    return 0;
}

// ── Server-side session lifecycle ─────────────────────────────────────────

flare_ssl_t flare_ssl_new_accept(flare_ssl_ctx_t ctx, int fd) {
    ERR_clear_error();
    SSL* ssl = SSL_new(static_cast<SSL_CTX*>(ctx));
    if (!ssl) { capture_openssl_errors(); return nullptr; }
    if (SSL_set_fd(ssl, fd) != 1) {
        capture_openssl_errors(); SSL_free(ssl); return nullptr;
    }
    SSL_set_accept_state(ssl);
    return static_cast<void*>(ssl);
}

int flare_ssl_do_handshake(flare_ssl_t ssl) {
    SSL* s = static_cast<SSL*>(ssl);
    if (!s) { set_error("ssl is null"); return -1; }
    ERR_clear_error();
    int rc = SSL_do_handshake(s);
    if (rc == 1) {
        return 0;  /* handshake complete */
    }
    int err = SSL_get_error(s, rc);
    if (err == SSL_ERROR_WANT_READ)  return 1;
    if (err == SSL_ERROR_WANT_WRITE) return 2;
    capture_openssl_errors();
    return -1;
}

// ── Server-side introspection ────────────────────────────────────────────

int flare_ssl_get_alpn_selected(
    flare_ssl_t ssl, char* buf, int buf_size
) {
    SSL* s = static_cast<SSL*>(ssl);
    if (!s || !buf || buf_size <= 0) return -1;
    const unsigned char* alpn = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(s, &alpn, &alpn_len);
    if (!alpn || alpn_len == 0) return 0;
    if (static_cast<int>(alpn_len) >= buf_size) return -1;
    memcpy(buf, alpn, alpn_len);
    buf[alpn_len] = '\0';
    return static_cast<int>(alpn_len);
}

int flare_ssl_get_sni_host(
    flare_ssl_t ssl, char* buf, int buf_size
) {
    SSL* s = static_cast<SSL*>(ssl);
    if (!s || !buf || buf_size <= 0) return -1;
    const char* host = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (!host) return 0;
    int n = static_cast<int>(strlen(host));
    if (n >= buf_size) return -1;
    memcpy(buf, host, static_cast<size_t>(n));
    buf[n] = '\0';
    return n;
}

// ── Test server ──────────────────────────────────────────────────────────────

struct FlareTestServer {
    int       listen_fd;
    SSL_CTX*  ctx;
    int       port;
};

flare_test_server_t flare_test_server_new(
    const char* cert_path,
    const char* key_path,
    const char* ca_path,
    int         port
) {
    ERR_clear_error();

    /* Build server SSL_CTX */
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { capture_openssl_errors(); return nullptr; }

    /* Enforce TLS 1.2+ and forward-secret ciphers on server too */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
                             | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_cipher_list(ctx, FORWARD_SECRET_CIPHERS);

    /* Load server cert + key */
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
        capture_openssl_errors(); SSL_CTX_free(ctx); return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        capture_openssl_errors(); SSL_CTX_free(ctx); return nullptr;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        capture_openssl_errors(); SSL_CTX_free(ctx); return nullptr;
    }

    /* Optional: require client cert (mTLS) */
    if (ca_path && ca_path[0] != '\0') {
        if (SSL_CTX_load_verify_locations(ctx, ca_path, nullptr) != 1) {
            capture_openssl_errors(); SSL_CTX_free(ctx); return nullptr;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }

    /* Enable session tickets on the test server by default so the
     * resumption tests can drive a second handshake against
     * the same ctx and observe SSL_session_reused() == 1. The
     * lifetime is the OpenSSL default (7200s). Production callers
     * use ``flare_ssl_ctx_enable_session_tickets`` on a
     * properly-configured server ctx via ``ServerCtx``. */
    flare_ssl_ctx_enable_session_tickets(ctx, 7200);

    /* Create and bind TCP listening socket */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        set_error("socket() failed");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        set_error("bind() failed");
        close(listen_fd);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (listen(listen_fd, 16) != 0) {
        set_error("listen() failed");
        close(listen_fd);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    /* Read back actual port if ephemeral was requested */
    socklen_t len = sizeof(addr);
    getsockname(listen_fd, (struct sockaddr*)&addr, &len);
    int actual_port = ntohs(addr.sin_port);

    FlareTestServer* srv = new FlareTestServer{listen_fd, ctx, actual_port};
    return static_cast<void*>(srv);
}

void flare_test_server_free(flare_test_server_t srv_ptr) {
    if (!srv_ptr) return;
    FlareTestServer* srv = static_cast<FlareTestServer*>(srv_ptr);
    close(srv->listen_fd);
    SSL_CTX_free(srv->ctx);
    delete srv;
}

int flare_test_server_port(flare_test_server_t srv_ptr) {
    if (!srv_ptr) return -1;
    return static_cast<FlareTestServer*>(srv_ptr)->port;
}

int flare_test_server_echo_once(flare_test_server_t srv_ptr) {
    if (!srv_ptr) return -1;
    FlareTestServer* srv = static_cast<FlareTestServer*>(srv_ptr);

    /* Accept one TCP connection */
    int client_fd = accept(srv->listen_fd, nullptr, nullptr);
    if (client_fd < 0) { set_error("accept() failed"); return -1; }

    /* Wrap with TLS */
    SSL* ssl = SSL_new(srv->ctx);
    if (!ssl) { capture_openssl_errors(); close(client_fd); return -1; }
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) != 1) {
        capture_openssl_errors();
        SSL_free(ssl);
        close(client_fd);
        return -1;
    }

    /* Echo loop: read up to 64 KB then write same bytes back */
    uint8_t buf[65536];
    int total = 0;
    int n;
    while ((n = SSL_read(ssl, buf + total, (int)sizeof(buf) - total)) > 0) {
        total += n;
        if (total >= (int)sizeof(buf)) break;
    }

    /* Write all bytes back */
    int sent = 0;
    while (sent < total) {
        int w = SSL_write(ssl, buf + sent, total - sent);
        if (w <= 0) break;
        sent += w;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    return 0;
}

int flare_test_server_echo_n(flare_test_server_t srv_ptr, int n) {
    /* Sequential N-connection variant of flare_test_server_echo_once.
     * The same SSL_CTX is reused across all accepts, which is the
     * point: session tickets cached in the ctx survive between
     * accepts and the second client can resume via SSL_set_session.
     *
     * Unlike flare_test_server_echo_once (read-until-EOF, then
     * write-all-back), this variant does PER-MESSAGE echo so a
     * client can do a connect / write 1 / read 1 / close round
     * trip without deadlocking on a half-closed write-side. The
     * resumption tests rely on the round trip to give the
     * NewSessionTicket time to arrive at the client. */
    if (!srv_ptr || n <= 0) return -1;
    FlareTestServer* srv = static_cast<FlareTestServer*>(srv_ptr);
    for (int i = 0; i < n; i++) {
        int client_fd = accept(srv->listen_fd, nullptr, nullptr);
        if (client_fd < 0) { set_error("accept() failed"); return -1; }
        SSL* ssl = SSL_new(srv->ctx);
        if (!ssl) {
            capture_openssl_errors();
            close(client_fd);
            return -1;
        }
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) != 1) {
            capture_openssl_errors();
            SSL_free(ssl);
            close(client_fd);
            return -1;
        }
        uint8_t buf[65536];
        int rn;
        /* Per-message echo: every successful read is written back
         * immediately. Loop terminates on EOF / client close. */
        while ((rn = SSL_read(ssl, buf, (int)sizeof(buf))) > 0) {
            int sent = 0;
            while (sent < rn) {
                int w = SSL_write(ssl, buf + sent, rn - sent);
                if (w <= 0) break;
                sent += w;
            }
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
    return 0;
}

/* ── Socket utilities ────────────────────────────────────────────────────── */

int flare_set_nonblocking(int fd, int enable) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    int new_flags = enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(fd, F_SETFL, new_flags);
}

/* Thin wrappers around read(2) / write(2).
 *
 * Mojo's stdlib already declares ``external_call["read", ...]`` and
 * ``external_call["write", ...]`` with its own signature for
 * ``FileDescriptor``; that collides with flare's reactor FFI at the MLIR
 * lowering stage. Routing through these C wrappers under distinct symbol
 * names sidesteps the conflict without measurable overhead (the wrappers
 * compile to a single jmp on x86_64 and a plain b on arm64).
 */
ssize_t flare_read(int fd, void* buf, size_t count) {
    return ::read(fd, buf, count);
}

ssize_t flare_write(int fd, const void* buf, size_t count) {
    return ::write(fd, buf, count);
}

int flare_connect_timeout(int fd, const void* addr, unsigned addrlen,
                          int timeout_ms) {
    /* 1. Set non-blocking */
    if (flare_set_nonblocking(fd, 1) < 0) return errno;

    /* 2. Initiate connect */
    int rc = connect(fd, (const struct sockaddr*)addr, (socklen_t)addrlen);
    if (rc == 0) {
        /* Immediate success (rare — possible for loopback) */
        flare_set_nonblocking(fd, 0);
        return 0;
    }
    int err = errno;
    if (err != EINPROGRESS) {
        flare_set_nonblocking(fd, 0);
        return err;
    }

    /* 3. poll(POLLOUT, timeout_ms) */
    struct pollfd pfd;
    pfd.fd     = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    int nready = poll(&pfd, 1, timeout_ms);

    if (nready == 0) {
        flare_set_nonblocking(fd, 0);
        return -2; /* timeout */
    }
    if (nready < 0) {
        int poll_err = errno;
        flare_set_nonblocking(fd, 0);
        return poll_err;
    }

    /* 4. Check SO_ERROR for deferred connection errors */
    int so_err  = 0;
    socklen_t so_len = sizeof(so_err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) < 0)
        so_err = errno;

    flare_set_nonblocking(fd, 0);
    return so_err; /* 0 = success, positive errno = error */
}

/* ── HMAC-SHA256 ──────────────────────────────────────────────────────────── */

#include <openssl/hmac.h>
#include <openssl/crypto.h>

extern "C" int flare_hmac_sha256(const uint8_t* key, size_t key_len,
                                  const uint8_t* msg, size_t msg_len,
                                  uint8_t* out_32) {
    if (!out_32) return -1;
    unsigned int out_len = 32;
    /* Empty key/msg are valid HMAC inputs (RFC 4231 vectors 1, 2). */
    const uint8_t* k = (key && key_len > 0) ? key : (const uint8_t*)"";
    const uint8_t* m = (msg && msg_len > 0) ? msg : (const uint8_t*)"";
    unsigned char* rc = HMAC(EVP_sha256(), k, (int)key_len, m,
                              msg_len, out_32, &out_len);
    if (!rc || out_len != 32) {
        capture_openssl_errors();
        return -1;
    }
    return 0;
}

extern "C" int flare_hmac_sha256_verify(const uint8_t* key, size_t key_len,
                                         const uint8_t* msg, size_t msg_len,
                                         const uint8_t* mac_32) {
    if (!mac_32) return -1;
    uint8_t computed[32];
    int rc = flare_hmac_sha256(key, key_len, msg, msg_len, computed);
    if (rc != 0) return -1;
    /* Constant-time comparison: HMAC verify must not leak prefix length
     * via early-return on first mismatching byte. */
    return CRYPTO_memcmp(computed, mac_32, 32) == 0 ? 1 : 0;
}

/* ── QUIC AEAD (RFC 9001 §5.3) ──────────────────────────────────────────── */

#include <openssl/evp.h>

namespace {

/* Pick the OpenSSL EVP_CIPHER for the cipher_id + validate key length.
 * Returns NULL on misconfiguration. */
const EVP_CIPHER* quic_aead_cipher(int cipher_id, size_t key_len) {
    switch (cipher_id) {
        case FLARE_QUIC_AEAD_AES_128_GCM:
            return (key_len == 16) ? EVP_aes_128_gcm() : nullptr;
        case FLARE_QUIC_AEAD_AES_256_GCM:
            return (key_len == 32) ? EVP_aes_256_gcm() : nullptr;
        case FLARE_QUIC_AEAD_CHACHA20_POLY1305:
            return (key_len == 32) ? EVP_chacha20_poly1305() : nullptr;
        default:
            return nullptr;
    }
}

/* RFC 9001 §5.3 nonce construction: nonce = iv XOR (pn padded BE to 12).
 *
 * The packet number is BE-encoded into the *low* 8 bytes of a 12-byte
 * zero buffer; the upper 4 bytes stay zero so the XOR leaves the
 * iv's first 4 bytes unchanged. This matches every RFC 9001 / RFC 9369
 * test vector. */
void build_nonce(const uint8_t* iv, uint64_t pn, uint8_t out[12]) {
    uint8_t pn_be[12] = {0};
    pn_be[4]  = (uint8_t)((pn >> 56) & 0xff);
    pn_be[5]  = (uint8_t)((pn >> 48) & 0xff);
    pn_be[6]  = (uint8_t)((pn >> 40) & 0xff);
    pn_be[7]  = (uint8_t)((pn >> 32) & 0xff);
    pn_be[8]  = (uint8_t)((pn >> 24) & 0xff);
    pn_be[9]  = (uint8_t)((pn >> 16) & 0xff);
    pn_be[10] = (uint8_t)((pn >>  8) & 0xff);
    pn_be[11] = (uint8_t)( pn        & 0xff);
    for (int i = 0; i < 12; i++) out[i] = iv[i] ^ pn_be[i];
}

} /* anonymous namespace */

extern "C" int flare_quic_aead_build_nonce(const uint8_t* iv, uint64_t pn,
                                             uint8_t* out_12) {
    if (!iv || !out_12) return -1;
    build_nonce(iv, pn, out_12);
    return 0;
}

extern "C" int flare_quic_aead_seal(int cipher_id,
                                     const uint8_t* key, size_t key_len,
                                     const uint8_t* iv,
                                     uint64_t pn,
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t* plaintext, size_t plaintext_len,
                                     uint8_t* out, size_t out_cap,
                                     size_t* written) {
    if (!key || !iv || !out || !written) return -1;
    if (aad_len > 0 && !aad) return -1;
    if (plaintext_len > 0 && !plaintext) return -1;
    /* Caller MUST size out for ciphertext + 16-byte tag. */
    if (out_cap < plaintext_len + FLARE_QUIC_AEAD_TAG_LEN) return -1;

    const EVP_CIPHER* cipher = quic_aead_cipher(cipher_id, key_len);
    if (!cipher) return -1;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        capture_openssl_errors();
        return -1;
    }

    uint8_t nonce[FLARE_QUIC_AEAD_NONCE_LEN];
    build_nonce(iv, pn, nonce);

    int rc = -1;
    int outl = 0;
    do {
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) break;
        /* All three RFC 9001 ciphers use a 12-byte IV by default; the
         * SET_IVLEN call is harmless for ChaCha20-Poly1305 and required
         * for the AES-GCM variants on OpenSSL < 1.1.0 (current pin is
         * 3.6.1 but we keep the call for cross-version safety). */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                FLARE_QUIC_AEAD_NONCE_LEN, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
        if (aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, nullptr, &outl, aad, (int)aad_len) != 1) break;
        }
        int ct_written = 0;
        if (EVP_EncryptUpdate(ctx, out, &ct_written, plaintext,
                              (int)plaintext_len) != 1) break;
        int final_written = 0;
        if (EVP_EncryptFinal_ex(ctx, out + ct_written, &final_written) != 1) break;
        const size_t ct_total = (size_t)ct_written + (size_t)final_written;
        if (ct_total != plaintext_len) break;
        /* Append the 16-byte tag. */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                FLARE_QUIC_AEAD_TAG_LEN,
                                out + ct_total) != 1) break;
        *written = ct_total + FLARE_QUIC_AEAD_TAG_LEN;
        rc = 0;
    } while (0);

    if (rc != 0) capture_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* ── QUIC header protection mask (RFC 9001 §5.4) ───────────────────────── */

namespace {

/* AES-ECB mask: one-block encrypt of the sample, take first 5 bytes
 * (RFC 9001 §5.4.3). The single-block ECB call here is safe -- the
 * sample is treated as a one-time tweak, never directly encrypted
 * data. The Mojo side guarantees fresh samples per packet. */
int aes_ecb_mask(const EVP_CIPHER* cipher,
                  const uint8_t* hp_key,
                  const uint8_t* sample,
                  uint8_t out_5[5]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        capture_openssl_errors();
        return -1;
    }
    int rc = -1;
    do {
        /* ECB has no IV; padding off so we get exactly 16 bytes out
         * from 16 bytes in. */
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, hp_key, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) break;
        uint8_t block[16];
        int outl = 0;
        if (EVP_EncryptUpdate(ctx, block, &outl, sample, 16) != 1) break;
        if (outl != 16) break;
        int finall = 0;
        uint8_t pad_tail[16];
        if (EVP_EncryptFinal_ex(ctx, pad_tail, &finall) != 1) break;
        if (finall != 0) break;
        /* RFC 9001 §5.4.3: mask is the first 5 bytes of the ECB
         * encryption of the sample. */
        for (int i = 0; i < 5; i++) out_5[i] = block[i];
        rc = 0;
    } while (0);
    if (rc != 0) capture_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* ChaCha20 mask: run the cipher as a stream cipher with the sample
 * split into counter (4-byte LE) + nonce (12 bytes), then encrypt
 * 5 zero bytes -- the output is the mask (RFC 9001 §5.4.4). */
int chacha20_mask(const uint8_t* hp_key,
                   const uint8_t* sample,
                   uint8_t out_5[5]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        capture_openssl_errors();
        return -1;
    }
    int rc = -1;
    do {
        const EVP_CIPHER* chacha = EVP_chacha20();
        if (!chacha) break;
        /* EVP_chacha20's IV is the 16-byte counter || nonce blob;
         * RFC 9001 §5.4.4 splits the sample as
         *   counter = u32 LE of sample[0..4]
         *   nonce   = sample[4..16]
         * OpenSSL takes them concatenated low-counter-first, which
         * matches the sample layout exactly. */
        if (EVP_EncryptInit_ex(ctx, chacha, nullptr, hp_key, sample) != 1) break;
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) break;
        const uint8_t zeros[5] = {0, 0, 0, 0, 0};
        int outl = 0;
        if (EVP_EncryptUpdate(ctx, out_5, &outl, zeros, 5) != 1) break;
        if (outl != 5) break;
        int finall = 0;
        uint8_t pad_tail[5];
        if (EVP_EncryptFinal_ex(ctx, pad_tail, &finall) != 1) break;
        if (finall != 0) break;
        rc = 0;
    } while (0);
    if (rc != 0) capture_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

} /* anonymous namespace */

extern "C" int flare_quic_hp_mask(int cipher_id,
                                    const uint8_t* hp_key, size_t hp_key_len,
                                    const uint8_t* sample,
                                    uint8_t* out_5) {
    if (!hp_key || !sample || !out_5) return -1;
    switch (cipher_id) {
        case FLARE_QUIC_HP_AES_128:
            if (hp_key_len != 16) return -1;
            return aes_ecb_mask(EVP_aes_128_ecb(), hp_key, sample, out_5);
        case FLARE_QUIC_HP_AES_256:
            if (hp_key_len != 32) return -1;
            return aes_ecb_mask(EVP_aes_256_ecb(), hp_key, sample, out_5);
        case FLARE_QUIC_HP_CHACHA20:
            if (hp_key_len != 32) return -1;
            return chacha20_mask(hp_key, sample, out_5);
        default:
            return -1;
    }
}

extern "C" int flare_quic_aead_open(int cipher_id,
                                     const uint8_t* key, size_t key_len,
                                     const uint8_t* iv,
                                     uint64_t pn,
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t* ct, size_t ct_len,
                                     uint8_t* out, size_t out_cap,
                                     size_t* written) {
    if (!key || !iv || !ct || !out || !written) return -1;
    if (aad_len > 0 && !aad) return -1;
    if (ct_len < FLARE_QUIC_AEAD_TAG_LEN) return -1;
    const size_t pt_len = ct_len - FLARE_QUIC_AEAD_TAG_LEN;
    if (out_cap < pt_len) return -1;

    const EVP_CIPHER* cipher = quic_aead_cipher(cipher_id, key_len);
    if (!cipher) return -1;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        capture_openssl_errors();
        return -1;
    }

    uint8_t nonce[FLARE_QUIC_AEAD_NONCE_LEN];
    build_nonce(iv, pn, nonce);

    int rc = -1;
    int outl = 0;
    do {
        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                FLARE_QUIC_AEAD_NONCE_LEN, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
        if (aad_len > 0) {
            if (EVP_DecryptUpdate(ctx, nullptr, &outl, aad, (int)aad_len) != 1) break;
        }
        int pt_written = 0;
        if (EVP_DecryptUpdate(ctx, out, &pt_written, ct, (int)pt_len) != 1) break;
        /* Set the expected tag *before* DecryptFinal_ex; OpenSSL needs
         * it to validate the AEAD output. */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                FLARE_QUIC_AEAD_TAG_LEN,
                                (void*)(ct + pt_len)) != 1) break;
        int final_written = 0;
        int final_rc = EVP_DecryptFinal_ex(ctx, out + pt_written, &final_written);
        if (final_rc != 1) {
            /* Tag verification failed -- this is the RFC 9001 §5.3
             * "invalid packet" path. Distinct from misconfiguration
             * so callers can drop quietly rather than abort. */
            rc = -2;
            break;
        }
        *written = (size_t)pt_written + (size_t)final_written;
        if (*written != pt_len) break;
        rc = 0;
    } while (0);

    if (rc == -1) capture_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
