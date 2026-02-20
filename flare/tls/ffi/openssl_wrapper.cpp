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

// ── Error ────────────────────────────────────────────────────────────────────

const char* flare_ssl_last_error(void) {
    return last_error_msg.c_str();
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

/* ── Socket utilities ────────────────────────────────────────────────────── */

int flare_set_nonblocking(int fd, int enable) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    int new_flags = enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(fd, F_SETFL, new_flags);
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
