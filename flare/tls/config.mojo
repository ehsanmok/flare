"""TLS configuration: certificates, keys, and verification policy.

The default CA bundle is sourced from the ``ca-certificates`` pixi dependency,
which places a portable PEM bundle at ``$CONDA_PREFIX/ssl/cacert.pem``.
This path works identically on macOS, Linux x86_64, and Linux aarch64.

When ``ca_bundle`` is the empty string (the factory default), the C
wrapper routes to ``SSL_CTX_set_default_verify_paths``, which in turn
picks up OpenSSL's compiled-in ``OPENSSLDIR``. conda-forge's OpenSSL
sets ``OPENSSLDIR=$PREFIX/ssl``, so the pixi-managed ``cacert.pem`` is
discovered automatically without flare ever constructing a
``CONDA_PREFIX + "/ssl/cacert.pem"`` string in Mojo. This sidesteps a
Mojo 0.26 ``String + String`` aliasing bug where two sequential
``getenv("CONDA_PREFIX") + literal`` concats can share backing memory,
clobbering the CA path mid-TLS-handshake (observed under strace as
``SSL_CTX_load_verify_locations`` being called with
``cacert.pemls.so``). The ``ca_bundle`` field is still honoured
verbatim when callers set it explicitly.
"""


struct TlsVerify:
    """Peer certificate verification mode constants.

    Use these with ``TlsConfig.verify``.
    """

    comptime NONE: Int = 0
    """Skip all certificate verification. Insecure — for testing only."""

    comptime REQUIRED: Int = 1
    """Verify peer certificate against the trusted CA bundle. Default."""


struct TlsConfig(Copyable, Movable):
    """Configuration for a TLS connection.

    Fields:
        verify: Verification mode (``TlsVerify.REQUIRED`` by default).
        ca_bundle: Path to a PEM CA bundle. Defaults to the pixi-managed
                     ``$CONDA_PREFIX/ssl/cacert.pem``; empty string falls
                     back to the OpenSSL system default.
        cert_file: Path to a PEM client certificate (mTLS), or ``""`` for none.
        key_file: Path to a PEM client private key (mTLS), or ``""`` for none.
        server_name: SNI hostname override. ``""`` means derive from the
                     connected host at runtime (strongly preferred).
        alpn: Application-Layer Protocol Negotiation protocol IDs to
                     advertise on the TLS ClientHello in preference order
                     (e.g. ``["h2", "http/1.1"]`` to prefer HTTP/2 with
                     fallback). Empty list (the default) disables ALPN
                     entirely. Per RFC 7301, each ID must be 1..255 bytes
                     and the wire-format blob (length-prefixed
                     concatenation) must total at most 255 bytes.

    Example:
        ```mojo
        # Default: verify server cert against pixi CA bundle
        var cfg = TlsConfig()

        # Custom CA for self-signed certs
        var cfg = TlsConfig(ca_bundle="/etc/myapp/ca.pem")

        # Mutual TLS (mTLS)
        var cfg = TlsConfig(
            cert_file="/etc/myapp/client.pem",
            key_file="/etc/myapp/client.key",
        )

        # HTTP/2-preferring client with HTTP/1.1 fallback
        var cfg = TlsConfig(alpn=["h2", "http/1.1"])
        ```
    """

    var verify: Int
    var ca_bundle: String
    var cert_file: String
    var key_file: String
    var server_name: String
    var alpn: List[String]

    def __init__(
        out self,
        verify: Int = TlsVerify.REQUIRED,
        ca_bundle: String = "",
        cert_file: String = "",
        key_file: String = "",
        server_name: String = "",
        var alpn: List[String] = List[String](),
    ):
        self.verify = verify
        # Empty ca_bundle is fine: the C wrapper
        # (flare_ssl_ctx_load_ca_bundle) routes empty paths to
        # SSL_CTX_set_default_verify_paths, which discovers
        # $CONDA_PREFIX/ssl/cacert.pem via OpenSSL's compiled-in
        # OPENSSLDIR. See the module docstring for the full rationale.
        self.ca_bundle = ca_bundle
        self.cert_file = cert_file
        self.key_file = key_file
        self.server_name = server_name
        self.alpn = alpn^

    @staticmethod
    def insecure() -> TlsConfig:
        """Return a config that skips certificate verification entirely.

        Warning:
            This is insecure and must never be used in production.
            Every ``TlsStream.connect`` call made with this config will
            print a ``[SECURITY WARNING]`` to stderr.
        """
        return TlsConfig(verify=TlsVerify.NONE)
