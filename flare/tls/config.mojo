"""TLS configuration: certificates, keys, and verification policy.

The default CA bundle is sourced from the ``ca-certificates`` pixi dependency,
which places a portable PEM bundle at ``$CONDA_PREFIX/ssl/cacert.pem``.
This path works identically on macOS, Linux x86_64, and Linux aarch64.

When ``ca_bundle`` is empty, the TLS implementation reads
``$CONDA_PREFIX/ssl/cacert.pem`` first; if absent it falls back to
OpenSSL's compiled-in system default (``SSL_CTX_set_default_verify_paths``).
"""

from os import getenv


fn _default_ca_bundle() -> String:
    """Return the pixi-managed CA bundle path, or empty for OS default.

    Returns:
        ``$CONDA_PREFIX/ssl/cacert.pem`` when running inside a pixi
        environment, otherwise ``""`` (OpenSSL system default).
    """
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix == "":
        return ""
    return prefix + "/ssl/cacert.pem"


struct TlsVerify:
    """Peer certificate verification mode constants.

    Use these with ``TlsConfig.verify``.
    """

    comptime NONE: Int = 0
    """Skip all certificate verification. Insecure — for testing only."""

    comptime REQUIRED: Int = 1
    """Verify peer certificate against the trusted CA bundle. Default."""


struct TlsConfig(Copyable, ImplicitlyCopyable, Movable):
    """Configuration for a TLS connection.

    Fields:
        verify:      Verification mode (``TlsVerify.REQUIRED`` by default).
        ca_bundle:   Path to a PEM CA bundle. Defaults to the pixi-managed
                     ``$CONDA_PREFIX/ssl/cacert.pem``; empty string falls
                     back to the OpenSSL system default.
        cert_file:   Path to a PEM client certificate (mTLS), or ``""`` for none.
        key_file:    Path to a PEM client private key (mTLS), or ``""`` for none.
        server_name: SNI hostname override. ``""`` means derive from the
                     connected host at runtime (strongly preferred).

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
        ```
    """

    var verify: Int
    var ca_bundle: String
    var cert_file: String
    var key_file: String
    var server_name: String

    fn __init__(
        out self,
        verify: Int = TlsVerify.REQUIRED,
        ca_bundle: String = "",
        cert_file: String = "",
        key_file: String = "",
        server_name: String = "",
    ):
        self.verify = verify
        # Use pixi-managed CA bundle when no explicit bundle is specified.
        self.ca_bundle = ca_bundle if ca_bundle != "" else _default_ca_bundle()
        self.cert_file = cert_file
        self.key_file = key_file
        self.server_name = server_name

    @staticmethod
    fn insecure() -> TlsConfig:
        """Return a config that skips certificate verification entirely.

        Warning:
            This is insecure and must never be used in production.
            Every ``TlsStream.connect`` call made with this config will
            print a ``[SECURITY WARNING]`` to stderr.
        """
        return TlsConfig(verify=TlsVerify.NONE)
