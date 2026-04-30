"""TLS-specific error types for ``flare.tls``.

All error types implement ``Copyable``, ``Movable``, and ``Writable``
so they can be raised, caught, printed, and logged uniformly.
"""

from std.format import Writable, Writer


struct TlsHandshakeError(Copyable, Movable, Writable):
    """The TLS handshake failed (generic failure not covered by cert errors).

    Fields:
        message: Human-readable OpenSSL error string.
    """

    var message: String

    def __init__(out self, message: String):
        """Create a TlsHandshakeError.

        Args:
            message: Error detail from the OpenSSL error queue.
        """
        self.message = message

    def write_to[W: Writer](self, mut writer: W):
        """Write ``"TlsHandshakeError: <message>"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("TlsHandshakeError: ", self.message)


struct CertificateExpired(Copyable, Movable, Writable):
    """The server certificate has passed its ``notAfter`` date.

    Fields:
        subject: Certificate subject DN from ``X509_NAME_oneline``.
    """

    var subject: String

    def __init__(out self, subject: String = ""):
        """Create a CertificateExpired error.

        Args:
            subject: Certificate subject DN string (may be empty).
        """
        self.subject = subject

    def write_to[W: Writer](self, mut writer: W):
        """Write the error to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("CertificateExpired: subject=", self.subject)


struct CertificateHostnameMismatch(Copyable, Movable, Writable):
    """The server certificate's CN/SAN does not match the target hostname.

    Fields:
        expected: The hostname that was required.
        subject: The certificate's subject DN.
    """

    var expected: String
    var subject: String

    def __init__(out self, expected: String, subject: String = ""):
        """Create a CertificateHostnameMismatch error.

        Args:
            expected: The hostname the client tried to connect to.
            subject: Certificate subject DN (may be empty if unavailable).
        """
        self.expected = expected
        self.subject = subject

    def write_to[W: Writer](self, mut writer: W):
        """Write the error to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write(
            "CertificateHostnameMismatch: expected=",
            self.expected,
            " subject=",
            self.subject,
        )


struct CertificateUntrusted(Copyable, Movable, Writable):
    """The server certificate is not trusted by any CA in the bundle.

    Raised for self-signed certs, expired CAs, or missing CA chains.

    Fields:
        reason: OpenSSL verification failure reason string.
    """

    var reason: String

    def __init__(out self, reason: String = ""):
        """Create a CertificateUntrusted error.

        Args:
            reason: OpenSSL verification error string.
        """
        self.reason = reason

    def write_to[W: Writer](self, mut writer: W):
        """Write the error to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("CertificateUntrusted: ", self.reason)
