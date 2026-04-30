"""Typed network errors for flare.

Every error type implements ``Writable`` so it can be
used with ``print()`` and ``String()``. All types also implement ``Copyable``
and ``Movable`` because errors are often returned from functions, stored in
Result types, or logged.

Design principle: every error instance carries enough context to understand
the failure without a stack trace. Include the peer address, hostname, or
port wherever relevant.
"""

from std.format import Writable, Writer


struct NetworkError(Copyable, Movable, Writable):
    """Generic network error — a catch-all for OS errors without a more
    specific typed variant.

    Fields:
        message: Human-readable description (from ``strerror`` or caller).
        code: OS ``errno`` value (0 if not applicable).

    Example:
        ```mojo
        raise NetworkError("connect failed", 111)
        ```
    """

    var message: String
    var code: Int

    def __init__(out self, message: String, code: Int = 0):
        """Initialise a NetworkError.

        Args:
            message: Human-readable description of the failure.
            code: OS errno value. Defaults to 0 (not an OS error).
        """
        self.message = message
        self.code = code

    def write_to[W: Writer](self, mut writer: W):
        """Write a one-line description to ``writer``.

        Args:
            writer: Destination writer (e.g. stdout, a String).
        """
        writer.write("NetworkError")
        if self.code != 0:
            writer.write("(errno ", self.code, ")")
        writer.write(": ", self.message)


struct ConnectionRefused(Copyable, Movable, Writable):
    """Raised when a TCP ``connect()`` fails with ``ECONNREFUSED``.

    Fields:
        addr: String representation of the refused address (e.g. ``"127.0.0.1:8080"``).
        code: OS errno value (always ``ECONNREFUSED``).

    Example:
        ```mojo
        raise ConnectionRefused("127.0.0.1:8080", 111)
        ```
    """

    var addr: String
    var code: Int

    def __init__(out self, addr: String, code: Int = 0):
        self.addr = addr
        self.code = code

    def write_to[W: Writer](self, mut writer: W):
        """Write ``"ConnectionRefused: addr"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("ConnectionRefused: ", self.addr)


struct ConnectionTimeout(Copyable, Movable, Writable):
    """Raised when a TCP ``connect()`` times out (``ETIMEDOUT``).

    Fields:
        addr: The target address that timed out.
        code: OS errno value.

    Example:
        ```mojo
        raise ConnectionTimeout("10.0.0.1:443", 110)
        ```
    """

    var addr: String
    var code: Int

    def __init__(out self, addr: String, code: Int = 0):
        self.addr = addr
        self.code = code

    def write_to[W: Writer](self, mut writer: W):
        """Write ``"ConnectionTimeout: addr"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("ConnectionTimeout: ", self.addr)


struct ConnectionReset(Copyable, Movable, Writable):
    """Raised when the peer forcibly closes a connection (``ECONNRESET``).

    Fields:
        addr: The remote address that sent a TCP RST.
        code: OS errno value.
    """

    var addr: String
    var code: Int

    def __init__(out self, addr: String, code: Int = 0):
        self.addr = addr
        self.code = code

    def write_to[W: Writer](self, mut writer: W):
        """Write a description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("ConnectionReset: ", self.addr)


struct AddressInUse(Copyable, Movable, Writable):
    """Raised when ``bind()`` fails because the port is in use (``EADDRINUSE``).

    Fields:
        addr: The address that could not be bound.
        code: OS errno value.

    Example:
        ```mojo
        raise AddressInUse("0.0.0.0:8080", 98)
        ```
    """

    var addr: String
    var code: Int

    def __init__(out self, addr: String, code: Int = 0):
        self.addr = addr
        self.code = code

    def write_to[W: Writer](self, mut writer: W):
        """Write a description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("AddressInUse: ", self.addr)


struct AddressParseError(Copyable, Movable, Writable):
    """Raised when an address string cannot be parsed.

    Fields:
        input: The invalid input string.

    Example:
        ```mojo
        raise AddressParseError("not_an_ip")
        ```
    """

    var input: String

    def __init__(out self, input: String):
        self.input = input

    def write_to[W: Writer](self, mut writer: W):
        """Write a description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("AddressParseError: invalid address '", self.input, "'")


struct BrokenPipe(Copyable, Movable, Writable):
    """Raised on write to a connection whose read end is closed (``EPIPE``).

    Fields:
        addr: The remote address of the closed connection (may be empty).
        code: OS errno value.
    """

    var addr: String
    var code: Int

    def __init__(out self, addr: String = "", code: Int = 0):
        self.addr = addr
        self.code = code

    def write_to[W: Writer](self, mut writer: W):
        """Write a description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("BrokenPipe")
        if self.addr != "":
            writer.write(": ", self.addr)


struct Timeout(Copyable, Movable, Writable):
    """Raised when a blocking I/O operation exceeds its timeout.

    Fields:
        op: Name of the operation that timed out (e.g. ``"recv"``).
        ms: Timeout in milliseconds that was set (0 if unknown).

    Example:
        ```mojo
        raise Timeout("recv", 5000)
        ```
    """

    var op: String
    var ms: Int

    def __init__(out self, op: String, ms: Int = 0):
        """Initialise a Timeout error.

        Args:
            op: The operation that timed out.
            ms: The configured timeout in milliseconds.
        """
        self.op = op
        self.ms = ms

    def write_to[W: Writer](self, mut writer: W):
        """Write ``"Timeout: op"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("Timeout: ", self.op)
        if self.ms > 0:
            writer.write(" (", self.ms, " ms)")


struct DnsError(Copyable, Movable, Writable):
    """Raised when DNS resolution fails.

    Fields:
        host: The hostname that could not be resolved.
        code: The ``getaddrinfo`` error code (from ``gai_strerror``).
        reason: Human-readable reason from ``gai_strerror``.

    Example:
        ```mojo
        raise DnsError("notexist.example.com", 8, "Servname not supported")
        ```
    """

    var host: String
    var code: Int
    var reason: String

    def __init__(out self, host: String, code: Int = 0, reason: String = ""):
        self.host = host
        self.code = code
        self.reason = reason

    def write_to[W: Writer](self, mut writer: W):
        """Write ``"DnsError(host): reason"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("DnsError(", self.host, "): ", self.reason)
