"""Typed network errors for flare.

Every error type implements ``Writable`` and ``Stringable`` so it can be
used with ``print()`` and ``String()``. All types also implement ``Copyable``
and ``Movable`` because errors are often returned from functions, stored in
Result types, or logged.

Design principle: every error instance carries enough context to understand
the failure without a stack trace. Include the peer address, hostname, or
port wherever relevant.
"""

from format import Writable, Writer


struct NetworkError(Copyable, Movable, Stringable, Writable):
    """Generic network error — a catch-all for OS errors without a more
    specific typed variant.

    Fields:
        message: Human-readable description (from ``strerror`` or caller).
        code:    OS ``errno`` value (0 if not applicable).

    Example:
        ```mojo
        raise NetworkError("connect failed", 111)
        ```
    """

    var message: String
    var code: Int

    fn __init__(out self, message: String, code: Int = 0):
        """Initialise a NetworkError.

        Args:
            message: Human-readable description of the failure.
            code:    OS errno value. Defaults to 0 (not an OS error).
        """
        self.message = message
        self.code = code

    fn write_to[W: Writer](self, mut writer: W):
        """Write a one-line description to ``writer``.

        Args:
            writer: Destination writer (e.g. stdout, a String).
        """
        writer.write("NetworkError")
        if self.code != 0:
            writer.write("(errno ", self.code, ")")
        writer.write(": ", self.message)

    fn __str__(self) -> String:
        """Return a human-readable one-liner.

        Returns:
            String of the form ``"NetworkError(errno N): message"``.
        """
        var s = String("NetworkError")
        if self.code != 0:
            s += "(errno " + String(self.code) + ")"
        return s + ": " + self.message


struct ConnectionRefused(Copyable, Movable, Stringable, Writable):
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

    fn __init__(out self, addr: String, code: Int = 0):
        self.addr = addr
        self.code = code

    fn write_to[W: Writer](self, mut writer: W):
        """Write ``"ConnectionRefused: addr"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("ConnectionRefused: ", self.addr)

    fn __str__(self) -> String:
        """Return ``"ConnectionRefused: addr"`` as a string.

        Returns:
            Human-readable error string.
        """
        return "ConnectionRefused: " + self.addr


struct ConnectionTimeout(Copyable, Movable, Stringable, Writable):
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

    fn __init__(out self, addr: String, code: Int = 0):
        self.addr = addr
        self.code = code

    fn write_to[W: Writer](self, mut writer: W):
        """Write ``"ConnectionTimeout: addr"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("ConnectionTimeout: ", self.addr)

    fn __str__(self) -> String:
        """Return a description string.

        Returns:
            ``"ConnectionTimeout: addr"``.
        """
        return "ConnectionTimeout: " + self.addr


struct ConnectionReset(Copyable, Movable, Stringable, Writable):
    """Raised when the peer forcibly closes a connection (``ECONNRESET``).

    Fields:
        addr: The remote address that sent a TCP RST.
        code: OS errno value.
    """

    var addr: String
    var code: Int

    fn __init__(out self, addr: String, code: Int = 0):
        self.addr = addr
        self.code = code

    fn write_to[W: Writer](self, mut writer: W):
        """Write a description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("ConnectionReset: ", self.addr)

    fn __str__(self) -> String:
        """Return a description string.

        Returns:
            ``"ConnectionReset: addr"``.
        """
        return "ConnectionReset: " + self.addr


struct AddressInUse(Copyable, Movable, Stringable, Writable):
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

    fn __init__(out self, addr: String, code: Int = 0):
        self.addr = addr
        self.code = code

    fn write_to[W: Writer](self, mut writer: W):
        """Write a description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("AddressInUse: ", self.addr)

    fn __str__(self) -> String:
        """Return ``"AddressInUse: addr"`` as a string.

        Returns:
            Human-readable error string.
        """
        return "AddressInUse: " + self.addr


struct AddressParseError(Copyable, Movable, Stringable, Writable):
    """Raised when an address string cannot be parsed.

    Fields:
        input: The invalid input string.

    Example:
        ```mojo
        raise AddressParseError("not_an_ip")
        ```
    """

    var input: String

    fn __init__(out self, input: String):
        self.input = input

    fn write_to[W: Writer](self, mut writer: W):
        """Write a description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("AddressParseError: invalid address '", self.input, "'")

    fn __str__(self) -> String:
        """Return a description string.

        Returns:
            ``"AddressParseError: invalid address 'input'"``.
        """
        return "AddressParseError: invalid address '" + self.input + "'"


struct BrokenPipe(Copyable, Movable, Stringable, Writable):
    """Raised on write to a connection whose read end is closed (``EPIPE``).

    Fields:
        addr: The remote address of the closed connection (may be empty).
        code: OS errno value.
    """

    var addr: String
    var code: Int

    fn __init__(out self, addr: String = "", code: Int = 0):
        self.addr = addr
        self.code = code

    fn write_to[W: Writer](self, mut writer: W):
        """Write a description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("BrokenPipe")
        if self.addr != "":
            writer.write(": ", self.addr)

    fn __str__(self) -> String:
        """Return a description string.

        Returns:
            ``"BrokenPipe"`` or ``"BrokenPipe: addr"``.
        """
        if self.addr != "":
            return "BrokenPipe: " + self.addr
        return "BrokenPipe"


struct Timeout(Copyable, Movable, Stringable, Writable):
    """Raised when a blocking I/O operation exceeds its timeout.

    Fields:
        op:  Name of the operation that timed out (e.g. ``"recv"``).
        ms:  Timeout in milliseconds that was set (0 if unknown).

    Example:
        ```mojo
        raise Timeout("recv", 5000)
        ```
    """

    var op: String
    var ms: Int

    fn __init__(out self, op: String, ms: Int = 0):
        """Initialise a Timeout error.

        Args:
            op: The operation that timed out.
            ms: The configured timeout in milliseconds.
        """
        self.op = op
        self.ms = ms

    fn write_to[W: Writer](self, mut writer: W):
        """Write ``"Timeout: op"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("Timeout: ", self.op)
        if self.ms > 0:
            writer.write(" (", self.ms, " ms)")

    fn __str__(self) -> String:
        """Return ``"Timeout: op"`` as a string.

        Returns:
            Human-readable timeout description.
        """
        var s = "Timeout: " + self.op
        if self.ms > 0:
            s += " (" + String(self.ms) + " ms)"
        return s


struct DnsError(Copyable, Movable, Stringable, Writable):
    """Raised when DNS resolution fails.

    Fields:
        host:   The hostname that could not be resolved.
        code:   The ``getaddrinfo`` error code (from ``gai_strerror``).
        reason: Human-readable reason from ``gai_strerror``.

    Example:
        ```mojo
        raise DnsError("notexist.example.com", 8, "Servname not supported")
        ```
    """

    var host: String
    var code: Int
    var reason: String

    fn __init__(out self, host: String, code: Int = 0, reason: String = ""):
        self.host = host
        self.code = code
        self.reason = reason

    fn write_to[W: Writer](self, mut writer: W):
        """Write ``"DnsError(host): reason"`` to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("DnsError(", self.host, "): ", self.reason)

    fn __str__(self) -> String:
        """Return ``"DnsError(host): reason"`` as a string.

        Returns:
            Human-readable DNS error string.
        """
        return "DnsError(" + self.host + "): " + self.reason
