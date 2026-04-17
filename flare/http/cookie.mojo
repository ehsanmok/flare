"""HTTP cookie support (RFC 6265).

Provides ``Cookie`` for individual cookies and ``CookieJar`` for managing
collections of cookies on both request and response sides.

Example:
    ```mojo
    from flare.http.cookie import Cookie, CookieJar

    var jar = CookieJar()
    jar.set(Cookie("session", "abc123", secure=True, http_only=True))
    var header = jar.to_request_header()  # "session=abc123"
    ```
"""

from std.format import Writable, Writer


struct SameSite:
    """SameSite attribute values for cookies."""

    comptime NONE: String = "None"
    comptime LAX: String = "Lax"
    comptime STRICT: String = "Strict"


struct Cookie(Copyable, Movable):
    """An HTTP cookie (RFC 6265).

    Fields:
        name:      Cookie name (must not be empty).
        value:     Cookie value.
        domain:    Domain attribute (empty = not set).
        path:      Path attribute (empty = not set).
        max_age:   Max-Age in seconds (-1 = not set, 0 = delete).
        secure:    Secure flag (HTTPS only).
        http_only: HttpOnly flag (not accessible to JavaScript).
        same_site: SameSite attribute (empty = not set).
    """

    var name: String
    var value: String
    var domain: String
    var path: String
    var max_age: Int
    var secure: Bool
    var http_only: Bool
    var same_site: String

    def __init__(
        out self,
        name: String,
        value: String,
        domain: String = "",
        path: String = "",
        max_age: Int = -1,
        secure: Bool = False,
        http_only: Bool = False,
        same_site: String = "",
    ):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.max_age = max_age
        self.secure = secure
        self.http_only = http_only
        self.same_site = same_site

    def to_set_cookie_header(self) -> String:
        """Serialise this cookie as a ``Set-Cookie`` header value.

        Returns:
            The full ``Set-Cookie`` value string.
        """
        var out = self.name + "=" + self.value
        if self.domain.byte_length() > 0:
            out += "; Domain=" + self.domain
        if self.path.byte_length() > 0:
            out += "; Path=" + self.path
        if self.max_age >= 0:
            out += "; Max-Age=" + String(self.max_age)
        if self.secure:
            out += "; Secure"
        if self.http_only:
            out += "; HttpOnly"
        if self.same_site.byte_length() > 0:
            out += "; SameSite=" + self.same_site
        return out^

    def to_request_pair(self) -> String:
        """Serialise as ``name=value`` for a ``Cookie`` request header."""
        return self.name + "=" + self.value


def parse_cookie_header(header: String) -> List[Cookie]:
    """Parse a ``Cookie`` request header value into individual cookies.

    Format: ``name1=value1; name2=value2; ...``

    Args:
        header: The ``Cookie`` header value string.

    Returns:
        A list of ``Cookie`` instances (name + value only).
    """
    var cookies = List[Cookie]()
    var pos = 0
    var n = header.byte_length()
    var ptr = header.unsafe_ptr()

    while pos < n:
        # Skip leading whitespace
        while pos < n and (ptr[pos] == 32 or ptr[pos] == 9):
            pos += 1

        # Find '='
        var eq = -1
        var scan = pos
        while scan < n:
            if ptr[scan] == 61:  # '='
                eq = scan
                break
            if ptr[scan] == 59:  # ';' before '=' means malformed, skip
                break
            scan += 1

        if eq < 0:
            # Skip to next ';'
            while pos < n and ptr[pos] != 59:
                pos += 1
            pos += 1
            continue

        var name = String(
            String(unsafe_from_utf8=header.as_bytes()[pos:eq]).strip()
        )

        # Find end of value (';' or end of string)
        var val_start = eq + 1
        var val_end = val_start
        while val_end < n and ptr[val_end] != 59:
            val_end += 1

        var value = String(
            String(
                unsafe_from_utf8=header.as_bytes()[val_start:val_end]
            ).strip()
        )
        cookies.append(Cookie(name, value))

        pos = val_end + 1

    return cookies^


def parse_set_cookie_header(header: String) -> Cookie:
    """Parse a ``Set-Cookie`` response header value.

    Args:
        header: The ``Set-Cookie`` header value string.

    Returns:
        A ``Cookie`` with all attributes populated.
    """
    var ptr = header.unsafe_ptr()
    var n = header.byte_length()

    # Split on first ';' to get name=value
    var semi = n
    for i in range(n):
        if ptr[i] == 59:
            semi = i
            break

    var nv = String(String(unsafe_from_utf8=header.as_bytes()[:semi]).strip())
    var eq = -1
    for i in range(nv.byte_length()):
        if nv.unsafe_ptr()[i] == 61:
            eq = i
            break

    var name: String
    var value: String
    if eq >= 0:
        name = String(String(unsafe_from_utf8=nv.as_bytes()[:eq]).strip())
        value = String(String(unsafe_from_utf8=nv.as_bytes()[eq + 1 :]).strip())
    else:
        name = nv
        value = String("")

    var cookie = Cookie(name, value)

    # Parse attributes
    var pos = semi + 1
    while pos < n:
        while pos < n and (ptr[pos] == 32 or ptr[pos] == 9):
            pos += 1

        var attr_end = pos
        while attr_end < n and ptr[attr_end] != 59:
            attr_end += 1

        var attr = String(
            String(unsafe_from_utf8=header.as_bytes()[pos:attr_end]).strip()
        )
        var attr_lower = String(capacity=attr.byte_length())
        for i in range(attr.byte_length()):
            var c = attr.unsafe_ptr()[i]
            if c >= 65 and c <= 90:
                attr_lower += chr(Int(c) + 32)
            else:
                attr_lower += chr(Int(c))

        # Check for attribute=value pairs
        var attr_eq = -1
        for i in range(attr_lower.byte_length()):
            if attr_lower.unsafe_ptr()[i] == 61:
                attr_eq = i
                break

        if attr_eq >= 0:
            var akey = String(
                String(unsafe_from_utf8=attr_lower.as_bytes()[:attr_eq]).strip()
            )
            var aval = String(
                String(unsafe_from_utf8=attr.as_bytes()[attr_eq + 1 :]).strip()
            )

            if akey == "domain":
                cookie.domain = aval
            elif akey == "path":
                cookie.path = aval
            elif akey == "max-age":
                var age = 0
                for i in range(aval.byte_length()):
                    var c = Int(aval.unsafe_ptr()[i])
                    if c >= 48 and c <= 57:
                        age = age * 10 + (c - 48)
                cookie.max_age = age
            elif akey == "samesite":
                cookie.same_site = aval
        else:
            if attr_lower == "secure":
                cookie.secure = True
            elif attr_lower == "httponly":
                cookie.http_only = True

        pos = attr_end + 1

    return cookie^


struct CookieJar(Movable):
    """A collection of cookies for request/response management.

    Stores cookies by name. Supports serialisation to request ``Cookie``
    header and response ``Set-Cookie`` headers.
    """

    var _cookies: List[Cookie]

    def __init__(out self):
        self._cookies = List[Cookie]()

    def set(mut self, var cookie: Cookie):
        """Add or replace a cookie by name.

        Args:
            cookie: The cookie to set (ownership taken).
        """
        for i in range(len(self._cookies)):
            if self._cookies[i].name == cookie.name:
                self._cookies[i] = cookie^
                return
        self._cookies.append(cookie^)

    def get(self, name: String) -> String:
        """Return the value of a cookie by name, or ``""`` if absent.

        Args:
            name: Cookie name.

        Returns:
            Cookie value or empty string.
        """
        for i in range(len(self._cookies)):
            if self._cookies[i].name == name:
                return self._cookies[i].value
        return ""

    def remove(mut self, name: String) -> Bool:
        """Remove a cookie by name.

        Args:
            name: Cookie name to remove.

        Returns:
            True if a cookie was removed.
        """
        var new_list = List[Cookie]()
        var removed = False
        for i in range(len(self._cookies)):
            if self._cookies[i].name == name:
                removed = True
            else:
                new_list.append(self._cookies[i].copy())
        self._cookies = new_list^
        return removed

    def contains(self, name: String) -> Bool:
        """Return True if a cookie with this name exists."""
        for i in range(len(self._cookies)):
            if self._cookies[i].name == name:
                return True
        return False

    def len(self) -> Int:
        """Return the number of cookies."""
        return len(self._cookies)

    def to_request_header(self) -> String:
        """Serialise all cookies as a ``Cookie`` request header value.

        Returns:
            ``"name1=value1; name2=value2; ..."`` format string.
        """
        var out = String(capacity=256)
        for i in range(len(self._cookies)):
            if i > 0:
                out += "; "
            out += self._cookies[i].to_request_pair()
        return out^
