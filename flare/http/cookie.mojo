"""HTTP cookie support (RFC 6265).

Provides ``Cookie`` for individual cookies and ``CookieJar`` for managing
collections of cookies on both request and response sides.

Example:
    ```mojo
    from flare.http.cookie import Cookie, CookieJar

    var jar = CookieJar()
    jar.set(Cookie("session", "abc123", secure=True, http_only=True))
    var header = jar.to_request_header() # "session=abc123"
    ```
"""

from std.collections.span import Span
from std.format import Writable, Writer


struct SameSite:
    """SameSite attribute values for cookies."""

    comptime NONE: String = "None"
    comptime LAX: String = "Lax"
    comptime STRICT: String = "Strict"


struct Cookie(Copyable):
    """An HTTP cookie (RFC 6265).

    Fields:
        name: Cookie name (must not be empty).
        value: Cookie value.
        domain: Domain attribute (empty = not set).
        path: Path attribute (empty = not set).
        max_age: Max-Age in seconds (-1 = not set, 0 = delete).
        secure: Secure flag (HTTPS only).
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

    @staticmethod
    def session(name: String, value: String) -> Cookie:
        """A cookie with the attributes a session cookie should have:
        ``Path=/``, ``Secure``, ``HttpOnly``, ``SameSite=Lax``.

        The plain constructor leaves all three flags off, which is the
        RFC 6265 default but the wrong one for anything that
        authenticates a user.
        """
        return Cookie(
            name,
            value,
            path="/",
            secure=True,
            http_only=True,
            same_site=SameSite.LAX,
        )

    def to_set_cookie_header(self) raises -> String:
        """Serialise this cookie as a ``Set-Cookie`` header value.

        Validates against RFC 6265 sec 4.1.1 first. ``;`` is the
        attribute separator, so a value or path holding one used to
        inject attributes of the sender's choosing -- ``value =
        "x; Domain=.evil.com"`` widened the cookie's scope.
        ``SameSite=None`` implies ``Secure``, which browsers require.

        Returns:
            The full ``Set-Cookie`` value string.

        Raises:
            Error: On an empty or non-token name, a value outside
                cookie-octet, a ``Domain`` or ``Path`` with a control
                byte or ``;``, or an unknown ``SameSite``.
        """
        if self.name.byte_length() == 0 or not _all_token(self.name):
            raise Error("Set-Cookie: invalid cookie name")
        if not _is_cookie_value(self.value):
            raise Error("Set-Cookie: invalid cookie value for " + self.name)
        if not _is_av_value(self.domain) or not _is_av_value(self.path):
            raise Error("Set-Cookie: invalid Domain or Path for " + self.name)
        var same_site = self.same_site
        if same_site.byte_length() > 0:
            var ss = same_site.lower()
            if ss == "strict":
                same_site = SameSite.STRICT
            elif ss == "lax":
                same_site = SameSite.LAX
            elif ss == "none":
                same_site = SameSite.NONE
            else:
                raise Error("Set-Cookie: invalid SameSite " + same_site)
        var out = self.name + "=" + self.value
        if self.domain.byte_length() > 0:
            out += "; Domain=" + self.domain
        if self.path.byte_length() > 0:
            out += "; Path=" + self.path
        if self.max_age >= 0:
            out += "; Max-Age=" + String(self.max_age)
        if self.secure or same_site == SameSite.NONE:
            out += "; Secure"
        if self.http_only:
            out += "; HttpOnly"
        if same_site.byte_length() > 0:
            out += "; SameSite=" + same_site
        return out^

    def to_request_pair(self) -> String:
        """Serialise as ``name=value`` for a ``Cookie`` request header."""
        return self.name + "=" + self.value


comptime _MAX_AGE_IGNORED: Int = -(1 << 62)


def _parse_max_age(v: String) -> Int:
    var n = v.byte_length()
    if n == 0:
        return _MAX_AGE_IGNORED
    var p = v.unsafe_ptr()
    var i = 0
    var neg = False
    if p[unsafe_offset=0] == 45:  # '-'
        neg = True
        i = 1
    if i >= n or n - i > 18:
        return _MAX_AGE_IGNORED
    var acc = 0
    while i < n:
        var c = Int(p[unsafe_offset=i])
        if c < 48 or c > 57:
            return _MAX_AGE_IGNORED
        acc = acc * 10 + (c - 48)
        i += 1
    return -acc if neg else acc


def _is_token_byte(c: UInt8) -> Bool:
    if c <= 32 or c >= 127:
        return False
    # RFC 9110 separators.
    for s in String('()<>@,;:\\"/[]?={}').as_bytes():
        if c == s:
            return False
    return True


def _all_token(s: String) -> Bool:
    for c in s.as_bytes():
        if not _is_token_byte(c):
            return False
    return True


def _is_cookie_value(s: String) -> Bool:
    """RFC 6265 cookie-value: cookie-octets, optionally in DQUOTEs."""
    var b = s.as_bytes()
    var start = 0
    var end = len(b)
    if end >= 2 and b[0] == 34 and b[end - 1] == 34:
        start = 1
        end -= 1
    for i in range(start, end):
        var c = b[i]
        if (
            c == 0x21
            or (c >= 0x23 and c <= 0x2B)
            or (c >= 0x2D and c <= 0x3A)
            or (c >= 0x3C and c <= 0x5B)
            or (c >= 0x5D and c <= 0x7E)
        ):
            continue
        return False
    return True


def _is_av_value(s: String) -> Bool:
    """Attribute value: any CHAR except controls and ';'."""
    for c in s.as_bytes():
        if c < 32 or c == 127 or c == 59:
            return False
    return True


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
        while pos < n and (
            ptr[unsafe_offset=pos] == 32 or ptr[unsafe_offset=pos] == 9
        ):
            pos += 1

        # Find '='
        var eq = -1
        var scan = pos
        while scan < n:
            if ptr[unsafe_offset=scan] == 61:  # '='
                eq = scan
                break
            if (
                ptr[unsafe_offset=scan] == 59
            ):  # ';' before '=' means malformed, skip
                break
            scan += 1

        if eq < 0:
            # Skip to next ';'
            while pos < n and ptr[unsafe_offset=pos] != 59:
                pos += 1
            pos += 1
            continue

        var name = String(
            String(unsafe_from_utf8=header.as_bytes()[pos:eq]).strip()
        )

        # Find end of value (';' or end of string)
        var val_start = eq + 1
        var val_end = val_start
        while val_end < n and ptr[unsafe_offset=val_end] != 59:
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
        if ptr[unsafe_offset=i] == 59:
            semi = i
            break

    var nv = String(String(unsafe_from_utf8=header.as_bytes()[:semi]).strip())
    var eq = -1
    for i in range(nv.byte_length()):
        if nv.unsafe_ptr()[unsafe_offset=i] == 61:
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
        while pos < n and (
            ptr[unsafe_offset=pos] == 32 or ptr[unsafe_offset=pos] == 9
        ):
            pos += 1

        var attr_end = pos
        while attr_end < n and ptr[unsafe_offset=attr_end] != 59:
            attr_end += 1

        var attr = String(
            String(unsafe_from_utf8=header.as_bytes()[pos:attr_end]).strip()
        )
        # Lowercase byte-for-byte (not via chr(), which re-encodes bytes
        # >= 128 as multi-byte UTF-8 and desyncs attr_lower's byte length
        # from attr's -- attr_eq below must stay a valid index into attr).
        var attr_lower_bytes = List[UInt8](capacity=attr.byte_length())
        for i in range(attr.byte_length()):
            var c = attr.unsafe_ptr()[unsafe_offset=i]
            if c >= 65 and c <= 90:
                attr_lower_bytes.append(c + 32)
            else:
                attr_lower_bytes.append(c)
        var attr_lower = String(
            unsafe_from_utf8=Span[UInt8, _](attr_lower_bytes)
        )

        # Check for attribute=value pairs
        var attr_eq = -1
        for i in range(attr_lower.byte_length()):
            if attr_lower.unsafe_ptr()[unsafe_offset=i] == 61:
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
                # RFC 6265 sec 5.2.2: an optional '-' then digits, else
                # the attribute is ignored; zero or negative means
                # "expire now". The old loop skipped the sign, so
                # ``Max-Age=-5`` (a delete) was stored as 5 seconds.
                var age = _parse_max_age(aval)
                if age != _MAX_AGE_IGNORED:
                    cookie.max_age = age if age > 0 else 0
            elif akey == "samesite":
                cookie.same_site = aval
        else:
            if attr_lower == "secure":
                cookie.secure = True
            elif attr_lower == "httponly":
                cookie.http_only = True

        pos = attr_end + 1

    return cookie^


struct CookieJar(Copyable, Defaultable):
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
        var out = String(capacity_bytes=256)
        for i in range(len(self._cookies)):
            if i > 0:
                out += "; "
            out += self._cookies[i].to_request_pair()
        return out^
