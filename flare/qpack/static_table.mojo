"""QPACK static table (RFC 9204 Appendix A).

The table holds 99 entries (indices 0..98) covering the most
common HTTP/3 header field shapes (``:authority``, ``:method``,
``:path``, ``:scheme``, ``:status`` plus a curated set of
request/response headers with their canonical values). The table
is read-only at compile time; the encoder picks the lowest-index
match, and the decoder maps a static index back to the
``(name, value)`` pair via ``static_table_lookup``.

Sans-I/O: pure data + pure functions.
"""

from std.collections import List

from flare.http2.hpack import HpackHeader as QpackHeader


comptime _NAMES: Array[StaticString, 99] = [
    ":authority",
    ":path",
    "age",
    "content-disposition",
    "content-length",
    "cookie",
    "date",
    "etag",
    "if-modified-since",
    "if-none-match",
    "last-modified",
    "link",
    "location",
    "referer",
    "set-cookie",
    ":method",
    ":method",
    ":method",
    ":method",
    ":method",
    ":method",
    ":method",
    ":scheme",
    ":scheme",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    "accept",
    "accept",
    "accept-encoding",
    "accept-ranges",
    "access-control-allow-headers",
    "access-control-allow-headers",
    "access-control-allow-origin",
    "cache-control",
    "cache-control",
    "cache-control",
    "cache-control",
    "cache-control",
    "cache-control",
    "content-encoding",
    "content-encoding",
    "content-type",
    "content-type",
    "content-type",
    "content-type",
    "content-type",
    "content-type",
    "content-type",
    "content-type",
    "content-type",
    "content-type",
    "content-type",
    "range",
    "strict-transport-security",
    "strict-transport-security",
    "strict-transport-security",
    "vary",
    "vary",
    "x-content-type-options",
    "x-xss-protection",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    "accept-language",
    "access-control-allow-credentials",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-methods",
    "access-control-allow-methods",
    "access-control-expose-headers",
    "access-control-request-headers",
    "access-control-request-method",
    "access-control-request-method",
    "alt-svc",
    "authorization",
    "content-security-policy",
    "early-data",
    "expect-ct",
    "forwarded",
    "if-range",
    "origin",
    "purpose",
    "server",
    "timing-allow-origin",
    "upgrade-insecure-requests",
    "user-agent",
    "x-forwarded-for",
    "x-frame-options",
    "x-frame-options",
]
"""Field names of RFC 9204 Appendix A, by static index 0..98."""

comptime _VALUES: Array[StaticString, 99] = [
    "",
    "/",
    "0",
    "",
    "0",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "CONNECT",
    "DELETE",
    "GET",
    "HEAD",
    "OPTIONS",
    "POST",
    "PUT",
    "http",
    "https",
    "103",
    "200",
    "304",
    "404",
    "503",
    "*/*",
    "application/dns-message",
    "gzip, deflate, br",
    "bytes",
    "cache-control",
    "content-type",
    "*",
    "max-age=0",
    "max-age=2592000",
    "max-age=604800",
    "no-cache",
    "no-store",
    "public, max-age=31536000",
    "br",
    "gzip",
    "application/dns-message",
    "application/javascript",
    "application/json",
    "application/x-www-form-urlencoded",
    "image/gif",
    "image/jpeg",
    "image/png",
    "text/css",
    "text/html; charset=utf-8",
    "text/plain",
    "text/plain;charset=utf-8",
    "bytes=0-",
    "max-age=31536000",
    "max-age=31536000; includesubdomains",
    "max-age=31536000; includesubdomains; preload",
    "accept-encoding",
    "origin",
    "nosniff",
    "1; mode=block",
    "100",
    "204",
    "206",
    "302",
    "400",
    "403",
    "421",
    "425",
    "500",
    "",
    "FALSE",
    "TRUE",
    "*",
    "get",
    "get, post, options",
    "options",
    "content-length",
    "content-type",
    "get",
    "post",
    "clear",
    "",
    "script-src 'none'; object-src 'none'; base-uri 'none'",
    "1",
    "",
    "",
    "",
    "",
    "prefetch",
    "",
    "*",
    "1",
    "",
    "",
    "deny",
    "sameorigin",
]
"""Field values of RFC 9204 Appendix A, parallel to :data:`_NAMES`."""


comptime QPACK_STATIC_TABLE_SIZE: Int = 99
"""Number of entries in the RFC 9204 Appendix A static table.

Lookups are comptime-unrolled over the literal table, so neither
side builds the table at run time.
"""


def static_name(index: Int) -> StaticString:
    """Name at ``index``; the caller has range-checked it. A comptime
    switch over the table, so no table is built per call."""
    comptime for i in range(QPACK_STATIC_TABLE_SIZE):
        if index == i:
            comptime n = _NAMES[i]
            return n
    return ""


def static_value(index: Int) -> StaticString:
    """Value at ``index``; the caller has range-checked it."""
    comptime for i in range(QPACK_STATIC_TABLE_SIZE):
        if index == i:
            comptime v = _VALUES[i]
            return v
    return ""


def static_table_lookup(index: Int) raises -> QpackHeader:
    """Return the ``(name, value)`` pair at ``index`` in the
    RFC 9204 Appendix A static table.

    Raises ``Error`` on out-of-range indices; the QPACK decoder
    surfaces this as a malformed-field-line failure.
    """
    if index < 0 or index >= QPACK_STATIC_TABLE_SIZE:
        raise Error(
            "qpack: static index "
            + String(index)
            + " out of range [0, "
            + String(QPACK_STATIC_TABLE_SIZE)
            + ")"
        )
    return QpackHeader(String(static_name(index)), String(static_value(index)))


def static_table_find(name: String, value: String) -> Int:
    """Return the lowest static-table index for the
    ``(name, value)`` pair, or ``-1`` if none matches.

    Unrolled at compile time against the literal table. Lookup is
    case-sensitive on both fields -- callers normalise header names
    to lowercase before consulting the table (HTTP/3 mandates
    lowercase field names on the wire, RFC 9114 §4.2).
    """
    var nlen = name.byte_length()
    var vlen = value.byte_length()
    comptime for i in range(QPACK_STATIC_TABLE_SIZE):
        comptime n = _NAMES[i]
        comptime v = _VALUES[i]
        comptime nl = n.byte_length()
        comptime vl = v.byte_length()
        if nlen == nl and vlen == vl and name == n and value == v:
            return i
    return -1


def static_table_find_name(name: String) -> Int:
    """Return the lowest static-table index whose name is ``name``,
    independent of value. Used by the encoder when no full
    ``(name, value)`` match exists but the name itself is
    present in the static table (literal-with-name-reference path).
    """
    var nlen = name.byte_length()
    comptime for i in range(QPACK_STATIC_TABLE_SIZE):
        comptime n = _NAMES[i]
        comptime nl = n.byte_length()
        if nlen == nl and name == n:
            return i
    return -1
