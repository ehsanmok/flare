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


def _qpack_static_table() -> List[QpackHeader]:
    """Build the RFC 9204 Appendix A static table.

    Index 0 -> (":authority", ""); the table runs through index
    98 in the order the RFC defines (no synthetic 0-th entry,
    unlike HPACK where index 0 is reserved). Callers receive a
    fresh list per invocation so mutation downstream is safe.
    """
    var t = List[QpackHeader](capacity=99)
    t.append(QpackHeader(":authority", ""))  # 0
    t.append(QpackHeader(":path", "/"))  # 1
    t.append(QpackHeader("age", "0"))  # 2
    t.append(QpackHeader("content-disposition", ""))  # 3
    t.append(QpackHeader("content-length", "0"))  # 4
    t.append(QpackHeader("cookie", ""))  # 5
    t.append(QpackHeader("date", ""))  # 6
    t.append(QpackHeader("etag", ""))  # 7
    t.append(QpackHeader("if-modified-since", ""))  # 8
    t.append(QpackHeader("if-none-match", ""))  # 9
    t.append(QpackHeader("last-modified", ""))  # 10
    t.append(QpackHeader("link", ""))  # 11
    t.append(QpackHeader("location", ""))  # 12
    t.append(QpackHeader("referer", ""))  # 13
    t.append(QpackHeader("set-cookie", ""))  # 14
    t.append(QpackHeader(":method", "CONNECT"))  # 15
    t.append(QpackHeader(":method", "DELETE"))  # 16
    t.append(QpackHeader(":method", "GET"))  # 17
    t.append(QpackHeader(":method", "HEAD"))  # 18
    t.append(QpackHeader(":method", "OPTIONS"))  # 19
    t.append(QpackHeader(":method", "POST"))  # 20
    t.append(QpackHeader(":method", "PUT"))  # 21
    t.append(QpackHeader(":scheme", "http"))  # 22
    t.append(QpackHeader(":scheme", "https"))  # 23
    t.append(QpackHeader(":status", "103"))  # 24
    t.append(QpackHeader(":status", "200"))  # 25
    t.append(QpackHeader(":status", "304"))  # 26
    t.append(QpackHeader(":status", "404"))  # 27
    t.append(QpackHeader(":status", "503"))  # 28
    t.append(QpackHeader("accept", "*/*"))  # 29
    t.append(QpackHeader("accept", "application/dns-message"))  # 30
    t.append(QpackHeader("accept-encoding", "gzip, deflate, br"))  # 31
    t.append(QpackHeader("accept-ranges", "bytes"))  # 32
    t.append(QpackHeader("access-control-allow-headers", "cache-control"))  # 33
    t.append(QpackHeader("access-control-allow-headers", "content-type"))  # 34
    t.append(QpackHeader("access-control-allow-origin", "*"))  # 35
    t.append(QpackHeader("cache-control", "max-age=0"))  # 36
    t.append(QpackHeader("cache-control", "max-age=2592000"))  # 37
    t.append(QpackHeader("cache-control", "max-age=604800"))  # 38
    t.append(QpackHeader("cache-control", "no-cache"))  # 39
    t.append(QpackHeader("cache-control", "no-store"))  # 40
    t.append(QpackHeader("cache-control", "public, max-age=31536000"))  # 41
    t.append(QpackHeader("content-encoding", "br"))  # 42
    t.append(QpackHeader("content-encoding", "gzip"))  # 43
    t.append(QpackHeader("content-type", "application/dns-message"))  # 44
    t.append(QpackHeader("content-type", "application/javascript"))  # 45
    t.append(QpackHeader("content-type", "application/json"))  # 46
    t.append(
        QpackHeader("content-type", "application/x-www-form-urlencoded")
    )  # 47
    t.append(QpackHeader("content-type", "image/gif"))  # 48
    t.append(QpackHeader("content-type", "image/jpeg"))  # 49
    t.append(QpackHeader("content-type", "image/png"))  # 50
    t.append(QpackHeader("content-type", "text/css"))  # 51
    t.append(QpackHeader("content-type", "text/html; charset=utf-8"))  # 52
    t.append(QpackHeader("content-type", "text/plain"))  # 53
    t.append(QpackHeader("content-type", "text/plain;charset=utf-8"))  # 54
    t.append(QpackHeader("range", "bytes=0-"))  # 55
    t.append(QpackHeader("strict-transport-security", "max-age=31536000"))  # 56
    t.append(
        QpackHeader(
            "strict-transport-security",
            "max-age=31536000; includesubdomains",
        )
    )  # 57
    t.append(
        QpackHeader(
            "strict-transport-security",
            "max-age=31536000; includesubdomains; preload",
        )
    )  # 58
    t.append(QpackHeader("vary", "accept-encoding"))  # 59
    t.append(QpackHeader("vary", "origin"))  # 60
    t.append(QpackHeader("x-content-type-options", "nosniff"))  # 61
    t.append(QpackHeader("x-xss-protection", "1; mode=block"))  # 62
    t.append(QpackHeader(":status", "100"))  # 63
    t.append(QpackHeader(":status", "204"))  # 64
    t.append(QpackHeader(":status", "206"))  # 65
    t.append(QpackHeader(":status", "302"))  # 66
    t.append(QpackHeader(":status", "400"))  # 67
    t.append(QpackHeader(":status", "403"))  # 68
    t.append(QpackHeader(":status", "421"))  # 69
    t.append(QpackHeader(":status", "425"))  # 70
    t.append(QpackHeader(":status", "500"))  # 71
    t.append(QpackHeader("accept-language", ""))  # 72
    t.append(QpackHeader("access-control-allow-credentials", "FALSE"))  # 73
    t.append(QpackHeader("access-control-allow-credentials", "TRUE"))  # 74
    t.append(QpackHeader("access-control-allow-headers", "*"))  # 75
    t.append(QpackHeader("access-control-allow-methods", "get"))  # 76
    t.append(
        QpackHeader("access-control-allow-methods", "get, post, options")
    )  # 77
    t.append(QpackHeader("access-control-allow-methods", "options"))  # 78
    t.append(
        QpackHeader("access-control-expose-headers", "content-length")
    )  # 79
    t.append(
        QpackHeader("access-control-request-headers", "content-type")
    )  # 80
    t.append(QpackHeader("access-control-request-method", "get"))  # 81
    t.append(QpackHeader("access-control-request-method", "post"))  # 82
    t.append(QpackHeader("alt-svc", "clear"))  # 83
    t.append(QpackHeader("authorization", ""))  # 84
    t.append(
        QpackHeader(
            "content-security-policy",
            "script-src 'none'; object-src 'none'; base-uri 'none'",
        )
    )  # 85
    t.append(QpackHeader("early-data", "1"))  # 86
    t.append(QpackHeader("expect-ct", ""))  # 87
    t.append(QpackHeader("forwarded", ""))  # 88
    t.append(QpackHeader("if-range", ""))  # 89
    t.append(QpackHeader("origin", ""))  # 90
    t.append(QpackHeader("purpose", "prefetch"))  # 91
    t.append(QpackHeader("server", ""))  # 92
    t.append(QpackHeader("timing-allow-origin", "*"))  # 93
    t.append(QpackHeader("upgrade-insecure-requests", "1"))  # 94
    t.append(QpackHeader("user-agent", ""))  # 95
    t.append(QpackHeader("x-forwarded-for", ""))  # 96
    t.append(QpackHeader("x-frame-options", "deny"))  # 97
    t.append(QpackHeader("x-frame-options", "sameorigin"))  # 98
    return t^


comptime QPACK_STATIC_TABLE_SIZE: Int = 99
"""Number of entries in the RFC 9204 Appendix A static table.

The table is small and tail-biased (most-common shapes early);
encoders that look up an entry walk the table linearly without
needing a perfect hash. Switching from a linear scan to a
perfect-hash side-table is a possible future optimisation;
static-only QPACK is correctness-bound, not lookup-bound.
"""


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
    var table = _qpack_static_table()
    return table[index].copy()


def static_table_find(name: String, value: String) -> Int:
    """Return the lowest static-table index for the
    ``(name, value)`` pair, or ``-1`` if none matches.

    The lookup is a linear scan. The 99-entry table is small
    enough that linear-scan latency is in cache for any
    real-world handler; a future cycle can drop in a PHF backed
    by the same surface. Lookup is case-sensitive on both fields
    -- callers normalise header names to lowercase before
    consulting the table (HTTP/3 mandates lowercase field names
    on the wire, RFC 9114 §4.2).
    """
    var table = _qpack_static_table()
    for i in range(QPACK_STATIC_TABLE_SIZE):
        if table[i].name == name and table[i].value == value:
            return i
    return -1


def static_table_find_name(name: String) -> Int:
    """Return the lowest static-table index whose name is ``name``,
    independent of value. Used by the encoder when no full
    ``(name, value)`` match exists but the name itself is
    present in the static table (literal-with-name-reference path).
    """
    var table = _qpack_static_table()
    for i in range(QPACK_STATIC_TABLE_SIZE):
        if table[i].name == name:
            return i
    return -1
