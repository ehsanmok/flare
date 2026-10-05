"""Signed cookies + typed sessions.

The ``SignedCookie`` primitive encodes a payload as
``base64url(payload) + "." + base64url(hmac_sha256(key, base64url(payload)))``
— the same shape JSON Web Signature uses, so the format is
familiar to anyone who has read RFC 7515. The MAC is computed
over the *base64url-encoded payload* (not the raw bytes) so the
verifier can split on ``.`` without first decoding.

``Session[T]`` wraps an arbitrary ``Copyable`` payload
and (de)serialises it through a user-supplied ``SessionCodec[T]``.
``SessionStore`` is the abstraction over storage; flare ships:

- ``CookieSessionStore`` — payload travels in the signed cookie
  itself (stateless).
- ``InMemorySessionStore`` — payload kept server-side, the
  cookie carries only an opaque (caller-supplied) session id.
- ``BackedSessionStore[B: SessionBackend]`` — the id is a CSPRNG token
  (``new_session_id``), the value lives in a pluggable ``SessionBackend``
  with a TTL, and ``destroy`` revokes it. ``MemorySessionBackend`` is the
  reference backend; a shared/Redis/SQL backend implements the same four
  methods (``get`` / ``set`` / ``delete`` / ``sweep``).

Sessions expire server-side by default: every store takes a ``ttl_s``
(default :data:`DEFAULT_SESSION_TTL_S`, one day; ``0`` opts out). The
cookie stores read the wall clock themselves and also offer ``encode_at`` /
``load_at`` / ``insert_at`` forms that take the time as an argument, the
way ``BackedSessionStore`` takes ``now_s``.

The two cookie stores share the ``SessionStore`` read trait
(``cookie_name`` + ``load``) so handler code can be generic over them.
Keys are rotated by passing ``previous_keys``; valid signatures under any
of the supplied keys are accepted (with the *current* key used to sign
new cookies).

Loading a session is done via ``store.load(req)`` (a
``BackedSessionStore`` adds ``now_s`` for TTL). It is deliberately not a
config-free ``Extractor``: an extractor only receives the ``Request`` and
cannot hold the runtime signing key / backend, so the store instance is
the injection point.

## Threat model

- The signing key is the trust anchor; rotate at the cadence your
  org demands. Library-level enforcement: ``Session.new`` rejects
  keys shorter than 16 bytes.
- HMAC-SHA256 verification is constant-time (``CRYPTO_memcmp``);
  no early-exit timing leak.
- Forged cookies (any byte tampered) raise on ``decode``; callers
  should treat the raise as "treat user as anonymous".
"""

from std.collections import Optional
from std.time import perf_counter_ns

from .request import Request
from .proto.utf8 import utf8_lossy_string
from ..runtime.date_cache import _realtime_seconds
from ..crypto import (
    base64url_decode,
    base64url_encode,
    hmac_sha256,
    hmac_sha256_verify,
)


# ── CSPRNG session id + monotonic clock ───────────────────────────────────


def new_session_id(n_bytes: Int = 32) raises -> String:
    """Return a fresh unguessable session id: ``n_bytes`` from the OS
    CSPRNG rendered as lowercase hex.

    32 bytes (256 bits) is the default -- well above the 128-bit floor
    for a session identifier that a signed cookie carries opaquely. The
    CSPRNG read is the trust anchor: a guessable id lets an attacker
    hijack a session, so this never falls back to a weak PRNG -- it
    raises if the entropy source is unavailable (which should not happen
    on Linux / macOS).
    """
    from flare.crypto.random import random_bytes

    var raw = random_bytes(n_bytes)
    var hex = String(capacity_bytes=n_bytes * 2 + 1)
    comptime digits = "0123456789abcdef"
    for i in range(n_bytes):
        var b = Int(raw[i])
        hex += digits[byte=(b >> 4) & 0xF]
        hex += digits[byte=b & 0xF]
    return hex^


def session_now_s() -> Int:
    """Monotonic seconds for TTL bookkeeping (relative expiry only)."""
    return Int(perf_counter_ns() // 1_000_000_000)


comptime DEFAULT_SESSION_TTL_S: Int = 86400
"""Default server-side lifetime of a session, in seconds (one day).

Every store in this module expires its sessions server-side after this
long unless told otherwise, so a stolen session cookie cannot be replayed
for as long as the signing key lives (``docs/threat-model.md``). Pass
``ttl_s=0`` to a store to opt out of expiry, or another value to change
the lifetime."""


def _wall_clock_s() -> Int:
    """Epoch seconds (``CLOCK_REALTIME``): the clock the cookie-borne
    expiry of :class:`CookieSessionStore` is compared with. It must be a
    wall clock, not :func:`session_now_s`: the cookie outlives the process
    that issued it."""
    return _realtime_seconds()


# ── SignedCookie: stateless payload carrier ───────────────────────────────


comptime MIN_SESSION_KEY_BYTES: Int = 16
"""Shortest HMAC key a session store or signed cookie will use, for
signing or for verifying. A shorter key -- above all an empty one, which
is what an unset environment variable produces -- makes every cookie
forgeable by anyone who knows the payload format."""


def _require_session_key(key: List[UInt8], who: String) raises:
    if len(key) < MIN_SESSION_KEY_BYTES:
        raise Error(
            who
            + ": signing key must be at least "
            + String(MIN_SESSION_KEY_BYTES)
            + " bytes, got "
            + String(len(key))
        )


def signed_cookie_encode(
    payload: List[UInt8], key: List[UInt8]
) raises -> String:
    """Encode ``payload`` into a ``"<b64>.<b64>"`` signed cookie value.

    ``key`` should be at least 16 bytes for security; the caller is
    responsible for ensuring that (``Session.new`` enforces it).

    Args:
        payload: Raw payload bytes.
        key: HMAC key.

    Returns:
        ``"<base64url(payload)>.<base64url(mac)>"`` cookie value.
    """
    var b64_payload = base64url_encode(payload)
    var b64_payload_bytes = List[UInt8](b64_payload.as_bytes())
    var mac = hmac_sha256(key, b64_payload_bytes)
    var b64_mac = base64url_encode(mac)
    return b64_payload + "." + b64_mac


def signed_cookie_decode(
    cookie: String, key: List[UInt8]
) raises -> List[UInt8]:
    """Decode + verify a signed cookie under one key.

    Returns the raw payload bytes if the MAC verifies. Raises ``Error``
    on any of: malformed shape, invalid base64, MAC mismatch.

    Args:
        cookie: Cookie value as produced by ``signed_cookie_encode``.
        key: HMAC key.

    Returns:
        Decoded payload bytes.

    Raises:
        Error: When the cookie is malformed or the MAC fails to
               verify under ``key``.
    """
    # Verifying under a short key is how the bypass worked: the stores
    # kept an empty key as an "invalid" marker, refused to *sign* with
    # it, and happily *verified* with it. HMAC under an empty key is
    # computable by anyone.
    if len(key) < MIN_SESSION_KEY_BYTES:
        raise Error("signed_cookie_decode: key shorter than 16 bytes")
    var dot = -1
    var src = cookie.unsafe_ptr()
    var n = cookie.byte_length()
    for i in range(n):
        if src[unsafe_offset=i] == 46:  # '.'
            dot = i
            break
    if dot < 0:
        raise Error("signed_cookie_decode: missing separator")
    var b64_payload = String(unsafe_from_utf8=cookie.as_bytes()[:dot])
    var b64_mac = String(unsafe_from_utf8=cookie.as_bytes()[dot + 1 :])
    var payload = base64url_decode(b64_payload)
    var mac = base64url_decode(b64_mac)
    var b64_payload_bytes = List[UInt8](b64_payload.as_bytes())
    var ok = hmac_sha256_verify(key, b64_payload_bytes, mac)
    if not ok:
        raise Error("signed_cookie_decode: MAC verification failed")
    return payload^


def signed_cookie_decode_keys(
    cookie: String, keys: List[List[UInt8]]
) raises -> List[UInt8]:
    """Decode a signed cookie under any of ``keys`` (key rotation).

    Tries each key in order; returns the payload as soon as one
    verifies. Raises if none do.

    Args:
        cookie: Cookie value.
        keys: Acceptable HMAC keys (current key first, previous
                keys after).

    Returns:
        Decoded payload bytes.

    Raises:
        Error: When no key successfully verifies the MAC.
    """
    if len(keys) == 0:
        raise Error("signed_cookie_decode_keys: no keys supplied")
    var last_err = String("signed_cookie_decode_keys: no key matched")
    for i in range(len(keys)):
        try:
            return signed_cookie_decode(cookie, keys[i])
        except e:
            last_err = String(e)
    raise Error(last_err)


# ── SessionCodec: payload <-> bytes ───────────────────────────────────────


trait SessionCodec(Copyable, Defaultable, Deinitable):
    """Encode / decode a typed payload to/from raw bytes.

    Implementations live alongside the user's payload type; the
    bundled ``StringSessionCodec`` carries opaque strings which is
    enough for the common "username + roles JSON blob" use case
    when paired with ``flare.json``.
    """

    @staticmethod
    def encode(payload: String) raises -> List[UInt8]:
        ...

    @staticmethod
    def decode(data: List[UInt8]) raises -> String:
        ...


@fieldwise_init
struct StringSessionCodec(Copyable, Defaultable, SessionCodec):
    """The default codec: payload is just a UTF-8 string.

    Pair with ``flare.json``-encoded text payloads (or any other
    string serialisation) when richer types are needed without
    writing a new codec.
    """

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    @staticmethod
    def encode(payload: String) raises -> List[UInt8]:
        return List[UInt8](payload.as_bytes())

    @staticmethod
    def decode(data: List[UInt8]) raises -> String:
        if len(data) == 0:
            return ""
        return utf8_lossy_string(Span[UInt8, _](data))


# ── Session[T] + SessionStore ─────────────────────────────────────────────


trait SessionStore(Copyable):
    """The read surface every cookie-backed session store shares.

    Lets handler code stay generic over the storage strategy
    (:class:`CookieSessionStore` stateless, :class:`InMemorySessionStore`
    server-side). Both never raise on load -- a missing / forged cookie
    yields :meth:`Session.empty` so the handler treats the caller as
    anonymous. The richer TTL / CSPRNG / destroy surface lives on
    :class:`BackedSessionStore` (which layers a pluggable
    :trait:`SessionBackend`).
    """

    def cookie_name(self) -> String:
        ...

    def load(self, req: Request) -> Session:
        ...


struct Session(Copyable, Defaultable):
    """A typed session payload, carried in either a signed cookie
    or an in-memory store.

    Construction: ``Session.empty()`` / ``Session(value)``.

    Field ``value`` is a ``String`` to keep the public surface
    simple; pair with ``flare.json`` if you need to roundtrip a
    structured payload (encode JSON in the handler, decode on the
    way out).
    """

    var value: String
    """Opaque session value (typically a JSON blob)."""

    var present: Bool
    """``True`` if the session was loaded from a valid cookie / store
    entry; ``False`` for anonymous requests."""

    def __init__(out self):
        self.value = ""
        self.present = False

    def __init__(out self, value: String):
        self.value = value
        self.present = True

    @staticmethod
    def empty() -> Session:
        var s = Session()
        s.value = ""
        s.present = False
        return s^


# ── CookieSessionStore: encode payload directly into a signed cookie ──────


struct CookieSessionStore(Copyable, SessionStore):
    """Stateless store: the entire session is encoded into the
    signed cookie. Suitable for small payloads (< 4 KiB).

    Stores no server-side state; payload size is bounded by the
    cookie size limit (RFC 6265 paragraph 6.1 recommends >= 4096
    bytes per cookie).

    The signed payload is ``"<expiry>|<value>"``, where ``<expiry>`` is
    the absolute epoch second after which :meth:`load` refuses the cookie
    (``0`` = never; only with ``ttl_s <= 0``). The expiry is covered by
    the MAC, so a client cannot extend it, and a validly signed payload
    without one -- such as a cookie issued before expiry existed -- is
    refused: its holder is treated as anonymous and signs in again.
    """

    var _key: List[UInt8]
    var _previous_keys: List[List[UInt8]]
    var _cookie_name: String
    var _ttl_s: Int

    def __init__(
        out self,
        key: List[UInt8],
        cookie_name: String = "flare_session",
        ttl_s: Int = DEFAULT_SESSION_TTL_S,
    ) raises:
        """Sign and verify with ``key``.

        Args:
            key: HMAC key, at least ``MIN_SESSION_KEY_BYTES`` bytes.
            cookie_name: Name of the session cookie.
            ttl_s: Lifetime of a cookie in seconds, counted from
                :meth:`encode`. ``0`` (or negative) issues cookies that
                never expire.

        Raises:
            Error: If ``key`` is shorter than ``MIN_SESSION_KEY_BYTES``.
                There is no default constructor: a store without a real
                key cannot be made.
        """
        _require_session_key(key, "CookieSessionStore")
        self._key = key.copy()
        self._previous_keys = List[List[UInt8]]()
        self._cookie_name = cookie_name
        self._ttl_s = ttl_s

    def add_previous_key(mut self, key: List[UInt8]) raises:
        """Accept ``key`` as a valid signing key for inbound cookies.

        Used during key rotation: set ``self._key`` to the new key,
        keep the old key here so existing browsers' cookies still
        verify until their natural expiry.

        Raises:
            Error: If ``key`` is shorter than ``MIN_SESSION_KEY_BYTES``.
        """
        _require_session_key(key, "CookieSessionStore.add_previous_key")
        self._previous_keys.append(key.copy())

    def cookie_name(self) -> String:
        return self._cookie_name

    def load(self, req: Request) -> Session:
        """Look up the session cookie on ``req`` and return a Session.

        Returns ``Session.empty()`` for any failure mode (cookie
        missing, malformed, MAC fails, expired, no expiry). Never
        raises -- handlers can treat the result as authoritative.
        """
        return self.load_at(req, _wall_clock_s())

    def load_at(self, req: Request, now_s: Int) -> Session:
        """:meth:`load` with the current epoch second given by the caller.

        A cookie whose expiry is ``<= now_s`` is refused.
        """
        var cookie_value = req.cookie(self._cookie_name)
        if cookie_value.byte_length() == 0:
            return Session.empty()
        var keys = List[List[UInt8]]()
        keys.append(self._key.copy())
        for k in self._previous_keys:
            keys.append(k.copy())
        try:
            var payload = signed_cookie_decode_keys(cookie_value, keys)
            # "<expiry>|<value>": digits up to the first '|'.
            var bar = -1
            var exp = 0
            for i in range(len(payload)):
                var c = Int(payload[i])
                if c == 124:  # '|'
                    bar = i
                    break
                if c < 48 or c > 57 or i >= 18:
                    return Session.empty()
                exp = exp * 10 + (c - 48)
            if bar < 1:
                return Session.empty()
            if exp != 0 and now_s >= exp:
                return Session.empty()
            var out = utf8_lossy_string(Span[UInt8, _](payload)[bar + 1 :])
            return Session(out^)
        except:
            return Session.empty()

    def encode(self, value: String) raises -> String:
        """Return a signed-cookie value carrying ``value`` as payload,
        expiring ``ttl_s`` seconds from now."""
        return self.encode_at(value, _wall_clock_s())

    def encode_at(self, value: String, now_s: Int) raises -> String:
        """:meth:`encode` with the current epoch second given by the caller."""
        if len(self._key) < 16:
            raise Error("CookieSessionStore: signing key shorter than 16 bytes")
        var exp = 0 if self._ttl_s <= 0 else now_s + self._ttl_s
        var payload = String(exp) + "|" + value
        return signed_cookie_encode(List[UInt8](payload.as_bytes()), self._key)


# ── InMemorySessionStore: signed cookie carries an opaque id ──────────────


struct InMemorySessionStore(Copyable, SessionStore):
    """Server-side session table keyed by signed session id.

    Entries expire ``ttl_s`` seconds after they are inserted (default
    :data:`DEFAULT_SESSION_TTL_S`; ``0`` = never). :meth:`load` refuses an
    expired entry and :meth:`sweep` evicts them.

    Concurrency note: the implementation is single-worker; for
    multi-worker mode the store is per-worker (each worker keeps
    its own table). A shared backend (Redis, DB) is a follow-up
    behind the same trait.
    """

    var _key: List[UInt8]
    var _previous_keys: List[List[UInt8]]
    var _cookie_name: String
    var _ids: List[String]
    var _values: List[String]
    var _expiry: List[Int]
    var _ttl_s: Int

    def __init__(
        out self,
        key: List[UInt8],
        cookie_name: String = "flare_session",
        ttl_s: Int = DEFAULT_SESSION_TTL_S,
    ) raises:
        """Sign and verify session ids with ``key``.

        Args:
            key: HMAC key, at least ``MIN_SESSION_KEY_BYTES`` bytes.
            cookie_name: Name of the session cookie.
            ttl_s: Lifetime of an entry in seconds, counted from
                :meth:`insert`. ``0`` (or negative) = never expires.

        Raises:
            Error: If ``key`` is shorter than ``MIN_SESSION_KEY_BYTES``.
        """
        _require_session_key(key, "InMemorySessionStore")
        self._key = key.copy()
        self._previous_keys = List[List[UInt8]]()
        self._cookie_name = cookie_name
        self._ids = List[String]()
        self._values = List[String]()
        self._expiry = List[Int]()
        self._ttl_s = ttl_s

    def cookie_name(self) -> String:
        return self._cookie_name

    def insert(mut self, id: String, value: String):
        """Replace any existing entry for ``id`` with ``value``; it
        expires ``ttl_s`` seconds from now."""
        self.insert_at(id, value, _wall_clock_s())

    def insert_at(mut self, id: String, value: String, now_s: Int):
        """:meth:`insert` with the current epoch second given by the
        caller. Replacing an entry restarts its lifetime."""
        var exp = 0 if self._ttl_s <= 0 else now_s + self._ttl_s
        for i in range(len(self._ids)):
            if self._ids[i] == id:
                self._values[i] = value
                self._expiry[i] = exp
                return
        self._ids.append(id)
        self._values.append(value)
        self._expiry.append(exp)

    def remove(mut self, id: String) -> Bool:
        """Drop the entry for ``id``. Returns ``True`` if present."""
        for i in range(len(self._ids)):
            if self._ids[i] == id:
                _ = self._ids.pop(i)
                _ = self._values.pop(i)
                _ = self._expiry.pop(i)
                return True
        return False

    def sweep(mut self, now_s: Int) -> Int:
        """Evict every entry expired at ``now_s``; return the count."""
        var removed = 0
        var i = 0
        while i < len(self._ids):
            if self._expiry[i] != 0 and now_s >= self._expiry[i]:
                _ = self._ids.pop(i)
                _ = self._values.pop(i)
                _ = self._expiry.pop(i)
                removed += 1
            else:
                i += 1
        return removed

    def encode_id(self, id: String) raises -> String:
        """Wrap ``id`` in a signed cookie value."""
        if len(self._key) < 16:
            raise Error(
                "InMemorySessionStore: signing key shorter than 16 bytes"
            )
        return signed_cookie_encode(List[UInt8](id.as_bytes()), self._key)

    def load(self, req: Request) -> Session:
        """Look up the session for ``req``; empty if the cookie is
        missing, forged, unknown or expired."""
        return self.load_at(req, _wall_clock_s())

    def load_at(self, req: Request, now_s: Int) -> Session:
        """:meth:`load` with the current epoch second given by the caller."""
        var cookie_value = req.cookie(self._cookie_name)
        if cookie_value.byte_length() == 0:
            return Session.empty()
        var keys = List[List[UInt8]]()
        keys.append(self._key.copy())
        for k in self._previous_keys:
            keys.append(k.copy())
        try:
            var payload = signed_cookie_decode_keys(cookie_value, keys)
            var id_str = utf8_lossy_string(Span[UInt8, _](payload))
            for i in range(len(self._ids)):
                if self._ids[i] == id_str:
                    if self._expiry[i] != 0 and now_s >= self._expiry[i]:
                        return Session.empty()
                    return Session(self._values[i])
            return Session.empty()
        except:
            return Session.empty()

    def __len__(self) -> Int:
        return len(self._ids)


# ── SessionBackend: pluggable server-side storage with TTL ────────────────


trait SessionBackend(Copyable, Deinitable):
    """Storage abstraction behind :class:`BackedSessionStore`.

    A backend maps an opaque session id to its value with a TTL. The
    reference :class:`MemorySessionBackend` is a per-process table; a
    shared backend (Redis / SQL / a cross-worker shared-memory map)
    implements the same four methods to survive restarts or fan out
    across workers. Time is caller-supplied (``now_s``) so the surface
    stays clock-free + deterministically testable.
    """

    def get(mut self, id: String, now_s: Int) raises -> Optional[String]:
        """Return the live value for ``id`` (``None`` if absent/expired).
        Expired entries are lazily dropped."""
        ...

    def set(mut self, id: String, value: String, now_s: Int, ttl_s: Int) raises:
        """Upsert ``id`` -> ``value``, expiring at ``now_s + ttl_s``
        (``ttl_s <= 0`` = never expires)."""
        ...

    def delete(mut self, id: String) raises -> Bool:
        """Drop ``id``; return ``True`` if it was present."""
        ...

    def sweep(mut self, now_s: Int) raises -> Int:
        """Evict all entries expired at ``now_s``; return the count."""
        ...


struct MemorySessionBackend(Copyable, Defaultable, SessionBackend):
    """Reference in-process :trait:`SessionBackend` with TTL expiry.

    ponytail: linear-scan parallel lists (id / value / expiry). Fine for
    the moderate per-worker session counts this backs; a shared/large
    deployment swaps in a hashed or external backend behind the same
    trait. Not thread-safe -- one instance per worker (the multi-worker
    server copies the store per worker).
    """

    var _ids: List[String]
    var _values: List[String]
    var _expiry: List[Int]

    def __init__(out self):
        self._ids = List[String]()
        self._values = List[String]()
        self._expiry = List[Int]()

    def get(mut self, id: String, now_s: Int) raises -> Optional[String]:
        for i in range(len(self._ids)):
            if self._ids[i] == id:
                if self._expiry[i] != 0 and now_s >= self._expiry[i]:
                    _ = self._ids.pop(i)
                    _ = self._values.pop(i)
                    _ = self._expiry.pop(i)
                    return Optional[String]()
                return Optional[String](self._values[i])
        return Optional[String]()

    def set(mut self, id: String, value: String, now_s: Int, ttl_s: Int) raises:
        var exp = 0 if ttl_s <= 0 else now_s + ttl_s
        for i in range(len(self._ids)):
            if self._ids[i] == id:
                self._values[i] = value
                self._expiry[i] = exp
                return
        self._ids.append(id)
        self._values.append(value)
        self._expiry.append(exp)

    def delete(mut self, id: String) raises -> Bool:
        for i in range(len(self._ids)):
            if self._ids[i] == id:
                _ = self._ids.pop(i)
                _ = self._values.pop(i)
                _ = self._expiry.pop(i)
                return True
        return False

    def sweep(mut self, now_s: Int) raises -> Int:
        var removed = 0
        var i = 0
        while i < len(self._ids):
            if self._expiry[i] != 0 and now_s >= self._expiry[i]:
                _ = self._ids.pop(i)
                _ = self._values.pop(i)
                _ = self._expiry.pop(i)
                removed += 1
            else:
                i += 1
        return removed

    def __len__(self) -> Int:
        return len(self._ids)


# ── BackedSessionStore: signed-id cookie + pluggable backend + TTL ────────


struct BackedSessionStore[B: SessionBackend](Copyable):
    """Server-side session store over a pluggable :trait:`SessionBackend`.

    The cookie carries only a CSPRNG session id (signed, so a client
    cannot forge one); the value lives in the backend with a TTL. This
    is the store to reach for when sessions must expire, be revocable
    (:meth:`destroy`), or share a backend across workers.

    Its load / save / destroy surface is ``mut self`` + ``raises`` +
    ``now_s`` (the backend mutates on lazy expiry and needs the clock),
    so -- unlike the two cookie stores -- it deliberately does not
    implement the minimal :trait:`SessionStore` read trait.
    """

    var _backend: Self.B
    var _key: List[UInt8]
    var _cookie_name: String
    var _ttl_s: Int

    def __init__(
        out self,
        var backend: Self.B,
        key: List[UInt8],
        cookie_name: String = "flare_session",
        ttl_s: Int = DEFAULT_SESSION_TTL_S,
    ) raises:
        """Sign session ids with ``key`` and keep values in ``backend``.

        Args:
            backend: The storage backend (ownership transferred).
            key: HMAC key, at least ``MIN_SESSION_KEY_BYTES`` bytes.
            cookie_name: Name of the session cookie.
            ttl_s: Lifetime of a saved session in seconds (default
                :data:`DEFAULT_SESSION_TTL_S`). ``0`` (or negative) saves
                sessions that never expire.

        Raises:
            Error: If ``key`` is shorter than ``MIN_SESSION_KEY_BYTES``.
        """
        _require_session_key(key, "BackedSessionStore")
        self._backend = backend^
        self._key = key.copy()
        self._cookie_name = cookie_name
        self._ttl_s = ttl_s

    def cookie_name(self) -> String:
        return self._cookie_name

    def _cookie_id(self, req: Request) -> Optional[String]:
        var cv = req.cookie(self._cookie_name)
        if cv.byte_length() == 0:
            return Optional[String]()
        try:
            var payload = signed_cookie_decode(cv, self._key)
            var id = utf8_lossy_string(Span[UInt8, _](payload))
            return Optional[String](id^)
        except:
            return Optional[String]()

    def load(mut self, req: Request, now_s: Int) raises -> Session:
        """Load the session for ``req`` (empty if no valid cookie / the
        backend entry is gone or expired)."""
        var idopt = self._cookie_id(req)
        if not idopt:
            return Session.empty()
        var v = self._backend.get(idopt.value(), now_s)
        if v:
            return Session(v.value())
        return Session.empty()

    def save(mut self, value: String, now_s: Int) raises -> String:
        """Store ``value`` under a fresh CSPRNG id and return the signed
        session-cookie value to set on the response."""
        if len(self._key) < 16:
            raise Error("BackedSessionStore: signing key shorter than 16 bytes")
        var id = new_session_id()
        self._backend.set(id, value, now_s, self._ttl_s)
        return signed_cookie_encode(List[UInt8](id.as_bytes()), self._key)

    def destroy(mut self, req: Request) raises -> Bool:
        """Revoke the session referenced by ``req``'s cookie; return
        ``True`` if a backend entry was removed."""
        var idopt = self._cookie_id(req)
        if not idopt:
            return False
        return self._backend.delete(idopt.value())

    def sweep(mut self, now_s: Int) raises -> Int:
        """Evict expired backend entries; return the count."""
        return self._backend.sweep(now_s)
