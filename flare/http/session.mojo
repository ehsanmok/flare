"""Signed cookies + typed sessions.

The ``SignedCookie`` primitive encodes a payload as
``base64url(payload) + "." + base64url(hmac_sha256(key, base64url(payload)))``
— the same shape JSON Web Signature uses, so the format is
familiar to anyone who has read RFC 7515. The MAC is computed
over the *base64url-encoded payload* (not the raw bytes) so the
verifier can split on ``.`` without first decoding.

``Session[T]`` wraps an arbitrary ``Copyable & Movable`` payload
and (de)serialises it through a user-supplied ``SessionCodec[T]``.
``SessionStore`` is the abstraction over storage; flare ships:

- ``CookieSessionStore[T]`` — payload travels in the signed cookie
  itself (stateless).
- ``InMemorySessionStore[T]`` — payload kept server-side, the
  cookie carries only an opaque session id.

Both stores integrate with the typed ``Handler`` surface via the
``Session[T, Codec]`` extractor. Keys are rotated by passing
``previous_keys`` to ``decode``; valid signatures under any of the
supplied keys are accepted (with the *current* key used to sign new
cookies).

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

from .request import Request
from ..crypto import (
    base64url_decode,
    base64url_encode,
    hmac_sha256,
    hmac_sha256_verify,
)


# ── SignedCookie: stateless payload carrier ───────────────────────────────


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
    var dot = -1
    var src = cookie.unsafe_ptr()
    var n = cookie.byte_length()
    for i in range(n):
        if src[i] == 46:  # '.'
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


trait SessionCodec(Copyable, Defaultable, ImplicitlyDestructible, Movable):
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
struct StringSessionCodec(Copyable, Defaultable, Movable, SessionCodec):
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
        var out = String(capacity=len(data) + 1)
        for b in data:
            out += chr(Int(b))
        return out^


# ── Session[T] + SessionStore ─────────────────────────────────────────────


struct Session(Copyable, Defaultable, Movable):
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


struct CookieSessionStore(Copyable, Defaultable, Movable):
    """Stateless store: the entire session is encoded into the
    signed cookie. Suitable for small payloads (< 4 KiB).

    Stores no server-side state; payload size is bounded by the
    cookie size limit (RFC 6265 paragraph 6.1 recommends >= 4096
    bytes per cookie).
    """

    var _key: List[UInt8]
    var _previous_keys: List[List[UInt8]]
    var _cookie_name: String

    def __init__(out self):
        self._key = List[UInt8]()
        self._previous_keys = List[List[UInt8]]()
        self._cookie_name = "flare_session"

    def __init__(
        out self, key: List[UInt8], cookie_name: String = "flare_session"
    ):
        if len(key) < 16:
            self._key = List[UInt8]()  # marker for invalid
        else:
            self._key = key.copy()
        self._previous_keys = List[List[UInt8]]()
        self._cookie_name = cookie_name

    def add_previous_key(mut self, key: List[UInt8]):
        """Accept ``key`` as a valid signing key for inbound cookies.

        Used during key rotation: set ``self._key`` to the new key,
        keep the old key here so existing browsers' cookies still
        verify until their natural expiry.
        """
        self._previous_keys.append(key.copy())

    def cookie_name(self) -> String:
        return self._cookie_name

    def load(self, req: Request) -> Session:
        """Look up the session cookie on ``req`` and return a Session.

        Returns ``Session.empty()`` for any failure mode (cookie
        missing, malformed, MAC fails). Never raises — handlers can
        treat the result as authoritative.
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
            var out = String(capacity=len(payload) + 1)
            for b in payload:
                out += chr(Int(b))
            return Session(out^)
        except:
            return Session.empty()

    def encode(self, value: String) raises -> String:
        """Return a signed-cookie value carrying ``value`` as payload."""
        if len(self._key) < 16:
            raise Error("CookieSessionStore: signing key shorter than 16 bytes")
        return signed_cookie_encode(List[UInt8](value.as_bytes()), self._key)


# ── InMemorySessionStore: signed cookie carries an opaque id ──────────────


struct InMemorySessionStore(Copyable, Defaultable, Movable):
    """Server-side session table keyed by signed session id.

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

    def __init__(out self):
        self._key = List[UInt8]()
        self._previous_keys = List[List[UInt8]]()
        self._cookie_name = "flare_session"
        self._ids = List[String]()
        self._values = List[String]()

    def __init__(
        out self, key: List[UInt8], cookie_name: String = "flare_session"
    ):
        if len(key) < 16:
            self._key = List[UInt8]()
        else:
            self._key = key.copy()
        self._previous_keys = List[List[UInt8]]()
        self._cookie_name = cookie_name
        self._ids = List[String]()
        self._values = List[String]()

    def cookie_name(self) -> String:
        return self._cookie_name

    def insert(mut self, id: String, value: String):
        """Replace any existing entry for ``id`` with ``value``."""
        for i in range(len(self._ids)):
            if self._ids[i] == id:
                self._values[i] = value
                return
        self._ids.append(id)
        self._values.append(value)

    def remove(mut self, id: String) -> Bool:
        """Drop the entry for ``id``. Returns ``True`` if present."""
        for i in range(len(self._ids)):
            if self._ids[i] == id:
                _ = self._ids.pop(i)
                _ = self._values.pop(i)
                return True
        return False

    def encode_id(self, id: String) raises -> String:
        """Wrap ``id`` in a signed cookie value."""
        if len(self._key) < 16:
            raise Error(
                "InMemorySessionStore: signing key shorter than 16 bytes"
            )
        return signed_cookie_encode(List[UInt8](id.as_bytes()), self._key)

    def load(self, req: Request) -> Session:
        var cookie_value = req.cookie(self._cookie_name)
        if cookie_value.byte_length() == 0:
            return Session.empty()
        var keys = List[List[UInt8]]()
        keys.append(self._key.copy())
        for k in self._previous_keys:
            keys.append(k.copy())
        try:
            var payload = signed_cookie_decode_keys(cookie_value, keys)
            var id_str = String(capacity=len(payload) + 1)
            for b in payload:
                id_str += chr(Int(b))
            for i in range(len(self._ids)):
                if self._ids[i] == id_str:
                    return Session(self._values[i])
            return Session.empty()
        except:
            return Session.empty()

    def __len__(self) -> Int:
        return len(self._ids)
