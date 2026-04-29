"""flare.crypto — minimal cryptographic primitives over the OpenSSL FFI.

flare relies on OpenSSL 3.x for TLS already (see ``flare.tls``); the
same shared object (``libflare_tls.so``) hosts the few non-TLS
primitives flare's HTTP layer needs — primarily the HMAC-SHA256
construction that drives signed cookies and typed sessions
(``flare.http.session``).

The C-side wrappers (``flare/tls/ffi/openssl_wrapper.cpp``) call
into ``EVP_*`` / ``HMAC_*`` and use ``CRYPTO_memcmp`` for verification
so timing leaks don't reveal which byte of a forged tag differs.

## Public API

```mojo
from flare.crypto import (
    hmac_sha256, hmac_sha256_verify,
    base64url_encode, base64url_decode,
)
```

- ``hmac_sha256(key, msg) -> List[UInt8]`` — 32-byte HMAC-SHA256
  digest of ``msg`` under ``key``. Empty key/msg are valid (RFC 4231).
- ``hmac_sha256_verify(key, msg, mac) -> Bool`` — constant-time
  comparison; ``False`` for any mismatch (length included).
- ``base64url_encode`` / ``base64url_decode`` — URL-safe base64
  with no padding (``-`` / ``_`` for ``+`` / ``/``). Used by
  ``SignedCookie`` to keep cookies cookie-safe.

## Threat model

flare's signed cookie / session APIs assume the secret key is a
high-entropy random byte string (>= 32 bytes). Rotating keys is
supported by passing a list to ``SignedCookie.decode`` (see
``flare.http.session``). HMAC-SHA256 is forgery-resistant under
the standard PRF assumption; key length below 16 bytes is
rejected by ``Session`` (see ``flare.http.session``).
"""

from .hmac import (
    hmac_sha256,
    hmac_sha256_verify,
    base64url_encode,
    base64url_decode,
)
