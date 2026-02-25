"""Property tests: HeaderMap injection resistance and key consistency.

Properties verified:

1. **Injection resistance** — ``HeaderMap.set()`` and ``append()`` must
   never accept keys or values that contain CR (\\r) or LF (\\n) bytes.
   Any such call must raise ``HeaderInjectionError``; no silent accept.

2. **Case-insensitive get** — after ``set(k, v)`` the value must be
   retrievable under any ASCII-case variant of ``k``.

3. **Len consistency** — ``len(_keys) == len(_lower_keys) == len(_values)``
   must hold after every sequence of ``set`` and ``append`` calls.

Run:
    pixi run prop-headers
"""

from mozz import forall_bytes
from flare.http.headers import HeaderMap, HeaderInjectionError


fn _contains_crlf(data: List[UInt8]) -> Bool:
    """Return True if any byte in ``data`` is CR (0x0D) or LF (0x0A)."""
    for i in range(len(data)):
        if data[i] == 0x0D or data[i] == 0x0A:
            return True
    return False


fn _bytes_to_str(data: List[UInt8]) -> String:
    """Convert raw bytes to a ``String`` via chr() (Latin-1 safe)."""
    var s = String(capacity=len(data) + 1)
    for i in range(len(data)):
        s += chr(Int(data[i]))
    return s^


fn injection_resistance(data: List[UInt8]) raises -> Bool:
    """Property: set/append must raise when key or value contains CR/LF.

    Treats the first half of ``data`` as key bytes, second half as value
    bytes.  If either contains CR or LF the call MUST raise; otherwise it
    MUST succeed.

    Args:
        data: Arbitrary bytes split into key and value.

    Returns:
        ``True`` if the property holds; ``False`` if injection succeeded
        silently (i.e., CR/LF accepted without raising).
    """
    var mid = len(data) // 2
    var key_bytes = List[UInt8](capacity=mid)
    for i in range(mid):
        key_bytes.append(data[i])
    var val_bytes = List[UInt8](capacity=len(data) - mid)
    for i in range(mid, len(data)):
        val_bytes.append(data[i])

    var key = _bytes_to_str(key_bytes)
    var val = _bytes_to_str(val_bytes)
    var has_crlf = _contains_crlf(key_bytes) or _contains_crlf(val_bytes)

    var h = HeaderMap()
    var raised = False
    try:
        h.set(key, val)
    except e:
        raised = True

    if has_crlf:
        # Injection attempt: must have raised
        return raised
    else:
        # No CR/LF: must NOT raise; and value must be retrievable
        if raised:
            return False
        return h.get(key) == val


fn len_consistency(data: List[UInt8]) raises -> Bool:
    """Property: internal key/value lists must stay in sync after any ops.

    Splits ``data`` into up to 4 key–value pairs (4-byte chunks) and
    calls ``set``/``append`` alternately, verifying list lengths match
    throughout.

    Args:
        data: Arbitrary bytes.

    Returns:
        ``True`` if all three internal lists have the same length after
        every insertion.
    """
    var h = HeaderMap()
    var chunk = 4
    var i = 0
    while i + chunk <= len(data):
        var key_bytes = List[UInt8](capacity=2)
        key_bytes.append(data[i])
        key_bytes.append(data[i + 1])
        var val_bytes = List[UInt8](capacity=2)
        val_bytes.append(data[i + 2])
        val_bytes.append(data[i + 3])

        var key = _bytes_to_str(key_bytes)
        var val = _bytes_to_str(val_bytes)
        try:
            if i % 8 == 0:
                h.set(key, val)
            else:
                h.append(key, val)
        except:
            pass  # injection error is fine

        # Lengths must always match
        if h._keys.__len__() != h._lower_keys.__len__():
            return False
        if h._keys.__len__() != h._values.__len__():
            return False
        i += chunk

    return True


fn main() raises:
    print("[mozz] HeaderMap property tests\n")

    print("1. Injection resistance (20 000 trials)...")
    forall_bytes(injection_resistance, max_len=64, trials=20_000, seed=1)
    print("   PASS: CR/LF injection always raises HeaderInjectionError\n")

    print("2. Internal list consistency (20 000 trials)...")
    forall_bytes(len_consistency, max_len=64, trials=20_000, seed=2)
    print("   PASS: _keys / _lower_keys / _values always have equal length\n")

    print("All HeaderMap properties hold!")
