"""``flare.quic.timers`` -- per-connection timer kinds + token encoding
for the QUIC reactor.

The reactor reuses the shared :class:`flare.runtime.timer_wheel.TimerWheel`
for every timeout it needs to track. The wheel's per-entry payload is a
single ``UInt64`` token, which means each in-flight QUIC timeout needs a
self-describing encoding that:

1. tells the reactor *which kind* of timeout fired (PTO vs idle vs
   ack-delay) so the right :class:`flare.quic.server.QuicConnection`
   callback runs, and
2. tells it *which connection slot* the timeout belongs to so the
   right :class:`QuicConnection` in the listener slab gets the call.

`encode_timer_token(kind, slot)` packs the two values into the high +
low halves of the ``UInt64`` token:

    | 63                    32 | 31                       0 |
    |  KIND (UInt32)           |  SLOT (UInt32)             |

`decode_timer_token(token) -> (kind, slot)` is the inverse. The split
keeps both fields wide enough for any reasonable QUIC server (4
billion concurrent connections, 4 billion timer kinds) while letting
the reactor dispatch with a single arithmetic comparison on the
high-half kind.

Three kinds ship here; the comments name the RFC sections
the reactor dispatch wires each one against:

- :data:`TIMER_KIND_PTO`        -- RFC 9002 §6.2 PTO probe timer.
- :data:`TIMER_KIND_IDLE`       -- RFC 9000 §10.1 idle timeout.
- :data:`TIMER_KIND_ACK_DELAY`  -- RFC 9000 §13.2 deferred-ACK timer.

Additional kinds (key-update, path-validation challenge, etc.) plug
into the same encoding; the dispatcher checks ``kind`` against the
known constants and falls back to a debug log for unknown kinds.
"""


# -- Timer-kind codepoints --------------------------------------------


comptime TIMER_KIND_PTO: Int = 1
"""RFC 9002 §6.2 PTO (Probe Timeout) timer.

Fires when the sender hasn't received an ACK for the longest-RTT-
worth of time after an ack-eliciting packet was sent. On expiry the
connection emits one or two PING/PADDING packets (a "PTO probe") so
the peer is forced to send an ACK that recovers the lost packet
numbers."""

comptime TIMER_KIND_IDLE: Int = 2
"""RFC 9000 §10.1 idle timeout. Fires after ``max_idle_timeout`` of
no activity in either direction; on expiry the connection silently
transitions to ``CLOSED`` per RFC 9000 §10.1.2."""

comptime TIMER_KIND_ACK_DELAY: Int = 3
"""RFC 9000 §13.2.1 deferred-ACK timer. Fires when the receiver has
queued an ACK but is waiting up to ``max_ack_delay`` to coalesce it
with other frames. On expiry the receiver emits the queued ACK as
its own packet."""


comptime _TIMER_KIND_MIN: Int = 1
"""Smallest valid kind code (PTO). Used by
:func:`decode_timer_token` to flag malformed tokens."""

comptime _TIMER_KIND_MAX: Int = 3
"""Largest valid kind code (ACK_DELAY). Update when adding new
kinds + extending the dispatcher."""


comptime _TIMER_SLOT_MASK: UInt64 = 0xFFFFFFFF
"""Low 32 bits of the token carry the slot index."""

comptime _TIMER_KIND_SHIFT: UInt64 = 32
"""High 32 bits of the token carry the kind. The bit-shift constant
sits next to the mask so both stay in sync if the layout ever
widens."""


# -- Token encode / decode --------------------------------------------


def encode_timer_token(kind: Int, slot: Int) raises -> UInt64:
    """Pack ``(kind, slot)`` into a single :class:`UInt64` token.

    Both fields must fit in their 32-bit halves; the function
    raises on out-of-range inputs so a misuse fails loudly rather
    than silently aliasing a different timer kind on dispatch.
    """
    if kind < _TIMER_KIND_MIN or kind > _TIMER_KIND_MAX:
        raise Error(
            "encode_timer_token: kind " + String(kind) + " out of range"
        )
    if slot < 0:
        raise Error("encode_timer_token: negative slot " + String(slot))
    if UInt64(slot) > _TIMER_SLOT_MASK:
        raise Error(
            "encode_timer_token: slot " + String(slot) + " exceeds 2**32 - 1"
        )
    return (UInt64(kind) << _TIMER_KIND_SHIFT) | UInt64(slot)


@fieldwise_init
struct DecodedTimerToken(Copyable, Movable):
    """``(kind, slot)`` pair returned by :func:`decode_timer_token`.

    Kept as a named struct so callers can destructure cleanly and
    the dispatcher's intent is obvious at the call site -- ``token.kind``
    instead of ``token[0]``.
    """

    var kind: Int
    var slot: Int


def decode_timer_token(token: UInt64) raises -> DecodedTimerToken:
    """Unpack the high-half kind + low-half slot.

    Raises if ``kind`` is outside the registered range so the
    dispatcher catches a stale wheel entry from a removed kind
    instead of silently misdispatching.
    """
    var kind = Int(token >> _TIMER_KIND_SHIFT)
    var slot = Int(token & _TIMER_SLOT_MASK)
    if kind < _TIMER_KIND_MIN or kind > _TIMER_KIND_MAX:
        raise Error("decode_timer_token: unknown kind " + String(kind))
    return DecodedTimerToken(kind=kind, slot=slot)


def timer_kind_name(kind: Int) -> String:
    """Human-readable name for log + assertion messages. Returns
    ``"UNKNOWN"`` for unregistered kinds so the dispatcher's
    debug paths don't fail."""
    if kind == TIMER_KIND_PTO:
        return String("PTO")
    if kind == TIMER_KIND_IDLE:
        return String("IDLE")
    if kind == TIMER_KIND_ACK_DELAY:
        return String("ACK_DELAY")
    return String("UNKNOWN")
