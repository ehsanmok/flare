"""Event primitives for the flare reactor.

Every fd registered with the reactor is associated with a user-supplied
``UInt64`` token. When the fd becomes readable/writable/etc., the reactor
reports back an ``Event`` carrying that token and a bitmask of readiness
flags.

Interest bits (what the caller wants):
    ``INTEREST_READ``, ``INTEREST_WRITE``, or both (``INTEREST_READ |
    INTEREST_WRITE``).

Event bits (what the reactor returns):
    ``EVENT_READABLE``, ``EVENT_WRITABLE``, ``EVENT_ERROR``, ``EVENT_HUP``.
    These may be ORed together when multiple conditions are satisfied
    simultaneously (e.g. a half-closed socket reports both READABLE and
    HUP).
"""


# ── Interest flags (caller -> reactor) ────────────────────────────────────────
comptime INTEREST_READ: Int = 1
comptime INTEREST_WRITE: Int = 2


# ── Event flags (reactor -> caller) ──────────────────────────────────────────
comptime EVENT_READABLE: Int = 1
comptime EVENT_WRITABLE: Int = 2
comptime EVENT_ERROR: Int = 4
comptime EVENT_HUP: Int = 8


# Sentinel token used for the reactor's internal wakeup fd.
# Caller tokens MUST NOT collide with this value. Any UInt64 < UInt64.MAX is
# safe for user code.
comptime WAKEUP_TOKEN: UInt64 = 0xFFFF_FFFF_FFFF_FFFF


struct Event(Copyable, ImplicitlyCopyable, Movable):
    """A readiness event for a single registered fd.

    Fields:
        token: The caller's per-fd token passed to ``register`` / ``modify``.
               ``WAKEUP_TOKEN`` (all 1s) is reserved for internal wakeup
               events and should be filtered out by the reactor layer.
        flags: Bitmask of ``EVENT_READABLE | WRITABLE | ERROR | HUP``.
    """

    var token: UInt64
    var flags: Int

    def __init__(out self, token: UInt64, flags: Int):
        """Construct an event with the given token and flags.

        Args:
            token: Per-fd token assigned at registration time.
            flags: Bitmask of ``EVENT_*`` bits describing which conditions
                the reactor observed on the fd.
        """
        self.token = token
        self.flags = flags

    @always_inline
    def is_readable(self) -> Bool:
        """Return True if ``EVENT_READABLE`` is set."""
        return (self.flags & EVENT_READABLE) != 0

    @always_inline
    def is_writable(self) -> Bool:
        """Return True if ``EVENT_WRITABLE`` is set."""
        return (self.flags & EVENT_WRITABLE) != 0

    @always_inline
    def is_error(self) -> Bool:
        """Return True if ``EVENT_ERROR`` is set."""
        return (self.flags & EVENT_ERROR) != 0

    @always_inline
    def is_hup(self) -> Bool:
        """Return True if ``EVENT_HUP`` is set (remote closed)."""
        return (self.flags & EVENT_HUP) != 0

    @always_inline
    def is_wakeup(self) -> Bool:
        """Return True if this event is the reactor's internal wakeup.

        Callers usually ignore wakeup events — they exist only to break
        ``poll`` out of its wait when another thread wants attention.
        """
        return self.token == WAKEUP_TOKEN
