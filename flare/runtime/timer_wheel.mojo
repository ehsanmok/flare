"""Hashed timing wheel for the flare reactor.

Manages per-connection timeouts in user space, independent of the kernel.
We manage timeouts here (rather than via ``SO_RCVTIMEO`` /
``SO_SNDTIMEO`` on sockets) because a non-blocking reactor integrates
cleaner with a single shared monotonic clock than with many per-socket
options, and because per-fd timer fd registration would explode fd usage
on large connection counts.

Design:
- **Single-level wheel, 512 slots, 1 ms per slot.** Covers any timeout up
  to ~512 ms in the wheel itself; longer timeouts go to an overflow list
  and get "promoted" into the wheel on each advance.
- **O(1) schedule** into the wheel slot or the overflow list.
- **O(1) cancel** (mark as inactive in a dict; physical removal on fire).
- **O(k) advance** where k = number of slots to traverse plus overflow
  entries to promote. In practice k is 1-2 per millisecond in a steady
  state.

Usage::

    from flare.runtime import TimerWheel
    var tw = TimerWheel(now_ms=monotonic_ms())

    var tid = tw.schedule(after_ms=500, token=UInt64(0x1234))
    # ... later ...
    _ = tw.cancel(tid)

    # On every reactor iteration:
    var fired = List[UInt64]()
    tw.advance(monotonic_ms(), fired)
    # dispatch each token in `fired` as a timeout
"""

from std.collections import Dict


comptime _WHEEL_SLOTS: Int = 512
comptime _WHEEL_MASK: Int = 511


struct _TimerEntry(Copyable, ImplicitlyCopyable, Movable):
    """One timer bookkeeping entry.

    Stored in ``TimerWheel._entries`` (dict by id) and referenced by ID
    from the slot lists.
    """

    var id: UInt64
    var fire_at_ms: UInt64
    var token: UInt64
    var active: Bool

    def __init__(
        out self,
        id: UInt64,
        fire_at_ms: UInt64,
        token: UInt64,
        active: Bool,
    ):
        """Construct a timer entry.

        Args:
            id: Monotonic timer identifier assigned by ``schedule``.
            fire_at_ms: Absolute millisecond time when this timer should
                fire.
            token: User-provided opaque token reported back on fire.
            active: False when cancelled; True otherwise.
        """
        self.id = id
        self.fire_at_ms = fire_at_ms
        self.token = token
        self.active = active


struct TimerWheel(Movable):
    """Fixed-size hashed timing wheel with an overflow list.

    Thread-unsafe; intended to be driven by the reactor on a single thread.
    Cross-thread cancellation is a Stage 2+ concern.
    """

    var _wheel: List[List[UInt64]]
    """``_WHEEL_SLOTS`` lists of timer IDs, one per slot."""

    var _overflow: List[UInt64]
    """Timer IDs whose fire_at is beyond one full wheel rotation."""

    var _entries: Dict[UInt64, _TimerEntry]
    """ID -> entry map for O(1) cancel and lookup."""

    var _current_slot: Int
    """Index (0.._WHEEL_SLOTS-1) of the slot representing the current tick.
    """

    var _current_tick_ms: UInt64
    """Absolute time (ms) corresponding to ``_current_slot``."""

    var _next_id: UInt64
    """Monotonically increasing ID counter; starts at 1 (0 is reserved)."""

    def __init__(out self, now_ms: UInt64 = 0):
        """Create a wheel anchored at the given monotonic time.

        Args:
            now_ms: Absolute millisecond value representing "now" at
                construction. Subsequent ``advance`` / ``schedule`` times
                must be expressed on the same clock.
        """
        self._wheel = List[List[UInt64]]()
        for _ in range(_WHEEL_SLOTS):
            self._wheel.append(List[UInt64]())
        self._overflow = List[UInt64]()
        self._entries = Dict[UInt64, _TimerEntry]()
        self._current_slot = 0
        self._current_tick_ms = now_ms
        self._next_id = 0

    def schedule(mut self, after_ms: Int, token: UInt64) raises -> UInt64:
        """Schedule a timer to fire after ``after_ms`` milliseconds.

        ``after_ms <= 0`` is clamped to 1 — timers fire on the next
        ``advance``, not on the current tick (``advance`` processes each
        tick *after* incrementing the clock, so a timer placed in the
        current slot would only fire after a full rotation).

        Args:
            after_ms: Delay in milliseconds relative to the current tick.
            token: Arbitrary user value reported back via ``advance``.

        Returns:
            A unique timer ID that can be passed to ``cancel``.
        """
        self._next_id += 1
        var id = self._next_id
        var delay = after_ms if after_ms >= 1 else 1
        var fire_at = self._current_tick_ms + UInt64(delay)
        self._entries[id] = _TimerEntry(id, fire_at, token, True)
        if delay < _WHEEL_SLOTS:
            var slot = (self._current_slot + delay) & _WHEEL_MASK
            self._wheel[slot].append(id)
        else:
            self._overflow.append(id)
        return id

    def cancel(mut self, id: UInt64) raises -> Bool:
        """Cancel a previously-scheduled timer.

        Safe to call for already-fired or never-scheduled IDs; returns
        False in those cases. The cancellation is lazy: the entry is
        flagged inactive and physically removed the next time the slot
        containing it is processed by ``advance``.

        Args:
            id: Timer ID returned by ``schedule``.

        Returns:
            True if a matching active timer was cancelled; False if the
            ID was already fired, already cancelled, or never scheduled.
        """
        if id in self._entries:
            var e = self._entries[id]
            if e.active:
                e.active = False
                self._entries[id] = e
                return True
        return False

    def advance(
        mut self, now_ms: UInt64, mut fired: List[UInt64]
    ) raises -> None:
        """Advance the wheel to ``now_ms``, appending fired tokens to ``fired``.

        Each tick (millisecond) between the current time and ``now_ms`` is
        processed in order:

        1. The current slot's entry list is drained; entries that are
           still ``active`` append their token to ``fired`` and are then
           removed from ``_entries``. Cancelled entries are silently
           removed.
        2. Any overflow entries whose ``fire_at_ms`` now fits within one
           rotation are promoted into the appropriate wheel slot.

        ``now_ms`` must be monotonically non-decreasing across calls.
        Regressing it is undefined behaviour.

        Args:
            now_ms: Current absolute millisecond time (same clock as
                ``now_ms`` passed to ``__init__``).
            fired: Output list; fired tokens are appended. The caller
                does not need to clear it first.
        """
        while self._current_tick_ms < now_ms:
            # Advance the clock FIRST, then process the slot that
            # corresponds to the new tick. This matches ``schedule``'s
            # choice of ``slot = (current_slot + delay)`` — a timer with
            # delay=D placed at slot s lands at the iteration whose
            # current_tick_ms == initial_tick + D.
            self._current_tick_ms += 1
            self._current_slot = (self._current_slot + 1) & _WHEEL_MASK

            # Drain the slot we just arrived at. Move the list out first
            # so mutation during iteration is impossible.
            var ids = self._wheel[self._current_slot].copy()
            self._wheel[self._current_slot] = List[UInt64]()
            for i in range(len(ids)):
                var eid = ids[i]
                if eid in self._entries:
                    var entry = self._entries[eid]
                    if entry.active:
                        fired.append(entry.token)
                    _ = self._entries.pop(eid)

            # Promote overflow entries whose fire time is within one
            # rotation of the new current tick, or whose fire time has
            # already passed.
            if len(self._overflow) > 0:
                var new_overflow = List[UInt64]()
                for i in range(len(self._overflow)):
                    var eid = self._overflow[i]
                    if eid not in self._entries:
                        continue  # already removed
                    var entry = self._entries[eid]
                    if not entry.active:
                        _ = self._entries.pop(eid)
                        continue
                    if entry.fire_at_ms <= self._current_tick_ms:
                        fired.append(entry.token)
                        _ = self._entries.pop(eid)
                    elif entry.fire_at_ms - self._current_tick_ms < UInt64(
                        _WHEEL_SLOTS
                    ):
                        var dt = Int(entry.fire_at_ms - self._current_tick_ms)
                        var target = (self._current_slot + dt) & _WHEEL_MASK
                        self._wheel[target].append(eid)
                    else:
                        new_overflow.append(eid)
                self._overflow = new_overflow^

    def now_ms(self) -> UInt64:
        """Return the current tick time tracked by the wheel."""
        return self._current_tick_ms

    def active_count(self) raises -> Int:
        """Return the number of scheduled-and-not-yet-cancelled timers.

        Inactive (cancelled but not yet reaped) entries are excluded.
        """
        var n = 0
        for entry in self._entries.values():
            if entry.active:
                n += 1
        return n

    def next_fire_ms(self) raises -> UInt64:
        """Absolute time of the soonest scheduled fire, or ``now_ms`` + 2^32
        if no timers are active.

        Useful for sizing the reactor poll timeout: the reactor should
        wake up at least by this time so the wheel can fire pending
        timers on its next ``advance``.
        """
        var earliest: UInt64 = self._current_tick_ms + UInt64(0xFFFFFFFF)
        for entry in self._entries.values():
            if entry.active and entry.fire_at_ms < earliest:
                earliest = entry.fire_at_ms
        return earliest
