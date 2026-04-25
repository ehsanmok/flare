"""Tests for ``flare.runtime.Pool[T]`` (v0.5.0 Step 2 / Track 1.2).

Closes the user-visible portion of criticism §2.9: ``UnsafePointer``
plumbing is confined to ``flare/runtime/`` (``Pool[T]``); the rest
of the library calls ``Pool[T].alloc_move`` / ``Pool[T].free`` and
stays at the typed-``Int``-address layer.

The "AddressSanitizer clean on a 24h soak" gate from design-0.5
§1.2 is Linux-only and lands with the soak commit (S3.7); this
test file covers the happy path + lifetime semantics that any
allocator must get right.

Covers:

- ``alloc_move`` returns a non-zero address.
- The address resolves to the moved-in value (verified via
  ``get_ptr``).
- ``free`` runs ``T``'s destructor (verified via a counted-
  destructor harness).
- ``free(0)`` is a no-op (the documented sentinel).
- Repeated alloc + free cycles don't leak destructor calls.
- Stress: 1000 alloc + free cycles.
- ``Pool[T]`` works for non-trivial ``T`` (struct with String
  field).
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    TestSuite,
)

from flare.runtime import Pool


# ── Counted-destructor harness ─────────────────────────────────────────────
#
# We track every destruct via a heap-allocated Int counter. The
# harness struct holds the counter address; its destructor
# increments. Tests can read the counter before / after free()
# calls and assert the destructor ran exactly once.


from std.memory import UnsafePointer, alloc as _raw_alloc


struct _Counted(ImplicitlyDestructible, Movable):
    """Test harness: holds a value + an external counter address.
    The destructor bumps the counter so tests can verify free()
    actually called __del__."""

    var value: Int
    var counter_addr: Int

    def __init__(out self, value: Int, counter_addr: Int):
        self.value = value
        self.counter_addr = counter_addr

    def __del__(deinit self):
        if self.counter_addr == 0:
            return
        var p = UnsafePointer[Int, MutExternalOrigin](
            unsafe_from_address=self.counter_addr
        )
        p[] = p[] + 1


def _new_counter() raises -> Int:
    """Allocate an Int counter, init to 0, return its address."""
    var p = _raw_alloc[Int](1)
    if Int(p) == 0:
        raise Error("counter alloc failed")
    p.init_pointee_copy(0)
    return Int(p)


def _read_counter(addr: Int) -> Int:
    var p = UnsafePointer[Int, MutExternalOrigin](unsafe_from_address=addr)
    return p[]


def _free_counter(addr: Int):
    var p = UnsafePointer[Int, MutExternalOrigin](unsafe_from_address=addr)
    p.destroy_pointee()
    p.free()


# ── Happy path ─────────────────────────────────────────────────────────────


def test_alloc_returns_nonzero_address() raises:
    var c = _new_counter()
    var addr = Pool[_Counted].alloc_move(_Counted(7, c))
    assert_true(addr != 0)
    Pool[_Counted].free(addr)
    _free_counter(c)


def test_alloc_then_get_ptr_reads_value() raises:
    var c = _new_counter()
    var addr = Pool[_Counted].alloc_move(_Counted(99, c))
    var ptr = Pool[_Counted].get_ptr(addr)
    assert_equal(ptr[].value, 99)
    Pool[_Counted].free(addr)
    _free_counter(c)


# ── Destructor ─────────────────────────────────────────────────────────────


def test_free_calls_destructor_exactly_once() raises:
    var c = _new_counter()
    var addr = Pool[_Counted].alloc_move(_Counted(0, c))
    assert_equal(_read_counter(c), 0)
    Pool[_Counted].free(addr)
    assert_equal(_read_counter(c), 1)
    _free_counter(c)


def test_free_zero_is_noop() raises:
    var c = _new_counter()
    Pool[_Counted].free(0)
    Pool[_Counted].free(0)
    Pool[_Counted].free(0)
    assert_equal(_read_counter(c), 0)
    _free_counter(c)


# ── Cycles ─────────────────────────────────────────────────────────────────


def test_alloc_free_cycle_no_leak() raises:
    """Allocate + free repeatedly with the same counter; the
    destructor count must equal the alloc count (no leaks, no
    double-frees).
    """
    var c = _new_counter()
    for i in range(50):
        var addr = Pool[_Counted].alloc_move(_Counted(i, c))
        Pool[_Counted].free(addr)
    assert_equal(_read_counter(c), 50)
    _free_counter(c)


def test_thousand_cycles() raises:
    """Stress: 1000 alloc + free pairs."""
    var c = _new_counter()
    for i in range(1000):
        var addr = Pool[_Counted].alloc_move(_Counted(i, c))
        Pool[_Counted].free(addr)
    assert_equal(_read_counter(c), 1000)
    _free_counter(c)


# ── Non-trivial T ──────────────────────────────────────────────────────────


struct _Boxed(ImplicitlyDestructible, Movable):
    """Larger struct with a String field; tests Pool[T] handles
    non-POD types."""

    var greeting: String
    var n: Int

    def __init__(out self, greeting: String, n: Int):
        self.greeting = greeting
        self.n = n


def test_pool_with_string_field() raises:
    var addr = Pool[_Boxed].alloc_move(_Boxed("hello world", 42))
    var ptr = Pool[_Boxed].get_ptr(addr)
    assert_equal(ptr[].greeting, "hello world")
    assert_equal(ptr[].n, 42)
    Pool[_Boxed].free(addr)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
