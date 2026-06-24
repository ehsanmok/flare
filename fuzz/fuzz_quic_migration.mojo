"""Fuzz harness: QUIC connection-migration frame state transitions.

Drives arbitrary bytes through :func:`flare.quic.state.handle_frame_buf`
against a real :class:`flare.quic.state.Connection`, so the
NEW_CONNECTION_ID / RETIRE_CONNECTION_ID / PATH_CHALLENGE /
PATH_RESPONSE apply paths (RFC 9000 §19.15-§19.18) run end-to-end
-- not just the parser, but the state mutations they drive
(``peer_cids`` table, ``retire_prior_to`` pruning, path-validation
match). The frame-codec safety itself is covered separately by
``fuzz_quic_frame_decode``; this target focuses on the migration
state machine reached through the dispatcher.

Properties checked:

1. **No panic.** ``handle_frame_buf`` either consumes ``[1, n]``
   bytes or raises a regular ``Error`` on malformed input; it must
   never panic on arbitrary bytes.

2. **CID-table invariant.** Every stored peer CID has a length in
   the RFC 9000 §19.15 range [1, 20] and a 16-byte reset token,
   regardless of input.

3. **retire_prior_to monotonicity.** After ingestion no stored CID
   sequence number is below ``active_dcid_seq`` once a retire has
   advanced it (retired entries are dropped from the table).

The harness also seeds ``outgoing_path_challenge`` so the
PATH_RESPONSE match arm (validated / ignored) is exercised.

Run:
    pixi run --environment fuzz fuzz-quic-migration
"""

from mozz import FuzzConfig, fuzz

from flare.quic.state import (
    Connection,
    ConnectionEvents,
    empty_events,
    handle_frame_buf,
    new_connection,
)
from std.memory import Span


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


def _check_invariants(conn: Connection) raises:
    for entry in conn.peer_cids.items():
        var cid_len = len(entry.value.cid)
        _assert(
            cid_len >= 1 and cid_len <= 20,
            "quic migration: stored CID length out of [1, 20]",
        )
        _assert(
            len(entry.value.reset_token) == 16,
            "quic migration: stored reset token not 16 bytes",
        )
        _assert(
            entry.key >= conn.active_dcid_seq,
            "quic migration: stored CID below active sequence",
        )


def target(data: List[UInt8]) raises:
    var n = len(data)
    if n == 0:
        return

    var conn = new_connection()
    # Seed an outstanding path probe (first 8 input bytes, padded)
    # so the PATH_RESPONSE match/ignore arms both get reached.
    var probe = List[UInt8]()
    for i in range(8):
        probe.append(data[i % n])
    conn.outgoing_path_challenge = probe^

    var events = empty_events()
    var pos = 0
    var guard = 0
    # Drain the buffer frame by frame; a malformed frame stops the
    # walk (the codec raised), which is a valid outcome.
    while pos < n and guard < 4096:
        guard += 1
        var rest = List[UInt8]()
        for i in range(pos, n):
            rest.append(data[i])
        var span = Span[UInt8, _](rest)
        try:
            var consumed = handle_frame_buf(conn, span, UInt64(guard), events)
            _assert(
                consumed >= 1 and consumed <= len(rest),
                "quic migration: consumed out of bounds",
            )
            pos += consumed
        except:
            break
        _check_invariants(conn)

    # PATH_RESPONSE validation is one-shot: once validated, the probe
    # is cleared.
    if conn.path_validated:
        _assert(
            len(conn.outgoing_path_challenge) == 0,
            "quic migration: validated path left a dangling probe",
        )


def main() raises:
    print("=" * 60)
    print("fuzz_quic_migration.mojo -- RFC 9000 §19.15-§19.18 migration")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    # NEW_CONNECTION_ID seq=1 rpt=0 cid=4B token=16B
    seeds.append(
        _bytes(
            "\x18\x01\x00\x04\xaa\xbb\xcc\xdd"
            "\x00\x01\x02\x03\x04\x05\x06\x07"
            "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        )
    )
    # NEW_CONNECTION_ID seq=2 rpt=2 (retires prior) cid + token
    seeds.append(
        _bytes(
            "\x18\x02\x02\x04\x11\x22\x33\x44"
            "\x10\x11\x12\x13\x14\x15\x16\x17"
            "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        )
    )
    seeds.append(_bytes("\x19\x03"))  # RETIRE_CONNECTION_ID seq=3
    seeds.append(
        _bytes("\x1a\x00\x01\x02\x03\x04\x05\x06\x07")
    )  # PATH_CHALLENGE
    seeds.append(
        _bytes("\x1b\x00\x01\x02\x03\x04\x05\x06\x07")
    )  # PATH_RESPONSE

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_migration",
            corpus_dir="fuzz/corpus/quic_migration",
            max_input_len=256,
        ),
        seeds,
    )
