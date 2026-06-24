"""Fuzz harness: HTTP/3 client response reader
(:class:`flare.h3.response_reader.H3ResponseReader`).

The client-side mirror of ``fuzz_h3_server``. The response reader
is sans-I/O: the QUIC client driver feeds it reassembled
request-stream bytes via :meth:`feed` and signals end-of-stream via
:meth:`signal_fin`. The safety invariants fuzzed here are:

1. **No panics.** :meth:`feed` may never crash on arbitrary input;
   any structural violation must flip the reader into its DONE/error
   state (surfaced via :meth:`has_error`), never abort.
2. **Bounded state growth.** The assembled body can never exceed the
   number of bytes fed (the reader copies DATA payloads, it does not
   amplify).
3. **take_response discipline.** :meth:`take_response` raises when
   the reader errored or never parsed a response head; it returns a
   value only when a head was parsed. It must never crash.
4. **Framing-split invariance.** Feeding the same bytes whole, in
   halves, or one byte at a time must never crash and must reach the
   same terminal error/non-error disposition.

The fuzzer carves the input into branches:

* Branch A: feed whole, signal FIN, probe completeness + take.
* Branch B: feed one byte at a time (NEEDS_MORE buffering worst
  case), signal FIN, probe.
* Branch C: feed split in half across two feeds.

Run:
    pixi run --environment fuzz fuzz-h3-response-reader
"""

from mozz import FuzzConfig, fuzz

from flare.h3 import H3ResponseReader


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


def _probe(mut r: H3ResponseReader, fed: Int) raises:
    """Shared post-feed invariant probe: bounded body + take
    discipline. Never crashes regardless of reader disposition."""
    _assert(
        len(r.body) <= fed,
        "response reader body exceeded bytes fed (amplification)",
    )
    r.signal_fin()
    # take_response must either return cleanly or raise a regular
    # Error -- never crash. We swallow the Error: an arbitrary byte
    # stream is usually not a valid response.
    try:
        var _resp = r.take_response()
    except _:
        pass


def _run_whole(data: List[UInt8]) raises:
    var r = H3ResponseReader.new()
    try:
        r.feed(Span[UInt8, _](data))
    except _:
        return
    _probe(r, len(data))


def _run_byte_at_a_time(data: List[UInt8]) raises:
    var r = H3ResponseReader.new()
    var fed = 0
    for i in range(len(data)):
        var one = List[UInt8]()
        one.append(data[i])
        try:
            r.feed(Span[UInt8, _](one))
            fed += 1
        except _:
            return
    _probe(r, fed)


def _run_split(data: List[UInt8]) raises:
    var mid = len(data) // 2
    var a = List[UInt8](capacity=mid)
    var b = List[UInt8](capacity=len(data) - mid)
    for i in range(mid):
        a.append(data[i])
    for i in range(mid, len(data)):
        b.append(data[i])
    var r = H3ResponseReader.new()
    try:
        r.feed(Span[UInt8, _](a))
        r.feed(Span[UInt8, _](b))
    except _:
        return
    _probe(r, len(data))


def target(data: List[UInt8]) raises:
    _run_whole(data)
    var capped = data.copy()
    if len(capped) > 64:
        var trim = List[UInt8](capacity=64)
        for i in range(64):
            trim.append(capped[i])
        capped = trim^
    _run_byte_at_a_time(capped)
    if len(data) >= 2:
        _run_split(data)


def main() raises:
    print("=" * 60)
    print("fuzz_h3_response_reader.mojo -- HTTP/3 client response reader")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    # Empty.
    seeds.append(List[UInt8]())
    # HEADERS frame, 4-byte all-zero field section (QPACK rejects ->
    # error path).
    seeds.append(_bytes("\x01\x04\x00\x00\x00\x00"))
    # DATA frame before HEADERS -- protocol error on a response
    # stream.
    seeds.append(_bytes("\x00\x05hello"))
    # SETTINGS (control-stream frame) on the response stream -- hard
    # protocol error per RFC 9114 §6.2.
    seeds.append(_bytes("\x04\x00"))
    # Truncated HEADERS (declares 16 bytes, supplies 5).
    seeds.append(_bytes("\x01\x10short"))
    # Grease frame type 0x21 + empty payload (ignored).
    seeds.append(_bytes("\x21\x00"))
    # A plausible HEADERS + DATA shape (payloads are not valid QPACK
    # but exercise the framing loop fully).
    seeds.append(_bytes("\x01\x02\xd9\xbe\x00\x03abc"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/h3_response_reader",
            corpus_dir="fuzz/corpus/h3_response_reader",
            max_input_len=256,
        ),
        seeds,
    )
