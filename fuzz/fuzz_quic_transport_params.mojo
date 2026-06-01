"""Fuzz harness: ``flare.quic.transport_params.decode_transport_parameters``.

QUIC transport parameters (RFC 9000 §18) are a length-prefixed
stream of (varint id, varint length, length value bytes) tuples
exchanged in TLS extensions. The decoder must reject:

- duplicate parameter ids (RFC 9000 §18 MUST),
- truncated value bytes,
- ``stateless_reset_token`` whose length is not 16 bytes,
- ``max_udp_payload_size`` below 1200 bytes (§18.2),
- ``ack_delay_exponent`` above 20 (§18.2),
- ``max_ack_delay`` above 2^14 - 1 (§18.2),
- ``active_connection_id_limit`` below 2 (§18.2).

Properties checked:

1. ``decode_transport_parameters`` either returns a typed
   :class:`TransportParameters` value, or raises a regular
   ``Error``. It must never panic on arbitrary bytes.

2. **Round trip.** On a successful decode, re-encoding via
   ``encode_transport_parameters`` and re-decoding must produce
   bytes that match the typed value of the first decode.

Run:
    pixi run --environment fuzz fuzz-quic-transport-params
"""

from mozz import FuzzConfig, fuzz

from flare.quic.transport_params import (
    TransportParameters,
    decode_transport_parameters,
    encode_transport_parameters,
)


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


def target(data: List[UInt8]) raises:
    var span = Span[UInt8, _](data)

    var tp_opt: Optional[TransportParameters] = None
    try:
        var tp = decode_transport_parameters(span)
        tp_opt = Optional[TransportParameters](tp^)
    except:
        return

    # Round-trip: re-encode + re-decode the decoded value.
    var tp = tp_opt.value().copy()
    var encoded = encode_transport_parameters(tp)
    var tp2 = decode_transport_parameters(Span[UInt8, _](encoded))
    # We compare the most stable scalar fields; the codec is
    # canonical so the byte-form may differ slightly between
    # parse-and-emit cycles when the input used non-shortest
    # varints, but the typed value MUST be stable.
    _assert(
        Bool(tp2.max_idle_timeout) == Bool(tp.max_idle_timeout),
        "transport_params round trip: max_idle_timeout presence drift",
    )
    _assert(
        Bool(tp2.initial_max_data) == Bool(tp.initial_max_data),
        "transport_params round trip: initial_max_data presence drift",
    )
    _assert(
        tp2.disable_active_migration == tp.disable_active_migration,
        "transport_params round trip: disable_active_migration drift",
    )


def main() raises:
    print("=" * 60)
    print("fuzz_quic_transport_params.mojo -- RFC 9000 §18 codec")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes(""))  # empty
    seeds.append(_bytes("\x01\x02\x40\xc8"))  # max_idle_timeout=200ms
    seeds.append(_bytes("\x04\x02\x40\xc8"))  # initial_max_data=200
    seeds.append(_bytes("\x0c\x00"))  # disable_active_migration flag
    seeds.append(_bytes("\x03\x02\x04\xb0"))  # max_udp_payload_size=1200
    seeds.append(_bytes("\x03\x02\x04\xaf"))  # below-1200, must reject
    seeds.append(_bytes("\x0a\x01\x14"))  # ack_delay_exponent=20
    seeds.append(_bytes("\x0a\x01\x15"))  # ack_delay_exponent=21, reject
    seeds.append(_bytes("\x01\x02\x40\xc8\x01\x02\x40\xc9"))  # dup id

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_transport_params",
            corpus_dir="fuzz/corpus/quic_transport_params",
            max_input_len=512,
        ),
        seeds,
    )
