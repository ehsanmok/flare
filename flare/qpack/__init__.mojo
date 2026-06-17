"""``flare.qpack`` -- static-only QPACK encoder/decoder (RFC 9204).

HTTP/3 uses QPACK on top of QUIC streams; this package ships the
**static-only** subset: every wire shape that references the RFC
9204 Appendix A static table, plus literal field lines with
literal names. Dynamic-table support (the encoder/decoder QUIC
streams + the in-band insertion protocol) is a follow-up.

The codec lives entirely in the sans-I/O sublayer; tests live in
``tests/qpack/test_qpack.mojo`` and the H3 frame layer
(``flare.h3``) is the call site that consumes it.
"""

from .codec import (
    QpackHeader,
    decode_field_section,
    encode_field_section,
)
from .static_table import (
    QPACK_STATIC_TABLE_SIZE,
    static_table_find,
    static_table_find_name,
    static_table_lookup,
)
